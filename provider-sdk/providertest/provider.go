/*
Copyright The Platform Mesh Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package providertest is a Provider-side for PM-side tests: the SDK's
// Connection API and Session registry, over a fake cluster, behind a TLS
// server standing in for the Provider's Edge. platform-mesh-operator's and
// the Connector's tests register, call and open Sessions against it.
package providertest

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/connapi"
	"go.platform-mesh.io/provider-sdk/internal/controllers"
	"go.platform-mesh.io/provider-sdk/internal/endpoint"
	"go.platform-mesh.io/provider-sdk/internal/metrics/metricstest"
	"go.platform-mesh.io/provider-sdk/internal/session"
	"go.platform-mesh.io/provider-sdk/token"
)

// basePath is where the Base URL sits on the test server: the Connection
// API routes by the path below /v1/connections/, wherever that is.
const basePath = "/provider"

// Option configures a Provider.
type Option func(*options)

type options struct {
	namespace   string
	now         func() time.Time
	retryWindow time.Duration
	watch       bool
}

// WithNamespace sets the namespace of the SDK's resources. Default
// "provider-system".
func WithNamespace(ns string) Option { return func(o *options) { o.namespace = ns } }

// WithClock sets the Provider-side's clock, e.g. to testvectors.Now when
// the PM-side uses its certificates. Default time.Now.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithRetryWindow sets how long after a token's expiry Registration
// retries are honoured. Default 7 days.
func WithRetryWindow(d time.Duration) Option { return func(o *options) { o.retryWindow = d } }

// WithProviderEndpointWatch makes the Provider-side watch each Connection's
// ProviderEndpoint over its Sessions, as provider-gateway does: it lists
// and watches through the Connector as soon as a Session opens.
func WithProviderEndpointWatch() Option { return func(o *options) { o.watch = true } }

// Provider is a Provider-side under test.
type Provider struct {
	// BaseURL is the Connection API's Base URL.
	BaseURL string
	// OuterRoots trust the stand-in Edge's certificate.
	OuterRoots *x509.CertPool
	// Client is the fake cluster with the SDK's resources, for direct edits.
	Client    client.Client
	Namespace string
	// Metrics are provider-gateway's.
	Metrics *prometheus.Registry

	t           testing.TB
	now         func() time.Time
	start       time.Time
	leader      atomic.Bool
	registry    *session.Registry
	keys        *controllers.ServerKeyReconciler
	nkeys       int
	connections *controllers.ConnectionReconciler
	tokens      *controllers.OnboardingTokenReconciler
}

// New starts a Provider-side with one ServerKey. It stops when the test
// ends.
func New(t testing.TB, opts ...Option) *Provider {
	t.Helper()
	o := options{namespace: "provider-system", now: time.Now, retryWindow: 7 * 24 * time.Hour}
	for _, opt := range opts {
		opt(&o)
	}

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&sdkv1alpha1.Connection{}, &sdkv1alpha1.OnboardingToken{}, &sdkv1alpha1.ServerKey{}).
		Build()

	m, reg := metricstest.New(t)
	p := &Provider{
		Client:    c,
		Namespace: o.namespace,
		Metrics:   reg,
		t:         t,
		now:       o.now,
		start:     o.now(),
		registry:  session.NewRegistry(),
		keys:      &controllers.ServerKeyReconciler{Client: c, Namespace: o.namespace},
	}
	p.leader.Store(true)
	p.registry.Metrics = m
	recorder := &record.FakeRecorder{} // no channel: Events are dropped
	p.connections = &controllers.ConnectionReconciler{
		Client: c, APIReader: c, Sessions: p.registry, Recorder: recorder, Now: o.now,
	}
	p.tokens = &controllers.OnboardingTokenReconciler{Client: c, RetryWindow: o.retryWindow, Now: o.now}
	if o.watch {
		endpoints := endpoint.NewManager(c, o.namespace, p.registry, recorder, logr.Discard())
		t.Cleanup(endpoints.Stop)
	}

	srv := httptest.NewTLSServer(connapi.New(connapi.Config{
		Client:      c,
		Namespace:   o.namespace,
		Keys:        &controllers.KeyStore{Client: c, Namespace: o.namespace},
		Sessions:    p.registry,
		RetryWindow: o.retryWindow,
		Limits:      connapi.Limits{UnknownInterval: time.Millisecond},
		IsLeader:    p.leader.Load,
		Metrics:     m,
		Now:         o.now,
		Log:         logr.Discard(),
	}))
	t.Cleanup(func() {
		// Hijacked connections outlive the server: end the Sessions first.
		var conns sdkv1alpha1.ConnectionList
		if err := c.List(context.Background(), &conns); err == nil {
			for _, conn := range conns.Items {
				p.registry.CloseConnection(conn.Name)
			}
		}
		srv.Close()
	})
	p.BaseURL = srv.URL + basePath
	p.OuterRoots = x509.NewCertPool()
	p.OuterRoots.AddCert(srv.Certificate())

	p.AddServerKey()
	return p
}

// SetLeader makes the Provider-side the active replica or a standby, which
// refuses upgrades with 503 and Retry-After.
func (p *Provider) SetLeader(leader bool) { p.leader.Store(leader) }

// AddServerKey adds a new ServerKey, the newest, as a rotation does, and
// returns its name. Connections move to it once their ProviderEndpoint
// lists it.
func (p *Provider) AddServerKey() string {
	p.t.Helper()
	p.nkeys++
	name := fmt.Sprintf("sk-%d", p.nkeys)
	require.NoError(p.t, p.Client.Create(context.Background(), &sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: p.Namespace,
		// Newest last, whatever the clock.
		CreationTimestamp: metav1.NewTime(p.start.Add(time.Duration(p.nkeys) * time.Second)),
	}}))
	_, err := p.keys.Reconcile(context.Background(), reconcile.Request{NamespacedName: p.name(name)})
	require.NoError(p.t, err)
	return name
}

// RetireServerKey sets a ServerKey's retireAt: no new tokens over it, and
// it's no longer announced from at.
func (p *Provider) RetireServerKey(name string, at time.Time) {
	p.t.Helper()
	var key sdkv1alpha1.ServerKey
	require.NoError(p.t, p.Client.Get(context.Background(), p.name(name), &key))
	retire := metav1.NewTime(at)
	key.Spec.RetireAt = &retire
	require.NoError(p.t, p.Client.Update(context.Background(), &key))
}

// ServerKeys are the announced Server Keys, oldest first, as the status
// call returns them.
func (p *Provider) ServerKeys() []connectionsv1.ServerKey {
	var out []connectionsv1.ServerKey
	for _, k := range p.announced() {
		out = append(out, connectionsv1.ServerKey{PublicKey: k.Status.PublicKey})
	}
	return out
}

// ServerKeyFingerprints are the announced Server Keys' key-sha256
// fingerprints, oldest first: what the PM-side pins.
func (p *Provider) ServerKeyFingerprints() []fingerprint.Fingerprint {
	p.t.Helper()
	var out []fingerprint.Fingerprint
	for _, k := range p.announced() {
		fp, err := fingerprint.ParseKind(k.Status.Fingerprint, fingerprint.KeySHA256)
		require.NoError(p.t, err)
		out = append(out, fp)
	}
	return out
}

func (p *Provider) announced() []sdkv1alpha1.ServerKey {
	p.t.Helper()
	var list sdkv1alpha1.ServerKeyList
	require.NoError(p.t, p.Client.List(context.Background(), &list, client.InNamespace(p.Namespace)))
	now := p.now()
	keys := slices.DeleteFunc(list.Items, func(k sdkv1alpha1.ServerKey) bool {
		return k.Status.PublicKey == "" ||
			!meta.IsStatusConditionTrue(k.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady) ||
			(k.Spec.RetireAt != nil && !now.Before(k.Spec.RetireAt.Time))
	})
	slices.SortFunc(keys, func(a, b sdkv1alpha1.ServerKey) int { return a.CreationTimestamp.Compare(b.CreationTimestamp.Time) })
	return keys
}

// IssueToken issues an Onboarding Token for owner over the newest usable
// ServerKey, as a portal does, and returns the token string.
func (p *Provider) IssueToken(owner string, ttl time.Duration) string {
	p.t.Helper()
	var list sdkv1alpha1.ServerKeyList
	require.NoError(p.t, p.Client.List(context.Background(), &list, client.InNamespace(p.Namespace)))
	key, err := token.PickServerKey(list.Items)
	require.NoError(p.t, err)
	tok, obj, err := token.New(p.BaseURL, owner, p.Namespace, ttl, key, p.now())
	require.NoError(p.t, err)
	require.NoError(p.t, p.Client.Create(context.Background(), obj))
	return tok
}

// ConnectionSpec describes a Connection created without Registration, as
// an import does.
type ConnectionSpec struct {
	// ClusterName is the Provider Workspace's logical cluster.
	ClusterName string
	// Secret is the Connection Secret; only its hash is stored.
	Secret credential.ConnectionSecret
	// ConnectorCASet becomes the Pinned Bundle.
	ConnectorCASet []byte
	// Owner defaults to "owner@example.com".
	Owner string
}

// AddConnection creates a Connection listing every announced ServerKey,
// and returns its ID.
func (p *Provider) AddConnection(spec ConnectionSpec) string {
	p.t.Helper()
	pinned, err := bundle.Parse(spec.ConnectorCASet, p.now())
	require.NoError(p.t, err)
	if spec.Owner == "" {
		spec.Owner = "owner@example.com"
	}
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{
			Name: credential.NewConnectionID(), Namespace: p.Namespace,
			Finalizers: []string{sdkv1alpha1.ConnectionFinalizer},
		},
		Spec: sdkv1alpha1.ConnectionSpec{
			Registration: sdkv1alpha1.ConnectionRegistration{Owner: spec.Owner, ClusterName: spec.ClusterName},
			PinnedBundle: string(pinned.Encode()),
		},
	}
	require.NoError(p.t, p.Client.Create(context.Background(), conn))
	conn.Status.SecretHash = spec.Secret.Hash().String()
	for _, k := range p.announced() {
		conn.Status.ListedServerKeys = append(conn.Status.ListedServerKeys, k.Name)
	}
	require.NoError(p.t, p.Client.Status().Update(context.Background(), conn))
	return conn.Name
}

// Connection returns the Connection id.
func (p *Provider) Connection(id string) (*sdkv1alpha1.Connection, error) {
	var conn sdkv1alpha1.Connection
	if err := p.Client.Get(context.Background(), p.name(id), &conn); err != nil {
		return nil, err
	}
	return &conn, nil
}

// DeleteConnection removes a Connection on the Provider-side, as the
// Owner's portal does, and closes its Sessions.
func (p *Provider) DeleteConnection(id string) {
	p.t.Helper()
	conn, err := p.Connection(id)
	require.NoError(p.t, err)
	require.NoError(p.t, p.Client.Delete(context.Background(), conn))
	p.Reconcile()
}

// Reconcile runs the Connection and OnboardingToken controllers once over
// every object: finalizers, Pinned Bundle re-checks, lastSeen, Ready,
// orphan expiry, token garbage collection.
func (p *Provider) Reconcile() {
	p.t.Helper()
	ctx := context.Background()
	var conns sdkv1alpha1.ConnectionList
	require.NoError(p.t, p.Client.List(ctx, &conns, client.InNamespace(p.Namespace)))
	for _, c := range conns.Items {
		_, err := p.connections.Reconcile(ctx, reconcile.Request{NamespacedName: p.name(c.Name)})
		require.NoError(p.t, err, c.Name)
	}
	var toks sdkv1alpha1.OnboardingTokenList
	require.NoError(p.t, p.Client.List(ctx, &toks, client.InNamespace(p.Namespace)))
	for _, tok := range toks.Items {
		_, err := p.tokens.Reconcile(ctx, reconcile.Request{NamespacedName: p.name(tok.Name)})
		require.NoError(p.t, err, tok.Name)
	}
}

func (p *Provider) name(n string) types.NamespacedName {
	return types.NamespacedName{Namespace: p.Namespace, Name: n}
}
