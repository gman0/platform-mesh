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

package connapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/innertls"
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/pmtest"
)

const ns = "wild-west-system"

// fixture is a Connection API server with one ServerKey, in front of a fake
// cluster, and a fake PM-side trusting it.
type fixture struct {
	t      *testing.T
	client client.Client
	srv    *httptest.Server
	server *Server
	key    innertls.ServerKey
	keyObj *sdkv1alpha1.ServerKey
	pm     *pmtest.PM
	now    time.Time
	leader bool
}

type keys map[string]innertls.ServerKey

func (k keys) Get(_ context.Context, name string) (innertls.ServerKey, error) {
	if key, ok := k[name]; ok {
		return key, nil
	}
	return innertls.ServerKey{}, fmt.Errorf("no key %s", name)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := innertls.NewServerKey(priv)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	require.NoError(t, err)

	keyObj := &sdkv1alpha1.ServerKey{
		ObjectMeta: metav1.ObjectMeta{Name: "sk-1", Namespace: ns},
		Status: sdkv1alpha1.ServerKeyStatus{
			PublicKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			Fingerprint: key.Fingerprint.String(),
			Conditions: []metav1.Condition{{
				Type: sdkv1alpha1.ServerKeyConditionReady, Status: metav1.ConditionTrue, Reason: sdkv1alpha1.ServerKeyReasonAsExpected,
			}},
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&sdkv1alpha1.Connection{}, &sdkv1alpha1.OnboardingToken{}, &sdkv1alpha1.ServerKey{}).
		WithObjects(keyObj).Build()

	f := &fixture{t: t, client: c, key: key, keyObj: keyObj, pm: pmtest.New(t), now: tv.Now, leader: true}
	f.server = New(Config{
		Client:    c,
		Namespace: ns,
		Keys:      keys{"sk-1": key},
		IsLeader:  func() bool { return f.leader },
		Limits:    Limits{UnknownInterval: time.Millisecond},
		Now:       func() time.Time { return f.now },
	})
	f.srv = httptest.NewTLSServer(http.StripPrefix("/pm", f.server))
	t.Cleanup(f.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	f.pm.OuterRoots = pool
	return f
}

// issue creates an OnboardingToken over the fixture's key and returns it.
func (f *fixture) issue(expiresIn time.Duration) credential.OnboardingToken {
	f.t.Helper()
	tok, err := credential.NewOnboardingToken(f.srv.URL+"/pm", f.key.Fingerprint)
	require.NoError(f.t, err)
	require.NoError(f.t, f.client.Create(context.Background(), &sdkv1alpha1.OnboardingToken{
		ObjectMeta: metav1.ObjectMeta{Name: tok.ID(), Namespace: ns},
		Spec: sdkv1alpha1.OnboardingTokenSpec{
			Owner:     "alice@example.com",
			ExpiresAt: metav1.NewTime(f.now.Add(expiresIn)),
			TokenHash: tok.SecretHash().String(),
			ServerKey: "sk-1",
		},
	}))
	return tok
}

func (f *fixture) register(tok credential.OnboardingToken, req connectionsv1.RegistrationRequest) (*connectionsv1.RegistrationResponse, error) {
	return f.pm.Register(context.Background(), tok, req)
}

func (f *fixture) request() connectionsv1.RegistrationRequest {
	return tv.RegistrationRequest(f.pm.ConnectorCASet())
}

func TestRegister(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)
	req := f.request()

	resp, err := f.register(tok, req)
	require.NoError(t, err)
	require.NoError(t, credential.ValidateConnectionID(resp.ConnectionID))
	assert.Equal(t, []connectionsv1.ServerKey{{PublicKey: f.keyObj.Status.PublicKey}}, resp.ServerKeys)

	var conn sdkv1alpha1.Connection
	require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: resp.ConnectionID}, &conn))
	assert.Equal(t, "alice@example.com", conn.Spec.Registration.Owner)
	assert.Equal(t, req.ClusterName, conn.Spec.Registration.ClusterName)
	assert.Equal(t, resp.UnusedExpiresAt, conn.Spec.Registration.UnusedExpiresAt.UTC())
	assert.Equal(t, req.SecretHash, conn.Status.SecretHash)
	assert.Equal(t, []string{"sk-1"}, conn.Status.ListedServerKeys)
	assert.Contains(t, conn.Finalizers, sdkv1alpha1.ConnectionFinalizer)

	var spent sdkv1alpha1.OnboardingToken
	require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: tok.ID()}, &spent))
	require.NotNil(t, spent.Status.Registration)
	assert.Equal(t, resp.ConnectionID, spent.Status.Registration.ConnectionID)
}

func TestRegisterRetries(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)
	first, err := f.register(tok, f.request())
	require.NoError(t, err)

	other := tv.CA(t, "after a Rollover", nil).PEM()
	for _, c := range tv.RegistrationRetries(f.pm.ConnectorCASet(), other) {
		resp, err := f.register(tok, c.Retry)
		if c.Want == "" {
			require.NoError(t, err, c.Name)
			assert.Equal(t, first, resp, c.Name)
		} else {
			assert.Equal(t, c.Want, pmtest.ReasonOf(err), c.Name)
		}
	}

	var conns sdkv1alpha1.ConnectionList
	require.NoError(t, f.client.List(context.Background(), &conns))
	assert.Len(t, conns.Items, 1, "retries never create a second Connection")

	// After the token's expiry, retries are honoured for the retry window.
	f.now = f.now.Add(time.Hour)
	resp, err := f.register(tok, f.request())
	require.NoError(t, err)
	assert.Equal(t, first, resp)
}

func TestRegisterRefusedBeforeUpgrade(t *testing.T) {
	f := newFixture(t)

	unknown, err := credential.NewOnboardingToken(f.srv.URL+"/pm", f.key.Fingerprint)
	require.NoError(t, err)
	expired := f.issue(-time.Minute)
	spent := f.issue(time.Minute)
	_, err = f.register(spent, f.request())
	require.NoError(t, err)

	cases := map[string]struct {
		tok    credential.OnboardingToken
		detail connectionsv1.TokenRefusal
		at     time.Time
	}{
		"unknown":                 {unknown, connectionsv1.TokenUnknown, f.now},
		"expired":                 {expired, connectionsv1.TokenExpired, f.now},
		"spent, past the window":  {spent, connectionsv1.TokenSpent, f.now.Add(8 * 24 * time.Hour)},
	}
	for name, c := range cases {
		f.now = c.at
		_, err := f.register(c.tok, f.request())
		var ue *pmtest.UpgradeError
		if assert.ErrorAs(t, err, &ue, name) && assert.NotNil(t, ue.Response, name) {
			assert.Equal(t, connectionsv1.ReasonTokenRefused, ue.Response.Reason, name)
			assert.Equal(t, string(c.detail), ue.Response.Detail, name)
		}
	}
}

func TestRegisterRetiredKey(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)

	retire := metav1.NewTime(f.now.Add(time.Hour))
	f.keyObj.Spec.RetireAt = &retire
	require.NoError(t, f.client.Update(context.Background(), f.keyObj))

	_, err := f.register(tok, f.request())
	var ue *pmtest.UpgradeError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, string(connectionsv1.TokenKeyUnusable), ue.Response.Detail)
}

func TestRegisterWrongSecret(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)

	other, err := credential.NewOnboardingToken(f.srv.URL+"/pm", f.key.Fingerprint)
	require.NoError(t, err)
	parts := strings.Split(tok.Reveal(), ".")
	parts[4] = strings.Split(other.Reveal(), ".")[4]
	wrong, err := credential.ParseOnboardingToken(strings.Join(parts, "."))
	require.NoError(t, err)

	_, err = f.register(wrong, f.request())
	assert.Equal(t, connectionsv1.ReasonUnauthorized, pmtest.ReasonOf(err))

	var spent sdkv1alpha1.OnboardingToken
	require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: tok.ID()}, &spent))
	assert.Nil(t, spent.Status.Registration, "a failed authentication changes nothing")
}

func TestRegisterInvalidRequests(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)

	for _, c := range tv.RegistrationRequests(f.pm.ConnectorCASet()) {
		if c.Valid {
			continue
		}
		_, err := f.register(tok, c.Request)
		assert.Equal(t, connectionsv1.ReasonInvalidRequest, pmtest.ReasonOf(err), c.Name)
	}

	for _, c := range tv.Bundles(t) {
		if c.Reason == "" {
			continue
		}
		req := f.request()
		req.ConnectorCASet = string(c.PEM)
		if req.ConnectorCASet == "" {
			continue // refused as an invalid request above
		}
		_, err := f.register(tok, req)
		var ce *pmtest.CallError
		if assert.ErrorAs(t, err, &ce, c.Name) {
			assert.Equal(t, connectionsv1.ReasonBundleInvalid, ce.Response.Reason, c.Name)
			assert.Equal(t, string(c.Reason), ce.Response.Detail, c.Name)
		}
	}
}

func TestStandbyRefuses(t *testing.T) {
	f := newFixture(t)
	tok := f.issue(30 * time.Minute)
	f.leader = false

	_, err := f.register(tok, f.request())
	var ue *pmtest.UpgradeError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, connectionsv1.ReasonUnavailable, pmtest.ReasonOf(err))
	assert.Equal(t, 5*time.Second, ue.RetryAfter)
}

func TestRouting(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/pm/v1/connections", "/pm/v1/connections/register", "/pm/v1/connections/a/b/c", "/pm/other"} {
		resp, err := f.srv.Client().Get(f.srv.URL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(Limits{PerKey: 2, Total: 3})
	r1, ok := l.acquire("a")
	require.True(t, ok)
	_, ok = l.acquire("a")
	require.True(t, ok)
	_, ok = l.acquire("a")
	assert.False(t, ok, "per key")
	_, ok = l.acquire("b")
	require.True(t, ok)
	_, ok = l.acquire("c")
	assert.False(t, ok, "total")

	r1()
	r1() // releasing twice is harmless
	_, ok = l.acquire("c")
	assert.True(t, ok)
}
