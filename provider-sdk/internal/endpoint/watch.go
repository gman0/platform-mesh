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

// Package endpoint follows each Connection's ProviderEndpoint in kcp, over
// the Connection's own Sessions, and applies what PM writes there: a new
// Connection Secret hash, and the Server Keys PM pins.
//
// The ProviderEndpoint is trusted because of how it arrives: over a Session
// whose Connector Certificate and Hello were verified, from the Connection's
// own Provider Workspace, from an object only PM can write, naming this
// Connection.
package endpoint

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

const (
	// endpointName is the fixed name of the ProviderEndpoint.
	endpointName = "default"
	// frontProxyHost is the placeholder the Provider-side uses for the
	// front-proxy; it's never resolved, and the Connector ignores it.
	frontProxyHost = "front-proxy.pm.invalid"
)

var gvr = schema.GroupVersionResource{Group: "providers.platform-mesh.io", Version: "v1alpha1", Resource: "providerendpoints"}

// Manager keeps one ProviderEndpoint watch per Connection with a Session.
type Manager struct {
	Client    client.Client
	Namespace string
	Recorder  record.EventRecorder
	Log       logr.Logger

	// OpenStream opens a Stream to the Provider Workspace. Defaults to the
	// Sessions registry.
	OpenStream func(connectionID string) (net.Conn, error)
	// HasSessions reports whether a Connection has a Session. Defaults to
	// the Sessions registry.
	HasSessions func(connectionID string) bool

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// NewManager returns a Manager over the Sessions registry and subscribes it
// to the registry's changes.
func NewManager(c client.Client, namespace string, sessions *session.Registry, recorder record.EventRecorder, log logr.Logger) *Manager {
	m := &Manager{
		Client: c, Namespace: namespace, Recorder: recorder, Log: log,
		OpenStream:  func(id string) (net.Conn, error) { return sessions.OpenStream(id, session.WorkspaceHost) },
		HasSessions: sessions.Has,
	}
	sessions.OnChange = func(id string) { m.Sync(context.Background(), id) }
	return m
}

// Sync starts the Connection's watch if it has a Session, and stops it if
// it has none or is gone.
func (m *Manager) Sync(ctx context.Context, connectionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running == nil {
		m.running = map[string]context.CancelFunc{}
	}
	stop, running := m.running[connectionID]
	want := m.HasSessions(connectionID)
	if want == running {
		return
	}
	if !want {
		stop()
		delete(m.running, connectionID)
		return
	}
	var conn sdkv1alpha1.Connection
	if err := m.Client.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: connectionID}, &conn); err != nil {
		return
	}
	wctx, cancel := context.WithCancel(context.Background())
	m.running[connectionID] = cancel
	go m.watch(wctx, connectionID, conn.Spec.Registration.ClusterName)
}

// Stop ends every watch.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, stop := range m.running {
		stop()
		delete(m.running, id)
	}
}

// watch runs a list-and-watch of the Connection's ProviderEndpoint until ctx
// ends.
func (m *Manager) watch(ctx context.Context, connectionID, clusterName string) {
	cfg := &rest.Config{
		Host: "http://" + frontProxyHost + "/clusters/" + clusterName,
		// Every connection is a Stream on one of the Connection's Sessions.
		Dial: func(context.Context, string, string) (net.Conn, error) { return m.OpenStream(connectionID) },
		// Never a proxy: in client-go, nil means from the environment.
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		m.Log.Error(err, "providerendpoint client", "connection", connectionID)
		return
	}
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dc, 0, metav1.NamespaceAll, func(o *metav1.ListOptions) {
		o.FieldSelector = "metadata.name=" + endpointName
	})
	informer := factory.ForResource(gvr).Informer()
	handle := func(obj any) {
		if u, ok := obj.(*unstructured.Unstructured); ok {
			m.apply(ctx, connectionID, u)
		}
	}
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handle,
		UpdateFunc: func(_, obj any) { handle(obj) },
	})
	informer.Run(ctx.Done())
}

// apply applies a ProviderEndpoint to its Connection.
func (m *Manager) apply(ctx context.Context, connectionID string, pe *unstructured.Unstructured) {
	id, _, _ := unstructured.NestedString(pe.Object, "spec", "connectionID")
	if id != connectionID {
		m.Log.Info("ignoring a ProviderEndpoint for another Connection", "connection", connectionID, "named", id)
		return
	}
	pending, _, _ := unstructured.NestedString(pe.Object, "spec", "pendingSecretHash")
	keys, _, _ := unstructured.NestedStringSlice(pe.Object, "spec", "serverKeys")

	var conn sdkv1alpha1.Connection
	if err := m.Client.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: connectionID}, &conn); err != nil {
		return
	}
	before := conn.DeepCopy()

	secretChanged := false
	if pending != "" && pending != conn.Status.SecretHash {
		if _, err := credential.ParseHash(pending); err == nil {
			conn.Status.SecretHash = pending
			secretChanged = true
		}
	}
	listed, err := m.listed(ctx, keys)
	if err != nil {
		return
	}
	if len(listed) > 0 {
		conn.Status.ListedServerKeys = listed
	}

	if !secretChanged && slices.Equal(before.Status.ListedServerKeys, conn.Status.ListedServerKeys) {
		return
	}
	// Optimistic locking: a concurrent change makes this retry on the next
	// event or resync.
	if err := m.Client.Status().Patch(ctx, &conn, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		m.Log.Error(err, "applying the ProviderEndpoint", "connection", connectionID)
		return
	}
	if secretChanged {
		m.Recorder.Event(&conn, corev1.EventTypeNormal, sdkv1alpha1.ConnectionEventSecretChanged, "the Connection Secret was changed by Platform Mesh")
	}
}

// listed maps the keys PM pins (PEM SubjectPublicKeyInfo) to the names of
// this Provider-side's ServerKeys, sorted. Keys are compared by their
// key-sha256 fingerprint, not their text, so any PEM formatting of a key
// matches. Keys it doesn't have, or that don't parse, are ignored.
func (m *Manager) listed(ctx context.Context, pems []string) ([]string, error) {
	pinned := map[string]bool{}
	for _, p := range pems {
		if fp, ok := keyFingerprint(p); ok {
			pinned[fp] = true
		}
	}
	var list sdkv1alpha1.ServerKeyList
	if err := m.Client.List(ctx, &list, client.InNamespace(m.Namespace)); err != nil {
		return nil, err
	}
	var out []string
	for _, k := range list.Items {
		if k.Status.Fingerprint != "" && pinned[k.Status.Fingerprint] {
			out = append(out, k.Name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// keyFingerprint returns the key-sha256 fingerprint of a PEM public key.
func keyFingerprint(p string) (string, bool) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(p)))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", false
	}
	fp, err := fingerprint.OfPublicKey(pub)
	if err != nil {
		return "", false
	}
	return fp.String(), true
}
