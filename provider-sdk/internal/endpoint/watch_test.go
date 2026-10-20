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

package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const (
	ns          = "wild-west-system"
	connID      = "c-abcdefghijklmnopqrstuvwxyz"
	clusterName = "2x8k9abc"
	oldHash     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newHash     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Two real Server Keys: their PEM and fingerprint.
var keyPEM1, keyFP1, keyPEM2, keyFP2 = newKey(), "", newKey(), ""

func init() {
	keyFP1, _ = keyFingerprint(keyPEM1)
	keyFP2, _ = keyFingerprint(keyPEM2)
}

func newKey() string {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: connID, Namespace: ns},
		Spec:       sdkv1alpha1.ConnectionSpec{Registration: sdkv1alpha1.ConnectionRegistration{Owner: "alice", ClusterName: clusterName}},
		Status:     sdkv1alpha1.ConnectionStatus{SecretHash: oldHash, ListedServerKeys: []string{"sk-1"}},
	}
	key := func(name, pem, fp string) *sdkv1alpha1.ServerKey {
		return &sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Status: sdkv1alpha1.ServerKeyStatus{PublicKey: pem, Fingerprint: fp}}
	}
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&sdkv1alpha1.Connection{}).
		WithObjects(conn, key("sk-1", keyPEM1, keyFP1), key("sk-2", keyPEM2, keyFP2)).Build()
}

func endpointObj(id, pending string, keys ...string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "providers.platform-mesh.io/v1alpha1",
		"kind":       "ProviderEndpoint",
		"metadata":   map[string]any{"name": "default", "resourceVersion": "1"},
		"spec":       map[string]any{"connectionID": id, "url": "https://wildwest.example.com/pm"},
	}}
	if pending != "" {
		_ = unstructured.SetNestedField(u.Object, pending, "spec", "pendingSecretHash")
	}
	_ = unstructured.SetNestedStringSlice(u.Object, keys, "spec", "serverKeys")
	return u
}

func newManager(t *testing.T, c client.Client) (*Manager, *record.FakeRecorder) {
	rec := record.NewFakeRecorder(10)
	return &Manager{Client: c, Namespace: ns, Recorder: rec, Log: logr.Discard()}, rec
}

func connection(t *testing.T, c client.Client) *sdkv1alpha1.Connection {
	t.Helper()
	var conn sdkv1alpha1.Connection
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: connID}, &conn))
	return &conn
}

func TestApplyAdoptsPendingSecretHash(t *testing.T) {
	c := newClient(t)
	m, rec := newManager(t, c)
	m.apply(context.Background(), connID, endpointObj(connID, newHash, keyPEM1))

	assert.Equal(t, newHash, connection(t, c).Status.SecretHash)
	assert.Equal(t, "Normal SecretChanged the Connection Secret was changed by Platform Mesh", <-rec.Events)

	// The same hash again changes nothing.
	m.apply(context.Background(), connID, endpointObj(connID, newHash, keyPEM1))
	assert.Empty(t, rec.Events)
}

func TestApplyIgnoresAnotherConnection(t *testing.T) {
	c := newClient(t)
	m, rec := newManager(t, c)
	m.apply(context.Background(), connID, endpointObj("c-zyxwvutsrqponmlkjihgfedcba", newHash, keyPEM2))
	assert.Equal(t, oldHash, connection(t, c).Status.SecretHash)
	assert.Equal(t, []string{"sk-1"}, connection(t, c).Status.ListedServerKeys)
	assert.Empty(t, rec.Events)
}

func TestApplyIgnoresMalformedHash(t *testing.T) {
	c := newClient(t)
	m, _ := newManager(t, c)
	m.apply(context.Background(), connID, endpointObj(connID, "sha256:nope", keyPEM1))
	assert.Equal(t, oldHash, connection(t, c).Status.SecretHash)
}

func TestApplyListedServerKeys(t *testing.T) {
	c := newClient(t)
	m, _ := newManager(t, c)
	unparseable := "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"
	m.apply(context.Background(), connID, endpointObj(connID, "", keyPEM2, keyPEM1, newKey(), unparseable))
	assert.Equal(t, []string{"sk-1", "sk-2"}, connection(t, c).Status.ListedServerKeys, "keys it doesn't have, or that don't parse, are ignored")
}

func TestApplyMatchesReformattedKeys(t *testing.T) {
	c := newClient(t)
	m, _ := newManager(t, c)
	// The same key, as an administrator might paste it: CRLF line ends, no
	// trailing newline, surrounding whitespace.
	reformatted := "  " + strings.TrimSuffix(strings.ReplaceAll(keyPEM2, "\n", "\r\n"), "\r\n") + "\n\n"
	require.NotEqual(t, keyPEM2, reformatted)
	m.apply(context.Background(), connID, endpointObj(connID, "", keyPEM1, reformatted))
	assert.Equal(t, []string{"sk-1", "sk-2"}, connection(t, c).Status.ListedServerKeys)
}

// fakeKCP serves the ProviderEndpoint list and a watch whose events come
// from events, over connections handed to it like Streams. It answers both
// a plain list-then-watch and client-go's watch-list mode.
type fakeKCP struct {
	done    chan struct{}
	once    sync.Once
	conns   chan net.Conn
	events  chan *unstructured.Unstructured
	paths   chan string
	initial *unstructured.Unstructured
}

func newFakeKCP(t *testing.T, initial *unstructured.Unstructured) *fakeKCP {
	f := &fakeKCP{done: make(chan struct{}), conns: make(chan net.Conn), events: make(chan *unstructured.Unstructured), paths: make(chan string, 16), initial: initial}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go func() { _ = srv.Serve(f) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

// open is a stand-in for OpenStream.
func (f *fakeKCP) open(string) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case f.conns <- b:
		return a, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

// Accept returns once Close is called: http.Server.Close waits for Serve to
// return.
func (f *fakeKCP) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *fakeKCP) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}
func (f *fakeKCP) Addr() net.Addr { return &net.TCPAddr{} }

func (f *fakeKCP) serve(w http.ResponseWriter, r *http.Request) {
	select {
	case f.paths <- r.URL.Path:
	default:
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("watch") != "true" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "providers.platform-mesh.io/v1alpha1", "kind": "ProviderEndpointList",
			"metadata": map[string]any{"resourceVersion": "1"},
			"items":    []any{f.initial.Object},
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	// client-go's watch-list mode asks for the initial state as events,
	// ended by a bookmark; until then, it holds back every event.
	if r.URL.Query().Get("sendInitialEvents") == "true" {
		enc := json.NewEncoder(w)
		_ = enc.Encode(map[string]any{"type": "ADDED", "object": f.initial.Object})
		_ = enc.Encode(map[string]any{"type": "BOOKMARK", "object": map[string]any{
			"apiVersion": "providers.platform-mesh.io/v1alpha1", "kind": "ProviderEndpoint",
			"metadata": map[string]any{
				"resourceVersion": "1",
				"annotations":     map[string]any{"k8s.io/initial-events-end": "true"},
			},
		}})
	}
	w.(http.Flusher).Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case u := <-f.events:
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "MODIFIED", "object": u.Object})
			w.(http.Flusher).Flush()
		}
	}
}

func TestWatchOverStreams(t *testing.T) {
	c := newClient(t)
	m, rec := newManager(t, c)
	kcp := newFakeKCP(t, endpointObj(connID, "", keyPEM1))
	hasSessions := true
	m.OpenStream = kcp.open
	m.HasSessions = func(string) bool { return hasSessions }

	m.Sync(context.Background(), connID)
	t.Cleanup(m.Stop)

	path := <-kcp.paths
	assert.True(t, strings.HasPrefix(path, "/clusters/"+clusterName+"/apis/providers.platform-mesh.io/v1alpha1/providerendpoints"), path)

	// A Secret Change written by PM arrives through the watch.
	updated := endpointObj(connID, newHash, keyPEM1)
	updated.SetResourceVersion("2")
	require.Eventually(t, func() bool {
		select {
		case kcp.events <- updated:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return connection(t, c).Status.SecretHash == newHash }, 5*time.Second, 10*time.Millisecond)
	assert.Contains(t, <-rec.Events, "SecretChanged")

	// Without Sessions, the watch stops.
	hasSessions = false
	m.Sync(context.Background(), connID)
	m.mu.Lock()
	assert.Empty(t, m.running)
	m.mu.Unlock()
}
