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

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/kubeconfig"
	"go.platform-mesh.io/provider-sdk/internal/metrics"
	"go.platform-mesh.io/provider-sdk/internal/metrics/metricstest"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

const (
	ns          = "wild-west-system"
	connID      = "c-abcdefghijklmnopqrstuvwxyz"
	credential  = "the-operators-credential"
	previous    = "the-previous-credential"
	gatewayName = "provider-gateway.wild-west-system.svc"
	vwHost      = "nereus.kcp.example.com"
)

// fakeSessions serves Streams from a fake kcp behind a Connector.
type fakeSessions struct {
	mu      sync.Mutex
	hosts   []string // hosts the Connection's Sessions serve; nil: no Sessions
	srv     *http.Server
	conns   chan net.Conn
	reports []string
}

func newFakeSessions(t *testing.T, hosts ...string) *fakeSessions {
	// An empty, non-nil list: Sessions that serve only the workspace.
	f := &fakeSessions{hosts: append([]string{}, hosts...), conns: make(chan net.Conn)}
	f.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"path":"`+r.URL.Path+`"}`)
	})}
	ln := &chanListener{conns: f.conns, done: make(chan struct{})}
	go func() { _ = f.srv.Serve(ln) }()
	t.Cleanup(func() { _ = f.srv.Close() })
	return f
}

func (f *fakeSessions) OpenStream(id, host string) (net.Conn, error) {
	f.mu.Lock()
	served := id == connID && (host == session.WorkspaceHost && f.hosts != nil || slices.Contains(f.hosts, host))
	f.mu.Unlock()
	if !served {
		return nil, session.ErrNoSession
	}
	a, b := net.Pipe()
	f.conns <- b
	return a, nil
}

func (f *fakeSessions) Has(id string) bool { return id == connID && f.hosts != nil }

func (f *fakeSessions) Report(_, host string, reachable bool, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := "reachable"
	if !reachable {
		state = "unreachable: " + msg
	}
	f.reports = append(f.reports, host+" "+state)
}

func (f *fakeSessions) lastReport() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		return ""
	}
	return f.reports[len(f.reports)-1]
}

type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

type fixture struct {
	t        *testing.T
	client   client.Client
	sessions *fakeSessions
	proxy    *Proxy
	srv      *httptest.Server
	bundle   []byte
	now      time.Time
	reg      *prometheus.Registry
}

func newFixture(t *testing.T, sessions *fakeSessions) *fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: connID, Namespace: ns},
		Status: sdkv1alpha1.ConnectionStatus{
			ProxyCredentialHash:         kubeconfig.HashCredential(credential),
			PreviousProxyCredentialHash: kubeconfig.HashCredential(previous),
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdkv1alpha1.Connection{}).WithObjects(conn).Build()

	ca, err := kubeconfig.EnsureCA(context.Background(), c, ns, kubeconfig.DefaultCASecretName, time.Now())
	require.NoError(t, err)
	src := &kubeconfig.SelfSigned{CA: ca, Names: []string{gatewayName}}

	m, reg := metricstest.New(t)
	f := &fixture{t: t, client: c, sessions: sessions, bundle: ca.Bundle(), now: time.Now(), reg: reg}
	f.proxy = &Proxy{Client: c, Namespace: ns, Sessions: sessions, TLS: src, Log: logr.Discard(), Metrics: m, Now: func() time.Time { return f.now }}
	f.srv = httptest.NewUnstartedServer(f.proxy)
	f.srv.TLS = &tls.Config{GetCertificate: src.GetCertificate}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// restConfig is what the kubeconfig gives client-go: the placeholder or a
// real virtual-workspace host, the proxy with the Connection's credential,
// and tls-server-name with the gateway's CA.
func (f *fixture) restConfig(host, user, pass string) *rest.Config {
	proxyURL := &url.URL{Scheme: "https", User: url.UserPassword(user, pass), Host: f.srv.Listener.Addr().String()}
	return &rest.Config{
		Host:            host,
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: rest.TLSClientConfig{ServerName: gatewayName, CAData: f.bundle},
	}
}

func (f *fixture) get(cfg *rest.Config, path string) (int, string, error) {
	f.t.Helper()
	hc, err := rest.HTTPClientFor(cfg)
	require.NoError(f.t, err)
	resp, err := hc.Get(cfg.Host + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func TestClientGoThroughTheProxy(t *testing.T) {
	f := newFixture(t, newFakeSessions(t, vwHost))

	// The Provider Workspace, through the placeholder.
	code, body, err := f.get(f.restConfig("https://front-proxy.pm.invalid/clusters/2x8k9abc", connID, credential), "/api")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.JSONEq(t, `{"path":"/clusters/2x8k9abc/api"}`, body)
	assert.Equal(t, " reachable", f.sessions.lastReport())

	// A virtual workspace by its real host, as endpoint slices name it.
	code, _, err = f.get(f.restConfig("https://"+vwHost+"/services/apiexport/2x8k9abc/cowboys", connID, credential), "/clusters/*/api")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, vwHost+" reachable", f.sessions.lastReport())
}

func TestUnreachableKcpReported(t *testing.T) {
	f := newFixture(t, newFakeSessions(t))
	code, _, err := f.get(f.restConfig("https://front-proxy.pm.invalid", connID, credential), "/bad")
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, code, "the Connector's answer passes through unchanged")
	assert.Equal(t, " unreachable: kcp not reached: 502 from the Connector", f.sessions.lastReport())
}

// connect sends a CONNECT by hand and returns the status.
func (f *fixture) connect(auth, target string) int {
	f.t.Helper()
	pool := x509.NewCertPool()
	require.True(f.t, pool.AppendCertsFromPEM(f.bundle))
	conn, err := tls.Dial("tcp", f.srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: gatewayName})
	require.NoError(f.t, err)
	defer conn.Close()
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth)) + "\r\n"
	}
	_, err = io.WriteString(conn, req+"\r\n")
	require.NoError(f.t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(f.t, err)
	return resp.StatusCode
}

func TestConnectRefusals(t *testing.T) {
	f := newFixture(t, newFakeSessions(t, vwHost))
	workspace := "front-proxy.pm.invalid:443"
	cases := map[string]struct {
		auth, target string
		want         int
	}{
		"no credential":          {"", workspace, http.StatusProxyAuthRequired},
		"wrong credential":       {connID + ":wrong", workspace, http.StatusProxyAuthRequired},
		"unknown Connection":     {"c-zyxwvutsrqponmlkjihgfedcba:" + credential, workspace, http.StatusNotFound},
		"host no Session serves": {connID + ":" + credential, "other.kcp.example.com:443", http.StatusNotFound},
		"current credential":     {connID + ":" + credential, workspace, http.StatusOK},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, f.connect(c.auth, c.target), name)
	}

	refused := func(reason string) float64 {
		return metricstest.Value(t, f.reg, "providersdk_operator_tunnels_refused_total", "reason", reason)
	}
	assert.Equal(t, 2.0, refused(metrics.TunnelCredential))
	assert.Equal(t, 1.0, refused(metrics.TunnelUnknownConnection))
	assert.Equal(t, 1.0, refused(metrics.TunnelUnknownHost))
	assert.Equal(t, 0.0, refused(metrics.TunnelNoSession))
}

func TestConnectWithoutSessions(t *testing.T) {
	f := newFixture(t, newFakeSessions(t))
	f.sessions.hosts = nil
	assert.Equal(t, http.StatusServiceUnavailable, f.connect(connID+":"+credential, "front-proxy.pm.invalid:443"))
	assert.Equal(t, 1.0, metricstest.Value(t, f.reg, "providersdk_operator_tunnels_refused_total", "reason", metrics.TunnelNoSession))
}

func TestTunnelsOpenGauge(t *testing.T) {
	f := newFixture(t, newFakeSessions(t))
	open := func() float64 { return metricstest.Value(t, f.reg, "providersdk_operator_tunnels") }

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(f.bundle))
	conn, err := tls.Dial("tcp", f.srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: gatewayName})
	require.NoError(t, err)
	auth := base64.StdEncoding.EncodeToString([]byte(connID + ":" + credential))
	_, err = io.WriteString(conn, "CONNECT front-proxy.pm.invalid:443 HTTP/1.1\r\nHost: front-proxy.pm.invalid:443\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1.0, open(), "counted before the 200")

	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return open() == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestPreviousCredential(t *testing.T) {
	f := newFixture(t, newFakeSessions(t))
	assert.Equal(t, http.StatusOK, f.connect(connID+":"+previous, "front-proxy.pm.invalid:443"), "accepted during a rotation")

	conn := func() *sdkv1alpha1.Connection {
		var c sdkv1alpha1.Connection
		require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: connID}, &c))
		return &c
	}

	require.NoError(t, f.proxy.DropUnusedPrevious(context.Background()))
	assert.NotEmpty(t, conn().Status.PreviousProxyCredentialHash, "used just now")

	f.now = f.now.Add(PreviousUnusedAfter)
	require.NoError(t, f.proxy.DropUnusedPrevious(context.Background()))
	assert.Empty(t, conn().Status.PreviousProxyCredentialHash, "dropped once unused")
	assert.Equal(t, http.StatusProxyAuthRequired, f.connect(connID+":"+previous, "front-proxy.pm.invalid:443"))
	assert.Equal(t, http.StatusOK, f.connect(connID+":"+credential, "front-proxy.pm.invalid:443"))
}

func TestStatusSniffer(t *testing.T) {
	cases := map[string]struct {
		chunks []string
		want   string
	}{
		"200":                {[]string{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}, "reachable"},
		"split status line":  {[]string{"HTTP/1.1 4", "04 Not Found\r\n"}, "reachable"},
		"502 from Connector": {[]string{"HTTP/1.1 502 Bad Gateway\r\n"}, "unreachable: kcp not reached: 502 from the Connector"},
		"504 from Connector": {[]string{"HTTP/1.1 504 Gateway Timeout\r\n"}, "unreachable: kcp not reached: 504 from the Connector"},
		"not HTTP":           {[]string{"garbage\r\n"}, "unreachable: malformed response through the Connector"},
		"nothing":            {nil, "unreachable: no response through the Connector"},
	}
	for name, c := range cases {
		var got []string
		s := &statusSniffer{report: func(reachable bool, msg string) {
			if reachable {
				got = append(got, "reachable")
			} else {
				got = append(got, "unreachable: "+msg)
			}
		}}
		for _, ch := range c.chunks {
			n, err := s.Write([]byte(ch))
			require.NoError(t, err)
			assert.Equal(t, len(ch), n, "every byte passes")
		}
		s.end()
		assert.Equal(t, []string{c.want}, got, name)
	}
}
