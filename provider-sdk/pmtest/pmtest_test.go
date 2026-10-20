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

package pmtest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"
	tv "go.platform-mesh.io/provider-protocol/testvectors"
	"go.platform-mesh.io/provider-protocol/wsconn"

	"go.platform-mesh.io/provider-sdk/pmtest"
)

// standIn is a minimal Provider-side for testing pmtest itself: one known
// token, one Connection, one Connection Secret.
type standIn struct {
	t        *testing.T
	key      innertls.ServerKey
	tokenID  string
	connID   string
	secret   credential.ConnectionSecret
	pinned   *bundle.Bundle
	register chan connectionsv1.RegistrationRequest
	hello    chan connectionsv1.Hello
	stream   chan *http.Response
}

// newStandIn serves below prefix, e.g. the path of the Base URL.
func newStandIn(t *testing.T, pm *pmtest.PM, prefix string) (*standIn, *httptest.Server) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := innertls.NewServerKey(k)
	require.NoError(t, err)
	pinned, err := bundle.Parse(pm.ConnectorCASet(), tv.Now)
	require.NoError(t, err)

	s := &standIn{
		t: t, key: key,
		tokenID:  credential.NewTokenID(),
		connID:   credential.NewConnectionID(),
		secret:   credential.NewConnectionSecret(),
		pinned:   pinned,
		register: make(chan connectionsv1.RegistrationRequest, 1),
		hello:    make(chan connectionsv1.Hello, 1),
		stream:   make(chan *http.Response, 1),
	}
	srv := httptest.NewTLSServer(http.StripPrefix(prefix, http.HandlerFunc(s.serve)))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	pm.OuterRoots = pool
	return s, srv
}

func (s *standIn) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case connectionsv1.RegisterPath(s.tokenID):
		s.serveRegister(w, r)
	case connectionsv1.ControlPath(s.connID):
		s.serveControl(w, r)
	case connectionsv1.SessionPath(s.connID):
		s.serveSession(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, connectionsv1.PathPrefix+"/register/") {
			_ = connectionsv1.WriteError(w, connectionsv1.ErrorResponse{Reason: connectionsv1.ReasonTokenRefused, Detail: string(connectionsv1.TokenUnknown)}, 0)
			return
		}
		_ = connectionsv1.WriteError(w, connectionsv1.ErrorResponse{Reason: connectionsv1.ReasonNotFound}, 0)
	}
}

func (s *standIn) upgrade(w http.ResponseWriter, r *http.Request, cfg *tls.Config) *tls.Conn {
	ws, err := wsconn.Upgrader().Upgrade(w, r, nil)
	require.NoError(s.t, err)
	conn := tls.Server(wsconn.New(ws, wsconn.Options{}), cfg)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil
	}
	return conn
}

func (s *standIn) serveRegister(w http.ResponseWriter, r *http.Request) {
	conn := s.upgrade(w, r, innertls.Server(s.key, []string{connectionsv1.ALPNRegister}))
	if conn == nil {
		return
	}
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	require.NoError(s.t, err)
	var body connectionsv1.RegistrationRequest
	require.NoError(s.t, connectionsv1.ReadJSON(req.Body, connectionsv1.MaxBodySize, &body))
	s.register <- body
	respond(conn, http.StatusCreated, connectionsv1.RegistrationResponse{
		ConnectionID:    s.connID,
		ServerKeys:      []connectionsv1.ServerKey{{PublicKey: "k"}},
		UnusedExpiresAt: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
	})
}

func (s *standIn) serveControl(w http.ResponseWriter, r *http.Request) {
	conn := s.upgrade(w, r, innertls.Server(s.key, []string{connectionsv1.ALPNControl}))
	if conn == nil {
		return
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		bearer, _ := connectionsv1.ParseBearer(req.Header.Get("Authorization"))
		if bearer != s.secret.Reveal() {
			respond(conn, http.StatusUnauthorized, connectionsv1.ErrorResponse{Reason: connectionsv1.ReasonUnauthorized})
			return // the first failed authentication closes the Control Session
		}
		respond(conn, http.StatusOK, connectionsv1.ConnectionStatus{Workspace: connectionsv1.HostStatus{Sessions: 1, KcpReachable: true}})
	}
}

func (s *standIn) serveSession(w http.ResponseWriter, r *http.Request) {
	// Test certificates are valid around testvectors.Now, not the real time.
	cfg := innertls.SessionServer(s.key, func() *bundle.Bundle { return s.pinned }, []string{connectionsv1.ALPNSession}, func() time.Time { return tv.Now })
	conn := s.upgrade(w, r, cfg)
	if conn == nil {
		return
	}
	defer conn.Close()
	h, err := connectionsv1.ReadHello(conn)
	require.NoError(s.t, err)
	s.hello <- h

	mux, err := yamux.Client(conn, nil)
	require.NoError(s.t, err)
	defer mux.Close()
	stream, err := mux.Open()
	require.NoError(s.t, err)
	req, _ := http.NewRequest(http.MethodGet, "https://front-proxy.pm.invalid/clusters/2x8k9abc/api", nil)
	require.NoError(s.t, req.Write(stream))
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	require.NoError(s.t, err)
	s.stream <- resp
	<-mux.CloseChan()
}

func respond(w io.Writer, status int, v any) {
	b, _ := json.Marshal(v)
	resp := &http.Response{
		StatusCode: status, ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {connectionsv1.ContentTypeJSON}},
		ContentLength: int64(len(b)),
		Body:          io.NopCloser(bytes.NewReader(b)),
	}
	_ = resp.Write(w)
}

func token(t *testing.T, srv *httptest.Server, id string, key fingerprint.Fingerprint) credential.OnboardingToken {
	t.Helper()
	tok, err := credential.NewOnboardingToken(srv.URL+"/pm", key)
	require.NoError(t, err)
	// Swap in the stand-in's known ID; the rest stays valid.
	parts := strings.Split(tok.Reveal(), ".")
	parts[3] = id
	tok, err = credential.ParseOnboardingToken(strings.Join(parts, "."))
	require.NoError(t, err)
	return tok
}

func TestRegister(t *testing.T) {
	pm := pmtest.New(t)
	s, srv := newStandIn(t, pm, "/pm")

	req := tv.RegistrationRequest(pm.ConnectorCASet())
	resp, err := pm.Register(context.Background(), token(t, srv, s.tokenID, s.key.Fingerprint), req)
	require.NoError(t, err)
	assert.Equal(t, s.connID, resp.ConnectionID)
	assert.Equal(t, req, recv(t, s.register))
}

func TestRegisterRefusedBeforeUpgrade(t *testing.T) {
	pm := pmtest.New(t)
	s, srv := newStandIn(t, pm, "/pm")

	_, err := pm.Register(context.Background(), token(t, srv, credential.NewTokenID(), s.key.Fingerprint), tv.RegistrationRequest(pm.ConnectorCASet()))
	var ue *pmtest.UpgradeError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, connectionsv1.ReasonTokenRefused, pmtest.ReasonOf(err))
	assert.Equal(t, string(connectionsv1.TokenUnknown), ue.Response.Detail)
}

func TestRegisterUnpinnedKey(t *testing.T) {
	pm := pmtest.New(t)
	s, srv := newStandIn(t, pm, "/pm")

	other, err := fingerprint.Parse("key-sha256:" + strings.Repeat("ab", 32))
	require.NoError(t, err)
	_, err = pm.Register(context.Background(), token(t, srv, s.tokenID, other), tv.RegistrationRequest(pm.ConnectorCASet()))
	assert.ErrorIs(t, err, innertls.ErrServerKeyNotPinned)
}

func TestControl(t *testing.T) {
	pm := pmtest.New(t)
	s, srv := newStandIn(t, pm, "")
	pins := []fingerprint.Fingerprint{s.key.Fingerprint}

	c, err := pm.Control(context.Background(), srv.URL, s.connID, pins, s.key.Fingerprint)
	require.NoError(t, err)
	defer c.Close()

	st, err := c.Status(s.secret)
	require.NoError(t, err)
	assert.True(t, st.Workspace.KcpReachable)

	_, err = c.Status(credential.NewConnectionSecret())
	assert.Equal(t, connectionsv1.ReasonUnauthorized, pmtest.ReasonOf(err))

	_, err = c.Status(s.secret)
	assert.Error(t, err, "the Control Session was closed after the failure")
}

func TestSession(t *testing.T) {
	pm := pmtest.New(t)
	s, srv := newStandIn(t, pm, "")
	hello := connectionsv1.Hello{ConnectionID: s.connID, ClusterName: "2x8k9abc", Hosts: []string{"nereus.kcp.example.com:443"}}

	sess, err := pm.OpenSession(context.Background(), srv.URL, s.connID, []fingerprint.Fingerprint{s.key.Fingerprint}, hello)
	require.NoError(t, err)
	defer sess.Close()
	go func() {
		_ = sess.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Path", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
	}()

	assert.Equal(t, hello, recv(t, s.hello))
	resp := recv(t, s.stream)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/clusters/2x8k9abc/api", resp.Header.Get("X-Path"))
}

// recv reads from ch, failing the test instead of hanging: in TLS 1.3 a
// refused Session shows only on the Provider-side, which then sends nothing.
func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: the stand-in sent nothing")
		var zero T
		return zero
	}
}
