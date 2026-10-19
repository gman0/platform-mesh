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

package pmtest

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/hashicorp/yamux"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"
)

// Session is an open Session, as a Connector holds it: the PM-side accepts
// the Streams the Provider-side opens.
type Session struct {
	conn *tls.Conn
	mux  *yamux.Session
	srv  *http.Server
}

// OpenSession opens a Session for a Connection with PM's Connector
// Certificate, pinning serverKeys, and sends hello.
//
// In TLS 1.3 the handshake completes before the Provider-side has checked
// the Connector Certificate, so a refused Session shows only later, in
// Done.
func (p *PM) OpenSession(ctx context.Context, baseURL, connectionID string, serverKeys []fingerprint.Fingerprint, hello connectionsv1.Hello) (*Session, error) {
	cert := p.Connector.TLS()
	conn, err := p.dial(ctx, baseURL, connectionsv1.SessionPath(connectionID), nil, innertls.ClientOptions{
		ServerKeys:  serverKeys,
		Protocols:   []string{connectionsv1.ALPNSession},
		Certificate: &cert,
	})
	if err != nil {
		return nil, err
	}
	if err := connectionsv1.WriteHello(conn, hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	mux, err := yamux.Server(conn, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{conn: conn, mux: mux}, nil
}

// Serve answers the HTTP requests on every Stream the Provider-side opens
// with h, standing in for kcp behind a Connector. It returns when the
// Session ends.
func (s *Session) Serve(h http.Handler) error {
	s.srv = &http.Server{Handler: h}
	return s.srv.Serve(s.mux)
}

// GoAway tells the Provider-side to open no more Streams on this Session.
func (s *Session) GoAway() error { return s.mux.GoAway() }

// Done is closed when the Session has ended, from either side.
func (s *Session) Done() <-chan struct{} { return s.mux.CloseChan() }

// NumStreams is the number of open Streams.
func (s *Session) NumStreams() int { return s.mux.NumStreams() }

// Close ends the Session.
func (s *Session) Close() error {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	return s.mux.Close()
}
