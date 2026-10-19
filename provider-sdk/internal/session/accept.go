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

package session

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/yamux"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/innertls"
	"go.platform-mesh.io/provider-protocol/wsconn"
)

// Accept is what accepting a Session needs from the Connection.
type Accept struct {
	ConnectionID string
	// ClusterName is the one stored at Registration; the Hello must name it.
	ClusterName string
	// Key is the Server Key the Session presents.
	Key innertls.ServerKey
	// Pinned returns the Connection's Pinned Bundle at handshake time, nil
	// if the Connection is gone.
	Pinned func() *bundle.Bundle
	// Timeout bounds the handshake and the Hello.
	Timeout time.Duration
	// Now is the time Connector Certificates are verified at; defaults to
	// time.Now.
	Now func() time.Time
}

// Accept upgrades r to a WebSocket and opens a Session: the mutual Inner
// TLS, the Hello, then yamux, with the Provider-side as client, since only
// it opens Streams. On success, the Session is registered until it ends;
// Accept returns once it's registered or refused.
func (r *Registry) Accept(w http.ResponseWriter, req *http.Request, a Accept) error {
	ws, err := wsconn.Upgrader().Upgrade(w, req, nil)
	if err != nil {
		return err // the upgrader has answered
	}
	conn := tls.Server(wsconn.New(ws, wsconn.Options{}),
		innertls.SessionServer(a.Key, a.Pinned, []string{connectionsv1.ALPNSession}, a.Now))
	_ = conn.SetDeadline(time.Now().Add(a.Timeout))

	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("inner TLS: %w", err)
	}
	hello, err := connectionsv1.ReadHello(conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("hello: %w", err)
	}
	// The essential check: one Connector Certificate serves every
	// Connection of a PM Instance.
	if err := hello.Check(a.ConnectionID, a.ClusterName); err != nil {
		_ = conn.Close()
		return err
	}
	_ = conn.SetDeadline(time.Time{})

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	mux, err := yamux.Client(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return err
	}
	r.add(&Session{
		ConnectionID: a.ConnectionID,
		ClusterName:  hello.ClusterName,
		Hosts:        hello.Hosts,
		Certificate:  innertls.ClientCertificate(conn.ConnectionState()),
		mux:          mux,
	})
	return nil
}
