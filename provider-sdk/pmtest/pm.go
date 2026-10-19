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

// Package pmtest is a fake PM-side for tests: it registers Connections,
// makes Control Calls and opens Sessions against a Provider's Base URL, the
// way platform-mesh-operator and the Connectors do, with test certificates.
package pmtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"
	tv "go.platform-mesh.io/provider-protocol/testvectors"
	"go.platform-mesh.io/provider-protocol/wsconn"
)

// PM is a fake PM Instance: a Connector CA, a Connector Certificate issued by
// it, and the outer TLS trust for the Provider's Base URL.
type PM struct {
	// CA is the Connector CA.
	CA tv.Cert
	// Connector is the Connector Certificate Sessions present.
	Connector tv.Cert
	// OuterRoots verify the Base URL's outer TLS; nil means the system roots.
	OuterRoots *x509.CertPool
}

// New returns a fake PM Instance with a fresh Connector CA and Connector
// Certificate, valid around testvectors.Now.
func New(t testing.TB) *PM {
	t.Helper()
	ca := tv.CA(t, "pmtest connector CA", nil)
	return &PM{CA: ca, Connector: tv.Leaf(t, ca)}
}

// ConnectorCASet is the Connector CA Set PM sends at Registration.
func (p *PM) ConnectorCASet() []byte { return p.CA.PEM() }

// UpgradeError is a WebSocket upgrade the Provider-side or its Edge refused.
type UpgradeError struct {
	StatusCode int
	// Response is the refusal, nil if it isn't the protocol's (e.g. an
	// Edge's page).
	Response   *connectionsv1.ErrorResponse
	RetryAfter time.Duration
}

func (e *UpgradeError) Error() string {
	if e.Response != nil {
		return fmt.Sprintf("upgrade refused: %d %s", e.StatusCode, e.Response.Reason)
	}
	return fmt.Sprintf("upgrade refused: %d (not a protocol response)", e.StatusCode)
}

// CallError is a refusal inside the Inner TLS.
type CallError struct {
	StatusCode int
	Response   connectionsv1.ErrorResponse
}

func (e *CallError) Error() string {
	return fmt.Sprintf("refused: %d %s %s", e.StatusCode, e.Response.Reason, e.Response.Detail)
}

// ReasonOf returns the protocol reason of an UpgradeError or CallError.
func ReasonOf(err error) connectionsv1.Reason {
	var ue *UpgradeError
	if errors.As(err, &ue) && ue.Response != nil {
		return ue.Response.Reason
	}
	var ce *CallError
	if errors.As(err, &ce) {
		return ce.Response.Reason
	}
	return ""
}

// dial upgrades to a WebSocket on path below baseURL and runs the Inner TLS
// client over it.
func (p *PM) dial(ctx context.Context, baseURL, path string, header http.Header, inner innertls.ClientOptions) (*tls.Conn, error) {
	u := strings.TrimSuffix(baseURL, "/") + path
	u = "wss" + strings.TrimPrefix(u, "https")

	d := wsconn.Dialer(&tls.Config{RootCAs: p.OuterRoots, MinVersion: tls.VersionTLS12}, nil)
	ws, resp, err := d.DialContext(ctx, u, header)
	if err != nil {
		if errors.Is(err, websocket.ErrBadHandshake) && resp != nil {
			defer resp.Body.Close()
			e, retry, rerr := connectionsv1.ReadError(resp, time.Now())
			ue := &UpgradeError{StatusCode: resp.StatusCode, RetryAfter: retry}
			if rerr == nil {
				ue.Response = &e
			}
			return nil, ue
		}
		return nil, err
	}

	conn := tls.Client(wsconn.New(ws, wsconn.Options{}), innertls.Client(inner))
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("inner TLS: %w", err)
	}
	return conn, nil
}

func pins(keys ...fingerprint.Fingerprint) []fingerprint.Fingerprint { return keys }
