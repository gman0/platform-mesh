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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"time"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"
)

// innerHost is the Host of requests inside the Inner TLS; the Provider-side
// routes by path only.
const innerHost = "connection.invalid"

// Register runs a Registration with token and returns the Provider-side's
// response. A refusal before the upgrade is an *UpgradeError, one inside an
// *CallError.
func (p *PM) Register(ctx context.Context, token credential.OnboardingToken, req connectionsv1.RegistrationRequest) (*connectionsv1.RegistrationResponse, error) {
	conn, err := p.dial(ctx, token.BaseURL(), connectionsv1.RegisterPath(token.ID()), nil, innertls.ClientOptions{
		ServerKeys: pins(token.ServerKey()),
		Protocols:  []string{connectionsv1.ALPNRegister},
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var out connectionsv1.RegistrationResponse
	if err := call(conn, bufio.NewReader(conn), http.MethodPost, connectionsv1.RegistrationCreatePath, token.RevealSecret(), nil, req, http.StatusCreated, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ControlSession is an open Control Session.
type ControlSession struct {
	conn *tls.Conn
	r    *bufio.Reader
	id   string
}

// Control opens a Control Session for a Connection, pinning serverKeys and
// asking for expect in PM-Server-Key.
func (p *PM) Control(ctx context.Context, baseURL, connectionID string, serverKeys []fingerprint.Fingerprint, expect fingerprint.Fingerprint) (*ControlSession, error) {
	h := http.Header{}
	h.Set(connectionsv1.HeaderServerKey, expect.String())
	conn, err := p.dial(ctx, baseURL, connectionsv1.ControlPath(connectionID), h, innertls.ClientOptions{
		ServerKeys: serverKeys,
		Protocols:  []string{connectionsv1.ALPNControl},
	})
	if err != nil {
		return nil, err
	}
	return &ControlSession{conn: conn, r: bufio.NewReader(conn), id: connectionID}, nil
}

// Status calls GET on the Connection.
func (c *ControlSession) Status(secret credential.ConnectionSecret) (*connectionsv1.ConnectionStatus, error) {
	var out connectionsv1.ConnectionStatus
	if err := call(c.conn, c.r, http.MethodGet, connectionsv1.ConnectionPath(c.id), secret.Reveal(), nil, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutConnectorCASet replaces the Pinned Bundle; etag is the current one,
// empty to send no If-Match.
func (c *ControlSession) PutConnectorCASet(secret credential.ConnectionSecret, etag string, pem []byte) error {
	h := http.Header{}
	if etag != "" {
		h.Set("If-Match", connectionsv1.FormatETag(etag))
	}
	return call(c.conn, c.r, http.MethodPut, connectionsv1.ConnectorCASetPath(c.id), secret.Reveal(), h,
		connectionsv1.ConnectorCASetUpdate{ConnectorCASet: string(pem)}, http.StatusNoContent, nil)
}

// Delete deletes the Connection.
func (c *ControlSession) Delete(secret credential.ConnectionSecret) error {
	return call(c.conn, c.r, http.MethodDelete, connectionsv1.ConnectionPath(c.id), secret.Reveal(), nil, nil, http.StatusNoContent, nil)
}

// Do sends any request on the Control Session, for scenarios the typed calls
// don't cover (another Connection's path, a malformed header). The caller
// reads and closes the body.
func (c *ControlSession) Do(req *http.Request) (*http.Response, error) {
	if err := req.Write(c.conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(c.r, req)
}

// Close closes the Control Session.
func (c *ControlSession) Close() error { return c.conn.Close() }

// call sends one request with a bearer and an optional JSON body, and
// decodes a response with status want into out, or returns a *CallError.
func call(w io.Writer, r *bufio.Reader, method, path, bearer string, header http.Header, body any, want int, out any) error {
	var payload io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://"+innerHost+path, payload)
	if err != nil {
		return err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", connectionsv1.BearerHeader(bearer))
	if body != nil {
		req.Header.Set("Content-Type", connectionsv1.ContentTypeJSON)
	}
	if err := req.Write(w); err != nil {
		return err
	}
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != want {
		e, _, rerr := connectionsv1.ReadError(resp, time.Now())
		if rerr != nil {
			return &CallError{StatusCode: resp.StatusCode}
		}
		return &CallError{StatusCode: resp.StatusCode, Response: e}
	}
	if out == nil {
		_, err := io.Copy(io.Discard, resp.Body)
		return err
	}
	return connectionsv1.ReadJSON(resp.Body, connectionsv1.MaxBodySize, out)
}
