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
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/wsconn"
)

// accept upgrades to a WebSocket and runs the Inner TLS server with cfg,
// within timeout. It returns nil after answering or closing on failure.
func accept(w http.ResponseWriter, r *http.Request, cfg *tls.Config, timeout time.Duration) *tls.Conn {
	ws, err := wsconn.Upgrader().Upgrade(w, r, nil)
	if err != nil {
		return nil // the upgrader has answered
	}
	conn := tls.Server(wsconn.New(ws, wsconn.Options{}), cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil
	}
	return conn
}

// innerConn reads requests and writes responses inside the Inner TLS, over
// HTTP/1.1.
type innerConn struct {
	conn *tls.Conn
	r    *bufio.Reader
}

func newInnerConn(conn *tls.Conn) *innerConn {
	return &innerConn{conn: conn, r: bufio.NewReader(conn)}
}

// errBody is returned for a request body without a length, or beyond
// connectionsv1.MaxBodySize. The caller closes the connection.
var errBody = errors.New("request body without length or too large")

// read reads the next request. Its body must have a known length within
// connectionsv1.MaxBodySize, so draining it before the next request stays
// bounded.
func (c *innerConn) read() (*http.Request, error) {
	req, err := http.ReadRequest(c.r)
	if err != nil {
		return nil, err
	}
	if req.ContentLength < 0 || req.ContentLength > connectionsv1.MaxBodySize {
		return nil, errBody
	}
	return req, nil
}

// respond writes v as JSON with status; v nil writes no body.
func (c *innerConn) respond(status int, v any) error {
	var body []byte
	if v != nil {
		var err error
		if body, err = json.Marshal(v); err != nil {
			return err
		}
	}
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	if v != nil {
		resp.Header.Set("Content-Type", connectionsv1.ContentTypeJSON)
	}
	return resp.Write(c.conn)
}

// refuse writes an ErrorResponse with its reason's status.
func (c *innerConn) refuse(reason connectionsv1.Reason, detail string, retryAfter time.Duration) error {
	return c.write(connectionsv1.ErrorResponse{Reason: reason, Detail: detail}, retryAfter)
}

// writeError writes e, e.g. a PreconditionFailed with the current etag.
func (c *innerConn) writeError(e connectionsv1.ErrorResponse) error { return c.write(e, 0) }

func (c *innerConn) write(e connectionsv1.ErrorResponse, retryAfter time.Duration) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	resp := &http.Response{
		StatusCode:    e.Reason.HTTPStatus(),
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {connectionsv1.ContentTypeJSON}},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	if retryAfter > 0 {
		resp.Header.Set("Retry-After", strconv.Itoa(int((retryAfter+time.Second-1)/time.Second)))
	}
	return resp.Write(c.conn)
}
