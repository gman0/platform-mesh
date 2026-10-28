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

package providertest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-sdk/internal/session"
)

// WorkspaceHost stands for the Provider Workspace in OpenStream and
// RoundTrip; every Session serves it.
const WorkspaceHost = session.WorkspaceHost

// Sessions is the number of the Connection's live Sessions serving host,
// not counting those the Connector sent go-away on.
func (p *Provider) Sessions(id, host string) int { return p.registry.Count(id, host) }

// WaitSessions waits until the Connection has n Sessions serving the
// Provider Workspace.
func (p *Provider) WaitSessions(id string, n int) {
	p.t.Helper()
	require.Eventually(p.t, func() bool { return p.Sessions(id, WorkspaceHost) == n },
		5*time.Second, 10*time.Millisecond, "waiting for %d Session(s) of %s", n, id)
}

// OpenStream opens a Stream for host on one of the Connection's Sessions,
// as the operator proxy does for each tunnel.
func (p *Provider) OpenStream(id, host string) (net.Conn, error) {
	return p.registry.OpenStream(id, host)
}

// RoundTrip sends req, HTTP/1.1, over a new Stream for host and returns the
// response; closing its body closes the Stream.
func (p *Provider) RoundTrip(id, host string, req *http.Request) (*http.Response, error) {
	stream, err := p.OpenStream(id, host)
	if err != nil {
		return nil, err
	}
	if err := req.Write(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	resp.Body = &streamBody{ReadCloser: resp.Body, stream: stream}
	return resp, nil
}

type streamBody struct {
	io.ReadCloser
	stream net.Conn
}

func (b *streamBody) Close() error {
	err := b.ReadCloser.Close()
	_ = b.stream.Close()
	return err
}
