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

// Package proxy is the operator proxy: an in-cluster HTTPS forward proxy
// through which the Provider's operator reaches kcp over a Connection's
// Sessions. Its client-go connects with the kubeconfig's proxy-url; every
// tunnel becomes one Stream.
package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/kubeconfig"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

// Sessions is what the proxy needs from the Session registry.
type Sessions interface {
	OpenStream(connectionID, host string) (net.Conn, error)
	Has(connectionID string) bool
	Report(connectionID, host string, reachable bool, err string)
}

// Proxy serves CONNECT.
type Proxy struct {
	Client    client.Client
	Namespace string
	Sessions  Sessions
	// TLS is the serving certificate inside every tunnel.
	TLS kubeconfig.Source
	// HandshakeTimeout bounds the TLS handshake inside a tunnel. Default 10s.
	HandshakeTimeout time.Duration
	Log              logr.Logger

	// Now defaults to time.Now.
	Now func() time.Time

	mu       sync.Mutex
	previous map[string]time.Time // connectionID → last use of the previous credential
}

// ServeHTTP handles one CONNECT.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
		return
	}
	id, credential, ok := proxyAuth(r)
	if !ok {
		authRequired(w)
		return
	}
	var conn sdkv1alpha1.Connection
	if err := p.Client.Get(r.Context(), types.NamespacedName{Namespace: p.Namespace, Name: id}, &conn); err != nil || conn.DeletionTimestamp != nil {
		http.Error(w, "unknown Connection", http.StatusNotFound)
		return
	}
	switch {
	case kubeconfig.MatchesHash(conn.Status.ProxyCredentialHash, credential):
	case kubeconfig.MatchesHash(conn.Status.PreviousProxyCredentialHash, credential):
		p.usedPrevious(id)
	default:
		authRequired(w)
		return
	}

	host := hostKey(r.Host)
	stream, err := p.Sessions.OpenStream(id, host)
	if err != nil && host != session.WorkspaceHost {
		// Endpoint slices may name a host without its default port.
		if h, port, splitErr := net.SplitHostPort(r.Host); splitErr == nil && port == "443" {
			host = h
			stream, err = p.Sessions.OpenStream(id, host)
		}
	}
	if err != nil {
		if p.Sessions.Has(id) {
			http.Error(w, "no Session serves this host", http.StatusNotFound)
		} else {
			// client-go retries; the message shows in the operator's logs.
			http.Error(w, "no Session for Connection "+id, http.StatusServiceUnavailable)
		}
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = stream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hj.Hijack()
	if err != nil {
		_ = stream.Close()
		return
	}
	// Bytes the server already read past the CONNECT, e.g. an eager
	// ClientHello, belong to the tunnel.
	go p.tunnel(&bufferedConn{Conn: raw, r: rw.Reader}, rw.Writer, stream, id, host)
}

// tunnel answers the CONNECT, terminates the TLS inside the tunnel, and
// copies bytes both ways, unchanged.
func (p *Proxy) tunnel(raw net.Conn, w io.Writer, stream net.Conn, id, host string) {
	defer raw.Close()
	defer stream.Close()
	if _, err := io.WriteString(w, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}

	timeout := p.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn := tls.Server(raw, &tls.Config{
		GetCertificate: p.TLS.GetCertificate,
		// A Stream carries one HTTP/1.1 connection: the Connector doesn't
		// speak h2c.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(context.Background()); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	sniffer := &statusSniffer{report: func(reachable bool, msg string) { p.Sessions.Report(id, host, reachable, msg) }}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, io.TeeReader(stream, sniffer))
		sniffer.end()
		done <- struct{}{}
	}()
	// Either direction ending ends the tunnel.
	<-done
}

func authRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="provider-gateway"`)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

// proxyAuth reads Proxy-Authorization: Basic connectionID:credential.
func proxyAuth(r *http.Request) (string, string, bool) {
	h := r.Header.Get("Proxy-Authorization")
	if h == "" {
		return "", "", false
	}
	req := &http.Request{Header: http.Header{"Authorization": {h}}}
	user, pass, ok := req.BasicAuth()
	if !ok || user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

// hostKey maps a CONNECT target to the registry's host: the placeholder is
// the Provider Workspace, served by every Session.
func hostKey(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil && h == kubeconfig.FrontProxyPlaceholder {
		return session.WorkspaceHost
	}
	return target
}

// bufferedConn reads what the HTTP server buffered before the hijack first.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
