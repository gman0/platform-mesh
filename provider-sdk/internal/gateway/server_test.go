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

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tv "go.platform-mesh.io/provider-protocol/testvectors"
)

// freeAddress returns a loopback address nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// start runs s until the test ends, and returns a channel with its result.
func start(t *testing.T, s *server) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(cancel)
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", s.addr)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	return cancel, done
}

func get(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

var hello = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") })

func TestServerPlain(t *testing.T) {
	s := &server{name: "test", addr: freeAddress(t), handler: hello}
	cancel, done := start(t, s)
	assert.Equal(t, "hello", get(t, http.DefaultClient, "http://"+s.addr))

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("not stopped")
	}
}

func TestServerTLS(t *testing.T) {
	ca := tv.CA(t, "serving", nil)
	leaf := tv.Leaf(t, ca, tv.ServerEKU, func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} })
	cert := leaf.TLS()
	s := &server{name: "test", addr: freeAddress(t), handler: hello, tls: serverTLS(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil })}
	start(t, s)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, Time: func() time.Time { return tv.Now }},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://" + s.addr)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 1, resp.ProtoMajor, "HTTP/1.1 only: upgrades and CONNECT need it")
}

func TestServerAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	s := &server{name: "test", addr: ln.Addr().String(), handler: hello}
	assert.Error(t, s.Start(context.Background()))
}

func TestLeaderElection(t *testing.T) {
	assert.False(t, (&server{}).NeedLeaderElection())
	assert.True(t, (&server{leader: true}).NeedLeaderElection())
	assert.False(t, anyReplica{}.NeedLeaderElection())
}
