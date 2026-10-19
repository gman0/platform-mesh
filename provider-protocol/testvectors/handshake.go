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

package testvectors

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// HandshakeResult is the outcome of both ends of a TLS handshake.
type HandshakeResult struct {
	Client, Server     error
	ClientState        tls.ConnectionState
	ServerState        tls.ConnectionState
}

// Handshake runs a TLS handshake between two configs over loopback TCP and
// returns both ends' results.
//
// In TLS 1.3 the client completes before the server has checked a client
// certificate, so a refused client certificate shows only in Server.
func Handshake(t testing.TB, client, server *tls.Config) HandshakeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Loopback TCP buffers writes; an unbuffered net.Pipe deadlocks when
	// both ends write at once, e.g. an alert and a Finished.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var r HandshakeResult
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc, err := ln.Accept()
		if err != nil {
			r.Server = err
			return
		}
		defer sc.Close()
		s := tls.Server(sc, server)
		if r.Server = s.HandshakeContext(ctx); r.Server == nil {
			r.ServerState = s.ConnectionState()
		}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer cc.Close()
	c := tls.Client(cc, client)
	if r.Client = c.HandshakeContext(ctx); r.Client == nil {
		r.ClientState = c.ConnectionState()
	} else {
		// Lets a server waiting for the client's Finished end too.
		_ = cc.Close()
	}
	wg.Wait()
	return r
}
