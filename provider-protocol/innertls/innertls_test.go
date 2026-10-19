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

package innertls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/bundle"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/internal/testcerts"
)

type result struct {
	client, server       error
	clientCS, serverCS   tls.ConnectionState
}

// handshake runs both ends over loopback TCP. Its buffers let a failing end
// write its alert while the other end is writing too, which an unbuffered
// net.Pipe would deadlock on. A failing end closes its connection, so the
// other one doesn't wait.
func handshake(t *testing.T, client, server *tls.Config) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var r result
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc, err := ln.Accept()
		if err != nil {
			r.server = err
			return
		}
		defer sc.Close()
		s := tls.Server(sc, server)
		if r.server = s.HandshakeContext(ctx); r.server != nil {
			return
		}
		r.serverCS = s.ConnectionState()
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	c := tls.Client(cc, client)
	if r.client = c.HandshakeContext(ctx); r.client == nil {
		r.clientCS = c.ConnectionState()
	}
	// Closing lets a server still waiting for the client's Finished, or for
	// an alert, finish with an error.
	if r.client != nil {
		_ = cc.Close()
	}
	wg.Wait()
	_ = cc.Close()
	return r
}

func newServerKey(t *testing.T) ServerKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sk, err := NewServerKey(key)
	require.NoError(t, err)
	return sk
}

func pinnedBundle(t *testing.T, cas ...testcerts.Cert) func() *bundle.Bundle {
	t.Helper()
	var data []byte
	for _, c := range cas {
		data = append(data, c.PEM()...)
	}
	b, err := bundle.Parse(data, testcerts.Now)
	require.NoError(t, err)
	return func() *bundle.Bundle { return b }
}

func fixedNow() time.Time { return testcerts.Now }

var control = []string{connectionsv1.ALPNControl}

func TestNewServerKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sk, err := NewServerKey(key)
	require.NoError(t, err)

	want, err := fingerprint.OfPublicKey(key.Public())
	require.NoError(t, err)
	assert.Equal(t, want, sk.Fingerprint)
	assert.Equal(t, want, fingerprint.OfCertificateKey(sk.Certificate.Leaf))
}

func TestControlHandshake(t *testing.T) {
	sk := newServerKey(t)
	r := handshake(t,
		Client(ClientOptions{ServerKeys: []fingerprint.Fingerprint{sk.Fingerprint}, Protocols: control}),
		Server(sk, control))
	require.NoError(t, r.client)
	require.NoError(t, r.server)

	assert.Equal(t, connectionsv1.ALPNControl, r.clientCS.NegotiatedProtocol)
	assert.Equal(t, uint16(tls.VersionTLS13), r.clientCS.Version)
	assert.Equal(t, sk.Fingerprint, PeerServerKey(r.clientCS))
	assert.Nil(t, ClientCertificate(r.serverCS), "no client certificate on control")
}

func TestClientAcceptsAnyPinnedKey(t *testing.T) {
	old, cur := newServerKey(t), newServerKey(t)
	pins := []fingerprint.Fingerprint{old.Fingerprint, cur.Fingerprint}
	for _, sk := range []ServerKey{old, cur} {
		r := handshake(t, Client(ClientOptions{ServerKeys: pins, Protocols: control}), Server(sk, control))
		assert.NoError(t, r.client)
	}
}

func TestClientRefusesUnpinnedKey(t *testing.T) {
	r := handshake(t,
		Client(ClientOptions{ServerKeys: []fingerprint.Fingerprint{newServerKey(t).Fingerprint}, Protocols: control}),
		Server(newServerKey(t), control))
	assert.ErrorIs(t, r.client, ErrServerKeyNotPinned)
	assert.Error(t, r.server)

	r = handshake(t, Client(ClientOptions{Protocols: control}), Server(newServerKey(t), control))
	assert.ErrorIs(t, r.client, ErrServerKeyNotPinned, "nothing pinned")
}

func TestProtocolsMustMatch(t *testing.T) {
	sk := newServerKey(t)
	pins := []fingerprint.Fingerprint{sk.Fingerprint}

	r := handshake(t,
		Client(ClientOptions{ServerKeys: pins, Protocols: []string{connectionsv1.ALPNRegister}}),
		Server(sk, control))
	assert.Error(t, r.client, "register client at a control server")
	assert.Error(t, r.server)

	noALPN := Client(ClientOptions{ServerKeys: pins})
	r = handshake(t, noALPN, Server(sk, control))
	assert.ErrorIs(t, r.server, ErrNoProtocol, "client offers no protocol")

	r = handshake(t, Client(ClientOptions{ServerKeys: pins, Protocols: control}), &tls.Config{Certificates: []tls.Certificate{sk.Certificate}})
	assert.ErrorIs(t, r.client, ErrNoProtocol, "server selects no protocol")
}

func TestTLS12Refused(t *testing.T) {
	sk := newServerKey(t)
	old := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: control}
	r := handshake(t, old, Server(sk, control))
	assert.Error(t, r.server)
}

func TestNoResumption(t *testing.T) {
	sk := newServerKey(t)
	client := Client(ClientOptions{ServerKeys: []fingerprint.Fingerprint{sk.Fingerprint}, Protocols: control})
	client.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	server := Server(sk, control)

	for range 2 {
		r := handshake(t, client, server)
		require.NoError(t, r.client)
		assert.False(t, r.clientCS.DidResume)
	}
}

var session = []string{connectionsv1.ALPNSession}

func sessionPair(t *testing.T, sk ServerKey, pinned func() *bundle.Bundle, cert *tls.Certificate) result {
	t.Helper()
	return handshake(t,
		Client(ClientOptions{ServerKeys: []fingerprint.Fingerprint{sk.Fingerprint}, Protocols: session, Certificate: cert}),
		SessionServer(sk, pinned, session, fixedNow))
}

func TestSessionHandshake(t *testing.T) {
	sk := newServerKey(t)
	ca := testcerts.CA(t, "connector-ca", nil)
	leaf := testcerts.Leaf(t, ca)
	cert := leaf.TLS()

	r := sessionPair(t, sk, pinnedBundle(t, ca), &cert)
	require.NoError(t, r.client)
	require.NoError(t, r.server)
	assert.Equal(t, connectionsv1.ALPNSession, r.serverCS.NegotiatedProtocol)
	assert.Equal(t, leaf.Cert.Raw, ClientCertificate(r.serverCS).Raw)
}

func TestSessionRefuses(t *testing.T) {
	sk := newServerKey(t)
	ca := testcerts.CA(t, "connector-ca", nil)
	other := testcerts.CA(t, "other", nil)
	intermediate := testcerts.CA(t, "intermediate", &ca)
	pinned := pinnedBundle(t, ca)
	expiredCA := testcerts.CA(t, "expired", nil, testcerts.Expired)
	withExpired := pinnedBundle(t, ca, expiredCA)

	tlsOf := func(c testcerts.Cert, chain ...testcerts.Cert) *tls.Certificate {
		x := c.TLS(chain...)
		return &x
	}
	viaIntermediate := testcerts.Leaf(t, intermediate)

	cases := map[string]struct {
		cert   *tls.Certificate
		pinned func() *bundle.Bundle
		want   error
	}{
		"no client certificate":     {nil, pinned, nil},
		"unpinned CA":               {tlsOf(testcerts.Leaf(t, other)), pinned, nil},
		"expired":                   {tlsOf(testcerts.Leaf(t, ca, testcerts.Expired)), pinned, nil},
		"no clientAuth EKU":         {tlsOf(testcerts.Leaf(t, ca, testcerts.NoEKU)), pinned, bundle.ErrClientUsage},
		"intermediate in chain":     {tlsOf(viaIntermediate, intermediate), pinned, ErrClientChain},
		"intermediate, no chain":    {tlsOf(viaIntermediate), pinned, nil},
		"extra certificate":         {tlsOf(testcerts.Leaf(t, ca), ca), pinned, ErrClientChain},
		"Connection gone":           {tlsOf(testcerts.Leaf(t, ca)), func() *bundle.Bundle { return nil }, ErrNoPinnedBundle},
		"pinned CA expired":         {tlsOf(testcerts.Leaf(t, expiredCA)), withExpired, nil},
	}
	// In TLS 1.3 the client completes before the server has checked its
	// certificate, so only the server's result counts here.
	for name, c := range cases {
		r := sessionPair(t, sk, c.pinned, c.cert)
		if assert.Error(t, r.server, name) && c.want != nil {
			assert.ErrorIs(t, r.server, c.want, name)
		}
	}
}

func TestSessionReadsBundleAtHandshake(t *testing.T) {
	sk := newServerKey(t)
	prev, cur := testcerts.CA(t, "previous", nil), testcerts.CA(t, "current", nil)
	both, onlyCur := pinnedBundle(t, prev, cur), pinnedBundle(t, cur)

	current := both
	pinned := func() *bundle.Bundle { return current() }
	cert := testcerts.Leaf(t, prev).TLS()

	assert.NoError(t, sessionPair(t, sk, pinned, &cert).server)
	current = onlyCur // the previous CA was dropped
	assert.Error(t, sessionPair(t, sk, pinned, &cert).server)
}
