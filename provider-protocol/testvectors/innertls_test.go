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

package testvectors_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"
	tv "go.platform-mesh.io/provider-protocol/testvectors"
)

var session = []string{connectionsv1.ALPNSession}

func serverKey(t *testing.T) innertls.ServerKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sk, err := innertls.NewServerKey(k)
	require.NoError(t, err)
	return sk
}

func TestClientCertificates(t *testing.T) {
	v := tv.ClientCertificates(t)
	pinned, err := bundle.Parse(v.Pinned, tv.Now)
	require.NoError(t, err)
	sk := serverKey(t)
	server := innertls.SessionServer(sk, func() *bundle.Bundle { return pinned }, session, func() time.Time { return tv.Now })

	for _, c := range v.Cases {
		cert := c.Certificate
		client := innertls.Client(innertls.ClientOptions{
			ServerKeys:  []fingerprint.Fingerprint{sk.Fingerprint},
			Protocols:   session,
			Certificate: &cert,
		})
		r := tv.Handshake(t, client, server)
		if c.Accepted {
			assert.NoError(t, r.Server, c.Name)
		} else {
			assert.Error(t, r.Server, c.Name)
		}
	}
}

func TestServerKeys(t *testing.T) {
	v := tv.ServerKeys(t)
	control := []string{connectionsv1.ALPNControl}
	client := innertls.Client(innertls.ClientOptions{ServerKeys: v.Pinned, Protocols: control})

	for _, c := range v.Cases {
		sk, err := innertls.NewServerKey(c.Key)
		require.NoError(t, err)
		r := tv.Handshake(t, client, innertls.Server(sk, control))
		if c.Accepted {
			assert.NoError(t, r.Client, c.Name)
		} else {
			assert.ErrorIs(t, r.Client, innertls.ErrServerKeyNotPinned, c.Name)
		}
	}
}

func TestProtocols(t *testing.T) {
	sk := serverKey(t)
	for _, c := range tv.Protocols() {
		client := innertls.Client(innertls.ClientOptions{ServerKeys: []fingerprint.Fingerprint{sk.Fingerprint}, Protocols: c.Client})
		r := tv.Handshake(t, client, innertls.Server(sk, c.Server))
		if c.OK {
			assert.NoError(t, r.Client, c.Name)
			assert.NoError(t, r.Server, c.Name)
		} else {
			assert.True(t, r.Client != nil || r.Server != nil, c.Name)
		}
	}
}

func TestHandshakeAgainstPlainTLS(t *testing.T) {
	// The helper itself: a plain TLS 1.3 pair succeeds.
	sk := serverKey(t)
	r := tv.Handshake(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, &tls.Config{Certificates: []tls.Certificate{sk.Certificate}})
	assert.NoError(t, r.Client)
	assert.NoError(t, r.Server)
	assert.Equal(t, uint16(tls.VersionTLS13), r.ClientState.Version)
}
