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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/fingerprint"
)

// ClientCertificateCase is a Connector Certificate presented in a Session's
// Inner TLS, possibly with extra certificates, and whether the Provider-side
// accepts it at Now against ClientCertificates' Pinned bundle.
type ClientCertificateCase struct {
	Name        string
	Certificate tls.Certificate
	Accepted    bool
}

// ClientCertificateVectors are the Pinned Bundle and the client
// certificates presented against it.
type ClientCertificateVectors struct {
	// Pinned is the Connection's Pinned Bundle: a current CA, a previous
	// one, and an expired one.
	Pinned []byte
	Cases  []ClientCertificateCase
}

// ClientCertificates are Connector Certificates for Sessions.
func ClientCertificates(t testing.TB) ClientCertificateVectors {
	t.Helper()
	current, previous := CA(t, "current", nil), CA(t, "previous", nil)
	expiredCA := CA(t, "expired", nil, Expired)
	unpinned := CA(t, "unpinned", nil)
	intermediate := CA(t, "intermediate", &current)
	viaIntermediate := Leaf(t, intermediate)

	return ClientCertificateVectors{
		Pinned: Join(current.PEM(), previous.PEM(), expiredCA.PEM()),
		Cases: []ClientCertificateCase{
			{"issued by the current CA", Leaf(t, current).TLS(), true},
			{"issued by the previous CA", Leaf(t, previous).TLS(), true},

			{"issued by an unpinned CA", Leaf(t, unpinned).TLS(), false},
			{"expired", Leaf(t, current, Expired).TLS(), false},
			{"issued by a pinned CA that has expired", Leaf(t, expiredCA).TLS(), false},
			{"without the clientAuth EKU", Leaf(t, current, NoEKU).TLS(), false},
			{"with serverAuth only", Leaf(t, current, ServerEKU).TLS(), false},
			{"without digitalSignature", Leaf(t, current, NoDigitalSignature).TLS(), false},
			{"issued by an intermediate, sent alone", viaIntermediate.TLS(), false},
			{"issued by an intermediate, sent with it", viaIntermediate.TLS(intermediate), false},
			{"valid, sent with its CA", Leaf(t, current).TLS(current), false},
			{"a pinned CA itself", current.TLS(), false},
		},
	}
}

// ServerKeyCase is a Server Key the Provider-side presents, and whether the
// PM-side, pinning ServerKeyVectors' Pinned, accepts it.
type ServerKeyCase struct {
	Name     string
	Key      crypto.Signer
	Accepted bool
}

// ServerKeyVectors are the keys the PM-side pins for a Connection and the
// keys presented to it.
type ServerKeyVectors struct {
	Pinned []fingerprint.Fingerprint
	Cases  []ServerKeyCase
}

// ServerKeys are Server Keys for all three channels. At Registration the
// pinned key is the one the Onboarding Token names, so "not pinned" is also
// the case of a token whose keyfp doesn't match the presented key.
func ServerKeys(t testing.TB) ServerKeyVectors {
	t.Helper()
	current, next, unpinned := newKey(t), newKey(t), newKey(t)
	return ServerKeyVectors{
		Pinned: []fingerprint.Fingerprint{keyFingerprint(t, current), keyFingerprint(t, next)},
		Cases: []ServerKeyCase{
			{"pinned", current, true},
			{"pinned, announced during a rotation", next, true},
			{"not pinned", unpinned, false},
		},
	}
}

// ProtocolCase is the ALPN protocols each end offers, and whether the
// handshake succeeds.
type ProtocolCase struct {
	Name           string
	Client, Server []string
	OK             bool
}

// Protocols are ALPN negotiations on a channel.
func Protocols() []ProtocolCase {
	reg, ctl := connectionsv1.ALPNRegister, connectionsv1.ALPNControl
	return []ProtocolCase{
		{"same protocol", []string{ctl}, []string{ctl}, true},
		{"another channel's protocol", []string{reg}, []string{ctl}, false},
		{"unknown version", []string{"pm-control/0"}, []string{ctl}, false},
		{"client offers none", nil, []string{ctl}, false},
		{"server selects none", []string{ctl}, nil, false},
	}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func keyFingerprint(t testing.TB, k crypto.Signer) fingerprint.Fingerprint {
	t.Helper()
	fp, err := fingerprint.OfPublicKey(k.Public())
	require.NoError(t, err)
	return fp
}
