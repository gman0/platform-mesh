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

// Package innertls builds the tls.Configs of the Inner TLS, the TLS 1.3
// handshake inside every WebSocket of the Connection API.
//
// The Inner TLS checks no hostnames. The Provider-side presents a
// self-signed certificate for a Server Key, and the PM-side accepts it only
// by the key's fingerprint. On Sessions, the Connector presents its Connector
// Certificate, which the Provider-side verifies against the Connection's
// Pinned Bundle. Every handshake is a full one: no session resumption.
package innertls

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"go.platform-mesh.io/provider-protocol/bundle"
	"go.platform-mesh.io/provider-protocol/fingerprint"
)

var (
	// ErrServerKeyNotPinned is returned when the Provider-side presents a key
	// the PM-side doesn't pin for the Connection.
	ErrServerKeyNotPinned = errors.New("server key not pinned")
	// ErrNoProtocol is returned when the handshake didn't agree on one of
	// the expected ALPN protocols.
	ErrNoProtocol = errors.New("no common application protocol")
	// ErrClientChain is returned when a Connector sends more than its
	// Connector Certificate.
	ErrClientChain = errors.New("client sent a certificate chain")
	// ErrNoPinnedBundle is returned when the Connection has no Pinned Bundle
	// anymore, e.g. it was deleted during the handshake.
	ErrNoPinnedBundle = errors.New("no pinned bundle")
)

// ServerKey is a Server Key ready for the Inner TLS: a self-signed
// certificate for it, and its key-sha256 fingerprint.
type ServerKey struct {
	Certificate tls.Certificate
	Fingerprint fingerprint.Fingerprint
}

// NewServerKey wraps a Server Key's signer, which may be backed by a KMS.
// Only the key matters to the PM-side, so the certificate is minimal and
// long-lived; it's signed once, here.
func NewServerKey(signer crypto.Signer) (ServerKey, error) {
	fp, err := fingerprint.OfPublicKey(signer.Public())
	if err != nil {
		return ServerKey{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pm-server-key"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return ServerKey{}, fmt.Errorf("self-signing server key: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return ServerKey{}, err
	}
	return ServerKey{
		Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer, Leaf: leaf},
		Fingerprint: fp,
	}, nil
}

// Server returns the Provider-side's config for Registration and Control
// Sessions: the Server Key, no client certificate, one of protocols.
func Server(key ServerKey, protocols []string) *tls.Config {
	c := base(protocols)
	c.Certificates = []tls.Certificate{key.Certificate}
	c.ClientAuth = tls.NoClientCert
	return c
}

// SessionServer returns the Provider-side's config for Sessions: the Server
// Key, and a Connector Certificate verified against the Connection's Pinned
// Bundle at the time of the handshake; pinned returns nil if the Connection
// is gone. now defaults to time.Now.
func SessionServer(key ServerKey, pinned func() *bundle.Bundle, protocols []string, now func() time.Time) *tls.Config {
	if now == nil {
		now = time.Now
	}
	c := Server(key, protocols)
	c.ClientAuth = tls.RequireAnyClientCert
	c.Time = now
	c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) != 1 {
			return ErrClientChain
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		b := pinned()
		if b == nil {
			return ErrNoPinnedBundle
		}
		return b.VerifyClient(leaf, now())
	}
	return c
}

// ClientOptions configure the PM-side's end.
type ClientOptions struct {
	// ServerKeys are the key-sha256 fingerprints pinned for the Connection:
	// the token's key at Registration, the Connection's keys afterwards.
	ServerKeys []fingerprint.Fingerprint
	// Protocols are the ALPN protocols to offer.
	Protocols []string
	// Certificate is the Connector Certificate, on Sessions only.
	Certificate *tls.Certificate
}

// Client returns the PM-side's config for all three channels.
func Client(o ClientOptions) *tls.Config {
	c := base(o.Protocols)
	if o.Certificate != nil {
		c.Certificates = []tls.Certificate{*o.Certificate}
	}
	// No hostname or chain checks: the server is accepted by its key alone,
	// in VerifyConnection. The handshake still proves possession of that
	// key.
	c.InsecureSkipVerify = true
	pinned := slices.Clone(o.ServerKeys)
	verifyALPN := c.VerifyConnection
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !slices.Contains(pinned, fingerprint.OfCertificateKey(cs.PeerCertificates[0])) {
			return ErrServerKeyNotPinned
		}
		return verifyALPN(cs)
	}
	return c
}

// PeerServerKey returns the fingerprint of the Server Key the Provider-side
// presented, after a handshake.
func PeerServerKey(cs tls.ConnectionState) fingerprint.Fingerprint {
	if len(cs.PeerCertificates) == 0 {
		return fingerprint.Fingerprint{}
	}
	return fingerprint.OfCertificateKey(cs.PeerCertificates[0])
}

// ClientCertificate returns the Connector Certificate a Session was opened
// with, to re-check it when the Pinned Bundle changes.
func ClientCertificate(cs tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

func base(protocols []string) *tls.Config {
	protocols = slices.Clone(protocols)
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             protocols,
		SessionTicketsDisabled: true,
		// Go accepts a handshake without ALPN on both sides; require it.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if !slices.Contains(protocols, cs.NegotiatedProtocol) {
				return ErrNoProtocol
			}
			return nil
		},
	}
}
