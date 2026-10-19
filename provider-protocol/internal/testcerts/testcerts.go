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

// Package testcerts creates Connector CAs and Connector Certificates for
// tests.
package testcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Now is the time certificates are valid around.
var Now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// Cert is a certificate and its key.
type Cert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// PEM returns the certificate as a PEM block.
func (c Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// TLS returns the certificate for a tls.Config, optionally with a chain.
func (c Cert) TLS(chain ...Cert) tls.Certificate {
	out := tls.Certificate{Certificate: [][]byte{c.Cert.Raw}, PrivateKey: c.Key, Leaf: c.Cert}
	for _, ch := range chain {
		out.Certificate = append(out.Certificate, ch.Cert.Raw)
	}
	return out
}

// Opt changes a certificate template before signing.
type Opt func(*x509.Certificate)

// Expired makes the certificate expire an hour before Now.
func Expired(c *x509.Certificate) {
	c.NotBefore = Now.Add(-48 * time.Hour)
	c.NotAfter = Now.Add(-time.Hour)
}

// NotCA clears basic constraints' CA flag.
func NotCA(c *x509.Certificate) { c.IsCA = false }

// NoCertSign removes the keyCertSign key usage.
func NoCertSign(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCertSign }

// NoEKU removes all extended key usages.
func NoEKU(c *x509.Certificate) { c.ExtKeyUsage = nil }

// ServerEKU replaces the extended key usages with serverAuth.
func ServerEKU(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }

// NoDigitalSignature removes all key usages.
func NoDigitalSignature(c *x509.Certificate) { c.KeyUsage = 0 }

var serial atomic.Int64

// CA returns a self-signed Connector CA, or one signed by parent.
func CA(t testing.TB, name string, parent *Cert, opts ...Opt) Cert {
	t.Helper()
	return sign(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             Now.Add(-time.Hour),
		NotAfter:              Now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, parent, opts...)
}

// Leaf returns a Connector Certificate issued by ca.
func Leaf(t testing.TB, ca Cert, opts ...Opt) Cert {
	t.Helper()
	return sign(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "connector"},
		NotBefore:             Now.Add(-time.Hour),
		NotAfter:              Now.Add(23 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &ca, opts...)
}

// Join concatenates byte slices, e.g. PEM blocks.
func Join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func sign(t testing.TB, tmpl *x509.Certificate, parent *Cert, opts ...Opt) Cert {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	for _, o := range opts {
		o(tmpl)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return Cert{Cert: cert, Key: key}
}
