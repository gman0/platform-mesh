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

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (i issued) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw})
}

// certOpt changes a certificate template before signing.
type certOpt func(*x509.Certificate)

func expired(c *x509.Certificate) {
	c.NotBefore = now.Add(-48 * time.Hour)
	c.NotAfter = now.Add(-time.Hour)
}

func notCA(c *x509.Certificate) { c.IsCA = false }

func noCertSign(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCertSign }

func noEKU(c *x509.Certificate) { c.ExtKeyUsage = nil }

func serverEKU(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }

func noDigitalSignature(c *x509.Certificate) { c.KeyUsage = 0 }

var serial int64

func sign(t *testing.T, tmpl *x509.Certificate, parent *issued, opts ...certOpt) issued {
	t.Helper()
	for _, o := range opts {
		o(tmpl)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return issued{cert: cert, key: key}
}

func nextSerial() *big.Int {
	serial++
	return big.NewInt(serial)
}

// newCA returns a self-signed Connector CA, or one signed by parent.
func newCA(t *testing.T, name string, parent *issued, opts ...certOpt) issued {
	t.Helper()
	return sign(t, &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, parent, opts...)
}

// newLeaf returns a Connector Certificate issued by ca.
func newLeaf(t *testing.T, ca issued, opts ...certOpt) issued {
	t.Helper()
	return sign(t, &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "connector"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(23 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &ca, opts...)
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
