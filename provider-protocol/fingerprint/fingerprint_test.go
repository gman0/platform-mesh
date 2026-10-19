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

package fingerprint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfCertificate(t *testing.T) {
	cert, key := testCert(t)

	f := OfCertificate(cert)
	assert.Equal(t, CertSHA256, f.Kind())
	assert.Equal(t, "cert-sha256:"+sha256Hex(cert.Raw), f.String())
	assert.Equal(t, sha256Hex(cert.Raw), f.Hex())

	k := OfCertificateKey(cert)
	assert.Equal(t, KeySHA256, k.Kind())
	assert.Equal(t, "key-sha256:"+sha256Hex(cert.RawSubjectPublicKeyInfo), k.String())

	// The certificate's key and the key itself give the same fingerprint.
	p, err := OfPublicKey(key.Public())
	require.NoError(t, err)
	assert.Equal(t, k, p)
	assert.NotEqual(t, f, k)
}

func TestOfPublicKeyUnsupported(t *testing.T) {
	_, err := OfPublicKey(struct{}{})
	assert.Error(t, err)
}

func TestOfPublicKeyEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f, err := OfPublicKey(pub)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	assert.Equal(t, "key-sha256:"+sha256Hex(der), f.String())
}

func TestParseRoundTrip(t *testing.T) {
	digits := strings.Repeat("0123456789abcdef", 4)
	for _, s := range []string{"cert-sha256:" + digits, "key-sha256:" + digits} {
		f, err := Parse(s)
		require.NoError(t, err, s)
		assert.Equal(t, s, f.String())
	}
}

func TestParseRefuses(t *testing.T) {
	digits := strings.Repeat("ab", 32)
	cases := map[string]string{
		"empty":            "",
		"no kind":          digits,
		"empty digits":     "key-sha256:",
		"unknown kind":     "sha256:" + digits,
		"kind case":        "KEY-SHA256:" + digits,
		"uppercase hex":    "key-sha256:" + strings.ToUpper(digits),
		"too short":        "key-sha256:" + digits[:63],
		"too long":         "key-sha256:" + digits + "a",
		"not hex":          "key-sha256:" + strings.Repeat("zz", 32),
		"openssl style":    "key-sha256:" + openSSLStyle(digits),
		"openssl output":   "SHA256 Fingerprint=" + openSSLStyle(strings.ToUpper(digits)),
		"leading space":    " key-sha256:" + digits,
		"trailing newline": "key-sha256:" + digits + "\n",
		"two colons":       "key-sha256::" + digits,
	}
	for name, s := range cases {
		_, err := Parse(s)
		assert.ErrorIs(t, err, ErrMalformed, name)
	}
}

func TestParseKind(t *testing.T) {
	s := "key-sha256:" + strings.Repeat("ab", 32)

	f, err := ParseKind(s, KeySHA256)
	require.NoError(t, err)
	assert.Equal(t, KeySHA256, f.Kind())

	_, err = ParseKind(s, CertSHA256)
	assert.ErrorIs(t, err, ErrWrongKind)

	_, err = ParseKind("bogus", KeySHA256)
	assert.ErrorIs(t, err, ErrMalformed)
}

func TestZero(t *testing.T) {
	var f Fingerprint
	assert.True(t, f.IsZero())
	assert.Equal(t, "", f.String())
	assert.Equal(t, "", f.Hex())
	_, err := f.MarshalText()
	assert.ErrorIs(t, err, ErrMalformed)
}

func TestJSON(t *testing.T) {
	s := "cert-sha256:" + strings.Repeat("cd", 32)
	var v struct {
		F Fingerprint `json:"f"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"f":"`+s+`"}`), &v))
	assert.Equal(t, s, v.F.String())

	b, err := json.Marshal(v)
	require.NoError(t, err)
	assert.JSONEq(t, `{"f":"`+s+`"}`, string(b))

	assert.Error(t, json.Unmarshal([]byte(`{"f":"bogus"}`), &v))
}

func testCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func openSSLStyle(digits string) string {
	pairs := make([]string, 0, len(digits)/2)
	for i := 0; i < len(digits); i += 2 {
		pairs = append(pairs, digits[i:i+2])
	}
	return strings.Join(pairs, ":")
}
