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
	"bytes"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/internal/testcerts"
)

func TestParse(t *testing.T) {
	a, b := testcerts.CA(t, "a", nil), testcerts.CA(t, "b", nil)

	got, err := Parse(testcerts.Join(a.PEM(), b.PEM()), testcerts.Now)
	require.NoError(t, err)
	assert.Len(t, got.Certificates(), 2)
	assert.True(t, got.Contains(fingerprint.OfCertificate(a.Cert)))
	assert.True(t, got.Contains(fingerprint.OfCertificate(b.Cert)))
	assert.False(t, got.Contains(fingerprint.OfCertificate(testcerts.CA(t, "c", nil).Cert)))

	fps := got.Fingerprints()
	assert.True(t, strings.Compare(fps[0].String(), fps[1].String()) < 0, "sorted")
}

func TestParseAllowsWhitespace(t *testing.T) {
	a, b := testcerts.CA(t, "a", nil), testcerts.CA(t, "b", nil)
	data := testcerts.Join([]byte("\n \t\r\n"), a.PEM(), []byte("\n\n  \r\n"), b.PEM(), []byte(" \n\t"))
	_, err := Parse(data, testcerts.Now)
	assert.NoError(t, err)
}

func TestParseKeepsSomeExpired(t *testing.T) {
	// An expired CA may be in the set, as long as one is unexpired.
	_, err := Parse(testcerts.Join(testcerts.CA(t, "old", nil, testcerts.Expired).PEM(), testcerts.CA(t, "new", nil).PEM()), testcerts.Now)
	assert.NoError(t, err)
}

func TestParseAcceptsIntermediateCA(t *testing.T) {
	// With an external PKI, PM's CA is an intermediate, pinned as the
	// anchor.
	root := testcerts.CA(t, "external root", nil)
	_, err := Parse(testcerts.CA(t, "pm", &root).PEM(), testcerts.Now)
	assert.NoError(t, err)
}

func TestParseRefuses(t *testing.T) {
	a, b := testcerts.CA(t, "a", nil), testcerts.CA(t, "b", nil)
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a.Cert.Raw})
	garbled := []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
	notDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	leaf := testcerts.Leaf(t, a)

	var many [][]byte
	for range MaxCertificates + 1 {
		many = append(many, testcerts.CA(t, "m", nil).PEM())
	}

	cases := map[string]struct {
		data   []byte
		reason Reason
	}{
		"empty":                     {nil, ReasonEmpty},
		"whitespace only":           {[]byte(" \n\t\r\n"), ReasonEmpty},
		"text before":               {testcerts.Join([]byte("ca:\n"), a.PEM()), ReasonTextOutsideBlocks},
		"text between":              {testcerts.Join(a.PEM(), []byte("# next\n"), b.PEM()), ReasonTextOutsideBlocks},
		"text after":                {testcerts.Join(a.PEM(), []byte("end")), ReasonTextOutsideBlocks},
		"garbled block":             {garbled, ReasonMalformedPEM},
		"garbled then good":         {testcerts.Join(garbled, a.PEM()), ReasonMalformedPEM},
		"unterminated":              {a.PEM()[:len(a.PEM())-10], ReasonMalformedPEM},
		"private key":               {testcerts.Join(a.PEM(), key), ReasonNotCertificate},
		"PEM headers":               {withHeaders, ReasonPEMHeaders},
		"not DER":                   {notDER, ReasonMalformedCertificate},
		"leaf, not CA":              {leaf.PEM(), ReasonNotCA},
		"CA:false":                  {testcerts.CA(t, "x", nil, testcerts.NotCA).PEM(), ReasonNotCA},
		"no keyCertSign":            {testcerts.CA(t, "x", nil, testcerts.NoCertSign).PEM(), ReasonNotCA},
		"duplicate":                 {testcerts.Join(a.PEM(), b.PEM(), a.PEM()), ReasonDuplicate},
		"only expired":              {testcerts.Join(testcerts.CA(t, "x", nil, testcerts.Expired).PEM(), testcerts.CA(t, "y", nil, testcerts.Expired).PEM()), ReasonAllExpired},
		"too many":                  {testcerts.Join(many...), ReasonTooMany},
		"too large":                 {testcerts.Join(a.PEM(), bytes.Repeat([]byte("\n"), MaxSize)), ReasonTooLarge},
	}
	for name, c := range cases {
		_, err := Parse(c.data, testcerts.Now)
		r, ok := ReasonOf(err)
		if assert.True(t, ok, "%s: %v", name, err) {
			assert.Equal(t, c.reason, r, name)
		}
	}
}

func TestParseRefusesTextOnEndLine(t *testing.T) {
	a := testcerts.CA(t, "a", nil)
	data := bytes.Replace(a.PEM(), []byte("-----END CERTIFICATE-----"), []byte("-----END CERTIFICATE----- x"), 1)
	_, err := Parse(data, testcerts.Now)
	r, _ := ReasonOf(err)
	assert.Equal(t, ReasonMalformedPEM, r)
}

func TestETagIgnoresOrderAndFormatting(t *testing.T) {
	a, b := testcerts.CA(t, "a", nil), testcerts.CA(t, "b", nil)

	ab, err := Parse(testcerts.Join(a.PEM(), b.PEM()), testcerts.Now)
	require.NoError(t, err)
	ba, err := Parse(testcerts.Join([]byte("\n\n"), b.PEM(), []byte("\r\n"), a.PEM()), testcerts.Now)
	require.NoError(t, err)
	only, err := Parse(a.PEM(), testcerts.Now)
	require.NoError(t, err)

	assert.Equal(t, ab.ETag(), ba.ETag())
	assert.True(t, ab.Equal(ba))
	assert.NotEqual(t, ab.ETag(), only.ETag())
	assert.False(t, ab.Equal(only))
	assert.Len(t, ab.ETag(), 64)
}

func TestEncodeIsCanonical(t *testing.T) {
	a, b := testcerts.CA(t, "a", nil), testcerts.CA(t, "b", nil)
	ba, err := Parse(testcerts.Join([]byte("\n"), b.PEM(), []byte("\n"), a.PEM()), testcerts.Now)
	require.NoError(t, err)

	again, err := Parse(ba.Encode(), testcerts.Now)
	require.NoError(t, err)
	assert.Equal(t, ba.Encode(), again.Encode())
	assert.Equal(t, ba.ETag(), again.ETag())
	assert.Equal(t, 2, bytes.Count(ba.Encode(), []byte("-----BEGIN CERTIFICATE-----\n")))
}

func TestParseStoredAcceptsOnlyExpired(t *testing.T) {
	data := testcerts.Join(testcerts.CA(t, "x", nil, testcerts.Expired).PEM(), testcerts.CA(t, "y", nil, testcerts.Expired).PEM())
	_, err := Parse(data, testcerts.Now)
	r, _ := ReasonOf(err)
	assert.Equal(t, ReasonAllExpired, r)

	b, err := ParseStored(data)
	require.NoError(t, err)
	assert.Len(t, b.Certificates(), 2)

	_, err = ParseStored(nil)
	r, _ = ReasonOf(err)
	assert.Equal(t, ReasonEmpty, r, "the other rules still apply")
}
