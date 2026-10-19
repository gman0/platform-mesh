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
)

func TestParse(t *testing.T) {
	a, b := newCA(t, "a", nil), newCA(t, "b", nil)

	got, err := Parse(join(a.pem(), b.pem()), now)
	require.NoError(t, err)
	assert.Len(t, got.Certificates(), 2)
	assert.True(t, got.Contains(fingerprint.OfCertificate(a.cert)))
	assert.True(t, got.Contains(fingerprint.OfCertificate(b.cert)))
	assert.False(t, got.Contains(fingerprint.OfCertificate(newCA(t, "c", nil).cert)))

	fps := got.Fingerprints()
	assert.True(t, strings.Compare(fps[0].String(), fps[1].String()) < 0, "sorted")
}

func TestParseAllowsWhitespace(t *testing.T) {
	a, b := newCA(t, "a", nil), newCA(t, "b", nil)
	data := join([]byte("\n \t\r\n"), a.pem(), []byte("\n\n  \r\n"), b.pem(), []byte(" \n\t"))
	_, err := Parse(data, now)
	assert.NoError(t, err)
}

func TestParseKeepsSomeExpired(t *testing.T) {
	// An expired CA may be in the set, as long as one is unexpired.
	_, err := Parse(join(newCA(t, "old", nil, expired).pem(), newCA(t, "new", nil).pem()), now)
	assert.NoError(t, err)
}

func TestParseAcceptsIntermediateCA(t *testing.T) {
	// With an external PKI, PM's CA is an intermediate, pinned as the
	// anchor.
	root := newCA(t, "external root", nil)
	_, err := Parse(newCA(t, "pm", &root).pem(), now)
	assert.NoError(t, err)
}

func TestParseRefuses(t *testing.T) {
	a, b := newCA(t, "a", nil), newCA(t, "b", nil)
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a.cert.Raw})
	garbled := []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
	notDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	leaf := newLeaf(t, a)

	var many [][]byte
	for range MaxCertificates + 1 {
		many = append(many, newCA(t, "m", nil).pem())
	}

	cases := map[string]struct {
		data   []byte
		reason Reason
	}{
		"empty":                     {nil, ReasonEmpty},
		"whitespace only":           {[]byte(" \n\t\r\n"), ReasonEmpty},
		"text before":               {join([]byte("ca:\n"), a.pem()), ReasonTextOutsideBlocks},
		"text between":              {join(a.pem(), []byte("# next\n"), b.pem()), ReasonTextOutsideBlocks},
		"text after":                {join(a.pem(), []byte("end")), ReasonTextOutsideBlocks},
		"garbled block":             {garbled, ReasonMalformedPEM},
		"garbled then good":         {join(garbled, a.pem()), ReasonMalformedPEM},
		"unterminated":              {a.pem()[:len(a.pem())-10], ReasonMalformedPEM},
		"private key":               {join(a.pem(), key), ReasonNotCertificate},
		"PEM headers":               {withHeaders, ReasonPEMHeaders},
		"not DER":                   {notDER, ReasonMalformedCertificate},
		"leaf, not CA":              {leaf.pem(), ReasonNotCA},
		"CA:false":                  {newCA(t, "x", nil, notCA).pem(), ReasonNotCA},
		"no keyCertSign":            {newCA(t, "x", nil, noCertSign).pem(), ReasonNotCA},
		"duplicate":                 {join(a.pem(), b.pem(), a.pem()), ReasonDuplicate},
		"only expired":              {join(newCA(t, "x", nil, expired).pem(), newCA(t, "y", nil, expired).pem()), ReasonAllExpired},
		"too many":                  {join(many...), ReasonTooMany},
		"too large":                 {join(a.pem(), bytes.Repeat([]byte("\n"), MaxSize)), ReasonTooLarge},
	}
	for name, c := range cases {
		_, err := Parse(c.data, now)
		r, ok := ReasonOf(err)
		if assert.True(t, ok, "%s: %v", name, err) {
			assert.Equal(t, c.reason, r, name)
		}
	}
}

func TestParseRefusesTextOnEndLine(t *testing.T) {
	a := newCA(t, "a", nil)
	data := bytes.Replace(a.pem(), []byte("-----END CERTIFICATE-----"), []byte("-----END CERTIFICATE----- x"), 1)
	_, err := Parse(data, now)
	r, _ := ReasonOf(err)
	assert.Equal(t, ReasonMalformedPEM, r)
}

func TestETagIgnoresOrderAndFormatting(t *testing.T) {
	a, b := newCA(t, "a", nil), newCA(t, "b", nil)

	ab, err := Parse(join(a.pem(), b.pem()), now)
	require.NoError(t, err)
	ba, err := Parse(join([]byte("\n\n"), b.pem(), []byte("\r\n"), a.pem()), now)
	require.NoError(t, err)
	only, err := Parse(a.pem(), now)
	require.NoError(t, err)

	assert.Equal(t, ab.ETag(), ba.ETag())
	assert.True(t, ab.Equal(ba))
	assert.NotEqual(t, ab.ETag(), only.ETag())
	assert.False(t, ab.Equal(only))
	assert.Len(t, ab.ETag(), 64)
}

func TestEncodeIsCanonical(t *testing.T) {
	a, b := newCA(t, "a", nil), newCA(t, "b", nil)
	ba, err := Parse(join([]byte("\n"), b.pem(), []byte("\n"), a.pem()), now)
	require.NoError(t, err)

	again, err := Parse(ba.Encode(), now)
	require.NoError(t, err)
	assert.Equal(t, ba.Encode(), again.Encode())
	assert.Equal(t, ba.ETag(), again.ETag())
	assert.Equal(t, 2, bytes.Count(ba.Encode(), []byte("-----BEGIN CERTIFICATE-----\n")))
}
