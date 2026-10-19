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

package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConnectionSecret(t *testing.T) {
	s := NewConnectionSecret()
	v := s.Reveal()

	assert.True(t, strings.HasPrefix(v, "pmc1_"))
	assert.Len(t, v, len("pmc1_")+43)

	p, err := ParseConnectionSecret(v)
	require.NoError(t, err)
	assert.Equal(t, s, p)
	assert.NotEqual(t, v, NewConnectionSecret().Reveal())
}

func TestConnectionSecretHash(t *testing.T) {
	s := NewConnectionSecret()
	sum := sha256.Sum256([]byte(s.Reveal()))
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), s.Hash().String())
	assert.True(t, s.Hash().Equal(s.Hash()))
	assert.False(t, s.Hash().Equal(NewConnectionSecret().Hash()))
}

func TestConnectionSecretNeverPrinted(t *testing.T) {
	s := NewConnectionSecret()
	for _, out := range []string{
		s.String(),
		s.GoString(),
		fmt.Sprintf("%v %+v %s %#v", s, s, s, s),
		fmt.Sprintf("%v", struct{ S ConnectionSecret }{s}),
	} {
		assert.NotContains(t, out, s.Reveal())
		assert.NotContains(t, out, "pmc1_")
	}
	assert.Equal(t, "<empty>", ConnectionSecret{}.String())
}

func TestParseConnectionSecretRefuses(t *testing.T) {
	good := strings.TrimPrefix(NewConnectionSecret().Reveal(), "pmc1_")
	cases := map[string]string{
		"empty":           "",
		"no prefix":       good,
		"other prefix":    "pmc2_" + good,
		"prefix only":     "pmc1_",
		"too short":       "pmc1_" + good[:42],
		"too long":        "pmc1_" + good + "A",
		"padding":         "pmc1_" + good + "=",
		"std alphabet":    "pmc1_" + strings.Repeat("+", 43),
		"whitespace":      "pmc1_" + good + "\n",
		"inner newline":   "pmc1_" + good[:20] + "\n" + good[20:],
		"inner CR":        "pmc1_" + good[:20] + "\r" + good[20:],
		"non-canonical":   "pmc1_" + good[:42] + nonCanonicalLast(good[42]),
		"leading space":   " pmc1_" + good,
		"token secret in": "pm1." + good,
	}
	for name, s := range cases {
		_, err := ParseConnectionSecret(s)
		assert.ErrorIs(t, err, ErrMalformedSecret, name)
	}
}

// nonCanonicalLast returns a last character that decodes to the same bytes
// but sets unused bits, which strict decoding refuses.
func nonCanonicalLast(c byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, c)
	// 32 bytes encode to 43 characters; the last carries 4 bits and 2 unused.
	return string(alphabet[i^1])
}
