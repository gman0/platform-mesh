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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashRoundTrip(t *testing.T) {
	h := NewConnectionSecret().Hash()
	p, err := ParseHash(h.String())
	require.NoError(t, err)
	assert.True(t, h.Equal(p))
	assert.Equal(t, h, p)
}

func TestHashZero(t *testing.T) {
	var z Hash
	assert.True(t, z.IsZero())
	assert.Equal(t, "", z.String())
	assert.False(t, z.Equal(z), "the zero value equals nothing, not even itself")
	assert.False(t, z.Equal(NewConnectionSecret().Hash()))
	_, err := z.MarshalText()
	assert.ErrorIs(t, err, ErrMalformedHash)
}

func TestParseHashRefuses(t *testing.T) {
	digits := strings.Repeat("ab", 32)
	cases := map[string]string{
		"empty":         "",
		"no prefix":     digits,
		"other prefix":  "sha512:" + digits,
		"prefix case":   "SHA256:" + digits,
		"uppercase hex": "sha256:" + strings.ToUpper(digits),
		"too short":     "sha256:" + digits[:63],
		"too long":      "sha256:" + digits + "a",
		"not hex":       "sha256:" + strings.Repeat("zz", 32),
		"fingerprint":   "key-sha256:" + digits,
		"whitespace":    "sha256:" + digits + " ",
	}
	for name, s := range cases {
		_, err := ParseHash(s)
		assert.ErrorIs(t, err, ErrMalformedHash, name)
	}
}

func TestHashJSON(t *testing.T) {
	h := NewConnectionSecret().Hash()
	b, err := json.Marshal(struct {
		H Hash `json:"secretHash"`
	}{h})
	require.NoError(t, err)
	assert.JSONEq(t, `{"secretHash":"`+h.String()+`"}`, string(b))

	var v struct {
		H Hash `json:"secretHash"`
	}
	require.NoError(t, json.Unmarshal(b, &v))
	assert.True(t, h.Equal(v.H))
	assert.Error(t, json.Unmarshal([]byte(`{"secretHash":"sha256:xx"}`), &v))
}
