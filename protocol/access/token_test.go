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

package access

import (
	"bytes"
	"errors"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	in := Token{
		URL:     "https://access.example/access",
		TokenID: "id-123",
		Secret:  []byte("secret-material"),
	}

	got, err := ParseToken(in.String())
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if got.URL != in.URL {
		t.Errorf("URL mismatch: got %q, want %q", got.URL, in.URL)
	}
	if got.TokenID != in.TokenID {
		t.Errorf("TokenID mismatch: got %q, want %q", got.TokenID, in.TokenID)
	}
	if !bytes.Equal(got.Secret, in.Secret) {
		t.Errorf("Secret mismatch: got %q, want %q", got.Secret, in.Secret)
	}
}

func TestParseTokenRejects(t *testing.T) {
	// Build a valid baseline we'll mutate.
	valid := Token{URL: "https://a.example/access", TokenID: "id", Secret: []byte("s")}.String()

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong prefix", "pma0." + valid[5:]},
		{"too few segments", "pma1.abc.def"},
		{"too many segments", valid + ".extra"},
		{"non-base64url url", "pma1.***.id.cw"},
		{"empty url", "pma1..id.cw"},
		{"empty tokenID", "pma1.aHR0cHM.." /* missing trailing */ + "cw"},
		{"empty secret", "pma1." + "aHR0cHM.id."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseToken(tc.in); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("want ErrInvalidToken, got %v", err)
			}
		})
	}
}

func TestTokenStringUsesRawBase64URL(t *testing.T) {
	// Raw (unpadded) base64url means '=' never appears on the wire; the
	// token format relies on splitting by '.' and would break if the
	// encoded URL / secret segment contained '.' or '='.
	tok := Token{URL: "https://a.example/access", TokenID: "id", Secret: []byte{0}}
	s := tok.String()
	for _, c := range s {
		if c == '=' {
			t.Fatalf("String produced padded base64: %q", s)
		}
	}
}
