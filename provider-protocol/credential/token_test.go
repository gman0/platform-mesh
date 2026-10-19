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
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/fingerprint"
)

const testBaseURL = "https://wildwest.example.com/pm"

func testKey(t *testing.T) fingerprint.Fingerprint {
	t.Helper()
	f, err := fingerprint.Parse("key-sha256:" + strings.Repeat("0f", 32))
	require.NoError(t, err)
	return f
}

func TestNewOnboardingToken(t *testing.T) {
	tok, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)

	assert.Equal(t, testBaseURL, tok.BaseURL())
	assert.Equal(t, testKey(t), tok.ServerKey())
	assert.NoError(t, ValidateTokenID(tok.ID()))

	parts := strings.Split(tok.Reveal(), ".")
	require.Len(t, parts, 5)
	assert.Equal(t, "pm1", parts[0])
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte(testBaseURL)), parts[1])
	assert.Equal(t, strings.Repeat("0f", 32), parts[2])
	assert.Equal(t, tok.ID(), parts[3])
	assert.Equal(t, tok.RevealSecret(), parts[4])
}

func TestNewOnboardingTokenRefuses(t *testing.T) {
	_, err := NewOnboardingToken("http://wildwest.example.com", testKey(t))
	assert.ErrorIs(t, err, ErrInvalidBaseURL)

	cert, err := fingerprint.Parse("cert-sha256:" + strings.Repeat("0f", 32))
	require.NoError(t, err)
	_, err = NewOnboardingToken(testBaseURL, cert)
	assert.ErrorIs(t, err, fingerprint.ErrWrongKind)

	_, err = NewOnboardingToken(testBaseURL, fingerprint.Fingerprint{})
	assert.ErrorIs(t, err, fingerprint.ErrWrongKind)
}

func TestOnboardingTokenRoundTrip(t *testing.T) {
	tok, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)

	p, err := ParseOnboardingToken(tok.Reveal())
	require.NoError(t, err)
	assert.Equal(t, tok, p)
}

func TestTokenSecretHash(t *testing.T) {
	tok, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)

	h, err := HashTokenSecret(tok.RevealSecret())
	require.NoError(t, err)
	assert.True(t, tok.SecretHash().Equal(h))

	other, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)
	h, err = HashTokenSecret(other.RevealSecret())
	require.NoError(t, err)
	assert.False(t, tok.SecretHash().Equal(h))

	for _, bad := range []string{"", "x", tok.Reveal(), tok.RevealSecret() + "="} {
		_, err := HashTokenSecret(bad)
		assert.ErrorIs(t, err, ErrMalformedTokenSecret, bad)
	}
}

func TestOnboardingTokenNeverPrinted(t *testing.T) {
	tok, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)
	for _, out := range []string{
		tok.String(),
		tok.GoString(),
		fmt.Sprintf("%v %+v %s %#v", tok, tok, tok, tok),
	} {
		assert.NotContains(t, out, tok.RevealSecret())
	}
	// The public parts stay visible for logs.
	assert.Contains(t, tok.String(), tok.ID())
	assert.Equal(t, "<empty>", OnboardingToken{}.String())
	assert.Equal(t, "", OnboardingToken{}.Reveal())
}

func TestParseOnboardingTokenRefuses(t *testing.T) {
	tok, err := NewOnboardingToken(testBaseURL, testKey(t))
	require.NoError(t, err)
	p := strings.Split(tok.Reveal(), ".")
	join := func(parts ...string) string { return strings.Join(parts, ".") }
	url := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	cases := map[string]string{
		"empty":             "",
		"four parts":        join(p[0], p[1], p[2], p[3]),
		"six parts":         join(append(p, "x")...),
		"other version":     join("pm2", p[1], p[2], p[3], p[4]),
		"url not base64url": join(p[0], "!!", p[2], p[3], p[4]),
		"url padded":        join(p[0], p[1]+"=", p[2], p[3], p[4]),
		"url with newline":  join(p[0], p[1][:4]+"\n"+p[1][4:], p[2], p[3], p[4]),
		"secret with CR":    join(p[0], p[1], p[2], p[3], p[4][:10]+"\r"+p[4][10:]),
		"url http":          join(p[0], url("http://wildwest.example.com"), p[2], p[3], p[4]),
		"key with kind":     join(p[0], p[1], "key-sha256:"+p[2], p[3], p[4]),
		"key uppercase":     join(p[0], p[1], strings.ToUpper(p[2]), p[3], p[4]),
		"key short":         join(p[0], p[1], p[2][:63], p[3], p[4]),
		"bad token ID":      join(p[0], p[1], p[2], "c-"+p[3][2:], p[4]),
		"secret short":      join(p[0], p[1], p[2], p[3], p[4][:42]),
		"secret padded":     join(p[0], p[1], p[2], p[3], p[4]+"="),
		"trailing newline":  tok.Reveal() + "\n",
		"too long":          join(p[0], url(testBaseURL+strings.Repeat("a", MaxTokenLength)), p[2], p[3], p[4]),
	}
	for name, s := range cases {
		_, err := ParseOnboardingToken(s)
		assert.ErrorIs(t, err, ErrMalformedToken, name)
	}
}

func TestValidateBaseURL(t *testing.T) {
	for _, s := range []string{
		"https://wildwest.example.com",
		"https://wildwest.example.com/",
		"https://wildwest.example.com/pm",
		"https://wildwest.example.com:8443/pm/",
		"https://10.0.0.1/pm",
		"https://[::1]:8443",
	} {
		assert.NoError(t, ValidateBaseURL(s), s)
	}

	for _, s := range []string{
		"",
		"wildwest.example.com",
		"/pm",
		"http://wildwest.example.com",
		"HTTPS://wildwest.example.com",
		"wss://wildwest.example.com",
		"https://",
		"https:wildwest.example.com",
		"https://user@wildwest.example.com",
		"https://user:pw@wildwest.example.com",
		"https://wildwest.example.com/pm?x=1",
		"https://wildwest.example.com/pm?",
		"https://wildwest.example.com/pm#x",
		"https://wildwest.example.com/a/../pm",
		"https://wildwest.example.com/./pm",
		"https://wildwest.example.com/pm/..",
		"https://wildwest.example.com/p m",
		"https://wildwest.example.com/" + strings.Repeat("a", MaxBaseURLLength),
	} {
		assert.ErrorIs(t, ValidateBaseURL(s), ErrInvalidBaseURL, s)
	}
}
