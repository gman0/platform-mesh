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
	"errors"
	"net/url"
	"strings"

	"go.platform-mesh.io/provider-protocol/fingerprint"
)

const (
	tokenPrefix = "pm1"

	// MaxTokenLength bounds an Onboarding Token's text form.
	MaxTokenLength = 4096

	// MaxBaseURLLength bounds a Base URL.
	MaxBaseURLLength = 2048
)

var (
	// ErrMalformedToken is returned for text that isn't an Onboarding Token.
	ErrMalformedToken = errors.New("malformed Onboarding Token")
	// ErrMalformedTokenSecret is returned for text that isn't a token secret.
	ErrMalformedTokenSecret = errors.New("malformed token secret")
	// ErrInvalidBaseURL is returned for a Base URL the protocol doesn't
	// accept.
	ErrInvalidBaseURL = errors.New("invalid Base URL")
)

// OnboardingToken is a single-use, short-lived token from a Provider's
// portal:
//
//	pm1.<base64url(Base URL)>.<keyfp>.<tokenID>.<tokenSecret>
//
// keyfp is the hex of the key-sha256 fingerprint of the Server Key that
// Registration pins; tokenSecret is 256 random bits, base64url without
// padding. The zero value is invalid.
type OnboardingToken struct {
	baseURL   string
	serverKey fingerprint.Fingerprint
	id        string
	secret    string
}

// NewOnboardingToken returns a new token with a random ID and secret, for a
// Base URL and the key-sha256 fingerprint of the Server Key it names.
func NewOnboardingToken(baseURL string, serverKey fingerprint.Fingerprint) (OnboardingToken, error) {
	if err := ValidateBaseURL(baseURL); err != nil {
		return OnboardingToken{}, err
	}
	if serverKey.Kind() != fingerprint.KeySHA256 {
		return OnboardingToken{}, fingerprint.ErrWrongKind
	}
	return OnboardingToken{
		baseURL:   baseURL,
		serverKey: serverKey,
		id:        NewTokenID(),
		secret:    randomSecret(),
	}, nil
}

// ParseOnboardingToken parses an Onboarding Token's text form.
func ParseOnboardingToken(s string) (OnboardingToken, error) {
	if len(s) > MaxTokenLength {
		return OnboardingToken{}, ErrMalformedToken
	}
	parts := strings.Split(s, ".")
	if len(parts) != 5 || parts[0] != tokenPrefix {
		return OnboardingToken{}, ErrMalformedToken
	}
	rawURL, ok := decodeB64(parts[1])
	if !ok || ValidateBaseURL(string(rawURL)) != nil {
		return OnboardingToken{}, ErrMalformedToken
	}
	key, err := fingerprint.ParseKind(string(fingerprint.KeySHA256)+":"+parts[2], fingerprint.KeySHA256)
	if err != nil {
		return OnboardingToken{}, ErrMalformedToken
	}
	if ValidateTokenID(parts[3]) != nil || !validSecret(parts[4]) {
		return OnboardingToken{}, ErrMalformedToken
	}
	return OnboardingToken{baseURL: string(rawURL), serverKey: key, id: parts[3], secret: parts[4]}, nil
}

// BaseURL is the Provider's Base URL, the only place the token is sent to.
func (t OnboardingToken) BaseURL() string { return t.baseURL }

// ServerKey is the key-sha256 fingerprint of the Server Key that
// Registration pins.
func (t OnboardingToken) ServerKey() fingerprint.Fingerprint { return t.serverKey }

// ID is the token ID, which names it in the Registration path.
func (t OnboardingToken) ID() string { return t.id }

// SecretHash is the hash of the token secret, which the Provider-side stores.
func (t OnboardingToken) SecretHash() Hash { return hashOf(t.secret) }

// RevealSecret returns the token secret, the bearer inside Registration.
func (t OnboardingToken) RevealSecret() string { return t.secret }

// Reveal returns the full text form, to hand the token to its Owner.
func (t OnboardingToken) Reveal() string {
	if t.IsZero() {
		return ""
	}
	return t.prefix() + "." + t.secret
}

// IsZero reports whether t is the zero value.
func (t OnboardingToken) IsZero() bool { return t.id == "" }

// String shows the token without its secret.
func (t OnboardingToken) String() string {
	if t.IsZero() {
		return redacted(true)
	}
	return t.prefix() + "." + redacted(false)
}

// GoString shows the token without its secret.
func (t OnboardingToken) GoString() string { return "credential.OnboardingToken(" + t.String() + ")" }

func (t OnboardingToken) prefix() string {
	return strings.Join([]string{
		tokenPrefix,
		b64.EncodeToString([]byte(t.baseURL)),
		t.serverKey.Hex(),
		t.id,
	}, ".")
}

// HashTokenSecret checks the form of a token secret received as a bearer and
// returns its hash, to compare with the stored one.
func HashTokenSecret(secret string) (Hash, error) {
	if !validSecret(secret) {
		return Hash{}, ErrMalformedTokenSecret
	}
	return hashOf(secret), nil
}

// ValidateBaseURL checks that s is an absolute https URL in canonical form,
// without user info, query, fragment or dot segments, and within
// MaxBaseURLLength. A path is allowed. Which addresses it may resolve to is
// checked when dialling.
func ValidateBaseURL(s string) error {
	if s == "" || len(s) > MaxBaseURLLength {
		return ErrInvalidBaseURL
	}
	u, err := url.Parse(s)
	if err != nil ||
		u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.String() != s {
		return ErrInvalidBaseURL
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return ErrInvalidBaseURL
		}
	}
	return nil
}
