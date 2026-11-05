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

// Package access carries the wire-format primitives shared between the
// PM-side access-operator and the user-side access SDK:
//
//   - the access token wire form pma1.<base64url(URL)>.<tokenID>.<secret>,
//   - the per-/access call credential (JWT HS256) and its verification,
//   - a bounded replay cache keyed by (tokenID, jti).
//
// See RFC 012 (remote access - baseline) for the protocol context.
package access

import (
	"encoding/base64"
	"errors"
	"strings"
)

// TokenPrefix is the wire-format version prefix. Clients split the access
// token on '.' and verify this is the first segment.
const TokenPrefix = "pma1"

// ErrInvalidToken is returned by ParseToken for any malformed access
// token: missing prefix, wrong segment count, invalid URL encoding, or
// empty tokenID / secret.
var ErrInvalidToken = errors.New("access: invalid access token")

// Token is the parsed form of an access token.
//
// URL is the /access endpoint the token is pinned to. TokenID is the
// public component (safe to log and surface in CRD status). Secret is
// the HMAC key material used to sign per-/access call credentials.
type Token struct {
	// URL is the fully-qualified /access endpoint URL encoded in the
	// token. Callers that need to validate it as a URL should use
	// net/url.Parse; the parse function here only base64-decodes it.
	URL string

	// TokenID identifies which AccessIdentity this token belongs to.
	// Not secret.
	TokenID string

	// Secret is the HMAC key material. Treat as sensitive.
	Secret []byte
}

// ParseToken parses a pma1.<base64url(URL)>.<tokenID>.<secret> wire
// string. Returns ErrInvalidToken on any shape error.
func ParseToken(s string) (Token, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return Token{}, ErrInvalidToken
	}
	if parts[0] != TokenPrefix {
		return Token{}, ErrInvalidToken
	}

	urlBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	if len(urlBytes) == 0 || parts[2] == "" || parts[3] == "" {
		return Token{}, ErrInvalidToken
	}

	secret, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return Token{}, ErrInvalidToken
	}

	return Token{
		URL:     string(urlBytes),
		TokenID: parts[2],
		Secret:  secret,
	}, nil
}

// String serializes a Token to its wire form. The URL and Secret are
// base64url-encoded without padding; TokenID is inlined as-is.
func (t Token) String() string {
	return strings.Join([]string{
		TokenPrefix,
		base64.RawURLEncoding.EncodeToString([]byte(t.URL)),
		t.TokenID,
		base64.RawURLEncoding.EncodeToString(t.Secret),
	}, ".")
}
