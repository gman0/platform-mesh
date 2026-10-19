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
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrMalformedHash is returned for text that isn't a hash.
var ErrMalformedHash = errors.New("malformed secret hash")

const hashPrefix = "sha256:"

// Hash is the SHA-256 of a secret value, in text form sha256:<hex> with
// lowercase hex. Secrets have 256 random bits, so a plain SHA-256 is enough.
// The zero value is invalid.
type Hash struct {
	sum [sha256.Size]byte
	set bool
}

func hashOf(value string) Hash {
	return Hash{sum: sha256.Sum256([]byte(value)), set: true}
}

// ParseHash parses sha256:<64 lowercase hex digits>.
func ParseHash(s string) (Hash, error) {
	digits, ok := strings.CutPrefix(s, hashPrefix)
	if !ok || len(digits) != 2*sha256.Size || strings.ToLower(digits) != digits {
		return Hash{}, ErrMalformedHash
	}
	h := Hash{set: true}
	if _, err := hex.Decode(h.sum[:], []byte(digits)); err != nil {
		return Hash{}, ErrMalformedHash
	}
	return h, nil
}

// IsZero reports whether h is the zero value.
func (h Hash) IsZero() bool { return !h.set }

// String returns the text form, or "" for the zero value.
func (h Hash) String() string {
	if !h.set {
		return ""
	}
	return hashPrefix + hex.EncodeToString(h.sum[:])
}

// Equal compares two hashes in constant time. The zero value equals nothing.
func (h Hash) Equal(o Hash) bool {
	if !h.set || !o.set {
		return false
	}
	return subtle.ConstantTimeCompare(h.sum[:], o.sum[:]) == 1
}

// MarshalText implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) {
	if !h.set {
		return nil, ErrMalformedHash
	}
	return []byte(h.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(b []byte) error {
	p, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = p
	return nil
}
