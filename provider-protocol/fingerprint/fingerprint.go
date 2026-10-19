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

// Package fingerprint computes and parses the protocol's fingerprints:
//
//   - cert-sha256:<hex>, the SHA-256 of a certificate's DER;
//   - key-sha256:<hex>, the SHA-256 of a public key's SubjectPublicKeyInfo
//     (DER).
//
// The text form is the kind, a colon and 64 lowercase hex digits; nothing
// else parses.
package fingerprint

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Kind is what a fingerprint was computed over.
type Kind string

const (
	CertSHA256 Kind = "cert-sha256"
	KeySHA256  Kind = "key-sha256"
)

var (
	// ErrMalformed is returned for text that isn't a fingerprint.
	ErrMalformed = errors.New("malformed fingerprint")
	// ErrWrongKind is returned when a fingerprint has another kind than
	// required.
	ErrWrongKind = errors.New("wrong fingerprint kind")
)

// Fingerprint is a fingerprint of a known kind. The zero value is invalid.
// Fingerprints are comparable with ==.
type Fingerprint struct {
	kind Kind
	sum  [sha256.Size]byte
}

// OfCertificate returns the cert-sha256 fingerprint of a certificate.
func OfCertificate(cert *x509.Certificate) Fingerprint {
	return Fingerprint{kind: CertSHA256, sum: sha256.Sum256(cert.Raw)}
}

// OfCertificateKey returns the key-sha256 fingerprint of a certificate's
// public key.
func OfCertificateKey(cert *x509.Certificate) Fingerprint {
	return Fingerprint{kind: KeySHA256, sum: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}
}

// OfPublicKey returns the key-sha256 fingerprint of a public key.
func OfPublicKey(pub crypto.PublicKey) (Fingerprint, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("encoding public key: %w", err)
	}
	return Fingerprint{kind: KeySHA256, sum: sha256.Sum256(der)}, nil
}

// Parse parses a fingerprint of either kind.
func Parse(s string) (Fingerprint, error) {
	kind, digits, ok := strings.Cut(s, ":")
	if !ok {
		return Fingerprint{}, ErrMalformed
	}
	switch Kind(kind) {
	case CertSHA256, KeySHA256:
	default:
		return Fingerprint{}, ErrMalformed
	}
	if len(digits) != 2*sha256.Size || strings.ToLower(digits) != digits {
		return Fingerprint{}, ErrMalformed
	}
	f := Fingerprint{kind: Kind(kind)}
	if _, err := hex.Decode(f.sum[:], []byte(digits)); err != nil {
		return Fingerprint{}, ErrMalformed
	}
	return f, nil
}

// ParseKind parses a fingerprint and requires its kind.
func ParseKind(s string, kind Kind) (Fingerprint, error) {
	f, err := Parse(s)
	if err != nil {
		return Fingerprint{}, err
	}
	if f.kind != kind {
		return Fingerprint{}, ErrWrongKind
	}
	return f, nil
}

// Kind returns the fingerprint's kind, empty for the zero value.
func (f Fingerprint) Kind() Kind { return f.kind }

// IsZero reports whether f is the zero value.
func (f Fingerprint) IsZero() bool { return f.kind == "" }

// String returns the text form, or "" for the zero value.
func (f Fingerprint) String() string {
	if f.IsZero() {
		return ""
	}
	return string(f.kind) + ":" + f.Hex()
}

// Hex returns the 64 lowercase hex digits without the kind, or "" for the
// zero value.
func (f Fingerprint) Hex() string {
	if f.IsZero() {
		return ""
	}
	return hex.EncodeToString(f.sum[:])
}

// MarshalText implements encoding.TextMarshaler.
func (f Fingerprint) MarshalText() ([]byte, error) {
	if f.IsZero() {
		return nil, ErrMalformed
	}
	return []byte(f.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *Fingerprint) UnmarshalText(b []byte) error {
	p, err := Parse(string(b))
	if err != nil {
		return err
	}
	*f = p
	return nil
}
