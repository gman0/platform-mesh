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

// Package bundle parses Pinned Bundles: the Connector CA certificates a
// Connection pins, as a PEM bundle. The same strict rules apply at
// Registration, to pushes and to administrators' re-pins.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"strings"
	"time"

	"go.platform-mesh.io/provider-protocol/fingerprint"
)

const (
	// MaxSize bounds a bundle's PEM text.
	MaxSize = 64 * 1024
	// MaxCertificates bounds the number of certificates in a bundle.
	MaxCertificates = 32
)

const (
	pemType  = "CERTIFICATE"
	pemBegin = "-----BEGIN "
)

// Bundle is a parsed Pinned Bundle: a non-empty set of CA certificates. It's
// immutable.
type Bundle struct {
	// certs and fps are sorted by fingerprint.
	certs []*x509.Certificate
	fps   []fingerprint.Fingerprint
}

// Parse parses a PEM bundle strictly:
//   - only CERTIFICATE blocks, without PEM headers;
//   - only whitespace before, between and after blocks;
//   - every certificate a CA (basic constraints CA:true, keyCertSign);
//   - no duplicates;
//   - at least one certificate, and at least one unexpired at now;
//   - at most MaxCertificates and MaxSize.
//
// Anything else is refused as a whole with an *Error carrying a stable
// Reason.
func Parse(data []byte, now time.Time) (*Bundle, error) {
	if len(data) > MaxSize {
		return nil, newError(ReasonTooLarge, -1, nil)
	}

	var certs []*x509.Certificate
	seen := map[fingerprint.Fingerprint]bool{}
	rest := trimSpace(data)
	for i := 0; len(rest) > 0; i++ {
		if !bytes.HasPrefix(rest, []byte(pemBegin)) {
			return nil, newError(ReasonTextOutsideBlocks, i, nil)
		}
		block, after := pem.Decode(rest)
		// pem.Decode skips a malformed block and returns the next one, so
		// make sure the block it returned is the one at the start.
		if block == nil || bytes.Count(rest[:len(rest)-len(after)], []byte(pemBegin)) != 1 {
			return nil, newError(ReasonMalformedPEM, i, nil)
		}
		if block.Type != pemType {
			return nil, newError(ReasonNotCertificate, i, nil)
		}
		if len(block.Headers) != 0 {
			return nil, newError(ReasonPEMHeaders, i, nil)
		}
		if len(certs) == MaxCertificates {
			return nil, newError(ReasonTooMany, i, nil)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, newError(ReasonMalformedCertificate, i, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, newError(ReasonNotCA, i, nil)
		}
		fp := fingerprint.OfCertificate(cert)
		if seen[fp] {
			return nil, newError(ReasonDuplicate, i, nil)
		}
		seen[fp] = true
		certs = append(certs, cert)
		rest = trimSpace(after)
	}

	if len(certs) == 0 {
		return nil, newError(ReasonEmpty, -1, nil)
	}
	if !slices.ContainsFunc(certs, func(c *x509.Certificate) bool { return validAt(c, now) }) {
		return nil, newError(ReasonAllExpired, -1, nil)
	}
	return newBundle(certs), nil
}

func newBundle(certs []*x509.Certificate) *Bundle {
	slices.SortFunc(certs, func(a, b *x509.Certificate) int {
		return strings.Compare(fingerprint.OfCertificate(a).String(), fingerprint.OfCertificate(b).String())
	})
	b := &Bundle{certs: certs}
	for _, c := range certs {
		b.fps = append(b.fps, fingerprint.OfCertificate(c))
	}
	return b
}

// Certificates returns the CA certificates, sorted by fingerprint.
func (b *Bundle) Certificates() []*x509.Certificate { return slices.Clone(b.certs) }

// Fingerprints returns the cert-sha256 fingerprints, sorted.
func (b *Bundle) Fingerprints() []fingerprint.Fingerprint { return slices.Clone(b.fps) }

// ETag identifies the set of certificates, whatever their order or the PEM
// formatting: the hex SHA-256 over the sorted cert-sha256 fingerprints, one
// per line.
func (b *Bundle) ETag() string {
	var s strings.Builder
	for _, fp := range b.fps {
		s.WriteString(fp.String())
		s.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(sum[:])
}

// Equal reports whether both bundles hold the same set of certificates.
func (b *Bundle) Equal(o *Bundle) bool { return slices.Equal(b.fps, o.fps) }

// Contains reports whether the bundle holds the certificate with this
// cert-sha256 fingerprint.
func (b *Bundle) Contains(fp fingerprint.Fingerprint) bool {
	_, ok := slices.BinarySearchFunc(b.fps, fp, func(a, t fingerprint.Fingerprint) int {
		return strings.Compare(a.String(), t.String())
	})
	return ok
}

// Encode returns the bundle in canonical form: the certificates sorted by
// fingerprint, standard PEM, nothing else.
func (b *Bundle) Encode() []byte {
	var out bytes.Buffer
	for _, c := range b.certs {
		_ = pem.Encode(&out, &pem.Block{Type: pemType, Bytes: c.Raw})
	}
	return out.Bytes()
}

func validAt(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

func trimSpace(b []byte) []byte {
	return bytes.TrimLeft(b, " \t\r\n")
}
