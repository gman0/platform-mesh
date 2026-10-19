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
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

var (
	// ErrClientUsage is returned for a client certificate without key usage
	// digitalSignature or EKU clientAuth.
	ErrClientUsage = errors.New("client certificate lacks digitalSignature or clientAuth")
	// ErrNotDirectlyIssued is returned for a client certificate that chains
	// to the bundle only through an intermediate, or is a bundle CA itself.
	ErrNotDirectlyIssued = errors.New("client certificate not issued directly by a pinned CA")
)

// VerifyClient checks a Connector Certificate presented in a Session's Inner
// TLS: issued directly by a CA in the bundle, valid at now, its CA too, with
// key usage digitalSignature and EKU clientAuth.
func (b *Bundle) VerifyClient(leaf *x509.Certificate, now time.Time) error {
	// Go treats a certificate without EKUs as valid for any usage, so
	// require clientAuth explicitly.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return ErrClientUsage
	}
	roots := x509.NewCertPool()
	for _, c := range b.certs {
		roots.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("verifying client certificate: %w", err)
	}
	for _, chain := range chains {
		if len(chain) == 2 {
			return nil
		}
	}
	return ErrNotDirectlyIssued
}

// Issued reports whether a CA in the bundle issued leaf directly, whatever
// the validity periods. Open Sessions are re-checked with it when the Pinned
// Bundle changes: only the issuer counts, not expiry.
func (b *Bundle) Issued(leaf *x509.Certificate) bool {
	for _, ca := range b.certs {
		if bytes.Equal(leaf.RawIssuer, ca.RawSubject) && leaf.CheckSignatureFrom(ca) == nil {
			return true
		}
	}
	return false
}
