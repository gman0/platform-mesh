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
	"crypto/rand"
	"errors"
	"strings"
)

// IDs are a prefix and 26 lowercase base32 characters (130 random bits): not
// secret, but unguessable, so probing paths finds nothing. They are valid
// Kubernetes object names and path segments.
const (
	tokenIDPrefix      = "t-"
	connectionIDPrefix = "c-"
	idRandomLen        = 26
)

// ErrMalformedID is returned for text that isn't a valid ID.
var ErrMalformedID = errors.New("malformed ID")

// NewTokenID returns a new, random Onboarding Token ID.
func NewTokenID() string { return tokenIDPrefix + randomID() }

// NewConnectionID returns a new, random Connection ID.
func NewConnectionID() string { return connectionIDPrefix + randomID() }

// ValidateTokenID checks the form of an Onboarding Token ID.
func ValidateTokenID(id string) error { return validateID(id, tokenIDPrefix) }

// ValidateConnectionID checks the form of a Connection ID.
func ValidateConnectionID(id string) error { return validateID(id, connectionIDPrefix) }

func randomID() string {
	// rand.Text returns 26 characters from the RFC 4648 base32 alphabet.
	return strings.ToLower(rand.Text())
}

func validateID(id, prefix string) error {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok || len(rest) != idRandomLen {
		return ErrMalformedID
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return ErrMalformedID
		}
	}
	return nil
}
