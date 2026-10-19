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

package v1

import (
	"errors"
	"fmt"
	"strings"

	"go.platform-mesh.io/provider-protocol/credential"
)

// MaxIdempotencyKeyLength bounds a Registration's idempotency key.
const MaxIdempotencyKeyLength = 128

// ErrInvalidRequest is returned for a malformed request; the message names
// the field.
var ErrInvalidRequest = errors.New("invalid request")

// Validate checks a RegistrationRequest's fields. The Connector CA Set is
// only checked for presence; its content is parsed by the bundle package.
func (r RegistrationRequest) Validate() error {
	if r.IdempotencyKey == "" || len(r.IdempotencyKey) > MaxIdempotencyKeyLength ||
		strings.ContainsFunc(r.IdempotencyKey, func(c rune) bool { return c < 0x21 || c > 0x7e }) {
		return fmt.Errorf("%w: idempotencyKey", ErrInvalidRequest)
	}
	if ValidateClusterName(r.ClusterName) != nil {
		return fmt.Errorf("%w: clusterName", ErrInvalidRequest)
	}
	if _, err := credential.ParseHash(r.SecretHash); err != nil {
		return fmt.Errorf("%w: secretHash", ErrInvalidRequest)
	}
	if r.ConnectorCASet == "" {
		return fmt.Errorf("%w: connectorCASet", ErrInvalidRequest)
	}
	return nil
}

// RetryOutcome decides a Registration on a token that's already spent,
// within the retry window, given the request that spent it:
//
//   - "": the same attempt (idempotency key, secret hash and cluster name);
//     it gets the stored response. A changed Connector CA Set is ignored.
//   - ReasonIdempotencyConflict: the same attempt with another secret hash
//     or cluster name.
//   - ReasonTokenRefused (TokenSpent): another attempt.
func RetryOutcome(stored, retry RegistrationRequest) Reason {
	if retry.IdempotencyKey != stored.IdempotencyKey {
		return ReasonTokenRefused
	}
	if retry.SecretHash != stored.SecretHash || retry.ClusterName != stored.ClusterName {
		return ReasonIdempotencyConflict
	}
	return ""
}
