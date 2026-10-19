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

package testvectors

import (
	"strings"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
)

// RegistrationRequest returns a valid Registration request carrying
// connectorCASet.
func RegistrationRequest(connectorCASet []byte) connectionsv1.RegistrationRequest {
	return connectionsv1.RegistrationRequest{
		IdempotencyKey: "6f1c2a7e-0b3d-4c55-9a2e-1d8f3b7c9e10",
		ClusterName:    HelloClusterName,
		SecretHash:     ConnectionSecretHash,
		ConnectorCASet: string(connectorCASet),
	}
}

// RegistrationRequestCase is a Registration request and whether its fields
// are valid.
type RegistrationRequestCase struct {
	Name    string
	Request connectionsv1.RegistrationRequest
	Valid   bool
}

// RegistrationRequests are first Registration requests.
func RegistrationRequests(connectorCASet []byte) []RegistrationRequestCase {
	with := func(change func(*connectionsv1.RegistrationRequest)) connectionsv1.RegistrationRequest {
		r := RegistrationRequest(connectorCASet)
		change(&r)
		return r
	}
	return []RegistrationRequestCase{
		{"valid", RegistrationRequest(connectorCASet), true},
		{"no idempotency key", with(func(r *connectionsv1.RegistrationRequest) { r.IdempotencyKey = "" }), false},
		{"idempotency key too long", with(func(r *connectionsv1.RegistrationRequest) {
			r.IdempotencyKey = strings.Repeat("a", connectionsv1.MaxIdempotencyKeyLength+1)
		}), false},
		{"idempotency key with whitespace", with(func(r *connectionsv1.RegistrationRequest) { r.IdempotencyKey = "a b" }), false},
		{"workspace path as clusterName", with(func(r *connectionsv1.RegistrationRequest) { r.ClusterName = "root:providers:wildwest" }), false},
		{"no clusterName", with(func(r *connectionsv1.RegistrationRequest) { r.ClusterName = "" }), false},
		{"the Connection Secret instead of its hash", with(func(r *connectionsv1.RegistrationRequest) { r.SecretHash = ConnectionSecret }), false},
		{"hash uppercase", with(func(r *connectionsv1.RegistrationRequest) { r.SecretHash = strings.ToUpper(ConnectionSecretHash) }), false},
		{"no Connector CA Set", with(func(r *connectionsv1.RegistrationRequest) { r.ConnectorCASet = "" }), false},
	}
}

// RegistrationRetryCase is a Registration on a token already spent by
// RegistrationRequest, within the retry window, and its outcome: "" for the
// stored response, or a refusal.
type RegistrationRetryCase struct {
	Name  string
	Retry connectionsv1.RegistrationRequest
	Want  connectionsv1.Reason
}

// RegistrationRetries are retries after a Registration whose result the
// PM-side may not have stored.
func RegistrationRetries(connectorCASet, otherCASet []byte) []RegistrationRetryCase {
	with := func(change func(*connectionsv1.RegistrationRequest)) connectionsv1.RegistrationRequest {
		r := RegistrationRequest(connectorCASet)
		change(&r)
		return r
	}
	return []RegistrationRetryCase{
		{"the same request", RegistrationRequest(connectorCASet), ""},
		{"a Connector CA Set changed by a Rollover", RegistrationRequest(otherCASet), ""},
		{"another secret hash", with(func(r *connectionsv1.RegistrationRequest) {
			r.SecretHash = "sha256:" + strings.Repeat("ab", 32)
		}), connectionsv1.ReasonIdempotencyConflict},
		{"another clusterName", with(func(r *connectionsv1.RegistrationRequest) { r.ClusterName = "other1" }), connectionsv1.ReasonIdempotencyConflict},
		{"another attempt", with(func(r *connectionsv1.RegistrationRequest) { r.IdempotencyKey = "another-uid" }), connectionsv1.ReasonTokenRefused},
	}
}
