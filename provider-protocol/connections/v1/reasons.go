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

import "net/http"

// Reason is the stable, machine-readable cause of a refusal, carried in an
// ErrorResponse. Reasons are part of the contract: they are never renamed or
// reused with another meaning.
//
// A response before a WebSocket upgrade is plain HTTP, so the Provider's Edge
// could have produced or changed it. The PM-side uses such reasons for
// reporting and retries only, never as proof of anything. Only a response
// inside the Inner TLS is trusted.
type Reason string

const (
	// ReasonTokenRefused: the Onboarding Token can't be used for
	// Registration. Sent before the upgrade on RegisterPath, with a
	// TokenRefusal as Detail.
	ReasonTokenRefused Reason = "TokenRefused"

	// ReasonConnectionUnknown: the Provider-side doesn't know the Connection,
	// or it was deleted. Before a Session's upgrade it's informational only;
	// inside a Control Session's Inner TLS it's the trusted answer that lets
	// an Owner onboard the same Provider again.
	ReasonConnectionUnknown Reason = "ConnectionUnknown"

	// ReasonUnavailable: try again later, after the response's Retry-After.
	// Sent by standby replicas, beyond the handshake limits, and instead of
	// ReasonConnectionUnknown while the Provider-side can't read its state.
	ReasonUnavailable Reason = "Unavailable"

	// ReasonUnauthorized: the token secret or the Connection Secret is wrong.
	// Uniform, without detail. On a Control Session, the Session closes after
	// it.
	ReasonUnauthorized Reason = "Unauthorized"

	// ReasonConnectionMismatch: a request inside a Control Session names
	// another Connection than the Control Session's path. The Control Session
	// closes after it. Not an authentication failure: the typical cause is an
	// Edge rewriting one Connection's path into another's.
	ReasonConnectionMismatch Reason = "ConnectionMismatch"

	// ReasonIdempotencyConflict: a Registration retry with the same token and
	// idempotency key, but a different secret hash or cluster name.
	ReasonIdempotencyConflict Reason = "IdempotencyConflict"

	// ReasonInvalidRequest: the request is malformed or misses a field.
	ReasonInvalidRequest Reason = "InvalidRequest"

	// ReasonBundleInvalid: a Connector CA Set was refused by the strict
	// parser, with the parser's stable reason as Detail.
	ReasonBundleInvalid Reason = "BundleInvalid"

	// ReasonPreconditionFailed: a Pinned Bundle replacement's If-Match
	// doesn't match the current etag, which the ErrorResponse carries.
	ReasonPreconditionFailed Reason = "PreconditionFailed"

	// ReasonRateLimited: too many requests; retry after the response's
	// Retry-After, with jitter.
	ReasonRateLimited Reason = "RateLimited"

	// ReasonNotFound: no such endpoint.
	ReasonNotFound Reason = "NotFound"
)

// TokenRefusal is the Detail of a ReasonTokenRefused response.
type TokenRefusal string

const (
	TokenUnknown     TokenRefusal = "Unknown"
	TokenExpired     TokenRefusal = "Expired"
	TokenSpent       TokenRefusal = "Spent"
	TokenKeyUnusable TokenRefusal = "KeyUnusable"
)

var reasonStatus = map[Reason]int{
	ReasonTokenRefused:        http.StatusForbidden,
	ReasonConnectionUnknown:   http.StatusNotFound,
	ReasonUnavailable:         http.StatusServiceUnavailable,
	ReasonUnauthorized:        http.StatusUnauthorized,
	ReasonConnectionMismatch:  http.StatusConflict,
	ReasonIdempotencyConflict: http.StatusConflict,
	ReasonInvalidRequest:      http.StatusBadRequest,
	ReasonBundleInvalid:       http.StatusUnprocessableEntity,
	ReasonPreconditionFailed:  http.StatusPreconditionFailed,
	ReasonRateLimited:         http.StatusTooManyRequests,
	ReasonNotFound:            http.StatusNotFound,
}

// HTTPStatus returns the HTTP status code a reason is sent with, or 500 for a
// reason this version doesn't define.
func (r Reason) HTTPStatus() int {
	if s, ok := reasonStatus[r]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// Known reports whether this version of the protocol defines the reason.
func (r Reason) Known() bool {
	_, ok := reasonStatus[r]
	return ok
}
