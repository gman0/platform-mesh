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
	"net/url"
	"time"
)

// PathPrefix is the prefix of every path, relative to the Provider's Base URL.
const PathPrefix = "/v1/connections"

// RegisterPath is the Registration endpoint for an Onboarding Token's ID.
func RegisterPath(tokenID string) string {
	return PathPrefix + "/register/" + url.PathEscape(tokenID)
}

// ControlPath is the Control Session endpoint of a Connection.
func ControlPath(connectionID string) string {
	return ConnectionPath(connectionID) + "/control"
}

// SessionPath is the Session endpoint of a Connection.
func SessionPath(connectionID string) string {
	return ConnectionPath(connectionID) + "/session"
}

// ConnectionPath is the path of a Connection inside a Control Session: the
// status GET and the DELETE.
func ConnectionPath(connectionID string) string {
	return PathPrefix + "/" + url.PathEscape(connectionID)
}

// ConnectorCASetPath is the path of the Pinned Bundle replacement inside a
// Control Session.
func ConnectorCASetPath(connectionID string) string {
	return ConnectionPath(connectionID) + "/connector-ca-set"
}

// RegistrationCreatePath is the path of the one request inside a
// Registration Session.
const RegistrationCreatePath = PathPrefix

// ALPN names of the three channels, negotiated in the Inner TLS.
const (
	ALPNRegister = "pm-register/1"
	ALPNControl  = "pm-control/1"
	ALPNSession  = "pm-session/1"
)

// HeaderServerKey is sent on a Control Session's upgrade by the PM-side. It
// carries the key-sha256 fingerprint of the Server Key the PM-side expects,
// so the Provider-side can present it even for a Connection it doesn't know,
// and answer "unknown" inside the Inner TLS.
const HeaderServerKey = "PM-Server-Key"

// ContentTypeJSON is the content type of every message body.
const ContentTypeJSON = "application/json"

// WebSocket framing, the same on Registration, Control Sessions and Sessions.
const (
	// MaxMessageSize is the largest WebSocket message either side sends or
	// accepts. TLS records are at most 16 KB; the cap keeps every message
	// under common Edge limits.
	MaxMessageSize = 32 * 1024

	// PingInterval is the interval of WebSocket pings at the outer level, so
	// Edge idle timeouts above it never fire.
	PingInterval = 30 * time.Second
)

// StandbyRetryAfter is the Retry-After a standby Provider-side replica sends
// when it refuses an upgrade with 503. The PM-side treats any Retry-After as
// the lower bound of its normal reconnect backoff.
const StandbyRetryAfter = 5 * time.Second
