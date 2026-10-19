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

import "time"

// Messages are JSON. Decoders ignore unknown fields, so a newer peer can add
// fields without breaking an older one; a field's meaning never changes.

// RegistrationRequest is the one request inside a Registration Session:
// POST RegistrationCreatePath, with the token secret as bearer.
type RegistrationRequest struct {
	// IdempotencyKey identifies the Registration attempt across retries: the
	// ProviderOnboardingRequest's UID.
	IdempotencyKey string `json:"idempotencyKey"`

	// ClusterName is the logical cluster name of the Provider Workspace, as
	// kcp assigns it. Immutable for the Connection's life.
	ClusterName string `json:"clusterName"`

	// SecretHash is the hash of the Connection Secret the PM-side generated.
	// The Connection Secret itself never leaves the PM-side.
	SecretHash string `json:"secretHash"`

	// ConnectorCASet is the PM-side's Connector CA Set as a PEM bundle; it
	// becomes the Connection's Pinned Bundle. Ignored on a retry.
	ConnectorCASet string `json:"connectorCASet"`
}

// RegistrationResponse answers a RegistrationRequest, and every matching
// retry, with the same content.
type RegistrationResponse struct {
	ConnectionID string `json:"connectionID"`

	// ServerKeys are the Provider-side's Server Keys, which the PM-side pins
	// for this Connection.
	ServerKeys []ServerKey `json:"serverKeys"`

	// UnusedExpiresAt is when the Provider-side removes the Connection if it
	// has seen neither an authenticated Control Call nor a verified Session
	// by then.
	UnusedExpiresAt time.Time `json:"unusedExpiresAt"`
}

// ServerKey is a public key the Provider-side presents in the Inner TLS.
type ServerKey struct {
	// PublicKey is the key's SubjectPublicKeyInfo, PEM-encoded
	// ("PUBLIC KEY").
	PublicKey string `json:"publicKey"`
}

// ConnectionStatus answers the status Control Call: GET ConnectionPath.
type ConnectionStatus struct {
	// Workspace is the Provider Workspace, reached through the front-proxy.
	// Every Session serves it.
	Workspace HostStatus `json:"workspace"`

	// VirtualWorkspaces are the virtual-workspace hosts the Provider-side's
	// clients use, keyed by host (host:port, as in endpoint slices).
	VirtualWorkspaces map[string]HostStatus `json:"virtualWorkspaces,omitempty"`

	// ServerKeys are the Server Keys the Provider-side announces: every key
	// it may present, including keys not yet pinned by the PM-side.
	ServerKeys []ServerKey `json:"serverKeys"`

	// PinnedBundle describes the Connection's Pinned Bundle.
	PinnedBundle PinnedBundleInfo `json:"pinnedBundle"`
}

// HostStatus is what the Provider-side observed for one host.
type HostStatus struct {
	// Sessions is the number of live Sessions serving the host.
	Sessions int `json:"sessions"`

	// KcpReachable is whether recent requests to the host reached kcp.
	KcpReachable bool `json:"kcpReachable"`

	// LastError is the last error seen for the host, without sensitive
	// detail. Empty if none.
	LastError string `json:"lastError,omitempty"`
}

// PinnedBundleInfo identifies a Pinned Bundle without its content.
type PinnedBundleInfo struct {
	// ETag is the Pinned Bundle's etag, to send as If-Match when replacing
	// it.
	ETag string `json:"etag"`

	// Fingerprints are the cert-sha256 fingerprints of its certificates,
	// sorted.
	Fingerprints []string `json:"fingerprints"`
}

// ConnectorCASetUpdate is the body of the Pinned Bundle replacement:
// PUT ConnectorCASetPath, with If-Match.
type ConnectorCASetUpdate struct {
	ConnectorCASet string `json:"connectorCASet"`
}

// ErrorResponse is the body of every refusal, before and after the upgrade.
type ErrorResponse struct {
	Reason Reason `json:"reason"`

	// Detail is a stable sub-reason where the reason has one: a TokenRefusal,
	// or the bundle parser's reason.
	Detail string `json:"detail,omitempty"`

	// Message is human-readable and never parsed.
	Message string `json:"message,omitempty"`

	// ETag is the current etag, on ReasonPreconditionFailed.
	ETag string `json:"etag,omitempty"`
}
