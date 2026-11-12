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

// Package v1 carries the v1 handshake request / response types for
// POST /v1/access. The URL path pins the wire-version; a later v2
// lives in protocol/access/v2.
package v1

// HandshakeRequest is the JSON body the PM-side access-operator POSTs
// to /v1/access.
type HandshakeRequest struct {
	// KcpURL is the PM kcp endpoint the user-side cluster should
	// dial back with the delivered kubeconfig's bearer token.
	KcpURL string `json:"kcpURL"`
	// KcpCABundle is the PEM-encoded CA bundle that signs the kcp
	// endpoint's TLS cert.
	KcpCABundle string `json:"kcpCABundle"`
	// SAToken is a ServiceAccount token minted in the Provider
	// Workspace that the user-side cluster presents back to kcp.
	SAToken string `json:"saToken"`
}

// HandshakeResponse is reserved for future use. v1 returns 200 empty
// on success; this struct exists so later versions have a clear
// migration target.
type HandshakeResponse struct{}
