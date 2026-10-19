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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The JSON below is the wire format. A test failing here means a protocol
// change, not a refactoring.

func TestRegistrationRequestWire(t *testing.T) {
	m := RegistrationRequest{
		IdempotencyKey: "uid-1",
		ClusterName:    "2x8k9abc",
		SecretHash:     "sha256:00",
		ConnectorCASet: "-----BEGIN CERTIFICATE-----\n",
	}
	assertWire(t, m, `{
		"idempotencyKey": "uid-1",
		"clusterName": "2x8k9abc",
		"secretHash": "sha256:00",
		"connectorCASet": "-----BEGIN CERTIFICATE-----\n"
	}`)
}

func TestRegistrationResponseWire(t *testing.T) {
	m := RegistrationResponse{
		ConnectionID:    "c-7f3k9q2mx8w4",
		ServerKeys:      []ServerKey{{PublicKey: "-----BEGIN PUBLIC KEY-----\n"}},
		UnusedExpiresAt: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC),
	}
	assertWire(t, m, `{
		"connectionID": "c-7f3k9q2mx8w4",
		"serverKeys": [{"publicKey": "-----BEGIN PUBLIC KEY-----\n"}],
		"unusedExpiresAt": "2026-10-23T10:00:00Z"
	}`)
}

func TestConnectionStatusWire(t *testing.T) {
	m := ConnectionStatus{
		Workspace: HostStatus{Sessions: 4, KcpReachable: true},
		VirtualWorkspaces: map[string]HostStatus{
			"nereus.kcp.example.com:443": {Sessions: 1, KcpReachable: false, LastError: "502 from Connector"},
		},
		ServerKeys:   []ServerKey{{PublicKey: "k"}},
		PinnedBundle: PinnedBundleInfo{ETag: "e", Fingerprints: []string{"cert-sha256:aa"}},
	}
	assertWire(t, m, `{
		"workspace": {"sessions": 4, "kcpReachable": true},
		"virtualWorkspaces": {
			"nereus.kcp.example.com:443": {"sessions": 1, "kcpReachable": false, "lastError": "502 from Connector"}
		},
		"serverKeys": [{"publicKey": "k"}],
		"pinnedBundle": {"etag": "e", "fingerprints": ["cert-sha256:aa"]}
	}`)
}

func TestConnectorCASetUpdateWire(t *testing.T) {
	assertWire(t, ConnectorCASetUpdate{ConnectorCASet: "pem"}, `{"connectorCASet": "pem"}`)
}

func TestErrorResponseWire(t *testing.T) {
	assertWire(t, ErrorResponse{Reason: ReasonTokenRefused, Detail: string(TokenSpent)},
		`{"reason": "TokenRefused", "detail": "Spent"}`)
	assertWire(t, ErrorResponse{Reason: ReasonPreconditionFailed, ETag: "e"},
		`{"reason": "PreconditionFailed", "etag": "e"}`)
}

func TestUnknownFieldsIgnored(t *testing.T) {
	var m RegistrationResponse
	require.NoError(t, json.Unmarshal([]byte(`{
		"connectionID": "c-1",
		"serverKeys": [{"publicKey": "k", "addedLater": true}],
		"unusedExpiresAt": "2026-10-23T10:00:00Z",
		"addedLater": {"x": 1}
	}`), &m))
	assert.Equal(t, "c-1", m.ConnectionID)
	assert.Equal(t, []ServerKey{{PublicKey: "k"}}, m.ServerKeys)
}

func assertWire(t *testing.T, m any, want string) {
	t.Helper()
	got, err := json.Marshal(m)
	require.NoError(t, err)
	assert.JSONEq(t, want, string(got))
}
