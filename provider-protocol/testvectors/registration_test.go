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

package testvectors_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	tv "go.platform-mesh.io/provider-protocol/testvectors"
)

func TestRegistrationRequests(t *testing.T) {
	set := tv.CA(t, "connector-ca", nil).PEM()
	for _, c := range tv.RegistrationRequests(set) {
		err := c.Request.Validate()
		if c.Valid {
			assert.NoError(t, err, c.Name)
		} else {
			assert.ErrorIs(t, err, connectionsv1.ErrInvalidRequest, c.Name)
		}
	}
}

func TestRegistrationRetries(t *testing.T) {
	set, other := tv.CA(t, "current", nil).PEM(), tv.CA(t, "after a Rollover", nil).PEM()
	stored := tv.RegistrationRequest(set)
	for _, c := range tv.RegistrationRetries(set, other) {
		assert.NoError(t, c.Retry.Validate(), c.Name)
		assert.Equal(t, c.Want, connectionsv1.RetryOutcome(stored, c.Retry), c.Name)
	}
}

func TestStreamPathsWellFormed(t *testing.T) {
	// The Connector runs these; here, only that the table is sound.
	seen := map[string]bool{}
	for _, c := range tv.StreamPaths() {
		assert.NotEmpty(t, c.Outcome, c.Name)
		assert.False(t, seen[c.Path], "duplicate path %q", c.Path)
		seen[c.Path] = true
	}
}
