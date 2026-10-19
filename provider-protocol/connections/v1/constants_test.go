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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPaths(t *testing.T) {
	assert.Equal(t, "/v1/connections/register/t-q8m2vx", RegisterPath("t-q8m2vx"))
	assert.Equal(t, "/v1/connections", RegistrationCreatePath)
	assert.Equal(t, "/v1/connections/c-7f3k9q2mx8w4", ConnectionPath("c-7f3k9q2mx8w4"))
	assert.Equal(t, "/v1/connections/c-7f3k9q2mx8w4/control", ControlPath("c-7f3k9q2mx8w4"))
	assert.Equal(t, "/v1/connections/c-7f3k9q2mx8w4/session", SessionPath("c-7f3k9q2mx8w4"))
	assert.Equal(t, "/v1/connections/c-7f3k9q2mx8w4/connector-ca-set", ConnectorCASetPath("c-7f3k9q2mx8w4"))
}

func TestPathsEscapeIDs(t *testing.T) {
	// IDs are validated elsewhere; paths must still never let an ID add
	// segments.
	assert.Equal(t, "/v1/connections/a%2Fb/session", SessionPath("a/b"))
	assert.Equal(t, "/v1/connections/register/..%2Fx", RegisterPath("../x"))
}

func TestALPN(t *testing.T) {
	assert.Equal(t, "pm-register/1", ALPNRegister)
	assert.Equal(t, "pm-control/1", ALPNControl)
	assert.Equal(t, "pm-session/1", ALPNSession)
}

func TestReasonHTTPStatus(t *testing.T) {
	cases := map[Reason]int{
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
	for r, s := range cases {
		assert.Equal(t, s, r.HTTPStatus(), r)
		assert.True(t, r.Known(), r)
	}
	assert.Len(t, reasonStatus, len(cases), "every reason has a test case")

	assert.Equal(t, http.StatusInternalServerError, Reason("Bogus").HTTPStatus())
	assert.False(t, Reason("Bogus").Known())
}
