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

package connapi

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	"go.platform-mesh.io/provider-sdk/internal/metrics"
	"go.platform-mesh.io/provider-sdk/pmtest"
)

const (
	registrationsRefused = "providersdk_registrations_refused_total"
	handshakesRefused    = "providersdk_handshakes_refused_total"
	authFailures         = "providersdk_authentication_failures_total"
	sessionsClosed       = "providersdk_sessions_closed_total"
)

func waitDone(t *testing.T, s *pmtest.Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the Session wasn't closed")
	}
}

func TestMetricsRegistrationRefused(t *testing.T) {
	f := newFixture(t)
	unknown, err := credential.NewOnboardingToken(f.srv.URL+"/pm", f.key.Fingerprint)
	require.NoError(t, err)
	_, _ = f.register(unknown, f.request())
	_, _ = f.register(f.issue(-time.Minute), f.request())

	tok := f.issue(30 * time.Minute)
	first := f.request()
	_, err = f.register(tok, first)
	require.NoError(t, err)

	other := first
	other.IdempotencyKey = "another-uid"
	_, _ = f.register(tok, other)
	conflict := first
	conflict.SecretHash = credential.NewConnectionSecret().Hash().String()
	_, _ = f.register(tok, conflict)

	for reason, want := range map[string]float64{
		string(connectionsv1.TokenUnknown):              1,
		string(connectionsv1.TokenExpired):              1,
		string(connectionsv1.TokenSpent):                1,
		string(connectionsv1.ReasonIdempotencyConflict): 1,
	} {
		assert.Equal(t, want, f.metric(registrationsRefused, "reason", reason), reason)
	}
}

func TestMetricsControl(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()

	_, _ = f.control(id).Status(credential.NewConnectionSecret())
	assert.Equal(t, 1.0, f.metric(authFailures, "endpoint", metrics.EndpointControl))

	c := f.control(id)
	assert.Equal(t, connectionsv1.ReasonPreconditionFailed, pmtest.ReasonOf(c.PutConnectorCASet(secret, "", f.pm.ConnectorCASet())))
	assert.Equal(t, 1.0, f.metric("providersdk_connector_ca_set_pushes_refused_total", "reason", string(connectionsv1.ReasonPreconditionFailed)))

	req, err := http.NewRequest(http.MethodGet, "https://connection.invalid"+connectionsv1.ConnectionPath(credential.NewConnectionID()), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", connectionsv1.BearerHeader(secret.Reveal()))
	resp, err := c.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, 1.0, f.metric("providersdk_connection_mismatches_total"))
}

func TestMetricsSessions(t *testing.T) {
	f := newFixture(t)
	f.sessions.Grace = 10 * time.Millisecond
	id, _ := f.registered()

	unknown := credential.NewConnectionID()
	_, _ = f.pm.OpenSession(context.Background(), f.srv.URL+"/pm", unknown, []fingerprint.Fingerprint{f.key.Fingerprint}, f.hello(unknown))
	assert.Equal(t, 1.0, f.metric(handshakesRefused, "endpoint", metrics.EndpointSession, "reason", metrics.HandshakeUnknownConnection))

	// A Connector CA that isn't pinned.
	refused := f.openSession(pmtest.New(t), id, f.hello(id))
	waitDone(t, refused)
	require.Eventually(t, func() bool { return f.metric(authFailures, "endpoint", metrics.EndpointSession) == 1 },
		5*time.Second, 10*time.Millisecond)

	// Two Sessions: one closed by a re-check, one with the Connection.
	s := f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)
	active, draining := f.sessions.Counts()
	assert.Equal(t, [2]int{1, 0}, [2]int{active, draining})

	other, err := bundle.Parse(tv.CA(t, "next", nil).PEM(), f.now)
	require.NoError(t, err)
	f.sessions.Recheck(id, other)
	waitDone(t, s)
	require.Eventually(t, func() bool { return f.metric(sessionsClosed, "reason", metrics.SessionBundleRecheck) == 1 },
		5*time.Second, 10*time.Millisecond)

	s = f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)
	f.sessions.CloseConnection(id)
	waitDone(t, s)
	require.Eventually(t, func() bool { return f.metric(sessionsClosed, "reason", metrics.SessionConnectionRemoved) == 1 },
		5*time.Second, 10*time.Millisecond)

	s = f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)
	require.NoError(t, s.Close())
	require.Eventually(t, func() bool { return f.metric(sessionsClosed, "reason", metrics.SessionDisconnected) == 1 },
		5*time.Second, 10*time.Millisecond)
}
