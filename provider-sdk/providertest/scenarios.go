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

package providertest

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
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// ControlClient adapts the PM-side Control client under test to the
// scenarios.
type ControlClient interface {
	// Open opens a Control Session to the Connection at p.BaseURL, trusting
	// p.OuterRoots and pinning p.ServerKeyFingerprints(). A client that
	// connects lazily may return its refusals from the first call instead.
	Open(ctx context.Context, p *Provider, connectionID string) (ControlSession, error)
	// ErrorResponse returns the protocol refusal err carries, nil if none,
	// and whether it was answered inside the Inner TLS: only there does
	// ConnectionUnknown mean the Connection is gone.
	ErrorResponse(err error) (resp *connectionsv1.ErrorResponse, inner bool)
}

// ControlSession is one open Control Session of the client under test.
type ControlSession interface {
	Status(secret credential.ConnectionSecret) (*connectionsv1.ConnectionStatus, error)
	// PutConnectorCASet sends If-Match with etag, none if etag is empty.
	PutConnectorCASet(secret credential.ConnectionSecret, etag string, pem []byte) error
	Delete(secret credential.ConnectionSecret) error
	Close() error
}

// Doer is implemented by a ControlSession that can send any request: the
// ConnectionMismatch scenario, which only an Edge rewriting paths causes,
// runs only then.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ControlScenario is a runnable vector for a PM-side Control client: each
// runs against its own Provider-side.
type ControlScenario struct {
	Name string
	Run  func(t *testing.T, c ControlClient)
}

// RunControlScenarios runs every ControlScenario as a subtest.
func RunControlScenarios(t *testing.T, c ControlClient) {
	for _, s := range ControlScenarios() {
		t.Run(s.Name, func(t *testing.T) { s.Run(t, c) })
	}
}

// scenario is a Provider-side at testvectors.Now with one Connection.
type scenario struct {
	p      *Provider
	c      ControlClient
	id     string
	secret credential.ConnectionSecret
	pinned *bundle.Bundle
}

func newScenario(t *testing.T, c ControlClient) *scenario {
	t.Helper()
	p := New(t, WithClock(func() time.Time { return tv.Now }))
	ca := tv.CA(t, "scenario connector CA", nil).PEM()
	secret := credential.NewConnectionSecret()
	id := p.AddConnection(ConnectionSpec{ClusterName: tv.HelloClusterName, Secret: secret, ConnectorCASet: ca})
	pinned, err := bundle.Parse(ca, tv.Now)
	require.NoError(t, err)
	return &scenario{p: p, c: c, id: id, secret: secret, pinned: pinned}
}

func (s *scenario) open(t *testing.T, id string) ControlSession {
	t.Helper()
	cs, err := s.c.Open(context.Background(), s.p, id)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// refusal asserts err is the protocol's refusal reason, answered inside the
// Inner TLS or not, and returns it.
func (s *scenario) refusal(t *testing.T, err error, reason connectionsv1.Reason, inner bool) *connectionsv1.ErrorResponse {
	t.Helper()
	require.Error(t, err)
	resp, gotInner := s.c.ErrorResponse(err)
	require.NotNil(t, resp, "not a protocol refusal: %v", err)
	assert.Equal(t, reason, resp.Reason)
	assert.Equal(t, inner, gotInner, "answered inside the Inner TLS")
	return resp
}

func (s *scenario) connection(t *testing.T) *sdkv1alpha1.Connection {
	t.Helper()
	conn, err := s.p.Connection(s.id)
	require.NoError(t, err)
	return conn
}

// ControlScenarios are the Control Session behaviours a PM-side client
// must handle (01 Protocol, "Control Sessions", "Errors and retries").
func ControlScenarios() []ControlScenario {
	return []ControlScenario{
		{"status", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			st, err := s.open(t, s.id).Status(s.secret)
			require.NoError(t, err)
			assert.Equal(t, s.p.ServerKeys(), st.ServerKeys)
			assert.Equal(t, s.pinned.ETag(), st.PinnedBundle.ETag)
			assert.NotNil(t, s.connection(t).Status.LastSeen, "an authenticated call marks the Connection used")
		}},

		{"first wrong secret closes the Control Session", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			cs := s.open(t, s.id)
			_, err := cs.Status(credential.NewConnectionSecret())
			s.refusal(t, err, connectionsv1.ReasonUnauthorized, true)
			_, err = cs.Status(s.secret)
			assert.Error(t, err, "closed after the first failed authentication")
			assert.Nil(t, s.connection(t).Status.LastSeen, "a failed authentication changes nothing")
		}},

		{"If-Match missing", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			next := tv.CA(t, "next", nil).PEM()
			resp := s.refusal(t, s.open(t, s.id).PutConnectorCASet(s.secret, "", next), connectionsv1.ReasonPreconditionFailed, true)
			assert.Equal(t, s.pinned.ETag(), resp.ETag, "the current etag comes back")
			assert.Equal(t, string(s.pinned.Encode()), s.connection(t).Spec.PinnedBundle)
		}},

		{"If-Match stale, then current", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			next := tv.CA(t, "next", nil).PEM()
			nextBundle, err := bundle.Parse(next, tv.Now)
			require.NoError(t, err)
			cs := s.open(t, s.id)

			resp := s.refusal(t, cs.PutConnectorCASet(s.secret, nextBundle.ETag(), next), connectionsv1.ReasonPreconditionFailed, true)
			require.Equal(t, s.pinned.ETag(), resp.ETag)
			require.NoError(t, cs.PutConnectorCASet(s.secret, resp.ETag, next), "the Control Session stays open")
			assert.Equal(t, string(nextBundle.Encode()), s.connection(t).Spec.PinnedBundle)
		}},

		{"same set is a no-op", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			cs := s.open(t, s.id)
			// The first authenticated call writes lastSeen; later ones within
			// the hour don't.
			_, err := cs.Status(s.secret)
			require.NoError(t, err)
			before := s.connection(t).ResourceVersion
			require.NoError(t, cs.PutConnectorCASet(s.secret, s.pinned.ETag(), s.pinned.Encode()))
			assert.Equal(t, before, s.connection(t).ResourceVersion, "nothing written")
		}},

		{"unknown inside the Inner TLS", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			_, err := s.open(t, credential.NewConnectionID()).Status(s.secret)
			s.refusal(t, err, connectionsv1.ReasonConnectionUnknown, true)

			s.p.DeleteConnection(s.id)
			_, err = s.open(t, s.id).Status(s.secret)
			s.refusal(t, err, connectionsv1.ReasonConnectionUnknown, true)
		}},

		{"a standby isn't unknown", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			s.p.SetLeader(false)
			cs, err := c.Open(context.Background(), s.p, s.id)
			if err == nil {
				t.Cleanup(func() { _ = cs.Close() })
				_, err = cs.Status(s.secret)
			}
			s.refusal(t, err, connectionsv1.ReasonUnavailable, false)
		}},

		{"delete", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			require.NoError(t, s.open(t, s.id).Delete(s.secret))
			conn, err := s.p.Connection(s.id)
			if err == nil {
				assert.NotNil(t, conn.DeletionTimestamp)
				assert.Equal(t, sdkv1alpha1.RemovalReasonDeletedByPlatformMesh, conn.Annotations[sdkv1alpha1.AnnotationRemovalReason])
			}
			s.p.Reconcile()
			_, err = s.p.Connection(s.id)
			assert.Error(t, err, "removed")
		}},

		{"ConnectionMismatch closes the Control Session", func(t *testing.T, c ControlClient) {
			s := newScenario(t, c)
			cs := s.open(t, s.id)
			doer, ok := cs.(Doer)
			if !ok {
				t.Skip("the client sends no arbitrary requests")
			}
			req, err := http.NewRequest(http.MethodGet, "https://connection.invalid"+connectionsv1.ConnectionPath(credential.NewConnectionID()), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", connectionsv1.BearerHeader(s.secret.Reveal()))
			resp, err := doer.Do(req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusConflict, resp.StatusCode)
			_, err = cs.Status(s.secret)
			assert.Error(t, err, "closed after ConnectionMismatch")
		}},
	}
}
