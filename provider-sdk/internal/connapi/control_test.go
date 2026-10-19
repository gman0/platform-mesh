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
	"k8s.io/apimachinery/pkg/types"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/pmtest"
)

// registered registers a Connection and returns its ID and Connection Secret.
func (f *fixture) registered() (string, credential.ConnectionSecret) {
	f.t.Helper()
	resp, err := f.register(f.issue(30*time.Minute), f.request())
	require.NoError(f.t, err)
	secret, err := credential.ParseConnectionSecret(tv.ConnectionSecret)
	require.NoError(f.t, err)
	return resp.ConnectionID, secret
}

func (f *fixture) control(id string) *pmtest.ControlSession {
	f.t.Helper()
	pins := []fingerprint.Fingerprint{f.key.Fingerprint}
	c, err := f.pm.Control(context.Background(), f.srv.URL+"/pm", id, pins, f.key.Fingerprint)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

func (f *fixture) connection(id string) *sdkv1alpha1.Connection {
	f.t.Helper()
	var conn sdkv1alpha1.Connection
	require.NoError(f.t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: id}, &conn))
	return &conn
}

func TestControlStatus(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()
	pinned, err := bundle.Parse(f.pm.ConnectorCASet(), f.now)
	require.NoError(t, err)

	st, err := f.control(id).Status(secret)
	require.NoError(t, err)
	assert.Equal(t, pinned.ETag(), st.PinnedBundle.ETag)
	assert.Equal(t, []string{pinned.Fingerprints()[0].String()}, st.PinnedBundle.Fingerprints)
	assert.Equal(t, []connectionsv1.ServerKey{{PublicKey: f.keyObj.Status.PublicKey}}, st.ServerKeys)

	require.NotNil(t, f.connection(id).Status.LastSeen, "an authenticated call is first contact")
}

func TestControlStatusReportsSessions(t *testing.T) {
	f := newFixture(t)
	f.server.cfg.Status = func(string) (connectionsv1.HostStatus, map[string]connectionsv1.HostStatus) {
		return connectionsv1.HostStatus{Sessions: 2, KcpReachable: true},
			map[string]connectionsv1.HostStatus{"nereus.kcp.example.com:443": {Sessions: 1}}
	}
	id, secret := f.registered()

	st, err := f.control(id).Status(secret)
	require.NoError(t, err)
	assert.Equal(t, 2, st.Workspace.Sessions)
	assert.Contains(t, st.VirtualWorkspaces, "nereus.kcp.example.com:443")
}

func TestControlWrongSecretClosesAndChangesNothing(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()
	c := f.control(id)

	_, err := c.Status(credential.NewConnectionSecret())
	assert.Equal(t, connectionsv1.ReasonUnauthorized, pmtest.ReasonOf(err))
	_, err = c.Status(secret)
	assert.Error(t, err, "closed after the first failed authentication")
	assert.Nil(t, f.connection(id).Status.LastSeen)
}

func TestControlUnknownInsideInnerTLS(t *testing.T) {
	f := newFixture(t)
	_, err := f.control(credential.NewConnectionID()).Status(credential.NewConnectionSecret())
	var ce *pmtest.CallError
	require.ErrorAs(t, err, &ce, "answered inside the Inner TLS, not before the upgrade")
	assert.Equal(t, connectionsv1.ReasonConnectionUnknown, ce.Response.Reason)
}

func TestControlMismatch(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()
	c := f.control(id)

	req, err := http.NewRequest(http.MethodGet, "https://connection.invalid"+connectionsv1.ConnectionPath(credential.NewConnectionID()), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", connectionsv1.BearerHeader(secret.Reveal()))
	resp, err := c.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	_, err = c.Status(secret)
	assert.Error(t, err, "closed after ConnectionMismatch")
}

func TestControlPutConnectorCASet(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()
	c := f.control(id)
	current, err := bundle.Parse(f.pm.ConnectorCASet(), f.now)
	require.NoError(t, err)
	next := tv.CA(t, "next", nil)
	both := tv.Join(f.pm.ConnectorCASet(), next.PEM())

	// Missing and stale If-Match get the current etag.
	for _, etag := range []string{"", "stale"} {
		err := c.PutConnectorCASet(secret, etag, both)
		var ce *pmtest.CallError
		if assert.ErrorAs(t, err, &ce, etag) {
			assert.Equal(t, connectionsv1.ReasonPreconditionFailed, ce.Response.Reason)
			assert.Equal(t, current.ETag(), ce.Response.ETag)
		}
	}

	// The same set in another form is a no-op.
	require.NoError(t, c.PutConnectorCASet(secret, current.ETag(), append([]byte("\n"), f.pm.ConnectorCASet()...)))
	assert.Equal(t, string(current.Encode()), f.connection(id).Spec.PinnedBundle)

	// A refused bundle keeps the Control Session open.
	err = c.PutConnectorCASet(secret, current.ETag(), tv.Leaf(t, f.pm.CA).PEM())
	var ce *pmtest.CallError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, connectionsv1.ReasonBundleInvalid, ce.Response.Reason)
	assert.Equal(t, string(bundle.ReasonNotCA), ce.Response.Detail)

	require.NoError(t, c.PutConnectorCASet(secret, current.ETag(), both))
	updated, err := bundle.Parse([]byte(f.connection(id).Spec.PinnedBundle), f.now)
	require.NoError(t, err)
	assert.Len(t, updated.Certificates(), 2)
}

func TestControlPushOverExpiredPins(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()

	// A Provider back after a long absence pins only expired CAs.
	old := tv.CA(t, "old", nil, tv.Expired).PEM()
	conn := f.connection(id)
	conn.Spec.PinnedBundle = string(old)
	require.NoError(t, f.client.Update(context.Background(), conn))
	stored, err := bundle.ParseStored(old)
	require.NoError(t, err)

	c := f.control(id)
	st, err := c.Status(secret)
	require.NoError(t, err)
	assert.Equal(t, stored.ETag(), st.PinnedBundle.ETag)
	assert.NoError(t, c.PutConnectorCASet(secret, st.PinnedBundle.ETag, f.pm.ConnectorCASet()))
}

func TestControlDelete(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()

	require.NoError(t, f.control(id).Delete(secret))
	assert.NotNil(t, f.connection(id).DeletionTimestamp, "the finalizer runs next")

	_, err := f.control(id).Status(secret)
	assert.Equal(t, connectionsv1.ReasonConnectionUnknown, pmtest.ReasonOf(err))
}

func TestUnknownLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newUnknownLimiter(2, time.Second, func() time.Time { return now })
	r1, ok := l.acquire()
	require.True(t, ok)
	_, ok = l.acquire()
	assert.False(t, ok, "too soon")
	now = now.Add(time.Second)
	_, ok = l.acquire()
	require.True(t, ok)
	now = now.Add(time.Second)
	_, ok = l.acquire()
	assert.False(t, ok, "two in progress")
	r1()
	_, ok = l.acquire()
	assert.True(t, ok)
}
