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
	"bufio"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	"go.platform-mesh.io/provider-sdk/internal/session"
	"go.platform-mesh.io/provider-sdk/pmtest"
)

const vwHost = "nereus.kcp.example.com:443"

func (f *fixture) hello(id string) connectionsv1.Hello {
	return connectionsv1.Hello{ConnectionID: id, ClusterName: tv.HelloClusterName, Hosts: []string{vwHost}}
}

// openSession opens a Session from pm and serves its Streams, answering
// with the request's path.
func (f *fixture) openSession(pm *pmtest.PM, id string, hello connectionsv1.Hello) *pmtest.Session {
	f.t.Helper()
	pm.OuterRoots = f.pm.OuterRoots
	s, err := pm.OpenSession(context.Background(), f.srv.URL+"/pm", id, []fingerprint.Fingerprint{f.key.Fingerprint}, hello)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = s.Close() })
	go func() {
		_ = s.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Path", r.URL.Path)
		}))
	}()
	return s
}

// roundTrip sends one request over a Stream for host.
func (f *fixture) roundTrip(id, host string) (*http.Response, error) {
	stream, err := f.sessions.OpenStream(id, host)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://front-proxy.pm.invalid/clusters/2x8k9abc/api", nil)
	if err := req.Write(stream); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(stream), req)
}

func (f *fixture) waitSessions(id string, n int) {
	f.t.Helper()
	require.Eventually(f.t, func() bool {
		ws, _ := f.sessions.Status(id)
		return ws.Sessions == n
	}, 5*time.Second, 10*time.Millisecond)
}

func TestSessionStreams(t *testing.T) {
	f := newFixture(t)
	id, _ := f.registered()
	f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)

	for _, host := range []string{session.WorkspaceHost, vwHost} {
		resp, err := f.roundTrip(id, host)
		require.NoError(t, err, host)
		assert.Equal(t, "/clusters/2x8k9abc/api", resp.Header.Get("X-Path"), host)
	}
	_, err := f.roundTrip(id, "other.kcp.example.com:443")
	assert.ErrorIs(t, err, session.ErrNoSession, "a host no Session serves")
}

func TestSessionInControlStatus(t *testing.T) {
	f := newFixture(t)
	id, secret := f.registered()
	f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)
	f.sessions.Report(id, vwHost, true, "")

	st, err := f.control(id).Status(secret)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Workspace.Sessions)
	assert.Equal(t, connectionsv1.HostStatus{Sessions: 1, KcpReachable: true}, st.VirtualWorkspaces[vwHost])
}

func TestSessionUnknownRefusedBeforeUpgrade(t *testing.T) {
	f := newFixture(t)
	_, err := f.pm.OpenSession(context.Background(), f.srv.URL+"/pm", "c-abcdefghijklmnopqrstuvwxyz", []fingerprint.Fingerprint{f.key.Fingerprint}, f.hello("c-abcdefghijklmnopqrstuvwxyz"))
	var ue *pmtest.UpgradeError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, connectionsv1.ReasonConnectionUnknown, pmtest.ReasonOf(err))
}

func TestSessionRefused(t *testing.T) {
	cases := map[string]func(f *fixture, id string) (*pmtest.PM, connectionsv1.Hello){
		"Hello for another Provider Workspace": func(f *fixture, id string) (*pmtest.PM, connectionsv1.Hello) {
			h := f.hello(id)
			h.ClusterName = "other1"
			return f.pm, h
		},
		"Hello for another Connection": func(f *fixture, id string) (*pmtest.PM, connectionsv1.Hello) {
			h := f.hello(id)
			h.ConnectionID = "c-abcdefghijklmnopqrstuvwxyz"
			return f.pm, h
		},
		"Connector CA not pinned": func(f *fixture, id string) (*pmtest.PM, connectionsv1.Hello) {
			return pmtest.New(f.t), f.hello(id)
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			id, _ := f.registered()
			pm, hello := c(f, id)
			s := f.openSession(pm, id, hello)
			select {
			case <-s.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the Session wasn't closed")
			}
			ws, _ := f.sessions.Status(id)
			assert.Zero(t, ws.Sessions)
		})
	}
}

func TestSessionRecheck(t *testing.T) {
	f := newFixture(t)
	f.sessions.Grace = 10 * time.Millisecond
	id, _ := f.registered()
	s := f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)

	// A bundle that still holds PM's CA keeps the Session.
	both, err := bundle.Parse(tv.Join(f.pm.ConnectorCASet(), tv.CA(t, "next", nil).PEM()), f.now)
	require.NoError(t, err)
	assert.Zero(t, f.sessions.Recheck(id, both))

	// Dropping it closes the Session after the grace period.
	other, err := bundle.Parse(tv.CA(t, "next", nil).PEM(), f.now)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sessions.Recheck(id, other))
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the Session wasn't closed")
	}
}

func TestSessionGoAwayFromConnector(t *testing.T) {
	f := newFixture(t)
	id, _ := f.registered()
	s := f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)

	require.NoError(t, s.GoAway())
	require.Eventually(t, func() bool {
		_, err := f.roundTrip(id, session.WorkspaceHost)
		return err != nil
	}, 5*time.Second, 10*time.Millisecond, "no new Streams on a Session the Connector is replacing")
}

func TestSessionCloseConnection(t *testing.T) {
	f := newFixture(t)
	id, _ := f.registered()
	s := f.openSession(f.pm, id, f.hello(id))
	f.waitSessions(id, 1)

	f.sessions.CloseConnection(id)
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the Session wasn't closed")
	}
	f.waitSessions(id, 0)
}
