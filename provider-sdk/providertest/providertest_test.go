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

package providertest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	tv "go.platform-mesh.io/provider-protocol/testvectors"

	"go.platform-mesh.io/provider-sdk/pmtest"
	"go.platform-mesh.io/provider-sdk/providertest"
)

// at runs the Provider-side at now: pmtest's certificates are valid around testvectors.Now.
func at(now time.Time) providertest.Option {
	return providertest.WithClock(func() time.Time { return now })
}

// pmClient adapts pmtest's Control Sessions to the scenarios.
type pmClient struct{ pm *pmtest.PM }

func (c pmClient) Open(ctx context.Context, p *providertest.Provider, id string) (providertest.ControlSession, error) {
	c.pm.OuterRoots = p.OuterRoots
	pins := p.ServerKeyFingerprints()
	cs, err := c.pm.Control(ctx, p.BaseURL, id, pins, pins[len(pins)-1])
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (pmClient) ErrorResponse(err error) (*connectionsv1.ErrorResponse, bool) {
	var ue *pmtest.UpgradeError
	if errors.As(err, &ue) {
		return ue.Response, false
	}
	var ce *pmtest.CallError
	if errors.As(err, &ce) {
		return &ce.Response, true
	}
	return nil, false
}

func TestControlScenarios(t *testing.T) {
	providertest.RunControlScenarios(t, pmClient{pm: pmtest.New(t)})
}

func TestRegistration(t *testing.T) {
	p := providertest.New(t, at(tv.Now))
	pm := pmtest.New(t)
	pm.OuterRoots = p.OuterRoots

	tok, err := credential.ParseOnboardingToken(p.IssueToken("alice@example.com", 30*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, p.BaseURL, tok.BaseURL())
	resp, err := pm.Register(context.Background(), tok, tv.RegistrationRequest(pm.ConnectorCASet()))
	require.NoError(t, err)
	assert.Equal(t, p.ServerKeys(), resp.ServerKeys)

	conn, err := p.Connection(resp.ConnectionID)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", conn.Spec.Registration.Owner)
	p.Reconcile()
}

func TestStandby(t *testing.T) {
	p := providertest.New(t, at(tv.Now))
	pm := pmtest.New(t)
	pm.OuterRoots = p.OuterRoots
	tok, err := credential.ParseOnboardingToken(p.IssueToken("alice@example.com", 30*time.Minute))
	require.NoError(t, err)

	p.SetLeader(false)
	_, err = pm.Register(context.Background(), tok, tv.RegistrationRequest(pm.ConnectorCASet()))
	var ue *pmtest.UpgradeError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, connectionsv1.ReasonUnavailable, pmtest.ReasonOf(err))
	assert.Equal(t, 5*time.Second, ue.RetryAfter)
}

func TestSessions(t *testing.T) {
	p := providertest.New(t, at(tv.Now))
	pm := pmtest.New(t)
	pm.OuterRoots = p.OuterRoots
	id := p.AddConnection(providertest.ConnectionSpec{
		ClusterName: tv.HelloClusterName, Secret: credential.NewConnectionSecret(), ConnectorCASet: pm.ConnectorCASet(),
	})
	const vwHost = "nereus.kcp.example.com:443"

	s, err := pm.OpenSession(context.Background(), p.BaseURL, id, p.ServerKeyFingerprints(), connectionsv1.Hello{
		ConnectionID: id, ClusterName: tv.HelloClusterName, Hosts: []string{vwHost},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	go func() {
		_ = s.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Path", r.URL.Path)
		}))
	}()
	p.WaitSessions(id, 1)
	assert.Equal(t, 1, p.Sessions(id, vwHost))
	assert.Zero(t, p.Sessions(id, "other.kcp.example.com:443"))

	req, err := http.NewRequest(http.MethodGet, "https://front-proxy.pm.invalid/clusters/"+tv.HelloClusterName+"/api", nil)
	require.NoError(t, err)
	resp, err := p.RoundTrip(id, vwHost, req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "/clusters/"+tv.HelloClusterName+"/api", resp.Header.Get("X-Path"))

	p.DeleteConnection(id)
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the Session wasn't closed")
	}
}

func TestServerKeyRotation(t *testing.T) {
	p := providertest.New(t, at(tv.Now))
	p.AddServerKey()
	pins := p.ServerKeyFingerprints()
	require.Len(t, pins, 2)

	tok, err := credential.ParseOnboardingToken(p.IssueToken("alice@example.com", time.Hour))
	require.NoError(t, err)
	assert.Equal(t, pins[1], tok.ServerKey(), "tokens use the newest key")

	p.RetireServerKey("sk-1", tv.Now)
	assert.Equal(t, pins[1:], p.ServerKeyFingerprints(), "a retired key isn't announced")
}
