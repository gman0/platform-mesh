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

package metrics_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/metrics"
	"go.platform-mesh.io/provider-sdk/internal/metrics/metricstest"
)

const ns = "wild-west-system"

func TestNilCountsNothing(t *testing.T) {
	var m *metrics.Metrics
	assert.NotPanics(t, func() {
		m.AuthenticationFailed(metrics.EndpointControl)
		m.ConnectionMismatch()
		m.RegistrationRefused("Spent")
		m.PushRefused("BundleInvalid", "Expired")
		m.HandshakeRefused(metrics.EndpointSession, metrics.HandshakeTimeout)
		m.SessionClosed(metrics.SessionGoAway)
		m.TunnelOpened()
		m.TunnelClosed()
		m.TunnelRefused(metrics.TunnelNoSession)
	})
}

func TestCounters(t *testing.T) {
	m, reg := metricstest.New(t)
	m.HandshakeRefused(metrics.EndpointSession, metrics.HandshakeTimeout)
	m.HandshakeRefused(metrics.EndpointSession, metrics.HandshakeTimeout)
	m.TunnelOpened()
	m.TunnelOpened()
	m.TunnelClosed()

	assert.Equal(t, 2.0, metricstest.Value(t, reg, "providersdk_handshakes_refused_total", "endpoint", "session", "reason", "timeout"))
	assert.Equal(t, 1.0, metricstest.Value(t, reg, "providersdk_operator_tunnels"))

	families, err := reg.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}
	assert.True(t, names["providersdk_sessions_closed_total"], "known reasons start at zero")
	assert.True(t, names["providersdk_authentication_failures_total"])

	_, err = metrics.New(reg)
	assert.Error(t, err, "registered once")
}

func TestState(t *testing.T) {
	seen := func(ago time.Duration) *metav1.Time { t := metav1.NewTime(tv.Now.Add(-ago)); return &t }
	conn := func(name string, lastSeen *metav1.Time, keys ...string) *sdkv1alpha1.Connection {
		return &sdkv1alpha1.Connection{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Status:     sdkv1alpha1.ConnectionStatus{LastSeen: lastSeen, ListedServerKeys: keys},
		}
	}
	retire := metav1.NewTime(tv.Now.Add(24 * time.Hour))
	scheme := runtime.NewScheme()
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{Name: "sk-old", Namespace: ns}, Spec: sdkv1alpha1.ServerKeySpec{RetireAt: &retire}},
		&sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{Name: "sk-new", Namespace: ns}},
		conn("c-1", seen(time.Hour), "sk-old", "sk-new"),
		conn("c-2", seen(2*time.Hour), "sk-old"),
		conn("c-3", seen(48*time.Hour), "sk-old"), // not seen recently
		conn("c-4", nil),                          // never seen
	).Build()

	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(&metrics.State{
		Client: c, Namespace: ns,
		Sessions: func() (int, int) { return 3, 1 },
		Now:      func() time.Time { return tv.Now },
	}))

	v := func(name string, labels ...string) float64 { return metricstest.Value(t, reg, name, labels...) }
	assert.Equal(t, 3.0, v("providersdk_sessions", "state", "active"))
	assert.Equal(t, 1.0, v("providersdk_sessions", "state", "draining"))
	assert.Equal(t, 4.0, v("providersdk_connections"))
	assert.Equal(t, 2.0, v("providersdk_server_key_connections", "key", "sk-old", "listed", "true"))
	assert.Equal(t, 0.0, v("providersdk_server_key_connections", "key", "sk-old", "listed", "false"))
	assert.Equal(t, 1.0, v("providersdk_server_key_connections", "key", "sk-new", "listed", "true"))
	assert.Equal(t, 1.0, v("providersdk_server_key_connections", "key", "sk-new", "listed", "false"),
		"c-2 is still missing the new key")
	assert.Equal(t, float64(retire.Unix()), v("providersdk_server_key_retire_at_seconds", "key", "sk-old"))
}
