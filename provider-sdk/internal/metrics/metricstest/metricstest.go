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

// Package metricstest reads metrics in tests.
package metricstest

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-sdk/internal/metrics"
)

// New returns Metrics on a fresh registry.
func New(t testing.TB) (*metrics.Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m, err := metrics.New(reg)
	require.NoError(t, err)
	return m, reg
}

// Value returns the counter or gauge name whose labels include the given
// name/value pairs, 0 if there's none.
func Value(t testing.TB, g prometheus.Gatherer, name string, labels ...string) float64 {
	t.Helper()
	require.Zero(t, len(labels)%2, "labels are name/value pairs")
	families, err := g.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	metric:
		for _, m := range f.GetMetric() {
			for i := 0; i < len(labels); i += 2 {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == labels[i] && l.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue metric
				}
			}
			if m.GetCounter() != nil {
				return m.GetCounter().GetValue()
			}
			return m.GetGauge().GetValue()
		}
	}
	return 0
}
