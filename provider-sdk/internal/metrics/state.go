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

package metrics

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const (
	// RecentlySeen is how recently a Connection must have been seen to
	// count in providersdk_server_key_connections: a key rotation only
	// waits for Connections in use.
	RecentlySeen = 24 * time.Hour

	collectTimeout = 5 * time.Second
)

var (
	sessionsDesc = prometheus.NewDesc(namespace+"_sessions",
		"Live Sessions, by state: active, or draining after go-away.", []string{"state"}, nil)
	connectionsDesc = prometheus.NewDesc(namespace+"_connections",
		"Connections.", nil, nil)
	serverKeyConnectionsDesc = prometheus.NewDesc(namespace+"_server_key_connections",
		"Connections seen within the last day, by ServerKey and whether they list it.", []string{"key", "listed"}, nil)
	serverKeyRetireDesc = prometheus.NewDesc(namespace+"_server_key_retire_at_seconds",
		"A ServerKey's retireAt, as a Unix time; absent without retireAt.", []string{"key"}, nil)
)

// State collects gauges read at scrape time: Sessions from the registry,
// Connections and ServerKeys from the cache.
type State struct {
	Client    client.Reader
	Namespace string
	// Sessions returns the live Sessions, active and draining.
	Sessions func() (active, draining int)
	// Now defaults to time.Now.
	Now func() time.Time
}

var _ prometheus.Collector = &State{}

// Describe implements prometheus.Collector.
func (s *State) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionsDesc
	ch <- connectionsDesc
	ch <- serverKeyConnectionsDesc
	ch <- serverKeyRetireDesc
}

// Collect implements prometheus.Collector.
func (s *State) Collect(ch chan<- prometheus.Metric) {
	if s.Sessions != nil {
		active, draining := s.Sessions()
		ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(active), "active")
		ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(draining), "draining")
	}

	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	// Read only: the cache's objects aren't copied.
	var conns sdkv1alpha1.ConnectionList
	if err := s.Client.List(ctx, &conns, client.InNamespace(s.Namespace), client.UnsafeDisableDeepCopy); err != nil {
		ch <- prometheus.NewInvalidMetric(connectionsDesc, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(connectionsDesc, prometheus.GaugeValue, float64(len(conns.Items)))

	var keys sdkv1alpha1.ServerKeyList
	if err := s.Client.List(ctx, &keys, client.InNamespace(s.Namespace), client.UnsafeDisableDeepCopy); err != nil {
		ch <- prometheus.NewInvalidMetric(serverKeyConnectionsDesc, err)
		return
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	recent := slices.DeleteFunc(slices.Clone(conns.Items), func(c sdkv1alpha1.Connection) bool {
		return c.Status.LastSeen == nil || now.Sub(c.Status.LastSeen.Time) > RecentlySeen
	})
	for _, k := range keys.Items {
		listed := 0
		for _, c := range recent {
			if slices.Contains(c.Status.ListedServerKeys, k.Name) {
				listed++
			}
		}
		ch <- prometheus.MustNewConstMetric(serverKeyConnectionsDesc, prometheus.GaugeValue, float64(listed), k.Name, strconv.FormatBool(true))
		ch <- prometheus.MustNewConstMetric(serverKeyConnectionsDesc, prometheus.GaugeValue, float64(len(recent)-listed), k.Name, strconv.FormatBool(false))
		if k.Spec.RetireAt != nil {
			ch <- prometheus.MustNewConstMetric(serverKeyRetireDesc, prometheus.GaugeValue, float64(k.Spec.RetireAt.Unix()), k.Name)
		}
	}
}
