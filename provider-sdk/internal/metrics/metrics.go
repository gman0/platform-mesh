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

// Package metrics defines provider-gateway's Prometheus metrics. They carry
// no connectionID labels: per-Connection detail is in the resources, their
// Events, the logs and the status call.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "providersdk"

// Endpoints of the Connection API.
const (
	EndpointRegister = "register"
	EndpointControl  = "control"
	EndpointSession  = "session"
)

// Reasons a handshake is refused before or during the upgrade.
const (
	HandshakeUnknownConnection = "unknown_connection"
	// HandshakeLimit is the limit for known IDs (or tokens).
	HandshakeLimit = "limit"
	// HandshakeUnknownLimit is the shared limit for unknown IDs.
	HandshakeUnknownLimit = "unknown_limit"
	HandshakeTimeout      = "timeout"
	// HandshakeTLS is a failed Inner TLS handshake on Registration or
	// Control Sessions, e.g. the PM-side not accepting the Server Key.
	HandshakeTLS = "tls"
)

// Reasons a Session is closed.
const (
	// SessionGoAway: the Connector sent go-away, replacing the Session.
	SessionGoAway = "go_away"
	// SessionBundleRecheck: its Connector Certificate is no longer covered
	// by the Pinned Bundle.
	SessionBundleRecheck = "bundle_recheck"
	// SessionConnectionRemoved: the Connection was deleted.
	SessionConnectionRemoved = "connection_removed"
	// SessionDisconnected: anything else, e.g. the Edge cut it.
	SessionDisconnected = "disconnected"
)

// Reasons an operator tunnel is refused.
const (
	TunnelCredential        = "credential"
	TunnelUnknownConnection = "unknown_connection"
	TunnelUnknownHost       = "unknown_host"
	TunnelNoSession         = "no_session"
)

// Metrics are the event counters. A nil *Metrics counts nothing.
type Metrics struct {
	authenticationFailures *prometheus.CounterVec
	connectionMismatches   prometheus.Counter
	registrationsRefused   *prometheus.CounterVec
	pushesRefused          *prometheus.CounterVec
	handshakesRefused      *prometheus.CounterVec
	sessionsClosed         *prometheus.CounterVec
	tunnelsOpen            prometheus.Gauge
	tunnelsRefused         *prometheus.CounterVec
}

// New returns the counters, registered with reg.
func New(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		authenticationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "authentication_failures_total",
			Help: "Failed authentications: a wrong Connection Secret on Control Sessions; a refused Connector Certificate or Hello on Sessions.",
		}, []string{"endpoint"}),
		connectionMismatches: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "connection_mismatches_total",
			Help: "Control Calls for another Connection than their Control Session's, e.g. an Edge rewriting paths.",
		}),
		registrationsRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "registrations_refused_total",
			Help: "Refused Registrations, by token refusal (Unknown, Expired, Spent, KeyUnusable) or protocol reason.",
		}, []string{"reason"}),
		pushesRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "connector_ca_set_pushes_refused_total",
			Help: "Refused Connector CA Set pushes, by protocol reason and, for BundleInvalid, the bundle's.",
		}, []string{"reason", "detail"}),
		handshakesRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "handshakes_refused_total",
			Help: "Upgrades and Inner TLS handshakes refused, by endpoint and reason.",
		}, []string{"endpoint", "reason"}),
		sessionsClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "sessions_closed_total",
			Help: "Closed Sessions, by reason.",
		}, []string{"reason"}),
		tunnelsOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "operator_tunnels",
			Help: "Open operator proxy tunnels.",
		}),
		tunnelsRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "operator_tunnels_refused_total",
			Help: "Refused operator proxy CONNECTs, by reason.",
		}, []string{"reason"}),
	}
	for _, c := range []prometheus.Collector{
		m.authenticationFailures, m.connectionMismatches, m.registrationsRefused, m.pushesRefused,
		m.handshakesRefused, m.sessionsClosed, m.tunnelsOpen, m.tunnelsRefused,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}

	// Known label values start at zero, so rates and alerts see them.
	for _, e := range []string{EndpointControl, EndpointSession} {
		m.authenticationFailures.WithLabelValues(e)
	}
	for _, r := range []string{SessionGoAway, SessionBundleRecheck, SessionConnectionRemoved, SessionDisconnected} {
		m.sessionsClosed.WithLabelValues(r)
	}
	for _, r := range []string{TunnelCredential, TunnelUnknownConnection, TunnelUnknownHost, TunnelNoSession} {
		m.tunnelsRefused.WithLabelValues(r)
	}
	return m, nil
}

// AuthenticationFailed counts a failed authentication on endpoint.
func (m *Metrics) AuthenticationFailed(endpoint string) {
	if m != nil {
		m.authenticationFailures.WithLabelValues(endpoint).Inc()
	}
}

// ConnectionMismatch counts a ConnectionMismatch refusal.
func (m *Metrics) ConnectionMismatch() {
	if m != nil {
		m.connectionMismatches.Inc()
	}
}

// RegistrationRefused counts a refused Registration.
func (m *Metrics) RegistrationRefused(reason string) {
	if m != nil {
		m.registrationsRefused.WithLabelValues(reason).Inc()
	}
}

// PushRefused counts a refused Connector CA Set push.
func (m *Metrics) PushRefused(reason, detail string) {
	if m != nil {
		m.pushesRefused.WithLabelValues(reason, detail).Inc()
	}
}

// HandshakeRefused counts a refused upgrade or handshake on endpoint.
func (m *Metrics) HandshakeRefused(endpoint, reason string) {
	if m != nil {
		m.handshakesRefused.WithLabelValues(endpoint, reason).Inc()
	}
}

// SessionClosed counts a closed Session.
func (m *Metrics) SessionClosed(reason string) {
	if m != nil {
		m.sessionsClosed.WithLabelValues(reason).Inc()
	}
}

// TunnelOpened counts an open operator tunnel until TunnelClosed.
func (m *Metrics) TunnelOpened() {
	if m != nil {
		m.tunnelsOpen.Inc()
	}
}

// TunnelClosed ends a TunnelOpened.
func (m *Metrics) TunnelClosed() {
	if m != nil {
		m.tunnelsOpen.Dec()
	}
}

// TunnelRefused counts a refused CONNECT.
func (m *Metrics) TunnelRefused(reason string) {
	if m != nil {
		m.tunnelsRefused.WithLabelValues(reason).Inc()
	}
}
