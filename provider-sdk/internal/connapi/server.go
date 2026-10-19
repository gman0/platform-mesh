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

// Package connapi serves the Connection API under the Provider's Base URL:
// Registration, Control Sessions and Sessions.
package connapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/innertls"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// Keys loads Server Keys for the Inner TLS, by ServerKey name.
type Keys interface {
	Get(ctx context.Context, name string) (innertls.ServerKey, error)
}

// Config configures the Connection API server.
type Config struct {
	// Client reads and writes the SDK's resources in Namespace.
	Client client.Client
	// APIReader reads uncached, before answering that a Connection is
	// unknown. Defaults to Client.
	APIReader client.Reader
	Namespace string
	Keys      Keys

	// Status reports a Connection's Sessions and whether they reach kcp,
	// for the status Control Call. Nil reports none.
	Status func(connectionID string) (workspace connectionsv1.HostStatus, virtualWorkspaces map[string]connectionsv1.HostStatus)

	// RetryWindow is how long after a token's expiry a Registration retry
	// is honoured; it also sets unusedExpiresAt. Default 7 days.
	RetryWindow time.Duration
	// HandshakeTimeout bounds the Inner TLS handshake and reading the first
	// request. Default 10 seconds.
	HandshakeTimeout time.Duration
	// Limits bound handshakes in progress.
	Limits Limits

	// IsLeader reports whether this replica is active; standbys refuse
	// upgrades with 503. Nil means always active.
	IsLeader func() bool
	// OnRegistered runs after a new Connection is created and its token
	// spent, e.g. to write its kubeconfig Secret. Optional.
	OnRegistered func(ctx context.Context, c *sdkv1alpha1.Connection) error

	// Now defaults to time.Now.
	Now func() time.Time
	Log logr.Logger
}

// Server is the Connection API's http.Handler.
type Server struct {
	cfg     Config
	limiter *limiter
	unknown *unknownLimiter
}

// New returns the Connection API server.
func New(cfg Config) *Server {
	if cfg.RetryWindow <= 0 {
		cfg.RetryWindow = 7 * 24 * time.Hour
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.IsLeader == nil {
		cfg.IsLeader = func() bool { return true }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.APIReader == nil {
		cfg.APIReader = cfg.Client
	}
	limits := cfg.Limits.withDefaults()
	return &Server{
		cfg:     cfg,
		limiter: newLimiter(limits),
		unknown: newUnknownLimiter(limits.UnknownTotal, limits.UnknownInterval, time.Now),
	}
}

const segment = connectionsv1.PathPrefix + "/"

// ServeHTTP routes by the path below /v1/connections/, wherever it is under
// the Base URL, so the server isn't bound to one host or path prefix.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	i := strings.Index(path, segment)
	if i < 0 || r.Method != http.MethodGet {
		refuse(w, connectionsv1.ReasonNotFound, "", 0)
		return
	}
	parts := strings.Split(path[i+len(segment):], "/")
	if len(parts) != 2 {
		refuse(w, connectionsv1.ReasonNotFound, "", 0)
		return
	}
	if !s.cfg.IsLeader() {
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}

	switch {
	case parts[0] == "register":
		s.serveRegister(w, r, parts[1])
	case parts[1] == "control":
		s.serveControl(w, r, parts[0])
	default:
		// Sessions follow in their own step.
		refuse(w, connectionsv1.ReasonNotFound, "", 0)
	}
}

// refuse answers before the upgrade.
func refuse(w http.ResponseWriter, reason connectionsv1.Reason, detail string, retryAfter time.Duration) {
	_ = connectionsv1.WriteError(w, connectionsv1.ErrorResponse{Reason: reason, Detail: detail}, retryAfter)
}
