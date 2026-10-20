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

// Package session holds the live Sessions PM's Connectors open to the
// Provider-side, and the Streams the Provider-side opens on them.
package session

import (
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
)

// WorkspaceHost stands for the Provider Workspace, which every Session
// serves.
const WorkspaceHost = ""

// ErrNoSession is returned when no Session of the Connection serves a host.
var ErrNoSession = errors.New("no session serves the host")

// Session is one live Session.
type Session struct {
	ConnectionID string
	ClusterName  string
	// Hosts are the virtual-workspace hosts from the Hello.
	Hosts []string
	// Certificate is the Connector Certificate it was opened with.
	Certificate *x509.Certificate

	mux *yamux.Session

	mu       sync.Mutex
	draining bool
}

// serves reports whether the Session serves host.
func (s *Session) serves(host string) bool {
	return host == WorkspaceHost || slices.Contains(s.Hosts, host)
}

func (s *Session) isDraining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

// drain sends go-away and closes the Session after grace.
func (s *Session) drain(grace time.Duration) {
	s.mu.Lock()
	if s.draining {
		s.mu.Unlock()
		return
	}
	s.draining = true
	s.mu.Unlock()
	_ = s.mux.GoAway()
	time.AfterFunc(grace, func() { _ = s.mux.Close() })
}

// outcome is the last request outcome for a host of a Connection.
type outcome struct {
	reachable bool
	lastError string
}

// Registry holds the live Sessions by Connection.
type Registry struct {
	// Grace is how long a Session that's no longer trusted may finish its
	// in-flight requests. Default 30 seconds.
	Grace time.Duration
	// OnChange is called, outside the registry's lock, when a Session of a
	// Connection is added or removed. Set it before Sessions arrive.
	OnChange func(connectionID string)

	mu       sync.Mutex
	sessions map[string][]*Session
	outcomes map[string]map[string]outcome
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{Grace: 30 * time.Second, sessions: map[string][]*Session{}, outcomes: map[string]map[string]outcome{}}
}

// add registers a Session until it ends.
func (r *Registry) add(s *Session) {
	r.mu.Lock()
	r.sessions[s.ConnectionID] = append(r.sessions[s.ConnectionID], s)
	r.mu.Unlock()
	r.changed(s.ConnectionID)
	go func() {
		<-s.mux.CloseChan()
		r.remove(s)
		r.changed(s.ConnectionID)
	}()
}

func (r *Registry) changed(connectionID string) {
	if r.OnChange != nil {
		r.OnChange(connectionID)
	}
}

// Has reports whether the Connection has a live Session.
func (r *Registry) Has(connectionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions[connectionID]) > 0
}

func (r *Registry) remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ConnectionID] = slices.DeleteFunc(r.sessions[s.ConnectionID], func(x *Session) bool { return x == s })
	if len(r.sessions[s.ConnectionID]) == 0 {
		delete(r.sessions, s.ConnectionID)
	}
}

// candidates are the Sessions serving host, least busy first.
func (r *Registry) candidates(connectionID, host string) []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Session
	for _, s := range r.sessions[connectionID] {
		if s.serves(host) && !s.isDraining() {
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, func(a, b *Session) int { return a.mux.NumStreams() - b.mux.NumStreams() })
	return out
}

// OpenStream opens a Stream on a Session of the Connection that serves host
// (WorkspaceHost for the Provider Workspace), spreading Streams across them.
// A Session the Connector has sent go-away on is skipped.
func (r *Registry) OpenStream(connectionID, host string) (net.Conn, error) {
	for _, s := range r.candidates(connectionID, host) {
		stream, err := s.mux.OpenStream()
		if err == nil {
			return stream, nil
		}
		if errors.Is(err, yamux.ErrRemoteGoAway) {
			s.mu.Lock()
			s.draining = true
			s.mu.Unlock()
		}
	}
	return nil, ErrNoSession
}

// Recheck closes the Connection's Sessions whose Connector Certificate the
// new Pinned Bundle no longer covers: go-away, then close after Grace. Only
// the issuer counts, not expiry.
func (r *Registry) Recheck(connectionID string, pinned *bundle.Bundle) int {
	closed := 0
	for _, s := range r.list(connectionID) {
		if !pinned.Issued(s.Certificate) {
			s.drain(r.Grace)
			closed++
		}
	}
	return closed
}

// CloseConnection ends every Session of a deleted Connection at once.
func (r *Registry) CloseConnection(connectionID string) {
	for _, s := range r.list(connectionID) {
		_ = s.mux.GoAway()
		_ = s.mux.Close()
	}
	r.mu.Lock()
	delete(r.outcomes, connectionID)
	r.mu.Unlock()
}

func (r *Registry) list(connectionID string) []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sessions[connectionID])
}

// Report records whether a request for host reached kcp; err is shown in
// the status, so it must hold no sensitive detail.
func (r *Registry) Report(connectionID, host string, reachable bool, err string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outcomes[connectionID] == nil {
		r.outcomes[connectionID] = map[string]outcome{}
	}
	r.outcomes[connectionID][host] = outcome{reachable: reachable, lastError: err}
}

// Status reports the Connection's Sessions per host that its clients use:
// the Provider Workspace, and each virtual-workspace host with a reported
// request.
func (r *Registry) Status(connectionID string) (connectionsv1.HostStatus, map[string]connectionsv1.HostStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := func(host string) int {
		n := 0
		for _, s := range r.sessions[connectionID] {
			if s.serves(host) && !s.isDraining() {
				n++
			}
		}
		return n
	}
	status := func(host string) connectionsv1.HostStatus {
		o := r.outcomes[connectionID][host]
		return connectionsv1.HostStatus{Sessions: count(host), KcpReachable: o.reachable, LastError: o.lastError}
	}
	vws := map[string]connectionsv1.HostStatus{}
	for host := range r.outcomes[connectionID] {
		if host != WorkspaceHost {
			vws[host] = status(host)
		}
	}
	if len(vws) == 0 {
		vws = nil
	}
	return status(WorkspaceHost), vws
}
