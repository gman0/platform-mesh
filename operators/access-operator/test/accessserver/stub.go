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

// Package accessserver is a cheap stub of the user-side /access
// endpoint for Stage 1 integration tests. It verifies the JWT call
// credential against an injected HMAC-secret lookup, runs the replay
// cache, and acknowledges with 200. It deliberately does not write
// any kubeconfig Secret or Access CR — that behaviour belongs to the
// real sdk/access server shipped in Stage 2.
package accessserver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	pmaccessproto "go.platform-mesh.io/protocol/access"
)

// SecretLookup maps a tokenID (the sub claim on the call credential)
// to the HMAC secret for that AccessIdentity. Returns ok=false for
// unknown identities.
type SecretLookup func(tokenID string) (secret []byte, ok bool)

// StaticLookup is a convenience SecretLookup backed by an in-memory
// map; sufficient for tests that register one or two known tokens.
func StaticLookup(entries map[string][]byte) SecretLookup {
	return func(tokenID string) ([]byte, bool) {
		v, ok := entries[tokenID]
		return v, ok
	}
}

// Options customise stub behaviour.
type Options struct {
	// SecretLookup resolves tokenID to HMAC secret. Required.
	SecretLookup SecretLookup

	// Skew is the clock-skew tolerance passed to protocol/access.Verify.
	// Zero means use protocol/access.DefaultCallCredentialSkew.
	Skew time.Duration

	// ReplayCacheSize bounds the stub's replay cache (fail-closed).
	// Zero disables the bound.
	ReplayCacheSize int

	// OnAccepted is called with the handshake body after a successful
	// verification. Tests can use it to assert on body contents.
	// Optional.
	OnAccepted func(tokenID string, body []byte)
}

// Server is a stub /access endpoint. Zero value is not usable;
// construct with New.
type Server struct {
	opts  Options
	cache *pmaccessproto.ReplayCache
	mu    sync.Mutex
}

// New builds a stub Server with the given options. Panics if
// SecretLookup is nil.
func New(opts Options) *Server {
	if opts.SecretLookup == nil {
		panic("accessserver: SecretLookup is required")
	}
	return &Server{
		opts:  opts,
		cache: pmaccessproto.NewReplayCache(opts.ReplayCacheSize),
	}
}

// Handler returns an http.Handler for POST /access. Any other method
// or path responds 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/access", s.handle)
	return mux
}

// NewHTTPTestServer is a convenience for tests: boots an httptest.Server
// with this stub installed. Caller is responsible for Close().
func (s *Server) NewHTTPTestServer() *httptest.Server {
	return httptest.NewServer(s.Handler())
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		http.Error(w, "missing Bearer credential", http.StatusForbidden)
		return
	}
	jwt := auth[len(prefix):]

	// Peek the sub claim to resolve the HMAC secret before verifying.
	pre, err := pmaccessproto.ParseUnverified(jwt)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse credential: %v", err), http.StatusForbidden)
		return
	}
	secret, ok := s.opts.SecretLookup(pre.Subject)
	if !ok {
		http.Error(w, "UnknownIdentity", http.StatusForbidden)
		return
	}

	claims, err := pmaccessproto.Verify(secret, jwt, body, s.opts.Skew)
	if err != nil {
		http.Error(w, fmt.Sprintf("verify: %v", err), http.StatusForbidden)
		return
	}

	// Replay check. exp was already validated by Verify; use it as the
	// cache entry's TTL so stale jtis age out naturally.
	exp := claims.ExpiresAt.Time
	if !s.cache.Seen(claims.Subject, claims.ID, exp) {
		http.Error(w, "Replay", http.StatusForbidden)
		return
	}

	if s.opts.OnAccepted != nil {
		s.opts.OnAccepted(claims.Subject, body)
	}

	w.WriteHeader(http.StatusOK)
}
