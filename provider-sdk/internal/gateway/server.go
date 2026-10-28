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

package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 5 * time.Second
)

// server serves handler on addr until the manager stops. Request contexts
// derive from the manager's, so upgraded connections end with it too.
type server struct {
	name    string
	addr    string
	handler http.Handler
	// tls, if set, terminates TLS; HTTP/1.1 only, which upgrades and
	// CONNECT need.
	tls *tls.Config
	// leader runs it on the elected replica only.
	leader bool
}

var _ manager.LeaderElectionRunnable = &server{}

func (s *server) NeedLeaderElection() bool { return s.leader }

func (s *server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("%s: %w", s.name, err)
	}
	if s.tls != nil {
		ln = tls.NewListener(ln, s.tls)
	}
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		return fmt.Errorf("%s: %w", s.name, err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", s.name, err)
	}
	return nil
}

// serverTLS is the TLS of the gateway's listeners.
func serverTLS(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: getCertificate,
	}
}

// anyReplica runs a Runnable on every replica, not only the elected one.
type anyReplica struct{ manager.Runnable }

func (anyReplica) NeedLeaderElection() bool { return false }
