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

package kubeconfig

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
)

// Source is the operator proxy's TLS: its serving certificate, and the
// trust bundle the kubeconfigs carry.
type Source interface {
	// GetCertificate is for tls.Config.GetCertificate.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Bundle is the PEM trust bundle.
	Bundle() ([]byte, error)
}

// FileSource serves a certificate cert-manager issues into a Secret mounted
// at a directory (tls.crt, tls.key, ca.crt), reloading it when it's renewed.
// The default: cert-manager renews the serving certificate, and its CA,
// which clients trust, doesn't change.
type FileSource struct {
	watcher *certwatcher.CertWatcher
	caPath  string
}

// NewFileSource reads the certificate in dir. Run Start to follow renewals.
func NewFileSource(dir string) (*FileSource, error) {
	w, err := certwatcher.New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		return nil, err
	}
	return &FileSource{watcher: w, caPath: filepath.Join(dir, caBundleKey)}, nil
}

// Start follows renewals until ctx ends.
func (s *FileSource) Start(ctx context.Context) error { return s.watcher.Start(ctx) }

// GetCertificate returns the current certificate.
func (s *FileSource) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.watcher.GetCertificate(h)
}

// Bundle returns ca.crt.
func (s *FileSource) Bundle() ([]byte, error) { return os.ReadFile(s.caPath) }

// SelfSigned is the fallback without cert-manager: serving certificates
// issued in memory, on each replica, from the self-generated CA.
type SelfSigned struct {
	CA *CA
	// Names are the names clients verify, as in the kubeconfigs'
	// tls-server-name.
	Names []string
	// Now defaults to time.Now.
	Now func() time.Time

	mu   sync.Mutex
	cert *tls.Certificate
}

// GetCertificate issues a serving certificate, and reissues it before it
// expires.
func (s *SelfSigned) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert != nil && s.cert.Leaf.NotAfter.Sub(now) > servingRenewAt {
		return s.cert, nil
	}
	cert, err := s.CA.Issue(s.Names, now)
	if err != nil {
		return nil, err
	}
	s.cert = cert
	return cert, nil
}

// Bundle returns the CA.
func (s *SelfSigned) Bundle() ([]byte, error) { return s.CA.Bundle(), nil }
