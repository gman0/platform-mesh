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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Serving TLS modes of the operator proxy.
const (
	// ServingTLSCertManager reads the serving certificate cert-manager
	// issues into a mounted Secret, and follows its renewals.
	ServingTLSCertManager = "cert-manager"
	// ServingTLSSelfSigned generates a CA once into a Secret and issues
	// serving certificates from it in memory.
	ServingTLSSelfSigned = "self-signed"
)

// Options configure provider-gateway.
type Options struct {
	// Namespace holds the SDK's resources and the kubeconfig Secrets.
	Namespace string

	// ConnectionAPIAddress serves the Connection API, plain HTTP: the
	// Provider's Edge terminates the outer TLS, the Inner TLS protects the
	// rest.
	ConnectionAPIAddress string
	// ConnectionAPITLSDir, if set, serves the Connection API over TLS with
	// tls.crt and tls.key from there, for Edges that re-encrypt.
	ConnectionAPITLSDir string
	// ProxyAddress serves the operator proxy, on the elected replica only.
	ProxyAddress   string
	MetricsAddress string
	HealthAddress  string

	// ServingTLS is the operator proxy's TLS: ServingTLSCertManager or
	// ServingTLSSelfSigned.
	ServingTLS string
	// ServingTLSDir is the mounted Secret with cert-manager.
	ServingTLSDir string
	// CASecretName is the CA's Secret when self-signed.
	CASecretName string
	// Names are the gateway Service's DNS names; the first is the
	// kubeconfigs' tls-server-name.
	Names []string
	// ProxyHost is the operator proxy's host:port in the kubeconfigs.
	// Default: the first name, at ProxyAddress's port.
	ProxyHost string

	// RetryWindow is how long after a token's expiry Registration retries
	// are honoured.
	RetryWindow time.Duration
	// ReadyDelay is how long a Connection's failure lasts before Ready
	// reports it.
	ReadyDelay time.Duration

	LeaderElection   bool
	LeaderElectionID string
}

// Complete fills in derived defaults and validates o.
func (o *Options) Complete() error {
	if o.ProxyHost == "" && len(o.Names) > 0 {
		_, port, err := net.SplitHostPort(o.ProxyAddress)
		if err != nil {
			return fmt.Errorf("proxy address: %w", err)
		}
		o.ProxyHost = net.JoinHostPort(o.Names[0], port)
	}
	return o.validate()
}

func (o *Options) validate() error {
	var errs []error
	if o.Namespace == "" {
		errs = append(errs, errors.New("namespace is required"))
	}
	if _, _, err := net.SplitHostPort(o.ConnectionAPIAddress); err != nil {
		errs = append(errs, fmt.Errorf("connection API address: %w", err))
	}
	if _, _, err := net.SplitHostPort(o.ProxyAddress); err != nil {
		errs = append(errs, fmt.Errorf("proxy address: %w", err))
	}
	switch o.ServingTLS {
	case ServingTLSCertManager:
		if o.ServingTLSDir == "" {
			errs = append(errs, errors.New("serving TLS directory is required with cert-manager"))
		}
	case ServingTLSSelfSigned:
		if o.CASecretName == "" {
			errs = append(errs, errors.New("CA Secret name is required when self-signed"))
		}
	default:
		errs = append(errs, fmt.Errorf("serving TLS %q: want %s or %s", o.ServingTLS, ServingTLSCertManager, ServingTLSSelfSigned))
	}
	if len(o.Names) == 0 {
		errs = append(errs, errors.New("at least one name is required"))
	}
	for _, n := range o.Names {
		if msgs := validation.IsDNS1123Subdomain(n); len(msgs) > 0 {
			errs = append(errs, fmt.Errorf("name %q: %s", n, strings.Join(msgs, "; ")))
		}
	}
	if o.ProxyHost != "" {
		if _, _, err := net.SplitHostPort(o.ProxyHost); err != nil {
			errs = append(errs, fmt.Errorf("proxy host: %w", err))
		}
	}
	if o.RetryWindow <= 0 {
		errs = append(errs, errors.New("retry window must be positive"))
	}
	if o.ReadyDelay < 0 {
		errs = append(errs, errors.New("ready delay must not be negative"))
	}
	if o.LeaderElection && o.LeaderElectionID == "" {
		errs = append(errs, errors.New("leader election ID is required"))
	}
	return errors.Join(errs...)
}
