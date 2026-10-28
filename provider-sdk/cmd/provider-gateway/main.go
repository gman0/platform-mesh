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

// provider-gateway is the Provider-side of Platform Mesh's Connection API.
// Every flag can also be set by environment variable: PROVIDER_GATEWAY_ and
// the flag's name in upper case, with "_" for "-".
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"go.platform-mesh.io/provider-sdk/internal/gateway"
	"go.platform-mesh.io/provider-sdk/internal/kubeconfig"
)

const (
	envPrefix     = "PROVIDER_GATEWAY_"
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

func main() {
	o := gateway.Options{}
	fs := flag.CommandLine
	fs.StringVar(&o.Namespace, "namespace", "", "namespace of the SDK's resources and keys (default: the pod's)")
	fs.StringVar(&o.KubeconfigNamespace, "kubeconfig-namespace", "", "namespace of the kubeconfig Secrets, apart from the keys so the Provider's operator can read it alone (default: --namespace)")
	fs.StringVar(&o.ConnectionAPIAddress, "connection-api-address", ":8080", "address of the Connection API, plain HTTP unless --connection-api-tls-dir is set")
	fs.StringVar(&o.ConnectionAPITLSDir, "connection-api-tls-dir", "", "directory with tls.crt and tls.key to serve the Connection API over TLS, for Edges that re-encrypt")
	fs.StringVar(&o.ProxyAddress, "proxy-address", ":3128", "address of the operator proxy")
	fs.StringVar(&o.MetricsAddress, "metrics-address", ":9090", `address of the metrics endpoint, "0" to disable`)
	fs.StringVar(&o.HealthAddress, "health-address", ":8081", "address of the liveness and readiness endpoints")
	fs.StringVar(&o.ServingTLS, "serving-tls", gateway.ServingTLSCertManager,
		fmt.Sprintf("the operator proxy's TLS: %s or %s", gateway.ServingTLSCertManager, gateway.ServingTLSSelfSigned))
	fs.StringVar(&o.ServingTLSDir, "serving-tls-dir", "/etc/provider-gateway/serving", "cert-manager's serving certificate Secret, mounted (tls.crt, tls.key, ca.crt)")
	fs.StringVar(&o.CASecretName, "ca-secret-name", kubeconfig.DefaultCASecretName, "the self-signed CA's Secret")
	fs.Func("names", "comma-separated DNS names of the gateway's Service; the first is the kubeconfigs' tls-server-name", func(s string) error {
		o.Names = strings.Split(s, ",")
		return nil
	})
	fs.StringVar(&o.ProxyHost, "proxy-host", "", "the operator proxy's host:port in kubeconfigs (default: the first name, at the proxy address's port)")
	fs.DurationVar(&o.RetryWindow, "retry-window", 7*24*time.Hour, "how long after a token's expiry Registration retries are honoured")
	fs.DurationVar(&o.ReadyDelay, "ready-delay", 5*time.Minute, "how long a Connection's failure lasts before Ready reports it")
	fs.BoolVar(&o.LeaderElection, "leader-election", true, "elect the active replica")
	fs.StringVar(&o.LeaderElectionID, "leader-election-id", "provider-gateway", "the leader election Lease")
	zopts := zap.Options{}
	zopts.BindFlags(fs)
	flag.Parse()
	if err := setFromEnv(fs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))
	log := ctrl.Log.WithName("setup")
	if o.Namespace == "" {
		if b, err := os.ReadFile(namespaceFile); err == nil {
			o.Namespace = strings.TrimSpace(string(b))
		}
	}

	if err := gateway.Run(ctrl.SetupSignalHandler(), ctrl.GetConfigOrDie(), o); err != nil {
		log.Error(err, "provider-gateway failed")
		os.Exit(1)
	}
}

// setFromEnv sets every flag not given on the command line from its
// environment variable, if there is one.
func setFromEnv(fs *flag.FlagSet) error {
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var err error
	fs.VisitAll(func(f *flag.Flag) {
		if given[f.Name] || err != nil {
			return
		}
		name := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok {
			if e := fs.Set(f.Name, v); e != nil {
				err = fmt.Errorf("%s: %w", name, e)
			}
		}
	})
	return err
}
