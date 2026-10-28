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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validOptions() Options {
	return Options{
		Namespace:            "wild-west-system",
		ConnectionAPIAddress: ":8080",
		ProxyAddress:         ":3128",
		ServingTLS:           ServingTLSCertManager,
		ServingTLSDir:        "/etc/provider-gateway/serving",
		Names:                []string{"provider-gateway.wild-west-system.svc"},
		RetryWindow:          7 * 24 * time.Hour,
		ReadyDelay:           5 * time.Minute,
		LeaderElection:       true,
		LeaderElectionID:     "provider-gateway",
	}
}

func TestOptionsProxyHost(t *testing.T) {
	o := validOptions()
	require.NoError(t, o.Complete())
	assert.Equal(t, "provider-gateway.wild-west-system.svc:3128", o.ProxyHost)

	o = validOptions()
	o.ProxyHost = "gw.example:443"
	require.NoError(t, o.Complete())
	assert.Equal(t, "gw.example:443", o.ProxyHost, "an explicit one is kept")
}

func TestOptionsKubeconfigNamespace(t *testing.T) {
	o := validOptions()
	require.NoError(t, o.Complete())
	assert.Equal(t, o.Namespace, o.KubeconfigNamespace, "defaults to the namespace")

	o = validOptions()
	o.KubeconfigNamespace = "wild-west-kubeconfigs"
	require.NoError(t, o.Complete())
	assert.Equal(t, "wild-west-kubeconfigs", o.KubeconfigNamespace)
}

func TestOptionsInvalid(t *testing.T) {
	cases := map[string]func(*Options){
		"no namespace":                     func(o *Options) { o.Namespace = "" },
		"invalid kubeconfig namespace":     func(o *Options) { o.KubeconfigNamespace = "Kube_Configs" },
		"bad connection API address":       func(o *Options) { o.ConnectionAPIAddress = "8080" },
		"bad proxy address":                func(o *Options) { o.ProxyAddress = "3128" },
		"unknown serving TLS":              func(o *Options) { o.ServingTLS = "vault" },
		"cert-manager without a directory": func(o *Options) { o.ServingTLSDir = "" },
		"self-signed without a Secret":     func(o *Options) { o.ServingTLS = ServingTLSSelfSigned },
		"no names":                         func(o *Options) { o.Names = nil },
		"invalid name":                     func(o *Options) { o.Names = []string{"Provider_Gateway"} },
		"bad proxy host":                   func(o *Options) { o.ProxyHost = "gw.example" },
		"no retry window":                  func(o *Options) { o.RetryWindow = 0 },
		"negative ready delay":             func(o *Options) { o.ReadyDelay = -time.Second },
		"leader election without an ID":    func(o *Options) { o.LeaderElectionID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := validOptions()
			mutate(&o)
			assert.Error(t, o.Complete())
		})
	}
}
