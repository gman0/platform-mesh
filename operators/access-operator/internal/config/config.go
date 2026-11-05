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

package config

import (
	"github.com/spf13/pflag"
)

// KCPConfig carries the details needed to reach PM's kcp admin plane.
// Mirrored on the platform-mesh-operator config of the same name so both
// operators can share kcp admin plumbing without a separate helper.
type KCPConfig struct {
	Url                    string
	Namespace              string
	RootShardName          string
	FrontProxyName         string
	FrontProxyPort         string
	ClusterAdminSecretName string

	// ExternalUrl is the publicly-reachable kcp URL propagated to
	// user-side clusters in the /access handshake body. Distinct from
	// Url which is the operator's internal (in-cluster) view. Required
	// for the handshake subroutine; the operator refuses to run it if
	// unset.
	ExternalUrl string

	// CABundlePath is the path to a PEM-encoded CA bundle mounted into
	// the operator's filesystem. Used as kcpCABundle in the /access
	// handshake body so the user-side cluster can trust kcp.
	CABundlePath string
}

// AccessAPIExportConfig points at the APIExportEndpointSlice that feeds
// AccessGrants from every Provider Workspace into this operator's
// manager. The Name and Workspace defaults match the apigen output in
// Taskfile.yaml.
type AccessAPIExportConfig struct {
	EndpointSliceName      string
	EndpointSliceWorkspace string
}

// HandshakeSubroutineConfig toggles the AccessGrant handshake subroutine.
type HandshakeSubroutineConfig struct {
	Enabled bool
}

type SubroutinesConfig struct {
	Handshake HandshakeSubroutineConfig
}

// OperatorConfig is the access-operator top-level config.
type OperatorConfig struct {
	KCP         KCPConfig
	Access      AccessAPIExportConfig
	Subroutines SubroutinesConfig
}

func NewOperatorConfig() OperatorConfig {
	return OperatorConfig{
		KCP: KCPConfig{
			Namespace:              "platform-mesh-system",
			RootShardName:          "root",
			FrontProxyName:         "frontproxy",
			FrontProxyPort:         "8443",
			ClusterAdminSecretName: "kcp-cluster-admin-client-cert",
		},
		Access: AccessAPIExportConfig{
			EndpointSliceName:      "access.platform-mesh.io",
			EndpointSliceWorkspace: "root:platform-mesh-system",
		},
		Subroutines: SubroutinesConfig{
			Handshake: HandshakeSubroutineConfig{Enabled: true},
		},
	}
}

func (c *OperatorConfig) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.KCP.Url, "kcp-url", c.KCP.Url, "Set KCP URL")
	fs.StringVar(&c.KCP.Namespace, "kcp-namespace", c.KCP.Namespace, "Set KCP namespace")
	fs.StringVar(&c.KCP.RootShardName, "kcp-root-shard-name", c.KCP.RootShardName, "Set KCP root shard name")
	fs.StringVar(&c.KCP.FrontProxyName, "kcp-front-proxy-name", c.KCP.FrontProxyName, "Set KCP front-proxy name")
	fs.StringVar(&c.KCP.FrontProxyPort, "kcp-front-proxy-port", c.KCP.FrontProxyPort, "Set KCP front-proxy port")
	fs.StringVar(&c.KCP.ClusterAdminSecretName, "kcp-cluster-admin-secret-name", c.KCP.ClusterAdminSecretName, "Set cluster-admin secret name")
	fs.StringVar(&c.KCP.ExternalUrl, "kcp-external-url", c.KCP.ExternalUrl, "Publicly-reachable kcp URL propagated into /access handshake body")
	fs.StringVar(&c.KCP.CABundlePath, "kcp-ca-bundle-path", c.KCP.CABundlePath, "Path to a PEM-encoded kcp CA bundle, mounted into the operator and propagated into /access handshake body")

	fs.StringVar(&c.Access.EndpointSliceName, "access-apiexport-endpointslice-name", c.Access.EndpointSliceName, "Access APIExportEndpointSlice name")
	fs.StringVar(&c.Access.EndpointSliceWorkspace, "access-apiexport-endpointslice-workspace", c.Access.EndpointSliceWorkspace, "Access APIExportEndpointSlice workspace")

	fs.BoolVar(&c.Subroutines.Handshake.Enabled, "subroutines-access-handshake-enabled", c.Subroutines.Handshake.Enabled, "Enable AccessGrant handshake subroutine")
}
