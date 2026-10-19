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

package testvectors

// PathOutcome is what the Connector does with a request's path.
type PathOutcome string

const (
	// PathFrontProxy: forwarded to the front-proxy.
	PathFrontProxy PathOutcome = "FrontProxy"
	// PathVirtualWorkspace: forwarded to this shard's APIExport virtual
	// workspace (if the Host is this shard's).
	PathVirtualWorkspace PathOutcome = "VirtualWorkspace"
	// PathNotCanonical: refused before parsing.
	PathNotCanonical PathOutcome = "NotCanonical"
	// PathWorkspacePath: refused with its own message: use the logical
	// cluster name.
	PathWorkspacePath PathOutcome = "WorkspacePath"
	// PathOutOfScope: another Connection's workspace, or all workspaces
	// through the front-proxy.
	PathOutOfScope PathOutcome = "OutOfScope"
	// PathUnknownShape: neither kcp path shape.
	PathUnknownShape PathOutcome = "UnknownShape"
)

// PathClusterName is the Connection's Provider Workspace in StreamPaths.
const PathClusterName = HelloClusterName

// StreamPathCase is a request path, escaped as it arrives on a Stream, and
// the Connector's outcome for a Connection whose Provider Workspace is
// PathClusterName.
type StreamPathCase struct {
	Name    string
	Path    string
	Outcome PathOutcome
}

// StreamPaths are request paths on a Stream. Where several outcomes apply,
// the first in this order counts: NotCanonical, UnknownShape, WorkspacePath,
// OutOfScope.
func StreamPaths() []StreamPathCase {
	const ws = "/clusters/" + PathClusterName
	const vw = "/services/apiexport/" + PathClusterName + "/cowboys.wildwest.dev"
	return []StreamPathCase{
		{"workspace resource", ws + "/api/v1/namespaces/default/configmaps", PathFrontProxy},
		{"workspace endpoint slices", ws + "/apis/apis.kcp.io/v1alpha1/apiexportendpointslices", PathFrontProxy},
		{"virtual workspace, all consumers", vw + "/clusters/*/apis/wildwest.dev/v1alpha1/cowboys", PathVirtualWorkspace},
		{"virtual workspace, one consumer", vw + "/clusters/3y7zcons/apis/wildwest.dev/v1alpha1/cowboys", PathVirtualWorkspace},

		{"dot-dot segment", ws + "/api/v1/../v1/secrets", PathNotCanonical},
		{"dot segment", ws + "/./api/v1/configmaps", PathNotCanonical},
		{"empty segment", "/clusters//api/v1/configmaps", PathNotCanonical},
		{"trailing empty segment", ws + "/api/v1/configmaps//", PathNotCanonical},
		{"encoded slash", ws + "/api/v1/namespaces/a%2Fb/configmaps", PathNotCanonical},
		{"encoded colon", "/clusters/root%3Aproviders/api/v1/configmaps", PathNotCanonical},
		{"needless escape", ws + "/api/v1/namespaces/%64efault/configmaps", PathNotCanonical},
		{"encoded dot-dot", ws + "/api/v1/%2e%2e/secrets", PathNotCanonical},

		{"workspace path", "/clusters/root:providers:wildwest/api/v1/configmaps", PathWorkspacePath},
		{"workspace path inside the virtual workspace", vw + "/clusters/root:orgs:acme/apis/wildwest.dev/v1alpha1/cowboys", PathWorkspacePath},

		{"another workspace", "/clusters/other1/api/v1/configmaps", PathOutOfScope},
		{"all workspaces through the front-proxy", "/clusters/*/api/v1/configmaps", PathOutOfScope},
		{"another workspace's export", "/services/apiexport/other1/cowboys.wildwest.dev/clusters/*/apis/wildwest.dev/v1alpha1/cowboys", PathOutOfScope},

		{"no cluster", "/api/v1/namespaces", PathUnknownShape},
		{"another virtual workspace", "/services/initializingworkspaces/root:x/clusters/*/api", PathUnknownShape},
		{"virtual workspace without inner cluster", vw + "/apis/wildwest.dev/v1alpha1/cowboys", PathUnknownShape},
	}
}
