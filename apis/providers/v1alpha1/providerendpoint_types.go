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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ProviderEndpointName is the fixed name of the one ProviderEndpoint in
	// a Provider Workspace.
	ProviderEndpointName = "default"

	// ConnectionExportName is the APIExport serving providerendpoints, in
	// :root:providers:system.
	ConnectionExportName = "connections.providers.platform-mesh.io"

	// ConnectionExportBindingName is the fixed name of its APIBinding in
	// every Provider Workspace.
	ConnectionExportBindingName = ConnectionExportName
)

// ProviderEndpointSpec is a Connection as Connectors and the Provider-side
// see it, written only by platform-mesh-operator.
type ProviderEndpointSpec struct {
	// connectionID is the Connection this workspace belongs to. The
	// Provider-side applies a ProviderEndpoint only if it's its own
	// Connection's.
	// +required
	// +kubebuilder:validation:Pattern=`^c-[a-z2-7]{26}$`
	ConnectionID string `json:"connectionID"`

	// url is the Provider's Base URL, which Connectors dial. A change makes
	// them replace their Sessions.
	// +required
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="isURL(self) && url(self).getScheme() == 'https'",message="url must be an https URL"
	URL string `json:"url"`

	// serverKeys are the Provider-side's pinned Server Keys for the Inner
	// TLS, as PEM SubjectPublicKeyInfo.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=2048
	// +kubebuilder:validation:items:Pattern=`^-----BEGIN PUBLIC KEY-----`
	ServerKeys []string `json:"serverKeys"`

	// caBundle is the Provider's spec.remote.caBundle: private CAs that
	// verify the Base URL's outer TLS instead of web PKI. A change makes
	// Connectors replace their Sessions.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	// +kubebuilder:validation:Pattern=`^\s*-----BEGIN CERTIFICATE-----`
	CABundle string `json:"caBundle,omitempty"`

	// pendingSecretHash is the hash of the Connection Secret
	// platform-mesh-operator is switching to; empty otherwise. The
	// Provider-side adopts it.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	PendingSecretHash string `json:"pendingSecretHash,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the ProviderEndpoint must be named default"
// +kubebuilder:printcolumn:JSONPath=".spec.connectionID",name="Connection",type=string,description="The Connection"
// +kubebuilder:printcolumn:JSONPath=".spec.url",name="URL",type=string,description="The Provider's Base URL"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ProviderEndpoint is the PM-side half of a remote Connection as Connectors
// and the Provider see it: one per Provider Workspace, served only by the
// Connection Export, read-only for the Provider. It has no status: nothing
// writes back to it.
type ProviderEndpoint struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the Connection
	// +required
	Spec ProviderEndpointSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// ProviderEndpointList contains a list of ProviderEndpoint
type ProviderEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderEndpoint `json:"items"`
}
