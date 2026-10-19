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

// Keys of a ProviderEndpointRegistration's Secret, named by
// ConnectionSecretName.
const (
	// ConnectionSecretKey holds the current Connection Secret.
	ConnectionSecretKey = "secret"
	// PendingConnectionSecretKey holds the Connection Secret being switched
	// to, only while it changes.
	PendingConnectionSecretKey = "pendingSecret"
)

// ConnectionSecretName is the name of the Secret holding a Connection's
// credentials, next to its ProviderEndpointRegistration.
func ConnectionSecretName(clusterName string) string { return clusterName + "-secret" }

// ProviderEndpointRegistrationSpec is everything PM knows about a remote
// Connection that can't be recomputed. The ProviderEndpoint is written from
// it.
type ProviderEndpointRegistrationSpec struct {
	// connectionID identifies the Connection, from Registration.
	// +optional
	// +kubebuilder:validation:Pattern=`^c-[a-z2-7]{26}$`
	ConnectionID string `json:"connectionID,omitempty"`

	// url is the Provider's Base URL. PM Administrators may change it when
	// the Provider moves.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="isURL(self) && url(self).getScheme() == 'https'",message="url must be an https URL"
	URL string `json:"url,omitempty"`

	// serverKeys are the Provider-side's Server Keys pinned for the
	// Connection, as PEM SubjectPublicKeyInfo, from Registration and updated
	// from the Provider-side's announcements.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=2048
	// +kubebuilder:validation:items:Pattern=`^-----BEGIN PUBLIC KEY-----`
	ServerKeys []string `json:"serverKeys,omitempty"`

	// unusedExpiresAt is when the Provider-side removes the Connection if
	// it's never reached by then, from Registration.
	// +optional
	UnusedExpiresAt *metav1.Time `json:"unusedExpiresAt,omitempty"`

	// rotationRequest is the last value of the Provider's
	// rotate-connection-secret annotation acted on.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	RotationRequest string `json:"rotationRequest,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:JSONPath=".spec.connectionID",name="Connection",type=string,description="The Connection"
// +kubebuilder:printcolumn:JSONPath=".spec.url",name="URL",type=string,description="The Provider's Base URL"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ProviderEndpointRegistration is the PM-side half of a remote Connection,
// in PM's runtime cluster, in platform-mesh-operator's namespace. It's named
// after the Provider Workspace's logical cluster and authoritative: it has
// no status, since nothing in it can be recomputed.
type ProviderEndpointRegistration struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec holds the Connection's state
	// +required
	Spec ProviderEndpointRegistrationSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// ProviderEndpointRegistrationList contains a list of
// ProviderEndpointRegistration
type ProviderEndpointRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderEndpointRegistration `json:"items"`
}
