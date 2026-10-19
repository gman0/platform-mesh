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

// ConnectionFinalizer closes a Connection's Sessions and deletes its
// kubeconfig Secret before the Connection goes.
const ConnectionFinalizer = "provider-sdk.platform-mesh.io/sessions"

// Connection conditions and reasons.
const (
	// ConnectionConditionReady: the Provider Workspace and every
	// virtual-workspace host the operator uses have a Session and reach kcp.
	// Failures are reported only after lasting a few minutes.
	ConnectionConditionReady = "Ready"

	ConnectionReasonAsExpected     = "AsExpected"
	ConnectionReasonNoSessions     = "NoSessions"
	ConnectionReasonKcpUnreachable = "KcpUnreachable"
)

// Events on a Connection. A Provider that tells its customers about changes
// watches these. Failed authentications are never Events.
const (
	ConnectionEventRegistered           = "Registered"
	ConnectionEventSecretChanged        = "SecretChanged"
	ConnectionEventPinnedBundleChanged  = "PinnedBundleChanged"
	ConnectionEventRemoved              = "Removed"
	ConnectionEventAdministrativeChange = "AdministrativeChange"
)

// Kubeconfig Secret metadata, and the annotation that rotates its credential.
const (
	// ConnectionLabel labels a Connection's kubeconfig Secret with its
	// connectionID.
	ConnectionLabel = "provider-sdk.platform-mesh.io/connection"

	// ClusterNameAnnotation carries the Provider Workspace's logical cluster
	// name on the kubeconfig Secret.
	ClusterNameAnnotation = "provider-sdk.platform-mesh.io/cluster-name"

	// KubeconfigKey is the kubeconfig's key in the Secret.
	KubeconfigKey = "kubeconfig"

	// AnnotationRotateProxyCredential on a Connection: every new value
	// writes a new proxy credential into its kubeconfig Secret; the old one
	// is accepted until it's unused.
	AnnotationRotateProxyCredential = "provider-sdk.platform-mesh.io/rotate-proxy-credential"
)

// ConnectionSpec is a Connection's registration and its Pinned Bundle.
type ConnectionSpec struct {
	// registration is fixed when the Connection is registered or imported.
	// +required
	Registration ConnectionRegistration `json:"registration"`

	// pinnedBundle is the Pinned Bundle: the Connector CA certificates (PEM)
	// Sessions are verified against. Written by a PM push or an
	// administrator's re-pin; every change re-checks open Sessions.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=65536
	// +kubebuilder:validation:Pattern=`^\s*-----BEGIN CERTIFICATE-----`
	PinnedBundle string `json:"pinnedBundle"`
}

// ConnectionRegistration is immutable as a whole.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="registration is immutable"
type ConnectionRegistration struct {
	// owner is the portal account that registered the Connection.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Owner string `json:"owner"`

	// clusterName is the Provider Workspace's logical cluster name.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
	ClusterName string `json:"clusterName"`

	// unusedExpiresAt is when the Connection is removed if it has seen
	// neither an authenticated Control Call nor a verified Session. Empty on
	// imported Connections, which never expire.
	// +optional
	UnusedExpiresAt *metav1.Time `json:"unusedExpiresAt,omitempty"`
}

// ConnectionStatus is written only by provider-gateway.
type ConnectionStatus struct {
	// conditions are Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// lastSeen is the last authenticated Control Call or verified Session:
	// the first at once, then at most hourly. Empty: never used.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`

	// listedServerKeys are the ServerKeys the Connection's ProviderEndpoint
	// last listed, by name.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	ListedServerKeys []string `json:"listedServerKeys,omitempty"`

	// secretHash is the current Connection Secret's hash. Empty after an
	// import, until PM repairs the Connection Secret.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SecretHash string `json:"secretHash,omitempty"`

	// proxyCredentialHash is the hash of the operator's proxy credential in
	// the kubeconfig Secret.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ProxyCredentialHash string `json:"proxyCredentialHash,omitempty"`

	// previousProxyCredentialHash is accepted next to proxyCredentialHash
	// while a rotation is in progress.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	PreviousProxyCredentialHash string `json:"previousProxyCredentialHash,omitempty"`

	// proxyCredentialRotation is the last value of the rotate-proxy-credential
	// annotation acted on.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ProxyCredentialRotation string `json:"proxyCredentialRotation,omitempty"`

	// observedGeneration is the last generation reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:selectablefield:JSONPath=`.spec.registration.owner`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^c-[a-z2-7]{26}$')",message="the name must be a connectionID"
// +kubebuilder:printcolumn:JSONPath=".spec.registration.owner",name="Owner",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.registration.clusterName",name="Cluster",type=string
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Ready')].status",name="Ready",type=string
// +kubebuilder:printcolumn:JSONPath=".status.lastSeen",name="Last Seen",type=date
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// Connection is the Provider-side half of a Connection to a Platform Mesh
// instance, named by its connectionID. Deleting it is the delete, whoever
// does it.
type Connection struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the Connection
	// +required
	Spec ConnectionSpec `json:"spec"`

	// status is written by provider-gateway
	// +optional
	Status ConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectionList contains a list of Connection
type ConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Connection `json:"items"`
}

func (c *Connection) GetConditions() []metav1.Condition { return c.Status.Conditions }

func (c *Connection) SetConditions(conditions []metav1.Condition) { c.Status.Conditions = conditions }
