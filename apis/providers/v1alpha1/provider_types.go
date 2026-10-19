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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Provider phases, for Local and Remote Providers alike, computed from the
// conditions. Degraded is only reached from Ready (see status.lastReadyTime).
const (
	ProviderPhasePending      = "Pending"
	ProviderPhaseProvisioning = "Provisioning"
	ProviderPhaseReady        = "Ready"
	ProviderPhaseDegraded     = "Degraded"
	ProviderPhaseDeleting     = "Deleting"
)

// Provider conditions: one per reconcile step, plus the aggregate Ready.
// ProtocolOutdated and TrustOutdated are warnings that don't affect Ready.
const (
	ProviderConditionReady = "Ready"

	// Local Providers.
	ProviderConditionWorkspace  = "Workspace"
	ProviderConditionKubeconfig = "Kubeconfig"

	// Remote Providers, besides Workspace.
	ProviderConditionConnectionBinding = "ConnectionBinding"
	ProviderConditionConnectorAccess   = "ConnectorAccess"
	ProviderConditionRegistered        = "Registered"
	ProviderConditionConnected         = "Connected"
	ProviderConditionProtocolOutdated  = "ProtocolOutdated"
	ProviderConditionTrustOutdated     = "TrustOutdated"
)

// Stable labels of Remote Provider conditions: the condition's reason, and
// the start of its message.
const (
	ProviderReasonEdgeUpgradeRefused  = "EdgeUpgradeRefused"
	ProviderReasonEdgeBotChallenge    = "EdgeBotChallenge"
	ProviderReasonEdgePayloadBlocked  = "EdgePayloadBlocked"
	ProviderReasonEdgeTimeout         = "EdgeTimeout"
	ProviderReasonEdgeTLS             = "EdgeTLS"
	ProviderReasonEdgePathRewritten   = "EdgePathRewritten"
	ProviderReasonControlUnreachable  = "ControlUnreachable"
	ProviderReasonSecretRejected      = "SecretRejected"
	ProviderReasonConnectionUnknown   = "ConnectionUnknown"
	ProviderReasonConnectionAbandoned = "ConnectionAbandoned"
	ProviderReasonConnectionIDMissing = "ConnectionIDMissing"
	ProviderReasonPolicyNotEnforced   = "PolicyNotEnforced"
	ProviderReasonNoSessions          = "NoSessions"
	ProviderReasonKcpUnreachable      = "KcpUnreachable"
)

// Annotations on a Remote Provider.
const (
	// AnnotationRotateConnectionSecret: every new value changes the
	// Connection Secret once; values arriving during a change are coalesced.
	AnnotationRotateConnectionSecret = "providers.platform-mesh.io/rotate-connection-secret"

	// AnnotationAbandonConnection gives up the Connection whose connectionID
	// it names, for a Provider that won't come back. The workspace and
	// consumers' bindings stay.
	AnnotationAbandonConnection = "providers.platform-mesh.io/abandon-connection"
)

// RemoteProviderServiceAccount is the admin ServiceAccount in every Remote
// Provider's workspace, in namespace default. Connectors act as it.
const RemoteProviderServiceAccount = "provider"

// ProviderSpec defines the desired state of Provider.
// Provider is a kcp-level resource that handles kcp-side bootstrap only
// (Workspace, ServiceAccount, RBAC, kubeconfig Secret). It has no runtime-side effects.
// A Remote Provider (spec.remote) is reached through a Connection instead of
// a kubeconfig.
//
// +kubebuilder:validation:XValidation:rule="!has(self.remote) || (!has(self.providerKubeconfigSecret) && !has(self.hostOverride))",message="providerKubeconfigSecret and hostOverride only apply to Local Providers"
// +kubebuilder:validation:XValidation:rule="has(oldSelf.remote) == has(self.remote)",message="a Provider can't switch between local and remote"
type ProviderSpec struct {
	// providerKubeconfigSecret is a Secret specification used to store
	// the provider's kubeconfig. This is the admin kubeconfig that provider controllers
	// can use to access the workspace in :root:providers:<WS name>.
	// If not provided, a default of Namespace:default, Name:<Provider.Name>-provider-kubeconfig,
	// Key:kubeconfig is used.
	//
	// +optional
	ProviderKubeconfigSecret *KubeconfigSecretSpec `json:"providerKubeconfigSecret,omitempty"`

	// hostOverride overrides the kcp front-proxy host written into the
	// generated kubeconfig Secret. Optional; defaults to the operator-configured
	// front-proxy URL.
	// +optional
	HostOverride string `json:"hostOverride,omitempty"`

	// remote makes this a Remote Provider, onboarded with a
	// ProviderOnboardingRequest and reached through a Connection.
	// +optional
	Remote *RemoteProviderSpec `json:"remote,omitempty"`
}

// RemoteProviderSpec configures a Remote Provider.
type RemoteProviderSpec struct {
	// caBundle holds private CA certificates (PEM, one or more) that verify
	// the outer TLS of the Provider's Base URL, instead of web PKI. To rotate,
	// add the new CA before the Provider switches, and remove the old one
	// afterwards.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	// +kubebuilder:validation:Pattern=`^\s*-----BEGIN CERTIFICATE-----`
	CABundle string `json:"caBundle,omitempty"`
}

// KubeconfigSecretSpec describes a Secret and the key with kubeconfig YAML content.
type KubeconfigSecretSpec struct {
	// name is the name of the Secret.
	Name string `json:"name"`

	// namespace is the namespace of the Secret.
	Namespace string `json:"namespace"`

	// key is the key in data map where the kubeconfig YAML content is stored.
	Key string `json:"key"`
}

// ProviderStatus defines the observed state of Provider.
type ProviderStatus struct {
	// phase summarises the state of the Provider, computed from the
	// conditions.
	// +optional
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Degraded;Deleting
	Phase string `json:"phase,omitempty"`

	// providerKubeconfigSecretRef points to the Secret that contains
	// the scoped kubeconfig for the provider workspace.
	// +optional
	ProviderKubeconfigSecretRef *corev1.SecretReference `json:"providerKubeconfigSecretRef,omitempty"`

	// conditions represent the current state of the Provider resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// lastReadyTime is when the Provider was last Ready; set once it has
	// been, so phase can tell Degraded from Provisioning.
	// +optional
	LastReadyTime *metav1.Time `json:"lastReadyTime,omitempty"`

	// connection is the Connection a Remote Provider uses, for the Owner's
	// information only.
	// +optional
	Connection *ProviderConnectionStatus `json:"connection,omitempty"`
}

// ProviderConnectionStatus shows a Remote Provider's Connection.
type ProviderConnectionStatus struct {
	// url is the Provider's Base URL.
	// +optional
	URL string `json:"url,omitempty"`

	// connectionID identifies the Connection.
	// +optional
	ConnectionID string `json:"connectionID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:JSONPath=".status.phase",name="Phase",type=string,description="Phase"
// +kubebuilder:printcolumn:JSONPath=".status.providerKubeconfigSecretRef.name",name="KubeconfigSecret",type=string,description="Name of the generated kubeconfig Secret"
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Ready')].status",name="Ready",type=string,description="Shows if resource is ready"

// Provider is the Schema for the providers API.
// It is a kcp-level resource that bootstraps provider RBAC and credentials.
type Provider struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of Provider
	// +required
	Spec ProviderSpec `json:"spec"`

	// status defines the observed state of Provider
	// +optional
	Status ProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProviderList contains a list of Provider
type ProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Provider `json:"items"`
}

func (i *Provider) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

func (i *Provider) SetConditions(conditions []metav1.Condition) {
	i.Status.Conditions = conditions
}
