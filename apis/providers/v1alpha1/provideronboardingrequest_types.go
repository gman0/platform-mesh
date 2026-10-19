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

// ProviderOnboardingRequest phases. A request ends at Registered or Failed;
// Failed is only possible before Registration succeeds.
const (
	ProviderOnboardingRequestPhasePending     = "Pending"
	ProviderOnboardingRequestPhaseRegistering = "Registering"
	ProviderOnboardingRequestPhaseRegistered  = "Registered"
	ProviderOnboardingRequestPhaseFailed      = "Failed"
)

// ProviderOnboardingRequestConditionRegistered is the request's condition.
// Its reason is one of the ProviderOnboardingRequestReason constants, and its
// message starts with the same label.
const ProviderOnboardingRequestConditionRegistered = "Registered"

// ProviderOnboardingRequest reasons.
const (
	// Waiting.
	ProviderOnboardingRequestReasonRemoteProvidersNotReady = "RemoteProvidersNotReady"
	ProviderOnboardingRequestReasonProviderNotFound        = "ProviderNotFound"
	ProviderOnboardingRequestReasonWorkspaceNotReady       = "WorkspaceNotReady"
	ProviderOnboardingRequestReasonProviderUnreachable     = "ProviderUnreachable"
	ProviderOnboardingRequestReasonRegistering             = "Registering"

	// Failed.
	ProviderOnboardingRequestReasonAnotherRequestActive = "AnotherRequestActive"
	ProviderOnboardingRequestReasonProviderNotRemote    = "ProviderNotRemote"
	ProviderOnboardingRequestReasonConnectionKnown      = "ConnectionKnown"
	ProviderOnboardingRequestReasonInvalidToken         = "InvalidToken"
	ProviderOnboardingRequestReasonTokenRefused         = "TokenRefused"

	// Done.
	ProviderOnboardingRequestReasonRegistered = "Registered"
)

// ProviderOnboardingRequestSpec defines a request to register a remote
// Provider's Connection with an Onboarding Token. The whole spec is
// immutable.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type ProviderOnboardingRequestSpec struct {
	// providerRef names the remote Provider, in the same workspace. The Owner
	// creates it; the request waits until it exists.
	// +required
	ProviderRef ProviderOnboardingRequestProviderRef `json:"providerRef"`

	// tokenSecretRef points to the Secret holding the Onboarding Token. Its
	// content is deleted once the token is spent.
	// +required
	TokenSecretRef TokenSecretReference `json:"tokenSecretRef"`

	// tokenID is the Onboarding Token's ID. A token Secret holding a token
	// with another ID is refused.
	// +required
	// +kubebuilder:validation:Pattern=`^t-[a-z2-7]{26}$`
	TokenID string `json:"tokenID"`
}

// ProviderOnboardingRequestProviderRef names a Provider.
type ProviderOnboardingRequestProviderRef struct {
	// name of the Provider.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// TokenSecretReference points to a key of a Secret.
type TokenSecretReference struct {
	// namespace of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`

	// name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// key in the Secret's data holding the token.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`
}

// ProviderOnboardingRequestStatus defines the observed state of a
// ProviderOnboardingRequest. Everything after Registration is reported on
// the Provider.
type ProviderOnboardingRequestStatus struct {
	// phase is Pending, Registering, Registered or Failed.
	// +optional
	// +kubebuilder:validation:Enum=Pending;Registering;Registered;Failed
	Phase string `json:"phase,omitempty"`

	// connectionID is the Connection the request registered.
	// +optional
	// +kubebuilder:validation:Pattern=`^c-[a-z2-7]{26}$`
	ConnectionID string `json:"connectionID,omitempty"`

	// conditions represent the current state of the request.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:JSONPath=".spec.providerRef.name",name="Provider",type=string,description="The remote Provider"
// +kubebuilder:printcolumn:JSONPath=".status.phase",name="Phase",type=string,description="Onboarding phase"
// +kubebuilder:printcolumn:JSONPath=".status.connectionID",name="Connection",type=string,description="The registered Connection"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ProviderOnboardingRequest spends an Onboarding Token to register a remote
// Provider's Connection. It's one action: done once Registered or Failed.
type ProviderOnboardingRequest struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the request
	// +required
	Spec ProviderOnboardingRequestSpec `json:"spec"`

	// status defines the observed state of the request
	// +optional
	Status ProviderOnboardingRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProviderOnboardingRequestList contains a list of ProviderOnboardingRequest
type ProviderOnboardingRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderOnboardingRequest `json:"items"`
}

func (r *ProviderOnboardingRequest) GetConditions() []metav1.Condition {
	return r.Status.Conditions
}

func (r *ProviderOnboardingRequest) SetConditions(conditions []metav1.Condition) {
	r.Status.Conditions = conditions
}
