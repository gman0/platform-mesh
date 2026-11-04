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

// Phase values on ProviderAccessRequestStatus.
const (
	// ProviderAccessRequestPhasePending is the initial phase. The provider
	// reconciler waits for the referenced Provider to exist with spec.remote
	// set.
	ProviderAccessRequestPhasePending = "Pending"

	// ProviderAccessRequestPhaseCompleted is a terminal phase. The access
	// token has been propagated to the Provider's AccessGrant and the
	// handshake is being driven by access-operator.
	ProviderAccessRequestPhaseCompleted = "Completed"

	// ProviderAccessRequestPhaseFailed is a terminal phase. See the Ready
	// condition for the specific reason.
	ProviderAccessRequestPhaseFailed = "Failed"
)

// Reason labels used on ProviderAccessRequest conditions.
const (
	// ProviderAccessRequestReasonProviderNotFound is set while the referenced
	// Provider doesn't exist; the request waits.
	ProviderAccessRequestReasonProviderNotFound = "ProviderNotFound"

	// ProviderAccessRequestReasonProviderNotRemoteMode is set when the
	// referenced Provider exists but lacks spec.remote. Terminal.
	ProviderAccessRequestReasonProviderNotRemoteMode = "ProviderNotRemoteMode"

	// ProviderAccessRequestReasonAnotherPARActive is set when another
	// non-terminal ProviderAccessRequest targets the same Provider.
	// Oldest wins. Terminal.
	ProviderAccessRequestReasonAnotherPARActive = "AnotherPARActive"

	// ProviderAccessRequestReasonInvalidAccessToken is set when the access
	// token Secret can't be resolved or its contents don't parse as a valid
	// access token. Terminal.
	ProviderAccessRequestReasonInvalidAccessToken = "InvalidAccessToken"

	// ProviderAccessRequestReasonAccepted is set on the Ready condition when
	// the request has been propagated to the Provider's AccessGrant.
	ProviderAccessRequestReasonAccepted = "Accepted"
)

// AccessTokenSecretRef references a Secret containing a pma1 access token.
type AccessTokenSecretRef struct {
	// name is the name of the Secret.
	// +required
	Name string `json:"name"`

	// namespace is the namespace of the Secret.
	// +required
	Namespace string `json:"namespace"`

	// key is the key within the Secret data holding the access token.
	// Defaults to "accessToken".
	// +kubebuilder:default=accessToken
	// +optional
	Key string `json:"key,omitempty"`
}

// ProviderAccessRequestSpec defines the desired state of
// ProviderAccessRequest.
type ProviderAccessRequestSpec struct {
	// providerRef references the Provider this request is binding to by
	// name. The Provider must exist with spec.remote set; if not, the
	// request waits (Provider missing) or fails (Provider not in remote
	// mode).
	// +required
	ProviderRef corev1.LocalObjectReference `json:"providerRef"`

	// accessTokenSecretRef references a Secret containing the pma1 access
	// token obtained from the user-side cluster. The access SDK's /access
	// URL and the HMAC credential for the initial handshake are derived
	// from the token's wire form.
	// +required
	AccessTokenSecretRef AccessTokenSecretRef `json:"accessTokenSecretRef"`
}

// ProviderAccessRequestStatus defines the observed state of
// ProviderAccessRequest.
type ProviderAccessRequestStatus struct {
	// phase summarises reconciliation state: Pending, Completed, or Failed.
	// +optional
	Phase string `json:"phase,omitempty"`

	// conditions represent the current state of the ProviderAccessRequest.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by the
	// controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:JSONPath=".spec.providerRef.name",name="Provider",type=string
// +kubebuilder:printcolumn:JSONPath=".status.phase",name="Phase",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ProviderAccessRequest is a one-shot auth-material delivery object. An
// Owner creates it to drive the user-side access SDK to mint a kubeconfig
// for a Provider Workspace on this PM.
//
// Reconciliation rules:
//   - Order-independent: if the referenced Provider doesn't exist yet, the
//     request sits in Pending until it does. If the Provider exists but
//     lacks spec.remote, the request goes Failed with
//     ProviderNotRemoteMode.
//   - One active request per Provider: new requests arriving while an
//     older non-terminal request exists for the same Provider go Failed
//     immediately with AnotherPARActive. Oldest wins.
//   - Terminal states (Completed, Failed) are not auto-touched.
//   - Deleting the referenced Provider cascades to all its
//     ProviderAccessRequests.
type ProviderAccessRequest struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of ProviderAccessRequest.
	// +required
	Spec ProviderAccessRequestSpec `json:"spec"`

	// status defines the observed state of ProviderAccessRequest.
	// +optional
	Status ProviderAccessRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProviderAccessRequestList contains a list of ProviderAccessRequest.
type ProviderAccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderAccessRequest `json:"items"`
}

func (p *ProviderAccessRequest) GetConditions() []metav1.Condition {
	return p.Status.Conditions
}

func (p *ProviderAccessRequest) SetConditions(conditions []metav1.Condition) {
	p.Status.Conditions = conditions
}
