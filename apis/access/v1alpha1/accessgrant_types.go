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

// Phase values on AccessGrantStatus.
const (
	// AccessGrantPhasePending is the initial phase. access-operator has not
	// yet completed the /access handshake with the user-side access SDK.
	AccessGrantPhasePending = "Pending"

	// AccessGrantPhaseActive means the /access handshake succeeded and the
	// user-side cluster holds a kubeconfig for the Provider Workspace.
	AccessGrantPhaseActive = "Active"
)

// Reason labels used on AccessGrant conditions.
const (
	// AccessGrantReasonHandshakePending is set while access-operator is
	// still attempting the initial /access handshake.
	AccessGrantReasonHandshakePending = "HandshakePending"

	// AccessGrantReasonHandshakeSucceeded is set on the Ready condition
	// after a successful /access 200.
	AccessGrantReasonHandshakeSucceeded = "HandshakeSucceeded"

	// AccessGrantReasonHandshakeRejected is set when the user-side access
	// SDK rejected the handshake (403). See the condition message for
	// detail.
	AccessGrantReasonHandshakeRejected = "HandshakeRejected"

	// AccessGrantReasonAccessURLUnreachable is set when access-operator
	// cannot dial the access SDK (TLS, DNS, network).
	AccessGrantReasonAccessURLUnreachable = "AccessURLUnreachable"
)

// AccessTokenSecretRef references a Secret in the same namespace as the
// AccessGrant containing the pma1 access token.
type AccessTokenSecretRef struct {
	// name is the name of the Secret.
	// +required
	Name string `json:"name"`

	// key is the key within the Secret data holding the access token.
	// Defaults to "accessToken".
	// +kubebuilder:default=accessToken
	// +optional
	Key string `json:"key,omitempty"`
}

// AccessGrantSpec defines the desired state of AccessGrant. AccessGrant
// lives in the Provider Workspace on the PM cluster; it is created by the
// provider reconciler on a successful ProviderAccessRequest and consumed
// by access-operator to drive the /access handshake.
type AccessGrantSpec struct {
	// saRef references the ServiceAccount, in the same namespace as this
	// AccessGrant, that access-operator mints tokens for via TokenRequest.
	// The minted SA token is delivered to the user-side cluster in the
	// /access request body.
	// +required
	SARef corev1.LocalObjectReference `json:"saRef"`

	// accessURL is the user-side access SDK's /access endpoint, extracted
	// from the access token's wire form by the provider reconciler.
	// +required
	AccessURL string `json:"accessURL"`

	// accessTokenSecretRef references a Secret in the same namespace as
	// the AccessGrant containing the full pma1.<...> access token string.
	// The Secret is created by the provider reconciler, propagating the
	// token from the ProviderAccessRequest's Secret. access-operator
	// derives the per-dial HMAC call credential from the token value.
	// A fresh PAR overwrites the Secret contents to drive re-onboarding.
	// +required
	AccessTokenSecretRef AccessTokenSecretRef `json:"accessTokenSecretRef"`

	// caBundle is an optional PEM-encoded CA bundle used to verify the
	// access SDK's /access TLS server certificate. Propagated from
	// Provider.spec.remote.caBundle. When empty, access-operator uses
	// system CAs.
	// +optional
	CABundle string `json:"caBundle,omitempty"`
}

// AccessGrantStatus defines the observed state of AccessGrant.
type AccessGrantStatus struct {
	// phase summarises reconciliation state: Pending or Active.
	// +optional
	Phase string `json:"phase,omitempty"`

	// conditions represent the current state of the AccessGrant.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by
	// access-operator.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:JSONPath=".status.phase",name="Phase",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.accessURL",name="AccessURL",type=string,priority=1
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// AccessGrant is the PM-side view of a remote-access connection to a
// Provider's user-side cluster. It is created in the Provider Workspace
// by the provider reconciler on a successful ProviderAccessRequest and
// consumed by access-operator, which runs the /access handshake and
// marks the grant Active.
//
// AccessGrant is torn down with the Provider Workspace on Provider
// deletion.
type AccessGrant struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of AccessGrant.
	// +required
	Spec AccessGrantSpec `json:"spec"`

	// status defines the observed state of AccessGrant.
	// +optional
	Status AccessGrantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessGrantList contains a list of AccessGrant.
type AccessGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessGrant `json:"items"`
}

func (a *AccessGrant) GetConditions() []metav1.Condition {
	return a.Status.Conditions
}

func (a *AccessGrant) SetConditions(conditions []metav1.Condition) {
	a.Status.Conditions = conditions
}
