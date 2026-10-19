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

// OnboardingTokenSpec is fixed when the portal issues the token.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type OnboardingTokenSpec struct {
	// owner is the portal account the token is issued to; it owns the
	// Connection the token registers.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Owner string `json:"owner"`

	// expiresAt is when the token can no longer start a Registration.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`

	// tokenHash is the hash of the token secret. The token itself is never
	// stored.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	TokenHash string `json:"tokenHash"`

	// serverKey names the ServerKey whose fingerprint the token carries;
	// Registration runs inside Inner TLS with it.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ServerKey string `json:"serverKey"`
}

// OnboardingTokenStatus records the Registration that spent the token.
type OnboardingTokenStatus struct {
	// registration is set when the token is spent, by compare-and-swap.
	// +optional
	Registration *TokenRegistration `json:"registration,omitempty"`
}

// TokenRegistration is the request that spent a token and its response,
// so that a retry of the same request gets the same response.
type TokenRegistration struct {
	// connectionID is the Connection the token registered.
	// +required
	// +kubebuilder:validation:Pattern=`^c-[a-z2-7]{26}$`
	ConnectionID string `json:"connectionID"`

	// idempotencyKey, secretHash and clusterName identify the request; a
	// retry must match all three.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	IdempotencyKey string `json:"idempotencyKey"`
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SecretHash string `json:"secretHash"`
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
	ClusterName string `json:"clusterName"`

	// serverKeys are the Server Keys returned, as PEM SubjectPublicKeyInfo.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	ServerKeys []string `json:"serverKeys"`

	// at is when the token was spent; retries are honoured for the retry
	// window after it.
	// +required
	At metav1.Time `json:"at"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:selectablefield:JSONPath=`.spec.owner`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^t-[a-z2-7]{26}$')",message="the name must be a token ID"
// +kubebuilder:printcolumn:JSONPath=".spec.owner",name="Owner",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.expiresAt",name="Expires",type=date
// +kubebuilder:printcolumn:JSONPath=".status.registration.connectionID",name="Connection",type=string,description="Set once spent"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// OnboardingToken is a single-use token a Provider's portal issued, named by
// its token ID. provider-gateway garbage-collects it: unspent at expiresAt,
// spent once the retry window has passed.
type OnboardingToken struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the token
	// +required
	Spec OnboardingTokenSpec `json:"spec"`

	// status records its Registration
	// +optional
	Status OnboardingTokenStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OnboardingTokenList contains a list of OnboardingToken
type OnboardingTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OnboardingToken `json:"items"`
}
