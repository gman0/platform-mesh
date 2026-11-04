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

// AcceptMode controls how an incoming /access call is handled.
// +kubebuilder:validation:Enum=Always;Manual
type AcceptMode string

const (
	// AcceptModeAlways accepts any /access call that passes HMAC
	// verification. The default for the direct deployment model.
	AcceptModeAlways AcceptMode = "Always"

	// AcceptModeManual queues an incoming /access call on
	// AccessIdentity.status.pendingConnections and returns 202. The
	// Provider approves by patching the identity. Deferred to Stage 4.
	AcceptModeManual AcceptMode = "Manual"
)

// PendingConnection is an entry in AccessIdentity.status.pendingConnections
// surfaced while spec.accept is Manual. Populated by the access SDK;
// approved/denied by the Provider patching the identity.
type PendingConnection struct {
	// tokenID identifies the incoming /access call; matches the tokenID
	// component of the access token.
	// +required
	TokenID string `json:"tokenID"`

	// receivedAt is when the access SDK first saw the call.
	// +required
	ReceivedAt metav1.Time `json:"receivedAt"`

	// expiresAt is when this pending entry will be dropped if not
	// approved. Derived from spec.pendingTTL.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// AccessIdentitySpec defines the desired state of an AccessIdentity.
type AccessIdentitySpec struct {
	// accept controls how incoming /access calls are handled.
	// Defaults to Always.
	// +kubebuilder:default=Always
	// +optional
	Accept AcceptMode `json:"accept,omitempty"`

	// maxPending caps the pending queue size while accept is Manual.
	// +optional
	MaxPending int32 `json:"maxPending,omitempty"`

	// pendingTTL is how long a pending connection stays in the queue
	// before being dropped. Only meaningful while accept is Manual.
	// +optional
	PendingTTL *metav1.Duration `json:"pendingTTL,omitempty"`
}

// AccessIdentityStatus defines the observed state of an AccessIdentity.
type AccessIdentityStatus struct {
	// tokenID is the public portion of the access token minted for this
	// identity. The full token lives in an owned Secret.
	// +optional
	TokenID string `json:"tokenID,omitempty"`

	// pendingConnections lists /access calls awaiting manual approval.
	// Populated only while spec.accept is Manual.
	// +listType=map
	// +listMapKey=tokenID
	// +optional
	PendingConnections []PendingConnection `json:"pendingConnections,omitempty"`

	// conditions represent the current state of the AccessIdentity.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by the
	// access SDK.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:JSONPath=".spec.accept",name="Accept",type=string
// +kubebuilder:printcolumn:JSONPath=".status.tokenID",name="TokenID",type=string,priority=1
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// AccessIdentity is a standing authorization on the user-side cluster for
// a PM instance to deliver kubeconfigs via /access. On creation, the
// access SDK mints an access token (tokenID + HMAC secret), writes the
// full token into an owned Secret, and starts serving /access calls
// authenticated against that identity's HMAC secret. One AccessIdentity
// maps to many Access objects over time.
type AccessIdentity struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of AccessIdentity.
	// +required
	Spec AccessIdentitySpec `json:"spec"`

	// status defines the observed state of AccessIdentity.
	// +optional
	Status AccessIdentityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessIdentityList contains a list of AccessIdentity.
type AccessIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessIdentity `json:"items"`
}

func (a *AccessIdentity) GetConditions() []metav1.Condition {
	return a.Status.Conditions
}

func (a *AccessIdentity) SetConditions(conditions []metav1.Condition) {
	a.Status.Conditions = conditions
}
