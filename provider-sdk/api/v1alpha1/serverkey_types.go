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

// ServerKey conditions and reasons.
const (
	ServerKeyConditionReady = "Ready"

	ServerKeyReasonAsExpected  = "AsExpected"
	ServerKeyReasonKeyMissing  = "KeyMissing"
	ServerKeyReasonKeyMismatch = "KeyMismatch"
)

// ServerKeyPrivateKey is the key of the private key (PKCS #8 PEM) in the
// ServerKey's Secret, which has the ServerKey's name and an owner reference
// to it.
const ServerKeyPrivateKey = "privateKey"

// ServerKeySpec controls a key's retirement.
type ServerKeySpec struct {
	// retireAt is when the key stops being presented. From then on, no new
	// tokens are issued over it, and unspent ones are refused.
	// +optional
	RetireAt *metav1.Time `json:"retireAt,omitempty"`
}

// ServerKeyStatus is written by provider-gateway once it has generated the
// key.
type ServerKeyStatus struct {
	// conditions are Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// publicKey is the key's SubjectPublicKeyInfo, PEM.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	PublicKey string `json:"publicKey,omitempty"`

	// fingerprint is the key's key-sha256 fingerprint.
	// +optional
	// +kubebuilder:validation:Pattern=`^key-sha256:[0-9a-f]{64}$`
	Fingerprint string `json:"fingerprint,omitempty"`

	// observedGeneration is the last generation reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:JSONPath=".status.fingerprint",name="Fingerprint",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.retireAt",name="Retire At",type=date
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Ready')].status",name="Ready",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ServerKey is a key the Provider-side presents in the Inner TLS, pinned by
// the PM-side. provider-gateway generates it (ECDSA P-256) on first
// reconcile and never replaces it: a different key is a new ServerKey.
type ServerKey struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec controls the key's retirement
	// +optional
	Spec ServerKeySpec `json:"spec,omitempty"`

	// status holds the public key
	// +optional
	Status ServerKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServerKeyList contains a list of ServerKey
type ServerKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServerKey `json:"items"`
}

func (k *ServerKey) GetConditions() []metav1.Condition { return k.Status.Conditions }

func (k *ServerKey) SetConditions(conditions []metav1.Condition) { k.Status.Conditions = conditions }
