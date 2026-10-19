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

// ConnectorCASetName is the name of the one ConnectorCASet.
const ConnectorCASetName = "default"

// ConnectorCASet conditions.
const (
	// ConnectorCASetConditionValid: the set isn't empty, and every trusted
	// certificate parses, is a CA, can sign and isn't expired.
	ConnectorCASetConditionValid = "Valid"
	// ConnectorCASetConditionConverged: every Connection platform-mesh-operator
	// reaches pins the current CA.
	ConnectorCASetConditionConverged = "Converged"
)

// ConnectorCASet reasons.
const (
	ConnectorCASetReasonPushing           = "Pushing"
	ConnectorCASetReasonDistrustUnmatched = "DistrustUnmatched"
)

// ConnectorCAState is a CA's state in the Connector CA Set.
// +kubebuilder:validation:Enum=Current;Previous;DistrustPending;Distrusted;Dropped
type ConnectorCAState string

const (
	// ConnectorCAStateCurrent: the current CA.
	ConnectorCAStateCurrent ConnectorCAState = "Current"
	// ConnectorCAStatePrevious: still in the set, until its drop time and the
	// leaf gate.
	ConnectorCAStatePrevious ConnectorCAState = "Previous"
	// ConnectorCAStateDistrustPending: distrusted, still in the set until its
	// gate is met.
	ConnectorCAStateDistrustPending ConnectorCAState = "DistrustPending"
	// ConnectorCAStateDistrusted: out of the set, never trusted again.
	ConnectorCAStateDistrusted ConnectorCAState = "Distrusted"
	// ConnectorCAStateDropped: out of the set after its drop time, still
	// unexpired.
	ConnectorCAStateDropped ConnectorCAState = "Dropped"
)

// DistrustResult is the outcome of a spec.distrust entry.
// +kubebuilder:validation:Enum=Pending;Applied;Unmatched
type DistrustResult string

const (
	DistrustResultPending   DistrustResult = "Pending"
	DistrustResultApplied   DistrustResult = "Applied"
	DistrustResultUnmatched DistrustResult = "Unmatched"
)

// ConnectorCASetSpec is written by PM Administrators.
type ConnectorCASetSpec struct {
	// distrust lists compromised Connector CAs by key. A distrusted CA is
	// dropped from every Connection and never trusted again.
	// +optional
	// +listType=map
	// +listMapKey=fingerprint
	// +kubebuilder:validation:MaxItems=32
	Distrust []ConnectorCADistrust `json:"distrust,omitempty"`
}

// ConnectorCADistrust distrusts one CA key.
type ConnectorCADistrust struct {
	// fingerprint is the CA's key-sha256 fingerprint.
	// +required
	// +kubebuilder:validation:Pattern=`^key-sha256:[0-9a-f]{64}$`
	Fingerprint string `json:"fingerprint"`

	// immediate drops the CA at once, without waiting for the new CA to
	// converge and every Connector to switch.
	// +optional
	Immediate bool `json:"immediate,omitempty"`
}

// ConnectorCASetStatus is derived on every reconcile; losing it costs
// nothing.
type ConnectorCASetStatus struct {
	// certificates are every unexpired Connector CA PM knows.
	// +optional
	// +listType=map
	// +listMapKey=certFingerprint
	// +kubebuilder:validation:MaxItems=64
	Certificates []ConnectorCAStatus `json:"certificates,omitempty"`

	// distrust has one result per spec.distrust entry.
	// +optional
	// +listType=map
	// +listMapKey=fingerprint
	// +kubebuilder:validation:MaxItems=32
	Distrust []ConnectorCADistrustStatus `json:"distrust,omitempty"`

	// conditions are Valid and Converged.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the last generation reconciled by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ConnectorCAStatus is one Connector CA.
type ConnectorCAStatus struct {
	// certFingerprint is the CA certificate's cert-sha256 fingerprint.
	CertFingerprint string `json:"certFingerprint"`

	// keyFingerprint is the CA key's key-sha256 fingerprint.
	KeyFingerprint string `json:"keyFingerprint"`

	// issued is when the CA's CertificateRequest became Ready.
	Issued metav1.Time `json:"issued"`

	// notAfter is when the CA certificate expires.
	NotAfter metav1.Time `json:"notAfter"`

	// state is the CA's state in the set.
	State ConnectorCAState `json:"state"`

	// distrust is set while the CA is distrusted.
	// +optional
	Distrust *ConnectorCADistrustProgress `json:"distrust,omitempty"`
}

// ConnectorCADistrustProgress shows how far a distrust has come.
type ConnectorCADistrustProgress struct {
	// since is when the distrust was first seen.
	Since metav1.Time `json:"since"`

	// waitingFor are the shards whose Connector Certificate still chains to
	// the CA.
	// +optional
	// +listType=set
	WaitingFor []string `json:"waitingFor,omitempty"`
}

// ConnectorCADistrustStatus is the result of one spec.distrust entry.
type ConnectorCADistrustStatus struct {
	// fingerprint is the entry's fingerprint.
	Fingerprint string `json:"fingerprint"`

	// result is Pending, Applied or Unmatched.
	Result DistrustResult `json:"result"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ccs
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the ConnectorCASet must be named default"
// +kubebuilder:printcolumn:JSONPath=".status.certificates[?(@.state=='Current')].keyFingerprint",name="Current",type=string,description="The current CA's key fingerprint"
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Converged')].status",name="Converged",type=string,description="Whether every reached Connection pins the current CA"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// ConnectorCASet represents the Connector CA Set, in PM's runtime cluster: the
// Connector CAs PM trusts and how far each has reached the Connections
// (status), and the CAs PM Administrators distrust (spec).
type ConnectorCASet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec holds the distrusted CAs
	// +optional
	Spec ConnectorCASetSpec `json:"spec,omitempty"`

	// status is derived from cert-manager's CertificateRequests
	// +optional
	Status ConnectorCASetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectorCASetList contains a list of ConnectorCASet
type ConnectorCASetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectorCASet `json:"items"`
}

func (s *ConnectorCASet) GetConditions() []metav1.Condition {
	return s.Status.Conditions
}

func (s *ConnectorCASet) SetConditions(conditions []metav1.Condition) {
	s.Status.Conditions = conditions
}
