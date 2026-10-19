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

// Package v1alpha1 contains the SDK's kinds: Connection, OnboardingToken and
// ServerKey, in the Provider's own cluster. They're the only source of truth
// for the Provider-side's state.
// +kubebuilder:object:generate=true
// +groupName=provider-sdk.platform-mesh.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// GroupName is the API group of the SDK's kinds.
	GroupName = "provider-sdk.platform-mesh.io"

	// GroupVersion is their version. It describes stored objects and is
	// independent of the protocol version.
	GroupVersion = "v1alpha1"
)

var (
	// SchemeBuilder registers the kinds.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the kinds to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme

	// SchemeGroupVersion is the group version of the kinds.
	SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: GroupVersion}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Connection{},
		&ConnectionList{},
		&OnboardingToken{},
		&OnboardingTokenList{},
		&ServerKey{},
		&ServerKeyList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
