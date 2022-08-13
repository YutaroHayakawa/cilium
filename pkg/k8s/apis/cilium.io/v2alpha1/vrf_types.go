//  Copyright 2022 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumvrf},singular="ciliumvrf",path="ciliumvrfs",scope="Cluster",shortName={cvrf}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumVRF is a Kubernetes third-party resource for instructing
// Cilium's VRF.
type CiliumVRF struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human readable description of a VRF
	//
	// +kubebuilder:validation:Required
	Spec CiliumVRFSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumVRFList is a list of CiliumVRF objects.
type CiliumVRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumVRF.
	Items []CiliumVRF `json:"items"`
}

type CiliumVRFSpec struct {
	// TableID specifies ID of the underlying routing table that
	// VRF uses.
	//
	// +kubebuilder:validation:Required
	TableID uint32 `json:"tableID"`
	// PodSelector selects a group of Pods belong to this VRF
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimmetav1.LabelSelector `json:"podSelector"`
}
