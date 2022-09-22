/*
Copyright 2021 The cert-manager Authors.

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
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/cert-manager/approver-policy/pkg/apis/policy"
)

// SchemeGroupVersion is group version used to register these objects
// +k8s:deepcopy-gen=false
var SchemeGroupVersion = schema.GroupVersion{Group: policy.GroupName, Version: "v1alpha1"}

var (
	// +k8s:deepcopy-gen=false
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	// +k8s:deepcopy-gen=false
	AddToScheme = localSchemeBuilder.AddToScheme

	// +k8s:deepcopy-gen=false
	GlobalScheme *runtime.Scheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)

	GlobalScheme = runtime.NewScheme()
	if err := scheme.AddToScheme(GlobalScheme); err != nil {
		panic(fmt.Sprintf("failed to add k8s.io scheme: %s", err))
	}
	if err := cmapi.AddToScheme(GlobalScheme); err != nil {
		panic(fmt.Sprintf("failed to add cert-manager.io scheme: %s", err))
	}
	if err := AddToScheme(GlobalScheme); err != nil {
		panic(fmt.Sprintf("failed to add policy.cert-manager.io scheme: %s", err))
	}
}

// Adds the list of known types to api.Scheme.
// +k8s:deepcopy-gen=false
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CertificateRequestPolicy{},
		&CertificateRequestPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
