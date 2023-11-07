/*
Copyright 2023 The cert-manager Authors.

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

package ssa_client

import (
	"encoding/json"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type certificateRequestPolicyStatusStatusApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *policyapi.CertificateRequestPolicyStatus `json:"status,omitempty"`
}

func GenerateCertificateRequestPolicyStatusPatch(
	name, namespace string,
	status *policyapi.CertificateRequestPolicyStatus,
) (*policyapi.CertificateRequestPolicy, client.Patch, error) {
	// This object is used to deduce the name & namespace + unmarshall the return value in
	crp := &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}

	// This object is used to render the patch
	b := &certificateRequestPolicyStatusStatusApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
	}
	b.WithName(name)
	b.WithNamespace(namespace)
	b.WithKind(policyapi.CertificateRequestPolicyKind)
	b.WithAPIVersion(policyapi.SchemeGroupVersion.Identifier())
	b.Status = status

	encodedPatch, err := json.Marshal(b)
	if err != nil {
		return crp, nil, err
	}

	return crp, applyPatch{encodedPatch}, nil
}
