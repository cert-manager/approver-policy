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

package manager

import (
	"fmt"
)

// PolicyMessage is a string that gives context as to why the policy manager
// made the decision to either approve, deny, or do nothing when evaluating a
// request.
type PolicyMessage string

func (p PolicyMessage) String() string {
	return string(p)
}

const (
	// MessageRejection indicates that the policy evaluation was successfully
	// executed however the policy rejected the request.
	MessageRejection PolicyMessage = "Evaluation rejection"

	// MessageError indicates that there was an error when trying to execute the
	// policy evaluation itself. The manager may attempt the same evaluation at
	// another time.
	MessageError PolicyMessage = "Evaluation error"

	// MessageNoExistingCertificateRequestPolicy indicates that there are no
	// policies currently installed within the cluster.
	MessageNoExistingCertificateRequestPolicy PolicyMessage = "No CertificateRequestPolicies exist"

	// MessageNoApplicableCertificateRequestPolicy indicates that there are no
	// existing CertificateRequestPolicies which are suitable to evaluate the
	// request, even though policies do exist.
	MessageNoApplicableCertificateRequestPolicy PolicyMessage = "No CertificateRequestPolicies bound or applicable"
)

func approvedMessage(policyName string) PolicyMessage {
	return PolicyMessage(fmt.Sprintf("Approved by CertificateRequestPolicy %q", policyName))
}

func deniedMessage(policyErrors map[string]string) PolicyMessage {
	return PolicyMessage(fmt.Sprintf("No policy approved this request: %v", policyErrors))
}
