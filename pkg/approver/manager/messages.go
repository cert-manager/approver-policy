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

const (
	// MessageRejection indicates that the review was successfully executed
	// however the policy rejected the request.
	MessageRejection = "Evaluation rejection"

	// MessageError indicates that there was an error when trying to review the
	// policy evaluation itself. The manager may attempt the same review at
	// another time.
	MessageError = "Evaluation error"

	// MessageNoExistingCertificateRequestPolicy indicates that there are no
	// policies currently installed within the cluster.
	MessageNoExistingCertificateRequestPolicy = "No CertificateRequestPolicies exist"

	// MessageNoApplicableCertificateRequestPolicy indicates that there are no
	// existing CertificateRequestPolicies which are suitable to review the
	// request, even though policies do exist.
	MessageNoApplicableCertificateRequestPolicy = "No CertificateRequestPolicies bound or applicable"
)

func approvedMessage(policyName string) string {
	return fmt.Sprintf("Approved by CertificateRequestPolicy %q", policyName)
}

func deniedMessage(policyErrors map[string]string) string {
	return fmt.Sprintf("No policy approved this request: %v", policyErrors)
}
