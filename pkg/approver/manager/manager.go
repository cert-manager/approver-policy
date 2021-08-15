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
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

// Interface is a approver manager that responsible for evaluating whether
// incoming CertificateRequests should be approved or denied, checking
// CertificateRequestPolicys against approvers that have been registered.
// Policies will be chosen based on their suitability for a particular request,
// namely whether they are bound to a policy via RBAC.
type Interface interface {
	// Review will evaluate whether the incoming CertificateRequest should be
	// approved or denied.
	// - Consumers should consider a true response meaning the CertificateRequest
	//   is **approved**.
	// - Consumers should consider a false response and no error to mean the
	//   CertificateRequest is **denied**.
	// - Consumers should treat any error response as marking the
	//   CertificateRequest as neither approved nor denied, and may consider
	//   re-evaluation at a later time.
	Review(ctx context.Context, cr *cmapi.CertificateRequest) (bool, string, error)
}
