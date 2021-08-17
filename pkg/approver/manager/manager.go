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

// ReviewResult is the result from an approver manager reviewing a
// CertificateRequest.
type ReviewResult int

const (
	// ResultApproved is the result of a review where the manager approves the
	// request.
	ResultApproved ReviewResult = iota + 1

	// ResultDenied is the result of a review where the manager denies the
	// request.
	ResultDenied

	// ResultUnprocessed is the result of a review where the manager has deemed
	// that the request is not appropriate for any evaluators given the current
	// policy. It is neither approved or denied by the manager.
	ResultUnprocessed
)

// ReviewResponse is the response to an approver manager request review.
type ReviewResponse struct {
	// Result is the actionable result code from running the review.
	Result ReviewResult

	// Message is optional context as to why the manager has given the result it
	// has.
	Message string
}

// Interface is an Approver Manager that responsible for evaluating whether
// incoming CertificateRequests should be approved or denied, checking
// CertificateRequestPolicies against approvers that have been registered.
// Policies will be chosen based on their suitability for a particular request.
type Interface interface {
	// Review will evaluate whether the incoming CertificateRequest should be
	// approved, denied, or if the review was unprocessed.
	// - Consumers should consider a ResultApproved response to mean the
	//   CertificateRequest is **approved**.
	// - Consumers should consider a ResultDenied response to mean
	//   the CertificateRequest is **denied**.
	// - Consumers should consider a ResultUnprocessed response to mean the
	//   manager doesn't consider the request to be appropriate for any evaluator
	//   and so no review was run. The request is neither approved or denied.
	// - Consumers should treat any error response as marking the
	//   CertificateRequest as neither approved nor denied, and may consider
	//   re-evaluation at a later time.
	Review(ctx context.Context, cr *cmapi.CertificateRequest) (ReviewResponse, error)
}
