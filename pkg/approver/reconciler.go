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

package approver

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

// ReconcilerReadyResponse is the response to this Reconciler evaluating
// whether the CertificateRequestPolicy is in a Ready state.
type ReconcilerReadyResponse struct {
	// Ready defines whether this Reconciler considers this
	// CertificateRequestPolicy to be in a ready state.
	Ready bool

	// Errors are list of errors that give context as to why the Ready field is
	// set to false. Only considered if Ready is set to false.
	Errors field.ErrorList

	// Result may be used by Reconciles to signal that the
	// CertificateRequestPolicies' status should be reconciled again and in what
	// duration into the future.
	// The CertificateRequestPolicy may be reconciled again sooner, but never
	// later than the RequeueAfter duration.
	// RequeueAfter is ignored if Request is false.
	ctrl.Result
}

// Reconciler is responsible for reconciling CertificateRequestPolicies and
// declaring what state they should be in.
type Reconciler interface {
	// Ready declares whether the CertificateRequestPolicy is in a Ready state
	// according to this Reconciler.
	// ReconcilerReadyResponse should be returned if Ready executed successfully
	// and should report the what the Ready status condition should be according
	// to this Reconciler.
	// A returned error means that there was an error when trying to evaluate the
	// Ready state. A returned error will have Ready be retried.
	Ready(context.Context, *policyapi.CertificateRequestPolicy) (ReconcilerReadyResponse, error)
}
