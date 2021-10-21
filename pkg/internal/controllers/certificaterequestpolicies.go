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

package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// certificaterequestpolicies is a controller-runtime Reconciler which handles
// the status of CertificateRequestPolicies. Status if built by approver
// Reconcilers determining the readiness.
type certificaterequestpolicies struct {
	// log is logger for the certificaterequestpolicies controller.
	log logr.Logger

	// clock returns time which can be overwritten for testing.
	clock clock.Clock

	// recorder is used for creating Kubernetes events on resources.
	recorder record.EventRecorder

	// client is a Kubernetes REST client to interact with objects in the API
	// server.
	client client.Client

	// lister makes requests to the informer cache for getting and listing
	// objects.
	lister client.Reader

	// reconcilers is the set of approver Reconcilers that are responsible for
	// building the Ready status conditions of CertificateRequestPolicies.
	// CertificateRequestPolicies that are not in a Ready state will not be used
	// to evaluate.
	reconcilers []approver.Reconciler
}

// addCertificateRequestPolicyController will register the
// certificaterequestpolicies controller with the controller-runtime Manager.
func addCertificateRequestPolicyController(ctx context.Context, opts Options) error {
	return ctrl.NewControllerManagedBy(opts.Manager).
		For(new(policyapi.CertificateRequestPolicy)).
		Complete(&certificaterequestpolicies{
			log:         opts.Log.WithName("certificaterequestpolicies"),
			clock:       clock.RealClock{},
			recorder:    opts.Manager.GetEventRecorderFor("policy.cert-manager.io"),
			client:      opts.Manager.GetClient(),
			lister:      opts.Manager.GetCache(),
			reconcilers: opts.Reconcilers,
		})
}

// Reconcile is the top level function for reconciling over synced
// CertificateRequestPolicies.
// Reconcile will be called whenever a CertificateRequestPolicy event happens.
// This function will call each approver Reconciler to build the Ready state of
// CertificateRequestPolicies.
func (c *certificaterequestpolicies) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("name", req.NamespacedName.Name)
	log.V(2).Info("syncing")

	policy := new(policyapi.CertificateRequestPolicy)
	if err := c.lister.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var (
		// Capture result so we can return Reconcile with correct requeue options.
		result ctrl.Result

		ready = true
		el    field.ErrorList
	)

	// Capture the ready response from each Reconciler.
	for _, reconciler := range c.reconcilers {
		response, err := reconciler.Ready(ctx, policy)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to evaluate ready state of CertificateRequestPolicy %q: %w",
				req.NamespacedName.Name, err)
		}

		// If any response is not ready, set ready to false.
		if !response.Ready {
			ready = false
		}

		// Capture requeue. If requeue is not currently set or the given
		// requeueAfter is smaller than the current, set to given requeueAfter.
		if response.Requeue || response.RequeueAfter > 0 {
			if !result.Requeue || result.RequeueAfter > response.RequeueAfter {
				result.RequeueAfter = response.RequeueAfter
			}
			result.Requeue = true
		}

		el = append(el, response.Errors...)
	}

	log = log.WithValues("ready", ready)

	var (
		status    corev1.ConditionStatus
		eventtype string
		reason    string
		message   string
	)

	if ready {
		status = corev1.ConditionTrue
		eventtype = corev1.EventTypeNormal
		reason = "Ready"
		message = "CertificateRequestPolicy is ready for approval evaluation"
	} else {
		status = corev1.ConditionFalse
		eventtype = corev1.EventTypeWarning
		reason = "NotReady"
		message = "CertificateRequestPolicy is not ready for approval evaluation"
		if len(el) > 0 {
			message = fmt.Sprintf("%s: %s", message, el.ToAggregate().Error())
			log = log.WithValues("errors", el.ToAggregate().Error())
		}
	}

	needsUpdate := c.setCertificateRequestPolicyCondition(policy, policyapi.CertificateRequestPolicyCondition{
		Type:    policyapi.CertificateRequestPolicyConditionReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	})

	log.V(2).Info("successfully synced")
	c.recorder.Event(policy, eventtype, reason, message)

	if needsUpdate {
		log.Info("updating ready condition status")
		return result, c.client.Status().Update(ctx, policy)
	}

	return result, nil
}

// setCertificateRequestPolicyCondition updates the CertificateRequestPolicy
// object with the given condition.
// Will overwrite any existing condition of the same type.
// ObservedGeneration of the condition will be set to the Generation of the
// CertificateRequestPolicy object.
// LastTransitionTime will not be updated if an existing condition of the same
// Type and Status already exists.
// Returns true if the condition has been updated or an existing condition has
// been updated. Returns false otherwise.
func (c *certificaterequestpolicies) setCertificateRequestPolicyCondition(policy *policyapi.CertificateRequestPolicy, condition policyapi.CertificateRequestPolicyCondition) bool {
	condition.LastTransitionTime = &metav1.Time{Time: c.clock.Now()}
	condition.ObservedGeneration = policy.Generation

	var updatedConditions []policyapi.CertificateRequestPolicyCondition
	for _, existingCondition := range policy.Status.Conditions {
		// Ignore any existing conditions which don't match the incoming type and
		// add back to set.
		if existingCondition.Type != condition.Type {
			updatedConditions = append(updatedConditions, existingCondition)
			continue
		}

		// If the status is the same, don't modify the last transaction time.
		if existingCondition.Status == condition.Status {
			condition.LastTransitionTime = existingCondition.LastTransitionTime
		}

		// If the condition hasn't changed the nreturn false early, signalling that
		// an update is not required.
		if apiequality.Semantic.DeepEqual(existingCondition, condition) {
			return false
		}
	}

	policy.Status.Conditions = append(updatedConditions, condition)

	return true
}
