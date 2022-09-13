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
	"errors"
	"os"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver/manager"
	internalmanager "github.com/cert-manager/approver-policy/pkg/internal/approver/manager"
)

// certificaterequests is a controller-runtime Reconciler which evaluates
// whether reconciled CertificateRequests should be Approved or Denied based on
// registered policy evaluators.
type certificaterequests struct {
	// log is logger for the certificaterequests controller.
	log logr.Logger

	// recorder is used for creating Kubernetes events on resources.
	recorder record.EventRecorder

	// client is a Kubernetes REST client to interact with objects in the API
	// server.
	client client.Client

	// lister makes requests to the informer cache for getting and listing
	// objects.
	lister client.Reader

	// manager is a Manager that is responsible for reviewing whether a
	// CertificateRequest should be approved or denied. This manager is expected
	// to manage all approvers which have been registered and active for this
	// controller.
	manager manager.Interface
}

// addCertificateRequestController will register the certificaterequests
// controller with the controller-runtime Manager.
func addCertificateRequestController(ctx context.Context, opts Options) error {
	c := &certificaterequests{
		log:      opts.Log.WithName("certificaterequests"),
		recorder: opts.Manager.GetEventRecorderFor("policy.cert-manager.io"),
		client:   opts.Manager.GetClient(),
		lister:   opts.Manager.GetCache(),
		manager:  internalmanager.New(opts.Manager.GetCache(), opts.Manager.GetClient(), opts.Evaluators),
	}

	enqueueRequestFromMapFunc := func(_ client.Object) []reconcile.Request {
		// If an error happens here and we do nothing, we run the risk of not
		// processing CertificateRequests.
		// Exiting error is the safest option, as it will force a resync on all
		// CertificateRequests on start.
		var crList cmapi.CertificateRequestList
		if err := c.lister.List(ctx, &crList); err != nil {
			c.log.Error(err, "failed to list all CertificateRequests, exiting error")
			os.Exit(-1)
		}

		var requests []reconcile.Request
		for _, cr := range crList.Items {
			// Check for approval status early, rather than relying on the
			// predicate or doing it in the actual Reconcile func.
			if apiutil.CertificateRequestIsApproved(&cr) || apiutil.CertificateRequestIsDenied(&cr) {
				continue
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name}},
			)
		}

		return requests
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		For(new(cmapi.CertificateRequest), builder.WithPredicates(
			// Only process CertificateRequests which have not yet got an approval
			// status.
			predicate.NewPredicateFuncs(func(obj client.Object) bool {
				cr := obj.(*cmapi.CertificateRequest)
				return !apiutil.CertificateRequestIsApproved(cr) && !apiutil.CertificateRequestIsDenied(cr)
			}),
		)).

		// Watch CertificateRequestPolicies. If a policy is created or updated,
		// then we need to process all CertificateRequests that do not yet have an
		// approved or denied condition since they may be relevant for the policy.
		Watches(&source.Kind{Type: new(policyapi.CertificateRequestPolicy)}, handler.EnqueueRequestsFromMapFunc(enqueueRequestFromMapFunc)).

		// Watch Roles, RoleBindings, ClusterRoles, and ClusterRoleBindings. If
		// RBAC changes in the cluster then CertificateRequestPolicies may become
		// appropriate for a CertificateRequest. On RBAC events, Reconcile all
		// CertificateRequests that are neither Approved or Denied.
		// Only need to cache metadata for RBAC resources since we do not need any
		// information in the spec.
		Watches(&source.Kind{Type: new(rbacv1.Role)}, handler.EnqueueRequestsFromMapFunc(enqueueRequestFromMapFunc), builder.OnlyMetadata).
		Watches(&source.Kind{Type: new(rbacv1.RoleBinding)}, handler.EnqueueRequestsFromMapFunc(enqueueRequestFromMapFunc), builder.OnlyMetadata).
		Watches(&source.Kind{Type: new(rbacv1.ClusterRole)}, handler.EnqueueRequestsFromMapFunc(enqueueRequestFromMapFunc), builder.OnlyMetadata).
		Watches(&source.Kind{Type: new(rbacv1.ClusterRoleBinding)}, handler.EnqueueRequestsFromMapFunc(enqueueRequestFromMapFunc), builder.OnlyMetadata).

		// Complete the controller builder.
		Complete(c)
}

// Reconcile is the top level function for reconciling over synced
// CertificateRequests.
// Reconcile will be called whenever a CertificateRequest event happens. This
// function will call the approver manager to evaluate whether a
// CertificateRequest should be approved, denied, or left alone.
func (c *certificaterequests) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("namespace", req.NamespacedName.Namespace, "name", req.NamespacedName.Name)
	log.V(2).Info("syncing certificaterequest")

	cr := new(cmapi.CertificateRequest)
	if err := c.lister.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Query review on the approver manager.
	response, err := c.manager.Review(ctx, cr)
	if err != nil {
		// If an error occurs when evaluating, we fire an event on the
		// CertificateRequest and return err to try again.
		// Here we don't send the error context in the Kubernetes Event to protect
		// information about the approver configuration being exposed to the
		// client.
		c.recorder.Eventf(cr, corev1.EventTypeWarning, "EvaluationError", "approver-policy failed to review the request and will retry")
		return ctrl.Result{}, err
	}

	var event struct {
		eventtype string
		reason    string
	}
	switch response.Result {
	case manager.ResultApproved:
		log.V(2).Info("approving request")
		event.eventtype = corev1.EventTypeNormal
		event.reason = "Approved"
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "policy.cert-manager.io", response.Message)

	case manager.ResultDenied:
		log.V(2).Info("denying request")
		event.eventtype = corev1.EventTypeWarning
		event.reason = "Denied"
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "policy.cert-manager.io", response.Message)

	case manager.ResultUnprocessed:
		log.V(2).Info("request was unprocessed")
		c.recorder.Event(cr, corev1.EventTypeNormal, "Unprocessed", "Request is not applicable for any policy so ignoring")
		return ctrl.Result{}, nil

	default:
		log.Error(errors.New(response.Message), "manager responded with an unknown result", "result", response.Result)
		c.recorder.Event(cr, corev1.EventTypeWarning, "UnknownResponse", "Policy returned an unknown result. This is a bug. Please check the approver-policy logs and file an issue")

		// We can do nothing but keep retrying the review here.
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
	}

	if err := c.client.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}

	c.recorder.Event(cr, event.eventtype, event.reason, response.Message)

	return ctrl.Result{}, nil
}
