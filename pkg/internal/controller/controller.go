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

package controller

import (
	"context"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmgr "sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/cert-manager/policy-approver/pkg/approver/manager"
	"github.com/cert-manager/policy-approver/pkg/registry"
)

// Options hold options for the policy-approver controller.
type Options struct {
	// Log is the Policy controller logger.
	Log logr.Logger
}

// controller is a controller-runtime Controller which evaluates whether
// reconciled CertificateRequests should be Approved or Denied based on
// registered policy evaluators.
type controller struct {
	// log is a shared logger for the policy controller.
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

// AddPolicyController will register the Policy controller with the
// controller-runtime Manager.
func AddPolicyController(mgr ctrlmgr.Manager, opts Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(new(cmapi.CertificateRequest)).
		Complete(&controller{
			log:      opts.Log.WithName("controller").WithName("policy"),
			recorder: mgr.GetEventRecorderFor("policy.cert-manager.io"),
			client:   mgr.GetClient(),
			lister:   mgr.GetCache(),
			manager:  manager.NewSubjectAccessReview(mgr.GetClient(), registry.Shared.Evaluators()),
		})
}

// Reconcile is the top level function for reconciling over synced
// CertificateRequests.
// Reconcile will be called whenever a CertificateRequest event happens. This
// func will call the evaluator manager to evaluate whether a
// CertificateRequest should be approved, denied, or left alone.
func (c *controller) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("certificaterequest", req.NamespacedName.Name)
	log.V(2).Info("syncing certificaterequest")

	cr := new(cmapi.CertificateRequest)
	if err := c.lister.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If the CertificateRequest has already been approved or denied, we
	// can ignore.
	if apiutil.CertificateRequestIsApproved(cr) || apiutil.CertificateRequestIsDenied(cr) {
		log.V(2).Info("request has already been approved or denied, ignoring")
		return ctrl.Result{}, nil
	}

	// Pass nil here as the policy object since the controller evaluator is
	// expected to handle gathering the applicable evaluators for this request.
	ok, message, err := c.manager.Review(ctx, cr)
	if err != nil {
		// If an error occurs when evaluating, we fire an event on the
		// CertificateRequest and return err to try again.
		c.recorder.Eventf(cr, corev1.EventTypeWarning, "EvaluationError", "%s: %s", message, err)
		return ctrl.Result{}, err
	}

	if ok {
		c.recorder.Event(cr, corev1.EventTypeNormal, "Approved", message)
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "policy.cert-manager.io", message)
	} else {
		c.recorder.Event(cr, corev1.EventTypeWarning, "Denied", message)
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "policy.cert-manager.io", message)
	}

	if err := c.client.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}