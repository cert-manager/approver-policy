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
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/cert-manager/policy-approver/internal/pkg/evaluator"
)

// Options hold options for the Policy controller.
type Options struct {
	// Log is the Policy controller logger.
	Log logr.Logger

	// Manager is the policy manager which is responsible for evaluating
	// CertificateRequests against relevant policies using registered evaluators.
	Manager *evaluator.Manager
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

	// manager is a evaluator manager responsible for evaluating whether a
	// CertificateRequest should be approved or denied
	manager *evaluator.Manager
}

// AddPolicyController will register the Policy controller with the
// controller-runtime Manager.
func AddPolicyController(mgr manager.Manager, opts Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(new(cmapi.CertificateRequest)).
		Complete(&controller{
			log:      opts.Log.WithName("controller"),
			recorder: mgr.GetEventRecorderFor("policy.cert-manager.io"),
			client:   mgr.GetClient(),
			lister:   mgr.GetCache(),
			manager:  opts.Manager,
		})
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CertificateRequestPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.2/pkg/reconcile
func (c *controller) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("certificaterequestpolicy", req.NamespacedName)
	log.Info("reconciling")

	cr := new(cmapi.CertificateRequest)
	if err := c.lister.Get(ctx, req.NamespacedName, cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if apiutil.CertificateRequestIsApproved(cr) || apiutil.CertificateRequestIsDenied(cr) {
		return ctrl.Result{}, nil
	}

	ok, reason, err := c.manager.Evaluate(ctx, cr)
	if err != nil {
		return ctrl.Result{}, err
	}

	if ok {
		c.recorder.Event(cr, corev1.EventTypeNormal, "Approved", reason.String())
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "policy.cert-manager.io", reason.String())
	} else {
		c.recorder.Event(cr, corev1.EventTypeWarning, "Denied", reason.String())
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "policy.cert-manager.io", reason.String())
	}

	if err := c.client.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
