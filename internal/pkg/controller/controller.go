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

	"github.com/cert-manager/policy-approver/internal/pkg/manager"
)

type CRController struct {
	client.Client

	log logr.Logger

	recorder record.EventRecorder
	manager  *manager.Manager
}

func New(log logr.Logger, client client.Client, recorder record.EventRecorder, manager *manager.Manager) *CRController {
	return &CRController{
		Client:   client,
		log:      log.WithName("certificate-requests"),
		recorder: recorder,
		manager:  manager,
	}
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
func (c *CRController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("certificaterequestpolicy", req.NamespacedName)
	log.Info("reconciling")

	cr := new(cmapi.CertificateRequest)
	if err := c.Get(ctx, req.NamespacedName, cr); err != nil {
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

	if err := c.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (c *CRController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		//For(&policycertmanageriov1alpha1.CertificateRequestPolicy{}).
		For(&cmapi.CertificateRequest{}).
		Complete(c)
}
