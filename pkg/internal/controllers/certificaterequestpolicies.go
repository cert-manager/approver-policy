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
	"reflect"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/internal/controllers/ssa_client"
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
func addCertificateRequestPolicyController(_ context.Context, opts Options) error {
	log := opts.Log.WithName("certificaterequestpolicies")
	genericChan := make(chan event.GenericEvent)

	// We use reflect.SelectCase along with reflect.Select as this allows us to
	// conveniently select on an arbitrary number of enqueueChans.
	var enqueueListSelect []reflect.SelectCase
	for _, reconciler := range opts.Reconcilers {
		if enqueueChan := reconciler.EnqueueChan(); enqueueChan != nil {
			enqueueListSelect = append(enqueueListSelect, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(enqueueChan)})
		}
	}

	// Only setup generic event triggers if at least one Reconciler gave an
	// enqueue channel.
	if len(enqueueListSelect) > 0 {
		if err := opts.Manager.Add(manager.RunnableFunc(func(ctx context.Context) error {
			enqueueListSelect = append(enqueueListSelect, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())})

			for {
				chosen, val, ok := reflect.Select(enqueueListSelect)
				if !ok {
					// Context is always the last index in the slice. Check if the
					// context has been cancelled, and exit go routine if so.
					if chosen == len(enqueueListSelect)-1 {
						log.Info("closing certificaterequestpolicy enqueue event watcher")
						return nil
					}
					enqueueListSelect[chosen].Chan = reflect.ValueOf(nil)
					continue
				}
				// Send a message to the generic channel to cause a sync by the
				// CertificateRequestPolicy controller.
				select {
				case <-ctx.Done():
					return nil
				case genericChan <- event.GenericEvent{Object: &policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: val.String()}}}:
					// Continue with loop
				}
			}
		})); err != nil {
			return fmt.Errorf("failed to add CertificateRequestPolicy generic event watcher: %w", err)
		}
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		For(new(policyapi.CertificateRequestPolicy)).
		WatchesRawSource(source.Channel(genericChan, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				log.Info("reconciling certificaterequestpolicy after receiving event message", "name", obj.GetName())
				return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: obj.GetName()}}}
			},
		))).
		Complete(&certificaterequestpolicies{
			log:         log,
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
	result, patch, resultErr := c.reconcileStatusPatch(ctx, req)
	if patch != nil {
		crp, patch, err := ssa_client.GenerateCertificateRequestPolicyStatusPatch(req.Name, patch)
		if err != nil {
			err = fmt.Errorf("failed to generate CertificateRequestPolicy.Status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}

		if err := c.client.Status().Patch(ctx, crp, patch, &client.SubResourcePatchOptions{
			PatchOptions: client.PatchOptions{
				FieldManager: "approver-policy",
				Force:        ptr.To(true),
			},
		}); err != nil {
			err = fmt.Errorf("failed to apply CertificateRequestPolicy.Status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}
	}

	return result, resultErr
}

func (c *certificaterequestpolicies) reconcileStatusPatch(ctx context.Context, req ctrl.Request) (ctrl.Result, *policyapi.CertificateRequestPolicyStatus, error) {
	log := c.log.WithValues("name", req.NamespacedName.Name)
	log.V(2).Info("syncing")

	policy := new(policyapi.CertificateRequestPolicy)
	if err := c.lister.Get(ctx, req.NamespacedName, policy); err != nil {
		return reconcile.Result{}, nil, client.IgnoreNotFound(err)
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
			return reconcile.Result{}, nil, fmt.Errorf("failed to evaluate ready state of CertificateRequestPolicy %q: %w", req.NamespacedName.Name, err)
		}

		// If any response is not ready, set ready to false.
		if !response.Ready {
			ready = false
		}

		// Capture requeue. If requeue is not currently set or the given
		// requeueAfter is smaller than the current, set to given requeueAfter.
		if response.RequeueAfter > 0 {
			if result.RequeueAfter == 0 || result.RequeueAfter > response.RequeueAfter {
				result.RequeueAfter = response.RequeueAfter
			}
		}

		el = append(el, response.Errors...)
	}

	log = log.WithValues("ready", ready)

	policyPatch := &policyapi.CertificateRequestPolicyStatus{}

	if !ready {
		log.V(2).Info("NOT ready for approval evaluation", "errors", el.ToAggregate())

		message := fmt.Sprintf("CertificateRequestPolicy is not ready for approval evaluation: %s", el.ToAggregate())
		c.recorder.Event(policy, corev1.EventTypeWarning, "NotReady", message)

		c.setCertificateRequestPolicyCondition(
			policy.Status.Conditions,
			&policyPatch.Conditions,
			policy.Generation,
			policyapi.CertificateRequestPolicyCondition{
				Type:    policyapi.CertificateRequestPolicyConditionReady,
				Status:  metav1.ConditionFalse,
				Reason:  "NotReady",
				Message: message,
			},
		)

		return result, policyPatch, nil
	}

	log.V(2).Info("ready for approval evaluation")

	message := "CertificateRequestPolicy is ready for approval evaluation"
	c.recorder.Event(policy, corev1.EventTypeNormal, "Ready", message)

	c.setCertificateRequestPolicyCondition(
		policy.Status.Conditions,
		&policyPatch.Conditions,
		policy.Generation,
		policyapi.CertificateRequestPolicyCondition{
			Type:    policyapi.CertificateRequestPolicyConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "Ready",
			Message: message,
		},
	)

	return result, policyPatch, nil
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
func (c *certificaterequestpolicies) setCertificateRequestPolicyCondition(
	existingConditions []policyapi.CertificateRequestPolicyCondition,
	patchConditions *[]policyapi.CertificateRequestPolicyCondition,
	generation int64,
	newCondition policyapi.CertificateRequestPolicyCondition,
) {
	newCondition.LastTransitionTime = metav1.Time{Time: c.clock.Now()}
	newCondition.ObservedGeneration = generation

	for _, existingCondition := range existingConditions {
		// Skip unrelated conditions
		if existingCondition.Type != newCondition.Type {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if existingCondition.Status == newCondition.Status {
			newCondition.LastTransitionTime = existingCondition.LastTransitionTime
		}
	}

	// Search through existing conditions
	for idx, patchCondition := range *patchConditions {
		// Skip unrelated conditions
		if patchCondition.Type != newCondition.Type {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if patchCondition.Status == newCondition.Status {
			newCondition.LastTransitionTime = patchCondition.LastTransitionTime
		}

		// Overwrite the existing condition
		(*patchConditions)[idx] = newCondition

		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	*patchConditions = append(*patchConditions, newCondition)
}
