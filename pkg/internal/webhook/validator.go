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

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/cert-manager/policy-approver/pkg/apis/policy"
	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// validator validates against policy.cert-manager.io resources.
type validator struct {
	lock sync.RWMutex
	log  logr.Logger

	webhooks []approver.Webhook

	lister  client.Reader
	decoder *admission.Decoder
}

// Handle is a Kubernetes validation webhook server handler. Returns an
// admission response containing whether the request is allowed or not.
func (v *validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := v.log.WithValues("name", req.Name)
	log.V(2).Info("received validation request")

	if req.RequestKind == nil {
		return admission.Errored(http.StatusBadRequest, errors.New("no resource kind sent in request"))
	}

	switch *req.RequestKind {
	case metav1.GroupVersionKind{Group: policy.GroupName, Version: "v1alpha1", Kind: "CertificateRequestPolicy"}:
		var policy policyapi.CertificateRequestPolicy

		v.lock.RLock()
		err := v.decoder.Decode(req, &policy)
		v.lock.RUnlock()

		if err != nil {
			log.Error(err, "failed to decode CertificateRequestPolicy")
			return admission.Errored(http.StatusBadRequest, err)
		}

		var (
			errs    []string
			allowed = true
		)
		for _, webhook := range v.webhooks {
			response, err := webhook.Validate(ctx, &policy)
			if err != nil {
				log.Error(err, "internal error occurred validating request")
				return admission.Errored(http.StatusInternalServerError, err)
			}
			if !response.Allowed {
				allowed = false
				errs = append(errs, response.Message)
			}
		}

		if !allowed {
			err := strings.Join(errs, ", ")
			v.log.V(2).Info("denied request", "reason", err)
			return admission.Denied(err)
		}

		log.V(2).Info("allowed request")
		return admission.Allowed("CertificateRequestPolicy validated")

	default:
		return admission.Denied(fmt.Sprintf("validation request for unrecognised resource type: %s/%s %s", req.RequestKind.Group, req.RequestKind.Version, req.RequestKind.Kind))
	}
}

// InjectDecoder is used by the controller-runtime manager to inject an object
// decoder to convert into know policy.cert-manager.io types.
func (v *validator) InjectDecoder(d *admission.Decoder) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.decoder = d
	return nil
}

// check is used by the shared readiness manager to expose whether the server
// is ready.
func (v *validator) check(_ *http.Request) error {
	v.lock.RLock()
	defer v.lock.RUnlock()

	if v.decoder != nil {
		return nil
	}

	return errors.New("not ready")
}
