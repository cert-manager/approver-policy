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
	"testing"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2/klogr"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
)

func Test_validatorHandle(t *testing.T) {
	tests := map[string]struct {
		req               admission.Request
		webhook           approver.Webhook
		expResp           admission.Response
		registeredPlugins []string
	}{
		"a request with no kind sent should return an Error response": {
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:       types.UID("abc"),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "NotCertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
}
`),
					},
				},
			},

			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "no resource kind sent in request", Code: 400},
				},
			},
		},
		"a resource who's type is not recognised should return a Denied response": {
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "NotCertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
	"apiVersion": "policy.cert-manager.io/v1alpha1",
	 "kind": "NotCertificateRequestPolicy",
	 "metadata": {
	 	"name": "testing"
	 },
}
		`),
					},
				},
			},

			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Reason: "validation request for unrecognised resource type: policy.cert-manager.io/v1alpha1 NotCertificateRequestPolicy", Code: 403},
				},
			},
		},
		"a CertificateRequestPolicy that fails to decode should return an Error response": {
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
	  "foo": "bar",
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "couldn't get version/kind; json parse error: invalid character '}' looking for beginning of object key string", Code: 400},
				},
			},
		},
		"a CertificateRequestPolicy which fails validation should return a Denied response": {
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{
					Allowed: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("hello-world"), "this is a denied message")},
				}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
		"selector": {
		  "issuerRef": {}
		}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Reason: "hello-world: Forbidden: this is a denied message", Code: 403},
				},
			},
		},
		"a CertificateRequestPolicy which succeeds validation should return an Allowed response": {
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{Allowed: true}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
		"selector": {
		  "issuerRef": {}
		}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result:  &metav1.Status{Reason: "CertificateRequestPolicy validated", Code: 200},
				},
			},
		},
		"a CertificateRequestPolicy where a webhook returns an error should return an internal error response": {
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{}, errors.New("this is an internal error")
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
		"selector": {
		  "issuerRef": {}
		}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "this is an internal error", Code: 500},
				},
			},
		},
		"a CertificateRequestPolicy whose issuerRef selector has not been defined should return 403": {
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{Allowed: true}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
		"selector": {}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Reason: "spec.selector.issuerRef: Required value: must be defined, hint: `{}` matches everything", Code: 403},
				},
			},
		},
		"a CertificateRequestPolicy whose defined plugins have not been registered and issuerRef selector not defined should return a 403": {
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{Allowed: true}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
	  "plugins": {
			"plugin-1": {},
			"plugin-2": {},
			"plugin-3": {}
		},
		"selector": {}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Reason: "[spec.plugins: Unsupported value: \"plugin-1\", spec.plugins: Unsupported value: \"plugin-2\", spec.plugins: Unsupported value: \"plugin-3\", spec.selector.issuerRef: Required value: must be defined, hint: `{}` matches everything]", Code: 403},
				},
			},
		},
		"a CertificateRequestPolicy whose some of the defined plugins have not been registered and issuerRef selector not defined should return a 403": {
			registeredPlugins: []string{"plugin-1", "plugin-2"},
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{Allowed: true}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
	  "plugins": {
			"plugin-1": {},
			"plugin-2": {},
			"plugin-3": {},
			"plugin-4": {}
		},
		"selector": {}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Reason: "[spec.plugins: Unsupported value: \"plugin-3\": supported values: \"plugin-1\", \"plugin-2\", spec.plugins: Unsupported value: \"plugin-4\": supported values: \"plugin-1\", \"plugin-2\", spec.selector.issuerRef: Required value: must be defined, hint: `{}` matches everything]", Code: 403},
				},
			},
		},
		"a CertificateRequestPolicy where all plugins used are registered with a valid issuerRef selector should return Allowed": {
			registeredPlugins: []string{"plugin-1", "plugin-2"},
			webhook: fake.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
				return approver.WebhookValidationResponse{Allowed: true}, nil
			}),
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID: types.UID("abc"),
					RequestKind: &metav1.GroupVersionKind{
						Group:   "policy.cert-manager.io",
						Version: "v1alpha1",
						Kind:    "CertificateRequestPolicy",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`
{
 "apiVersion": "policy.cert-manager.io/v1alpha1",
	"kind": "CertificateRequestPolicy",
	"metadata": {
		"name": "testing"
	},
	"spec": {
	  "plugins": {
			"plugin-1": {},
			"plugin-2": {}
		},
		"selector": {
		  "issuerRef": {
			  "name": "foo-bar"
			}
		}
	}
}
`),
					},
				},
			},
			expResp: admission.Response{
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result:  &metav1.Status{Reason: "CertificateRequestPolicy validated", Code: 200},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				Build()

			decoder, err := admission.NewDecoder(policyapi.GlobalScheme)
			if err != nil {
				t.Fatal(err)
			}

			v := &validator{lister: fakeclient, decoder: decoder, log: klogr.New(), webhooks: []approver.Webhook{test.webhook}, registeredPlugins: test.registeredPlugins}
			assert.Equal(t, test.expResp, v.Handle(context.TODO(), test.req), "expected the same admission response")
		})
	}
}
