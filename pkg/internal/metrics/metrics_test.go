/*
Copyright 2023 The cert-manager Authors.

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

package metrics

import (
	"context"
	"strings"
	"testing"

	crpapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Test_Metrics(t *testing.T) {
	t.Run("approved_count counts the CRs that have the Approved condition", func(t *testing.T) {
		mock := mockCollector(t, []runtime.Object{
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "baz", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
		})
		const expected = `
            # HELP approverpolicy_certificaterequest_approved_count Number of CertificateRequests that have been approved (Approved=True).
			# TYPE approverpolicy_certificaterequest_approved_count gauge
            approverpolicy_certificaterequest_approved_count{namespace="bar"} 2
            approverpolicy_certificaterequest_approved_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_approved_count")
		require.NoError(t, err)
	})

	t.Run("denied_count counts the CRs that have the Denied condition", func(t *testing.T) {
		mock := mockCollector(t, []runtime.Object{
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "baz", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
		})
		const expected = `
		# HELP approverpolicy_certificaterequest_denied_count Number of CertificateRequests that have been denied (Denied=True).
		# TYPE approverpolicy_certificaterequest_denied_count gauge
		approverpolicy_certificaterequest_denied_count{namespace="bar"} 2
		approverpolicy_certificaterequest_denied_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_denied_count")
		require.NoError(t, err)
	})

	t.Run("unmatched_count is only about CRs with no Approved and Denied condition", func(t *testing.T) {
		mock := mockCollector(t, []runtime.Object{
			// Three unmatched CRs.
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			// The three following CRs have been happily matched by an approver,
			// and the last one has been denied.
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo4", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo5", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			&cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo6", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
		})
		const expected = `
        	# HELP approverpolicy_certificaterequest_unmatched_count Number of CertificateRequests not matched to any policy, i.e., that don't have an Approved or Denied condition set yet.
        	# TYPE approverpolicy_certificaterequest_unmatched_count gauge
			approverpolicy_certificaterequest_unmatched_count{namespace="bar"} 2
            approverpolicy_certificaterequest_unmatched_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_unmatched_count")
		require.NoError(t, err)
	})

	t.Run("certificaterequestpolicy_status", func(t *testing.T) {
		mock := mockCollector(t, []runtime.Object{
			// Three unmatched CRs.
			&crpapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1"},
				Status: crpapi.CertificateRequestPolicyStatus{Conditions: []crpapi.CertificateRequestPolicyCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			&crpapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2"},
				Status: crpapi.CertificateRequestPolicyStatus{Conditions: []crpapi.CertificateRequestPolicyCondition{
					{Type: "Ready", Status: "True"},
				}},
			},
		})
		const expected = `
            # HELP approverpolicy_certificaterequestpolicy_status Status of the CertificateRequestPolicy resources.
            # TYPE approverpolicy_certificaterequestpolicy_status gauge
            approverpolicy_certificaterequestpolicy_status{name="foo1",ready_status="False"} 1
            approverpolicy_certificaterequestpolicy_status{name="foo2",ready_status="True"} 1
        `
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequestpolicy_status")
		require.NoError(t, err)
	})
}

func mockCollector(t *testing.T, objs []runtime.Object) *collector {
	return &collector{
		cache: &mockCache{t: t, objects: objs},
		ctx:   context.Background(),
		log:   logr.Discard(),
	}
}

type mockCache struct {
	t       *testing.T
	objects []runtime.Object
}

// The only two functions we care about are WaitForCacheSync and List.
func (mock *mockCache) WaitForCacheSync(ctx context.Context) bool {
	return true
}
func (mock *mockCache) List(ctx context.Context, given client.ObjectList, opts ...client.ListOption) error {
	switch given.(type) {
	case *cmapi.CertificateRequestList:
		for _, obj := range mock.objects {
			cr, ok := obj.(*cmapi.CertificateRequest)
			if !ok {
				continue
			}
			given.(*cmapi.CertificateRequestList).Items = append(given.(*cmapi.CertificateRequestList).Items, *cr)
		}
		return nil
	case *crpapi.CertificateRequestPolicyList:
		for _, obj := range mock.objects {
			crp, ok := obj.(*crpapi.CertificateRequestPolicy)
			if !ok {
				continue
			}
			given.(*crpapi.CertificateRequestPolicyList).Items = append(given.(*crpapi.CertificateRequestPolicyList).Items, *crp)
		}
		return nil
	default:
		mock.t.FailNow()
		return nil
	}
}

// The rest of the functions are stubbed out.
func (mock *mockCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	mock.t.FailNow()
	return nil, nil
}
func (mock *mockCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption) (cache.Informer, error) {
	mock.t.FailNow()
	return nil, nil
}
func (mock *mockCache) Start(ctx context.Context) error {
	mock.t.FailNow()
	return nil
}
func (mock *mockCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	return nil
}
func (mock *mockCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return nil
}
