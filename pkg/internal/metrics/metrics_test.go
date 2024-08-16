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
	"errors"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Test_Metrics(t *testing.T) {
	t.Run("approved_count counts the CRs that have the Approved condition", func(t *testing.T) {
		mock := mockCollector(t, []cmapi.CertificateRequest{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
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
		mock := mockCollector(t, []cmapi.CertificateRequest{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			{
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
		mock := mockCollector(t, []cmapi.CertificateRequest{
			// Three unmatched CRs.
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			// The three following CRs have been happily matched by an approver,
			// and the last one has been denied.
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo4", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo5", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
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

}

func mockCollector(t *testing.T, crs []cmapi.CertificateRequest) *collector {
	return &collector{
		cache: &mockCache{t: t, objects: crs},
		ctx:   context.Background(),
		log:   logr.Discard(),
	}
}

var errNotImplemented = errors.New("not implemented")

type mockCache struct {
	t       *testing.T
	objects []cmapi.CertificateRequest
}

// The only two functions we care about are WaitForCacheSync and List.
func (mock *mockCache) WaitForCacheSync(ctx context.Context) bool {
	return true
}
func (mock *mockCache) List(ctx context.Context, given client.ObjectList, opts ...client.ListOption) error {
	require.IsType(mock.t, &cmapi.CertificateRequestList{}, given)
	crList := given.(*cmapi.CertificateRequestList)
	crList.Items = mock.objects
	return nil
}

// The rest of the functions are stubbed out.
func (mock *mockCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, errNotImplemented
}
func (mock *mockCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	return errNotImplemented
}
func (mock *mockCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, errNotImplemented
}
func (mock *mockCache) Start(ctx context.Context) error {
	return errNotImplemented
}
func (mock *mockCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	return errNotImplemented
}
func (mock *mockCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return errNotImplemented
}
