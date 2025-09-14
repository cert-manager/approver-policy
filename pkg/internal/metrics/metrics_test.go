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
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

func Test_Metrics(t *testing.T) {
	t.Run("certificaterequests_approval reports the approval status of CertificateRequests", func(t *testing.T) {
		mock := mockCollector(t, []*cmapi.CertificateRequest{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "approved-1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "approved-2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "approved-3", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "approved-4", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "denied-1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "denied-2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "denied-3", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Denied", Status: "True"},
				}},
			},
			// Three unmatched CRs.
			{
				ObjectMeta: metav1.ObjectMeta{Name: "unmatched-1", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "unmatched-2", Namespace: "bar"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "unmatched-3", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
		})
		const expected = `
			# HELP certmanager_approverpolicy_certificaterequests_approval The approval status of CertificateRequests. Possible values for the 'status' label: 'approved', 'denied', 'unmatched'.
			# TYPE certmanager_approverpolicy_certificaterequests_approval gauge
			certmanager_approverpolicy_certificaterequests_approval{namespace="bar",status="approved"} 3
			certmanager_approverpolicy_certificaterequests_approval{namespace="bar",status="denied"} 2
			certmanager_approverpolicy_certificaterequests_approval{namespace="bar",status="unmatched"} 2
			certmanager_approverpolicy_certificaterequests_approval{namespace="other",status="approved"} 1
			certmanager_approverpolicy_certificaterequests_approval{namespace="other",status="denied"} 1
			certmanager_approverpolicy_certificaterequests_approval{namespace="other",status="unmatched"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "certmanager_approverpolicy_certificaterequests_approval")
		require.NoError(t, err)
	})

	t.Run("approved_count counts the CRs that have the Approved condition", func(t *testing.T) {
		mock := mockCollector(t, []*cmapi.CertificateRequest{
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
            # HELP approverpolicy_certificaterequest_approved_count DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests that have been approved (Approved=True).
			# TYPE approverpolicy_certificaterequest_approved_count gauge
            approverpolicy_certificaterequest_approved_count{namespace="bar"} 2
            approverpolicy_certificaterequest_approved_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_approved_count")
		require.NoError(t, err)
	})

	t.Run("denied_count counts the CRs that have the Denied condition", func(t *testing.T) {
		mock := mockCollector(t, []*cmapi.CertificateRequest{
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
		# HELP approverpolicy_certificaterequest_denied_count DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests that have been denied (Denied=True).
		# TYPE approverpolicy_certificaterequest_denied_count gauge
		approverpolicy_certificaterequest_denied_count{namespace="bar"} 2
		approverpolicy_certificaterequest_denied_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_denied_count")
		require.NoError(t, err)
	})

	t.Run("unmatched_count is only about CRs with no Approved and Denied condition", func(t *testing.T) {
		mock := mockCollector(t, []*cmapi.CertificateRequest{
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
        	# HELP approverpolicy_certificaterequest_unmatched_count DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests not matched to any policy, i.e., that don't have an Approved or Denied condition set yet.
        	# TYPE approverpolicy_certificaterequest_unmatched_count gauge
			approverpolicy_certificaterequest_unmatched_count{namespace="bar"} 2
            approverpolicy_certificaterequest_unmatched_count{namespace="other"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_unmatched_count")
		require.NoError(t, err)
	})

}

func mockCollector(t *testing.T, crs []*cmapi.CertificateRequest) *collector {
	objs := make([]runtime.Object, len(crs))
	for i, cr := range crs {
		objs[i] = cr
	}

	return &collector{
		reader: fake.NewClientBuilder().
			WithScheme(policyapi.GlobalScheme).
			WithRuntimeObjects(objs...).
			Build(),
		ctx: t.Context(),
		log: logr.Discard(),
	}
}
