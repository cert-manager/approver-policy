package metrics

import (
	"context"
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
					{Type: "Approved", Status: "False"},
				}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "baz", Namespace: "other"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
					{Type: "Approved", Status: "False"},
				}},
			},
		})
		const expected = `
			# HELP approverpolicy_certificaterequest_approved_count Number of CertificateRequests that were been approved or denied (Approved=True or Approved=False).
			# TYPE approverpolicy_certificaterequest_approved_count gauge
			approverpolicy_certificaterequest_approved_count{approved_status="False",namespace="bar"} 1
			approverpolicy_certificaterequest_approved_count{approved_status="False",namespace="other"} 1
			approverpolicy_certificaterequest_approved_count{approved_status="True",namespace="bar"} 1
		`
		err := testutil.CollectAndCompare(mock, strings.NewReader(expected), "approverpolicy_certificaterequest_approved_count")
		require.NoError(t, err)
	})

	t.Run("unmatched_count is only about CRs with no Approved condition", func(t *testing.T) {
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
				ObjectMeta: metav1.ObjectMeta{Name: "foo3", Namespace: "baz"},
				Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{
					{Type: "Ready", Status: "False"},
				}},
			},
			// Two happy CRs.
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
					{Type: "Approved", Status: "False"},
				}},
			},
		})
		const expected = `
        	# HELP approverpolicy_certificaterequest_unmatched_count Number of CertificateRequests not matched to any policy, i.e., that don't have an Approved condition set yet.
        	# TYPE approverpolicy_certificaterequest_unmatched_count gauge
        	approverpolicy_certificaterequest_unmatched_count{namespace="bar"} 2
            approverpolicy_certificaterequest_unmatched_count{namespace="baz"} 1
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
