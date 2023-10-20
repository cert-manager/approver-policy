package metrics

import (
	"context"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// approvedCount counts the number of CertificateRequest currently approved
	// or denied by looking at the Approved condition. For context, the Approved
	// condition looks like this:
	//
	//  conditions:
	//  - type: Approved
	//    status: "True"
	//    reason: policy.cert-manager.io
	//    message: 'Approved by CertificateRequestPolicy: "mael"'
	//
	// This is a gauge rather than a counter because certificate requests may
	// get removed over time e.g. with revisionHistoryLimit.
	approvedCount = prometheus.NewDesc(
		"approverpolicy_certificaterequest_approved_count",
		"Number of CertificateRequests that were been approved or denied (Approved=True or Approved=False).",
		[]string{
			"namespace",
			"approved_status",
		},
		nil,
	)

	// orphanCount counts the current number of certificate requests that have
	// not been matched by any approvers. We call then "orphans". Orphans don't
	// have the Approved condition.
	orphanCount = prometheus.NewDesc(
		"approverpolicy_certificaterequest_orphan_count",
		"Number of orphan CertificateRequests, i.e., that don't have an Approved condition set.",
		[]string{
			"name",
			"namespace",
		},
		nil,
	)
)

// You don't need to wait for the cache to be synced before calling this. This
// function is non-blocking.
func RegisterMetrics(ctx context.Context, log logr.Logger, c cache.Cache) {
	metrics.Registry.MustRegister(collector{ctx, log, c})
}

// We use a custom collector instead of prometheus.NewGaugeVec because it is
// much easier to list all of the certificate requests when the `/metrics`
// endpoint is hit rather than using a controller-runtime reconciler.
type collector struct {
	ctx   context.Context
	log   logr.Logger
	cache cache.Cache
}

func (cc collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc collector) Collect(ch chan<- prometheus.Metric) {
	// We found a niche problem where `/metrics` would hang forever in case of a
	// misconfigured RBAC. This was due to `cache.List` hanging until the cache
	// is synced. To prevent that, we skip reporting this subset of the metrics.
	if !hasSynced(cc.cache) {
		cc.log.Info("cache not synced yet, skipping metrics approverpolicy_certificaterequest_*")
		return
	}

	collectCRsApproved(cc.ctx, cc.log, cc.cache, ch)
	collectCRsOrphans(cc.log, cc.cache, ch)
}

// hasSynced returns true if the cache has synced. Otherwise, it returns false.
// It is non-blocking.
func hasSynced(cache cache.Cache) bool {
	// Why tempCtx? Controller-runtime doesn't give us a non-blocking way to
	// know if the cache is in sync. The only way it to use `WaitForCacheSync`,
	// but that's a blocking operation. 10 milliseconds seems like plenty enough
	// time since `WaitForCacheSync` doesn't do any network call to know if the
	// cache is ready.
	tempCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	return cache.WaitForCacheSync(tempCtx)
}

func collectCRsApproved(ctx context.Context, log logr.Logger, c cache.Cache, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := c.List(ctx, list)
	if err != nil {
		log.Error(err, "unable to list CertificateRequests")
		return
	}

	type label struct {
		namespace, approvedStatus string
	}

	// Let's remember the order of the labels so that we can send the metrics
	// deterministically. Undeterministic outputs are a pain to test and debug.
	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		approvedStatus, _ := getReason(cr.Status.Conditions, "Approved", func(c cmapi.CertificateRequestCondition) (typ, status, reason string) {
			return string(c.Type), string(c.Status), string(c.Reason)
		})
		if approvedStatus == "Unknown" {
			continue
		}

		k := label{
			namespace:      cr.Namespace,
			approvedStatus: string(approvedStatus),
		}

		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}

		count[k] += 1
	}

	for _, key := range labels {
		ch <- prometheus.MustNewConstMetric(
			approvedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
			key.approvedStatus,
		)
	}
}

func collectCRsOrphans(logger logr.Logger, c cache.Cache, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := c.List(context.Background(), list)
	if err != nil {
		logger.Error(err, "unable to list CertificateRequests")
		return
	}

	for _, cr := range list.Items {
		approvedStatus, _ := getReason(cr.Status.Conditions, "Approved", func(c cmapi.CertificateRequestCondition) (typ, status, reason string) {
			return string(c.Type), string(c.Status), string(c.Reason)
		})

		if approvedStatus != "Unknown" {
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			orphanCount,
			prometheus.GaugeValue,
			1.,
			cr.Name,
			cr.Namespace,
		)
	}
}

// getReason returns the status and reason of a condition of a given type (e.g.,
// "Ready"). When this condition type isn't found in the list of conditions,
// getReason returns "Unknown" and "Unknown".
//
// Imagine you have the following conditions:
//
//	conditions:
//	- type: Ready
//	  status: "True"
//	  reason: Issued
//	  message: The Certificate has been issued
//
// You can use getReason to fetch the status and reason of that "Ready"
// condition:
//
//	status, reason := getReason(conditions, "Ready", func(cond ConnectionCondition) (typ, sta, reason string) {
//	  return string(cond.Type), string(cond.Status), string(cond.Reason)
//	})
func getReason[C any](conditions []C, typ string, readCond func(cond C) (typ, status, reason string)) (status, reason string) {
	for _, cond := range conditions {
		t, status, reason := readCond(cond)
		if t == typ {
			return status, reason
		}
	}
	return "Unknown", "Unknown"
}
