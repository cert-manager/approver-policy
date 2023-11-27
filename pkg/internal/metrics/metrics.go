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
	"time"

	crpapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
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
		"Number of CertificateRequests that have been approved (Approved=True).",
		[]string{
			"namespace",
		},
		nil,
	)

	// deniedCount counts the number of CertificateRequest currently denied by
	// looking at the Denied condition.
	//
	// - type: Denied
	//   status: "True"
	//   reason: policy.cert-manager.io
	//   message: 'No policy approved this request: [issuer-2: spec.allowed.dnsNames.values:
	//     Invalid value: []string{"forbidden-domain-41.com"}: *.example.com, *.ca-wont-accept.org]'
	deniedCount = prometheus.NewDesc(
		"approverpolicy_certificaterequest_denied_count",
		"Number of CertificateRequests that have been denied (Denied=True).",
		[]string{
			"namespace",
		},
		nil,
	)

	// unmatchedCount counts the current number of certificate requests that
	// have not been matched by any approvers. An unmatched certificate request
	// is defined as a certificate requests that doesn't have the Approved
	// condition.
	unmatchedCount = prometheus.NewDesc(
		"approverpolicy_certificaterequest_unmatched_count",
		"Number of CertificateRequests not matched to any policy, i.e., that don't have an Approved or Denied condition set yet.",
		[]string{
			"namespace",
		},
		nil,
	)

	// crPolicyStatus tells you the status of the CertificateRequestPolicy's
	// Ready condition. We don't report the `message` field from the condition
	// because it isn't machine-readable (i.e., it's a free-text string that
	// changes for each object and isn't meant to be used for filtering and
	// grouping in Prometheus). We also don't report the `reason` field because
	// it is paraphrasing the `status` (it says "Ready" or "NotReady").
	crPolicyStatus = prometheus.NewDesc(
		"approverpolicy_certificaterequestpolicy_status",
		"Status of the CertificateRequestPolicy resources.",
		[]string{
			"name",
			"ready_status",
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
// much easier to list resources when the `/metrics` endpoint is hit rather than
// using a controller-runtime reconciler.
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
	collectCRsDenied(cc.ctx, cc.log, cc.cache, ch)
	collectCRsUnmatched(cc.log, cc.cache, ch)
	collectCRPolicyStatuses(cc.ctx, cc.log, cc.cache, ch)
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

	type label struct{ namespace string }

	// Let's remember the order of the labels so that we can send the metrics
	// deterministically. Undeterministic outputs are a pain to test and debug.
	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		// A certificate request is said to be approved if it has the condition
		// Approved=True.
		approvedStatus := getStatus(cmapi.CertificateRequestConditionApproved, cr.Status.Conditions)
		if approvedStatus != "True" {
			continue
		}

		k := label{namespace: cr.Namespace}
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
		)
	}
}

func collectCRsDenied(ctx context.Context, log logr.Logger, c cache.Cache, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := c.List(ctx, list)
	if err != nil {
		log.Error(err, "unable to list CertificateRequests")
		return
	}

	type label struct{ namespace string }

	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		deniedStatus := getStatus(cmapi.CertificateRequestConditionDenied, cr.Status.Conditions)
		// A certificate request is said to be denied if it has the condition
		// Denied=True.
		if deniedStatus != "True" {
			continue
		}

		k := label{namespace: cr.Namespace}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k] += 1
	}

	for _, key := range labels {
		ch <- prometheus.MustNewConstMetric(
			deniedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
		)
	}
}

func collectCRsUnmatched(logger logr.Logger, c cache.Cache, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := c.List(context.Background(), list)
	if err != nil {
		logger.Error(err, "unable to list CertificateRequests")
		return
	}

	type label struct {
		namespace string
	}

	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		// A certificate request is said to be unmatched if it doesn't have the
		// Approved and Denied conditions.
		approvedStatus := getStatus(cmapi.CertificateRequestConditionApproved, cr.Status.Conditions)
		deniedStatus := getStatus(cmapi.CertificateRequestConditionDenied, cr.Status.Conditions)
		if approvedStatus == "True" || deniedStatus == "True" {
			continue
		}

		k := label{namespace: cr.Namespace}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k] += 1
	}

	for _, key := range labels {
		ch <- prometheus.MustNewConstMetric(
			unmatchedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
		)
	}
}

func collectCRPolicyStatuses(ctx context.Context, log logr.Logger, c cache.Cache, ch chan<- prometheus.Metric) {
	list := &crpapi.CertificateRequestPolicyList{}
	err := c.List(ctx, list)
	if err != nil {
		log.Error(err, "unable to list CertificateRequestPolicies")
		return
	}

	for _, crp := range list.Items {
		ch <- prometheus.MustNewConstMetric(
			crPolicyStatus,
			prometheus.GaugeValue,
			float64(1),
			crp.Name,
			string(getReadyStatusCRP(crp.Status.Conditions)),
		)
	}
}

// Returns "True" or "False", or "Unknown" if the condition with the given type
// (e.g., "Approved" or "Denied") exists, or "" if the condition is not found.
func getStatus(condTyp cmapi.CertificateRequestConditionType, conditions []cmapi.CertificateRequestCondition) cmmeta.ConditionStatus {
	for _, cond := range conditions {
		if cond.Type == condTyp {
			return cond.Status
		}
	}

	return cmmeta.ConditionUnknown
}

// Same but for the CertificateRequestPolicy resource, and only meant for the
// Ready condition since CertificateRequestPolicy only uses the Ready condition.
func getReadyStatusCRP(conditions []crpapi.CertificateRequestPolicyCondition) corev1.ConditionStatus {
	for _, cond := range conditions {
		if cond.Type == crpapi.CertificateRequestPolicyConditionReady {
			return cond.Status
		}
	}

	return corev1.ConditionUnknown
}
