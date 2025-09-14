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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// certificateRequestsApproval reports the number of CertificateRequest resources
	// with approver-policy conditions set.
	//
	// It is a GaugeVec with the following labels:
	//   - "namespace": the namespace of the CertificateRequest.
	//   - "status": the approval status of the CertificateRequest.
	//     Possible values are:
	//       * "approved"    — the CertificateRequest has been approved.
	//       * "denied"      — the CertificateRequest has been denied.
	//       * "unmatched"   — the CertificateRequest not matched by any approvers.
	//
	// Exposed as the metric `certmanager_approverpolicy_certificaterequests_approval`.
	certificateRequestsApproval = prometheus.NewDesc(
		"certmanager_approverpolicy_certificaterequests_approval",
		"The approval status of CertificateRequests. Possible values for the 'status' label: 'approved', 'denied', 'unmatched'.",
		[]string{
			"namespace",
			"status",
		},
		nil,
	)

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
		"DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests that have been approved (Approved=True).",
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
		"DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests that have been denied (Denied=True).",
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
		"DEPRECATED: use certmanager_approverpolicy_certificaterequests_approval instead. Number of CertificateRequests not matched to any policy, i.e., that don't have an Approved or Denied condition set yet.",
		[]string{
			"namespace",
		},
		nil,
	)
)

// You don't need to wait for the cache to be synced before calling this. This
// function is non-blocking.
func RegisterMetrics(ctx context.Context, log logr.Logger, r client.Reader) {
	metrics.Registry.MustRegister(collector{ctx, log, r})
}

// We use a custom collector instead of prometheus.NewGaugeVec because it is
// much easier to list all of the certificate requests when the `/metrics`
// endpoint is hit rather than using a controller-runtime reconciler.
type collector struct {
	ctx    context.Context
	log    logr.Logger
	reader client.Reader
}

func (cc collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc collector) Collect(ch chan<- prometheus.Metric) {
	collectCertificateRequestsApproval(cc.ctx, cc.log, cc.reader, ch)
	collectCRsApproved(cc.ctx, cc.log, cc.reader, ch)
	collectCRsDenied(cc.ctx, cc.log, cc.reader, ch)
	collectCRsUnmatched(cc.ctx, cc.log, cc.reader, ch)
}

func collectCertificateRequestsApproval(ctx context.Context, log logr.Logger, r client.Reader, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := r.List(ctx, list)
	if err != nil {
		log.Error(err, "unable to list CertificateRequests")
		return
	}

	type label struct {
		namespace string
		status    string
	}

	// Let's remember the order of the labels so that we can send the metrics
	// deterministically. Undeterministic outputs are a pain to test and debug.
	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		status := "unmatched"
		switch {
		case isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionApproved):
			status = "approved"
		case isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionDenied):
			status = "denied"
		}

		k := label{namespace: cr.Namespace, status: status}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k]++
	}

	for _, key := range labels {
		ch <- prometheus.MustNewConstMetric(
			certificateRequestsApproval,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
			key.status,
		)
	}
}

func collectCRsApproved(ctx context.Context, log logr.Logger, r client.Reader, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := r.List(ctx, list)
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
		if !isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionApproved) {
			continue
		}

		k := label{namespace: cr.Namespace}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k]++
	}

	for _, key := range labels {
		//nolint:promlinter // This metric is deprecated and will eventually be removed, https://github.com/cert-manager/approver-policy/issues/713.
		ch <- prometheus.MustNewConstMetric(
			approvedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
		)
	}
}

func collectCRsDenied(ctx context.Context, log logr.Logger, r client.Reader, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := r.List(ctx, list)
	if err != nil {
		log.Error(err, "unable to list CertificateRequests")
		return
	}

	type label struct{ namespace string }

	var labels []label
	count := make(map[label]int)

	for _, cr := range list.Items {
		// A certificate request is said to be denied if it has the condition
		// Denied=True.
		if !isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionDenied) {
			continue
		}

		k := label{namespace: cr.Namespace}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k]++
	}

	for _, key := range labels {
		//nolint:promlinter // This metric is deprecated and will eventually be removed, https://github.com/cert-manager/approver-policy/issues/713.
		ch <- prometheus.MustNewConstMetric(
			deniedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
		)
	}
}

func collectCRsUnmatched(ctx context.Context, logger logr.Logger, r client.Reader, ch chan<- prometheus.Metric) {
	list := &cmapi.CertificateRequestList{}
	err := r.List(ctx, list)
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
		if isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionApproved) || isStatusConditionTrue(cr.Status.Conditions, cmapi.CertificateRequestConditionDenied) {
			continue
		}

		k := label{namespace: cr.Namespace}
		_, exists := count[k]
		if !exists {
			labels = append(labels, k)
		}
		count[k]++
	}

	for _, key := range labels {
		//nolint:promlinter // This metric is deprecated and will eventually be removed, ref. https://github.com/cert-manager/approver-policy/issues/713.
		ch <- prometheus.MustNewConstMetric(
			unmatchedCount,
			prometheus.GaugeValue,
			float64(count[key]),
			key.namespace,
		)
	}
}

// isStatusConditionTrue returns true when the conditionType is present and status set to `True`.
func isStatusConditionTrue(conditions []cmapi.CertificateRequestCondition, conditionType cmapi.CertificateRequestConditionType) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == cmmeta.ConditionTrue
		}
	}
	return false
}
