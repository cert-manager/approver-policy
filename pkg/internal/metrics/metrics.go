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
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
)

type LeaderAwareCollector interface {
	prometheus.Collector
	manager.Runnable
	manager.LeaderElectionRunnable
}

// NewCollector initializes a new collector, but it still needs to be started.
func NewCollector(log logr.Logger, r client.Reader) LeaderAwareCollector {
	return &collector{log: log, reader: r}
}

// We use a custom collector instead of prometheus.NewGaugeVec because it is
// much easier to list all the certificate requests when the `/metrics`
// endpoint is hit rather than using a controller-runtime reconciler.
type collector struct {
	ctx    context.Context
	log    logr.Logger
	reader client.Reader
}

func (cc *collector) Start(ctx context.Context) error {
	cc.ctx = ctx
	if err := metrics.Registry.Register(cc); err != nil {
		return fmt.Errorf("unable to register metrics collector: %w", err)
	}

	// Block until the context is done.
	<-ctx.Done()
	metrics.Registry.Unregister(cc)

	return nil
}

func (cc *collector) NeedLeaderElection() bool {
	return true
}

func (cc *collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc *collector) Collect(ch chan<- prometheus.Metric) {
	collectCertificateRequestsApproval(cc.ctx, cc.log, cc.reader, ch)
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

// isStatusConditionTrue returns true when the conditionType is present and status set to `True`.
func isStatusConditionTrue(conditions []cmapi.CertificateRequestCondition, conditionType cmapi.CertificateRequestConditionType) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == cmmeta.ConditionTrue
		}
	}
	return false
}
