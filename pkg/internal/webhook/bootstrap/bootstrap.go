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

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/rest"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// webhookCertificateRequestSelector is a client.ListOptions  used for listing
// CertificateRequests in the cert-manager namespace that have been labelled as
// being used for the Webhook.
var (
	webhookCertificateRequestListOptions *client.ListOptions
)

func init() {
	r, err := labels.NewRequirement("policy.cert-manager.io/webhook", selection.Equals, []string{"bootstrap"})
	if err != nil {
		panic(err)
	}
	webhookCertificateRequestListOptions = &client.ListOptions{
		LabelSelector: labels.NewSelector().Add(*r),
		Namespace:     "cert-manager",
	}
}

// Options hold options for the policy-approver Webhook Bootstraper.
type Options struct {
	// Log is the logger used by the webhook bootstraper.
	Log logr.Logger

	// RestConfig is the shared base rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	// Evaluator is the Approver Evaluator that is responsible for evaluating
	// whether CertificateRequests that are watched by the bootstraper are valid
	// for the policy-approver Webhook and should be approved.
	Evaluator approver.Evaluator

	// WebhookCertificatesDir is the directory that holds the certificate and key
	// (tls.crt, tls.key) which are used to server the Webhook server. The
	// bootstraper waits for these files to become available before returning
	// from Start().
	WebhookCertificatesDir string
}

// bootstrapper is responsible for evaluating and setting the approval
// condition of CertificateRequests that are considered for the Webhook serving
// certificate.
type bootstrapper struct {
	// bootstrapper logger
	log logr.Logger

	// evaluator is used to gate whether a CertificateRequest should be approved or denied.
	evaluator approver.Evaluator

	// client is used to interact with resources in the API server.
	client client.Client

	// Target directory that the webhook's certificate key pair are stored
	certDir string

	// webhookFileCheckRetryPeriod is the period in which the webhook certificate
	// and key will be checked. Made variable for testing.
	webhookFileCheckRetryPeriod time.Duration
}

// Run will start the Webhook bootstrap operation for policy-approver. Start
// will block until all needed resources for the policy-approver are made
// available.  Start will continue to manage these resources in the background.
func Run(ctx context.Context, opts Options) error {
	client, err := client.New(opts.RestConfig, client.Options{Scheme: cmpapi.GlobalScheme})
	if err != nil {
		return fmt.Errorf("failed to build bootstrapper client: %w", err)
	}

	b := &bootstrapper{
		log:                         opts.Log.WithName("webhook").WithName("bootstrapper"),
		evaluator:                   opts.Evaluator,
		client:                      client,
		webhookFileCheckRetryPeriod: time.Second * 2,
		certDir:                     opts.WebhookCertificatesDir,
	}

	cache, err := cache.New(opts.RestConfig, cache.Options{
		Scheme: cmpapi.GlobalScheme, Namespace: "cert-manager",
		SelectorsByObject: cache.SelectorsByObject{
			&cmapi.CertificateRequest{}: {Label: labels.SelectorFromSet(labels.Set{"policy.cert-manager.io/webhook": "bootstrap"})},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to build bootstrapper cache: %w", err)
	}

	informer, err := cache.GetInformer(ctx, &cmapi.CertificateRequest{})
	if err != nil {
		return fmt.Errorf("failed to build bootstrapper informer: %w", err)
	}

	// queue is used to enqueue CertificateRequests to evaluate approval.
	queue := make(chan *cmapi.CertificateRequest)

	informer.AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { queue <- obj.(*cmapi.CertificateRequest).DeepCopy() },
		UpdateFunc: func(_, obj interface{}) { queue <- obj.(*cmapi.CertificateRequest).DeepCopy() },
	})

	go func() {
		if err := cache.Start(ctx); err != nil {
			b.log.Error(err, "error running bootstrapper cache")
			return
		}
	}()

	if !cache.WaitForCacheSync(ctx) {
		return errors.New("failed to wait for cache to sync")
	}

	go func() {
		defer close(queue)

		for {
			select {
			case cr := <-queue:
				log := b.log.WithValues("namespace", cr.Namespace, "name", cr.Name)
				log.V(2).Info("received certificaterequest event")

				if err := b.evaluateWebhookCertificateRequest(ctx, log, cr); err != nil {
					log.Error(err, "failed to evaluate request, re-queueing...")
					go func() {
						time.Sleep(time.Second / 2)
						queue <- cr
					}()
				}

			case <-ctx.Done():
				b.log.Info("shutting down")
				return
			}
		}
	}()

	return b.waitForWebhookCertificateKey(ctx)
}

// waitForWebhookCertificateKey is a blocking func which waits for the
// Webhook's certificate and private key to be available on file.
func (b *bootstrapper) waitForWebhookCertificateKey(ctx context.Context) error {
	certFile := filepath.Join(b.certDir, "tls.crt")
	keyFile := filepath.Join(b.certDir, "tls.key")
	log := b.log.WithValues("cert", certFile, "key", keyFile)

	checkFiles := func() (bool, error) {
		for _, file := range []string{certFile, keyFile} {
			_, err := os.Stat(file)
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
		}
		return true, nil
	}

	ticker := time.NewTicker(b.webhookFileCheckRetryPeriod)
	defer ticker.Stop()

	for {
		log.V(2).Info("checking for presence of webhook certificate and key files")

		ok, err := checkFiles()
		if err != nil {
			log.Error(err, "error checking presence of webhook certificate and key")
		} else if ok {
			log.Info("webhook certificate and key ready")
			return nil
		}

		log.Info("webhook certificate and key not available, waiting..")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			break
		}
	}
}

// evaluateWebhookCertificateRequest evaluates whether a CertificateRequest is
// proper for the policy-approver webhook serving certificate, and should be
// marked as approved or denied.
func (b *bootstrapper) evaluateWebhookCertificateRequest(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest) error {
	if apiutil.CertificateRequestIsApproved(cr) || apiutil.CertificateRequestIsDenied(cr) {
		log.V(4).Info("ignoring certificaterequest that is already approved or denied")
		return nil
	}

	var (
		denied        bool
		deniedMessage string
	)

	if ref := cr.Spec.IssuerRef; ref.Name != "cert-manager-policy-approver" || ref.Kind != "Issuer" || ref.Group != "cert-manager.io" {
		deniedMessage = "certificaterequest has wrong issuer ref"
		denied = true
		log = log.WithValues("ref", cr.Spec.IssuerRef)
		log.Info(deniedMessage)
	} else {
		resp, err := b.evaluator.Evaluate(ctx, webhookPolicy(), cr)
		if err != nil {
			return fmt.Errorf("failed to evaluate webhook certificaterequest with bootstrapper policy: %w", err)
		}

		if resp.Result == approver.ResultDenied {
			denied = true
			deniedMessage = resp.Message
			log = log.WithValues("denied", "true", "errors", deniedMessage)
		}
	}

	if denied {
		log.Info("denying request")
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "webhook.policy.cert-manager.io", deniedMessage)
	} else {
		log = log.WithValues("approved", "true")
		log.Info("approving request")
		apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "webhook.policy.cert-manager.io", "policy-approver webhook certificate passes policy")
	}

	if err := b.client.Status().Update(ctx, cr); err != nil {
		return fmt.Errorf("failed to update the certificaterequest approval condition: %w", err)
	}

	return nil
}

// webhookPolicy returns the CertificateRequestPolicy that is used to evaluate
// whether a CertificateRequest should be approved to be used as a
// policy-approver webhook serving certificate.
func webhookPolicy() *cmpapi.CertificateRequestPolicy {
	alg := cmapi.ECDSAKeyAlgorithm
	return &cmpapi.CertificateRequestPolicy{
		Spec: cmpapi.CertificateRequestPolicySpec{
			AllowedDNSNames: &[]string{"cert-manager-policy-approver.cert-manager.svc"},
			AllowedUsages:   &[]cmapi.KeyUsage{cmapi.UsageServerAuth},
			AllowedPrivateKey: &cmpapi.CertificateRequestPolicyPrivateKey{
				AllowedAlgorithm: &alg,
				MinSize:          pointer.Int(521),
				MaxSize:          pointer.Int(521),
			},
		},
	}
}
