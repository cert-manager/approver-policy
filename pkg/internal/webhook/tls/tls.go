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

package tls

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/pkg/webhook/authority"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
)

// Options hold options for the approver-policy Webhook TLS provider.
type Options struct {
	// Log is the logger used by the webhook tls provider.
	Log logr.Logger

	// RestConfig is the shared base rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	// WebhookCertificatesDir is the directory that holds the certificate and key
	// (tls.crt, tls.key) which are used to server the Webhook server. The
	// TLS proivder waits for these files to become available before returning
	// from New().
	WebhookCertificatesDir string

	// CASecretNamespace is the namespace that the
	// cert-manager-approver-policy-tls Secret is stored.
	CASecretNamespace string
}

// TLS is a TLS provider which is used for populating a serving key and
// certificate for the webhook server.
type TLS struct {
	log logr.Logger

	// caManager is responsible for populating a valid CA certificate which is
	// used by the TLS provider for signing certificates used for serving the
	// webhook.
	caManager *authority.DynamicAuthority

	webhookCertificatesDir string

	lock             sync.Mutex
	nextRenewCh      chan time.Time
	authorityErrChan chan error
}

// New constructs a TLS provider. The provider will ensure that a certificate
// and key pair are available for serving the webhook.
func New(ctx context.Context, opts Options) (*TLS, error) {
	log := opts.Log.WithName("tls")
	t := &TLS{
		log:                    log,
		webhookCertificatesDir: opts.WebhookCertificatesDir,
		nextRenewCh:            make(chan time.Time, 1),
		authorityErrChan:       make(chan error),
		caManager: &authority.DynamicAuthority{
			SecretNamespace: opts.CASecretNamespace,
			SecretName:      "cert-manager-approver-policy-tls",
			RESTConfig:      opts.RestConfig,
			Log:             log.WithName("certificate-authority"),
			CADuration:      time.Hour * 24,
			LeafDuration:    time.Hour,
		},
	}

	// Run the authority in a separate goroutine
	go func() {
		defer close(t.authorityErrChan)
		t.authorityErrChan <- t.caManager.Run(ctx.Done())
	}()

	// initially fetch a certificate from the signing CA
	interval := time.Second
	if err := wait.PollUntil(interval, func() (done bool, err error) {
		// check for errors from the authority here too, to prevent retrying
		// if the authority has failed to start
		select {
		case err, ok := <-t.authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, context.Canceled
			}
		default:
			// this case avoids blocking if the authority is still running
		}

		if err := t.regenerateCertificate(t.nextRenewCh); err != nil {
			t.log.Error(err, "failed to generate initial serving certificate, retrying...", "interval", interval.String())
			return false, nil
		}
		return true, nil
	}, ctx.Done()); err != nil {
		// In case of an error, the stopCh is closed; wait for authorityErrChan to be closed too
		<-t.authorityErrChan

		// If there was an ErrWaitTimeout error, this must be caused by closing stopCh
		if errors.Is(err, wait.ErrWaitTimeout) {
			return nil, context.Canceled
		}

		return nil, err
	}

	return t, nil
}

// Start will start the TLS provider which ensures that the webhook server
// always has a valid certificate and key for the current serving CA.
func (t *TLS) Start(ctx context.Context) error {
	t.log.Info("starting webhook tls manager")

	// watch for changes to the root CA
	renewalChan := func() <-chan struct{} {
		ch := make(chan struct{})
		go func() {
			defer close(ch)

			var renewMoment time.Time
			select {
			case renewMoment = <-t.nextRenewCh:
				// We recevieved a renew moment
			default:
				// This should never happen
				panic("Unreacheable")
			}

			for {
				timer := time.NewTimer(time.Until(renewMoment))
				defer timer.Stop()

				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					// Try to send a message on ch, but also allow for a stop signal or
					// a new renewMoment to be received
					select {
					case <-ctx.Done():
						return
					case ch <- struct{}{}:
						// Message was sent on channel
					case renewMoment = <-t.nextRenewCh:
						// We recevieved a renew moment, next loop iteration will update the timer
					}
				case renewMoment = <-t.nextRenewCh:
					// We recevieved a renew moment, next loop iteration will update the timer
				}
			}
		}()
		return ch
	}()

	rotationChan := t.caManager.WatchRotation(ctx.Done())
	// check the current certificate every 10s in case it needs updating
	return wait.PollImmediateUntil(time.Second*10, func() (done bool, err error) {
		// regenerate the serving certificate if the root CA has been rotated
		select {
		// if the authority has stopped for whatever reason, exit and return the error
		case err, ok := <-t.authorityErrChan:
			if err != nil {
				return true, fmt.Errorf("failed to run certificate authority: %w", err)
			}
			if !ok {
				return true, context.Canceled
			}
		// trigger regeneration if the root CA has been rotated
		case _, ok := <-rotationChan:
			if !ok {
				return true, context.Canceled
			}
			t.log.Info("detected root CA rotation - regenerating serving certificates")
			if err := t.regenerateCertificate(t.nextRenewCh); err != nil {
				t.log.Error(err, "failed to regenerate serving certificate")
				return false, nil
			}
		// trigger regeneration if a renewal is required
		case <-renewalChan:
			t.log.Info("serving certificate requires renewal, regenerating")
			if err := t.regenerateCertificate(t.nextRenewCh); err != nil {
				t.log.Error(err, "failed to regenerate serving certificate")
				return false, nil
			}
		case <-ctx.Done():
			return true, context.Canceled
		}
		return false, nil
	}, ctx.Done())
}

// regenerateCertificate will trigger the cached certificate and private key to
// be regenerated by requesting a new certificate from the authority.
func (t *TLS) regenerateCertificate(nextRenew chan<- time.Time) error {
	t.log.V(2).Info("generating new ECDSA private key")

	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return err
	}

	// create the certificate template to be signed
	template := &x509.Certificate{
		Version:            2,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          pk.Public(),
		DNSNames:           []string{"cert-manager-approver-policy.cert-manager.svc"},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	t.log.V(2).Info("signing new serving certificate")
	cert, err := t.caManager.Sign(template)
	if err != nil {
		return err
	}

	t.log.V(2).Info("signed new serving certificate")

	if err := t.updateCertificate(pk, cert, nextRenew); err != nil {
		return err
	}
	return nil
}

// updateCertificate will write the given private key and certificate to the
// file at the webhook certificates directory.
func (t *TLS) updateCertificate(pk crypto.Signer, cert *x509.Certificate, nextRenew chan<- time.Time) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		return err
	}

	certData, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(t.webhookCertificatesDir, "tls.crt"), certData, 0644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(t.webhookCertificatesDir, "tls.key"), pkData, 0644); err != nil {
		return err
	}

	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	// renew the certificate 1/3 of the time before its expiry
	nextRenew <- cert.NotAfter.Add(certDuration / -3)

	t.log.Info("updated serving TLS certificate")

	return nil
}

// All webhook TLS providers need to keep their respective key and certificate
// up-to-date, regardless of whether they are leader or not.
func (t *TLS) NeedLeaderElection() bool {
	return false
}
