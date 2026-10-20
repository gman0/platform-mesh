/*
Copyright The Platform Mesh Authors.

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

// Package kubeconfig gives the Provider's operator its way to kcp: one
// kubeconfig Secret per Connection, pointing at provider-gateway's operator
// proxy, and the TLS that proxy serves.
package kubeconfig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DefaultCASecretName is the Secret of the self-generated CA, in
	// cert-manager's layout: tls.crt and tls.key for the CA, ca.crt for the
	// trust bundle.
	DefaultCASecretName = "provider-gateway-ca"

	caBundleKey = "ca.crt"

	servingLife    = 30 * 24 * time.Hour
	servingRenewAt = 10 * 24 * time.Hour // remaining
)

// noExpiry is RFC 5280's "no well-defined expiration date" for the
// self-generated CA, which is never rotated.
var noExpiry = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// CA is the self-generated CA.
type CA struct {
	cert   *x509.Certificate
	key    crypto.Signer
	bundle []byte
}

// Bundle is the PEM trust bundle for kubeconfigs.
func (ca *CA) Bundle() []byte { return ca.bundle }

// EnsureCA loads the CA from its Secret, or generates it once if there's
// none. It's never rotated: clients trust it, and only short-lived serving
// certificates change. A Secret written by someone else in the same layout
// is used as it is.
func EnsureCA(ctx context.Context, c client.Client, namespace, name string, now time.Time) (*CA, error) {
	var secret corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret)
	if apierrors.IsNotFound(err) {
		return createCA(ctx, c, namespace, name, now)
	}
	if err != nil {
		return nil, err
	}
	return parseCA(&secret)
}

func createCA(ctx context.Context, c client.Client, namespace, name string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "provider-gateway CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              noExpiry,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			caBundleKey:             certPEM,
		},
	}
	if err := c.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another replica was first.
			return EnsureCA(ctx, c, namespace, name, now)
		}
		return nil, err
	}
	return parseCA(secret)
}

func parseCA(secret *corev1.Secret) (*CA, error) {
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, fmt.Errorf("CA Secret %s: %w", secret.Name, err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA Secret %s: tls.crt isn't a CA", secret.Name)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key can't sign")
	}
	bundle := secret.Data[caBundleKey]
	if len(bytes.TrimSpace(bundle)) == 0 {
		bundle = secret.Data[corev1.TLSCertKey]
	}
	return &CA{cert: cert, key: signer, bundle: bundle}, nil
}

// Issue returns a serving certificate for names, valid from now.
func (ca *CA) Issue(names []string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(servingLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
