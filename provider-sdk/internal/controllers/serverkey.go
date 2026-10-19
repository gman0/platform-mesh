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

// Package controllers reconciles the SDK's resources.
package controllers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.platform-mesh.io/provider-protocol/fingerprint"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// ServerKeyReconciler generates Server Keys and checks them.
type ServerKeyReconciler struct {
	Client    client.Client
	Namespace string
}

// Reconcile publishes a new ServerKey's key and checks a published one
// against its Secret. It never generates a key under a name whose key is
// already published: Connections pin it.
func (r *ServerKeyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var key sdkv1alpha1.ServerKey
	if err := r.Client.Get(ctx, req.NamespacedName, &key); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if key.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}

	signer, owned, err := r.loadSecret(ctx, &key)
	missing := apierrors.IsNotFound(err)
	if err != nil && !missing && !errors.Is(err, errKeyUnparseable) {
		return reconcile.Result{}, err
	}

	if key.Status.PublicKey == "" {
		if missing {
			if signer, err = r.generate(ctx, &key); err != nil {
				return reconcile.Result{}, err
			}
		} else if !owned || signer == nil {
			return r.setReady(ctx, &key, metav1.ConditionFalse, sdkv1alpha1.ServerKeyReasonKeyMismatch,
				"a Secret of this name exists that this ServerKey doesn't own, or it holds no usable key")
		}
		// A key generated before a crash is published from its Secret.
		pub, fp, err := publicKey(signer.Public())
		if err != nil {
			return reconcile.Result{}, err
		}
		key.Status.PublicKey, key.Status.Fingerprint = pub, fp
		return r.setReady(ctx, &key, metav1.ConditionTrue, sdkv1alpha1.ServerKeyReasonAsExpected, "")
	}

	if missing {
		return r.setReady(ctx, &key, metav1.ConditionFalse, sdkv1alpha1.ServerKeyReasonKeyMissing,
			"the private key's Secret is missing; rotate to a new ServerKey")
	}
	if signer == nil {
		return r.setReady(ctx, &key, metav1.ConditionFalse, sdkv1alpha1.ServerKeyReasonKeyMismatch,
			"the private key's Secret holds no usable key; rotate to a new ServerKey")
	}
	if pub, _, err := publicKey(signer.Public()); err != nil || pub != key.Status.PublicKey {
		return r.setReady(ctx, &key, metav1.ConditionFalse, sdkv1alpha1.ServerKeyReasonKeyMismatch,
			"the private key doesn't match status.publicKey; rotate to a new ServerKey")
	}
	return r.setReady(ctx, &key, metav1.ConditionTrue, sdkv1alpha1.ServerKeyReasonAsExpected, "")
}

// loadSecret reads the key's Secret and whether this ServerKey owns it.
func (r *ServerKeyReconciler) loadSecret(ctx context.Context, key *sdkv1alpha1.ServerKey) (crypto.Signer, bool, error) {
	var secret corev1.Secret
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: key.Namespace, Name: key.Name}, &secret); err != nil {
		return nil, false, err
	}
	owned := metav1.IsControlledBy(&secret, key)
	signer, err := parsePrivateKey(secret.Data[sdkv1alpha1.ServerKeyPrivateKey])
	if err != nil {
		// Unparseable counts as not this key.
		return nil, owned, fmt.Errorf("%w: %v", errKeyUnparseable, err)
	}
	return signer, owned, nil
}

var errKeyUnparseable = errors.New("server key secret holds no usable private key")

func (r *ServerKeyReconciler) generate(ctx context.Context, key *sdkv1alpha1.ServerKey) (crypto.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			sdkv1alpha1.ServerKeyPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		},
	}
	if err := controllerutil.SetControllerReference(key, secret, r.Client.Scheme()); err != nil {
		return nil, err
	}
	if err := r.Client.Create(ctx, secret); err != nil {
		return nil, err
	}
	return priv, nil
}

func (r *ServerKeyReconciler) setReady(ctx context.Context, key *sdkv1alpha1.ServerKey, status metav1.ConditionStatus, reason, msg string) (reconcile.Result, error) {
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               sdkv1alpha1.ServerKeyConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: key.Generation,
	})
	key.Status.ObservedGeneration = key.Generation
	return reconcile.Result{}, r.Client.Status().Update(ctx, key)
}

// SetupWithManager watches ServerKeys and their Secrets.
func (r *ServerKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdkv1alpha1.ServerKey{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// EnsureServerKey creates a first ServerKey when there's none, so a new
// installation can issue tokens.
func EnsureServerKey(ctx context.Context, c client.Client, namespace string) error {
	var list sdkv1alpha1.ServerKeyList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return err
	}
	if len(list.Items) > 0 {
		return nil
	}
	return c.Create(ctx, &sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{GenerateName: "sk-", Namespace: namespace}})
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS #8 PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("not a signing key")
	}
	return signer, nil
}

// publicKey returns a public key as PEM SubjectPublicKeyInfo, and its
// key-sha256 fingerprint.
func publicKey(pub crypto.PublicKey) (string, string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	fp, err := fingerprint.OfPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), fp.String(), nil
}
