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

// Package controller hosts the access SDK's controllers that run on the
// user-side cluster. Currently just AccessIdentity.
package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	pmaccessproto "go.platform-mesh.io/protocol/access"
	accessv1alpha1 "go.platform-mesh.io/sdk/access/apis/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	// readyConditionType is the condition type the reconciler writes
	// reasons onto.
	readyConditionType = "Ready"

	// AccessTokenSecretKey is the Secret data key under which the full
	// pma1.<...> wire string is stored.
	AccessTokenSecretKey = "accessToken"

	// TokenIDIndex is the name of the field indexer registered on
	// AccessIdentity.status.tokenID. The /access HTTP handler uses it
	// to resolve the sub claim on an incoming call credential to the
	// AccessIdentity + owned Secret.
	TokenIDIndex = ".status.tokenID"

	// Reason labels.
	ReasonTokenMinted         = "TokenMinted"
	ReasonTokenSecretMissing  = "TokenSecretMissing"
	ReasonTokenAdopted        = "TokenAdopted"
	ReasonAwaitingSecretWrite = "AwaitingSecretWrite"
)

func accessTokenSecretName(identity *accessv1alpha1.AccessIdentity) string {
	return identity.Name + "-access-token"
}

// AccessIdentityReconciler mints an access token (tokenID + HMAC
// secret) on first reconcile of an AccessIdentity, writes the wire
// string into an owned Secret, and surfaces the public tokenID on
// status. The Secret is the source of truth for the HMAC secret; if
// deleted externally, the Identity transitions to Ready=False with
// reason TokenSecretMissing (we can't re-mint without losing
// in-flight tokens on the PM side).
type AccessIdentityReconciler struct {
	Client ctrlruntimeclient.Client
	Scheme *runtime.Scheme

	// PublicURL is the base URL that user-side cluster publishes for
	// /access. Encoded into the wire token so PM dials this exact host.
	// Required; reconciler errors out if empty when minting.
	PublicURL string
}

func (r *AccessIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	identity := &accessv1alpha1.AccessIdentity{}
	if err := r.Client.Get(ctx, req.NamespacedName, identity); err != nil {
		return ctrl.Result{}, ctrlruntimeclient.IgnoreNotFound(err)
	}

	secretName := accessTokenSecretName(identity)
	secret := &corev1.Secret{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: identity.Namespace}, secret)

	switch {
	case apierrors.IsNotFound(err):
		if identity.Status.TokenID != "" {
			// Secret vanished after it was minted; we don't have the
			// HMAC secret anymore. Refuse to silently re-mint (would
			// confuse PM-side with a new token under the same
			// Identity).
			r.setReady(identity, metav1.ConditionFalse, ReasonTokenSecretMissing,
				fmt.Sprintf("owned Secret %q no longer exists; delete and recreate the AccessIdentity to re-mint", secretName))
			return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
		}
		// First mint.
		if r.PublicURL == "" {
			return ctrl.Result{}, fmt.Errorf("AccessIdentityReconciler: PublicURL is required to mint access tokens")
		}
		return r.mint(ctx, identity, secretName)

	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get owned Secret %q: %w", secretName, err)
	}

	// Secret exists — confirm status + Ready condition.
	if identity.Status.TokenID == "" {
		// Status was wiped out or hasn't converged after an earlier
		// Create. Parse the wire string from the Secret to recover.
		wire, ok := secret.Data[AccessTokenSecretKey]
		if !ok || len(wire) == 0 {
			r.setReady(identity, metav1.ConditionFalse, ReasonAwaitingSecretWrite,
				"owned Secret exists but has no access-token value")
			return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
		}
		parsed, perr := pmaccessproto.ParseToken(string(wire))
		if perr != nil {
			r.setReady(identity, metav1.ConditionFalse, ReasonAwaitingSecretWrite,
				fmt.Sprintf("owned Secret contents did not parse: %v", perr))
			return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
		}
		identity.Status.TokenID = parsed.TokenID
		r.setReady(identity, metav1.ConditionTrue, ReasonTokenAdopted,
			"adopted existing access token from owned Secret")
		return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
	}

	r.setReady(identity, metav1.ConditionTrue, ReasonTokenMinted,
		"access token minted and owned Secret present")
	return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
}

// mint generates a fresh (tokenID, hmacSecret), writes the owned
// Secret, and updates status.tokenID.
func (r *AccessIdentityReconciler) mint(ctx context.Context, identity *accessv1alpha1.AccessIdentity, secretName string) (ctrl.Result, error) {
	tokenID, err := newTokenID()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("generate tokenID: %w", err)
	}
	hmacSecret, err := newHMACSecret()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("generate HMAC secret: %w", err)
	}

	wire := pmaccessproto.Token{
		URL:     r.PublicURL,
		TokenID: tokenID,
		Secret:  hmacSecret,
	}.String()

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: identity.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(identity, secret, r.Scheme); err != nil {
			return err
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[AccessTokenSecretKey] = []byte(wire)
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("upsert owned Secret %q: %w", secretName, err)
	}

	identity.Status.TokenID = tokenID
	r.setReady(identity, metav1.ConditionTrue, ReasonTokenMinted,
		"access token minted and written to owned Secret")
	return ctrl.Result{}, r.Client.Status().Update(ctx, identity)
}

func (r *AccessIdentityReconciler) setReady(identity *accessv1alpha1.AccessIdentity, status metav1.ConditionStatus, reason, msg string) {
	apimeta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
		Type:               readyConditionType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: identity.Generation,
	})
}

// SetupWithManager registers the field indexer and the reconciler.
func (r *AccessIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&accessv1alpha1.AccessIdentity{},
		TokenIDIndex,
		func(obj ctrlruntimeclient.Object) []string {
			id := obj.(*accessv1alpha1.AccessIdentity)
			if id.Status.TokenID == "" {
				return nil
			}
			return []string{id.Status.TokenID}
		},
	); err != nil {
		return fmt.Errorf("register %s indexer: %w", TokenIDIndex, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("AccessIdentityReconciler").
		For(&accessv1alpha1.AccessIdentity{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// newTokenID returns a short random tokenID safe to log and to put in
// URLs. 128 bits of entropy, base64url-encoded.
func newTokenID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// newHMACSecret returns 256 bits of cryptographic random bytes for use
// as the HMAC key in the per-/access call credential.
func newHMACSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
