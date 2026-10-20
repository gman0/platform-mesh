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

package controllers

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// OnboardingTokenReconciler deletes tokens that can no longer be used:
// unspent ones at expiresAt, spent ones once Registration retries are no
// longer honoured.
type OnboardingTokenReconciler struct {
	Client client.Client
	// RetryWindow must be the Connection API's. Default 7 days.
	RetryWindow time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Reconcile deletes the token at its deadline, or requeues until then.
func (r *OnboardingTokenReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if r.RetryWindow <= 0 {
		r.RetryWindow = 7 * 24 * time.Hour
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	var tok sdkv1alpha1.OnboardingToken
	if err := r.Client.Get(ctx, req.NamespacedName, &tok); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if tok.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}
	if wait := r.deadline(&tok).Sub(r.Now()); wait > 0 {
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	return reconcile.Result{}, client.IgnoreNotFound(r.Client.Delete(ctx, &tok))
}

// deadline is when the token is no longer of use. A spent token stays while
// a retry of its Registration is honoured, which is until expiresAt plus
// the retry window.
func (r *OnboardingTokenReconciler) deadline(tok *sdkv1alpha1.OnboardingToken) time.Time {
	if tok.Status.Registration != nil {
		return tok.Spec.ExpiresAt.Add(r.RetryWindow)
	}
	return tok.Spec.ExpiresAt.Time
}

// SetupWithManager watches OnboardingTokens.
func (r *OnboardingTokenReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&sdkv1alpha1.OnboardingToken{}).Complete(r)
}
