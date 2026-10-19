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

// Package token issues Onboarding Tokens for a Provider's portal. The token
// string is shown to its Owner once and never stored; the OnboardingToken
// object holds only its hash.
//
// A portal in another language reproduces New from the protocol
// specification: a random ID and secret, the secret's hash, and the token
// format.
package token

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// ErrNoUsableServerKey is returned when no ServerKey is Ready without
// retireAt.
var ErrNoUsableServerKey = errors.New("no usable ServerKey")

// Usable reports whether tokens may be issued and used over a ServerKey:
// it's Ready, has its fingerprint, and has no retireAt.
func Usable(key *sdkv1alpha1.ServerKey) bool {
	return key.DeletionTimestamp == nil &&
		key.Spec.RetireAt == nil &&
		key.Status.Fingerprint != "" &&
		meta.IsStatusConditionTrue(key.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady)
}

// PickServerKey returns the newest usable ServerKey.
func PickServerKey(keys []sdkv1alpha1.ServerKey) (*sdkv1alpha1.ServerKey, error) {
	usable := slices.DeleteFunc(slices.Clone(keys), func(k sdkv1alpha1.ServerKey) bool { return !Usable(&k) })
	if len(usable) == 0 {
		return nil, ErrNoUsableServerKey
	}
	newest := slices.MaxFunc(usable, func(a, b sdkv1alpha1.ServerKey) int {
		return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
	})
	return &newest, nil
}

// New returns a new Onboarding Token over key for owner, valid for ttl from
// now, and the OnboardingToken object to create in namespace. The token
// string is the Owner's credential until it's spent: show it once.
func New(baseURL, owner, namespace string, ttl time.Duration, key *sdkv1alpha1.ServerKey, now time.Time) (string, *sdkv1alpha1.OnboardingToken, error) {
	if owner == "" {
		return "", nil, errors.New("owner is required")
	}
	if ttl <= 0 {
		return "", nil, errors.New("ttl must be positive")
	}
	if !Usable(key) {
		return "", nil, fmt.Errorf("ServerKey %s: %w", key.Name, ErrNoUsableServerKey)
	}
	fp, err := fingerprint.ParseKind(key.Status.Fingerprint, fingerprint.KeySHA256)
	if err != nil {
		return "", nil, fmt.Errorf("ServerKey %s: %w", key.Name, err)
	}
	tok, err := credential.NewOnboardingToken(baseURL, fp)
	if err != nil {
		return "", nil, err
	}
	obj := &sdkv1alpha1.OnboardingToken{
		ObjectMeta: metav1.ObjectMeta{Name: tok.ID(), Namespace: namespace},
		Spec: sdkv1alpha1.OnboardingTokenSpec{
			Owner:     owner,
			ExpiresAt: metav1.NewTime(now.Add(ttl)),
			TokenHash: tok.SecretHash().String(),
			ServerKey: key.Name,
		},
	}
	return tok.Reveal(), obj, nil
}

// Issue picks the newest usable ServerKey in namespace, creates the
// OnboardingToken there, and returns the token string.
func Issue(ctx context.Context, c client.Client, namespace, baseURL, owner string, ttl time.Duration) (string, error) {
	var keys sdkv1alpha1.ServerKeyList
	if err := c.List(ctx, &keys, client.InNamespace(namespace)); err != nil {
		return "", fmt.Errorf("listing ServerKeys: %w", err)
	}
	key, err := PickServerKey(keys.Items)
	if err != nil {
		return "", err
	}
	tok, obj, err := New(baseURL, owner, namespace, ttl, key, time.Now())
	if err != nil {
		return "", err
	}
	if err := c.Create(ctx, obj); err != nil {
		return "", fmt.Errorf("creating OnboardingToken: %w", err)
	}
	return tok, nil
}
