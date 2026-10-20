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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const tokenID = "t-abcdefghijklmnopqrstuvwxyz"

func newToken(expiresAt time.Time, spent bool) *sdkv1alpha1.OnboardingToken {
	tok := &sdkv1alpha1.OnboardingToken{
		ObjectMeta: metav1.ObjectMeta{Name: tokenID, Namespace: ns},
		Spec: sdkv1alpha1.OnboardingTokenSpec{
			Owner: "alice@example.com", ExpiresAt: metav1.NewTime(expiresAt),
			TokenHash: "sha256:" + strings.Repeat("ab", 32), ServerKey: "sk-1",
		},
	}
	if spent {
		tok.Status.Registration = &sdkv1alpha1.TokenRegistration{
			ConnectionID: connID, IdempotencyKey: "uid", SecretHash: "sha256:" + strings.Repeat("cd", 32),
			ClusterName: "2x8k9abc", At: metav1.NewTime(expiresAt.Add(-10 * time.Minute)),
		}
	}
	return tok
}

func TestOnboardingTokenGC(t *testing.T) {
	expires := tv.Now.Add(30 * time.Minute)
	window := 7 * 24 * time.Hour
	cases := map[string]struct {
		spent   bool
		at      time.Time
		deleted bool
		requeue time.Duration
	}{
		"unspent, before expiry":         {false, tv.Now, false, 30 * time.Minute},
		"unspent, expired":               {false, expires, true, 0},
		"spent, before expiry":           {true, tv.Now, false, 30*time.Minute + window},
		"spent, expired, in the window":  {true, expires.Add(time.Hour), false, window - time.Hour},
		"spent, past the window":         {true, expires.Add(window), true, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cl := newClient(t, newToken(expires, c.spent))
			r := &OnboardingTokenReconciler{Client: cl, Now: func() time.Time { return c.at }}
			res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: tokenID}})
			require.NoError(t, err)
			assert.Equal(t, c.requeue, res.RequeueAfter)

			var tok sdkv1alpha1.OnboardingToken
			err = cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: tokenID}, &tok)
			assert.Equal(t, c.deleted, err != nil)
		})
	}
}
