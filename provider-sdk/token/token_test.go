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

package token

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.platform-mesh.io/provider-protocol/credential"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const (
	ns      = "wild-west-system"
	baseURL = "https://wildwest.example.com/pm"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func serverKey(name string, created time.Time, opts ...func(*sdkv1alpha1.ServerKey)) sdkv1alpha1.ServerKey {
	k := sdkv1alpha1.ServerKey{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, CreationTimestamp: metav1.NewTime(created)},
		Status: sdkv1alpha1.ServerKeyStatus{
			Fingerprint: "key-sha256:" + strings.Repeat("0f", 32),
			Conditions: []metav1.Condition{{
				Type: sdkv1alpha1.ServerKeyConditionReady, Status: metav1.ConditionTrue, Reason: sdkv1alpha1.ServerKeyReasonAsExpected,
			}},
		},
	}
	for _, o := range opts {
		o(&k)
	}
	return k
}

func retiring(k *sdkv1alpha1.ServerKey) { t := metav1.NewTime(now.Add(time.Hour)); k.Spec.RetireAt = &t }
func notReady(k *sdkv1alpha1.ServerKey) { k.Status.Conditions[0].Status = metav1.ConditionFalse }
func noFingerprint(k *sdkv1alpha1.ServerKey) { k.Status.Fingerprint = "" }
func deleting(k *sdkv1alpha1.ServerKey) { t := metav1.NewTime(now); k.DeletionTimestamp = &t }

func TestPickServerKey(t *testing.T) {
	older := serverKey("sk-old", now.Add(-48*time.Hour))
	newer := serverKey("sk-new", now.Add(-time.Hour))

	k, err := PickServerKey([]sdkv1alpha1.ServerKey{older, newer})
	require.NoError(t, err)
	assert.Equal(t, "sk-new", k.Name)

	// A newer key that isn't usable is skipped.
	for name, opt := range map[string]func(*sdkv1alpha1.ServerKey){
		"retiring": retiring, "not ready": notReady, "no fingerprint": noFingerprint, "deleting": deleting,
	} {
		k, err := PickServerKey([]sdkv1alpha1.ServerKey{older, serverKey("sk-new", now.Add(-time.Hour), opt)})
		require.NoError(t, err, name)
		assert.Equal(t, "sk-old", k.Name, name)
	}

	_, err = PickServerKey([]sdkv1alpha1.ServerKey{serverKey("sk", now, retiring)})
	assert.ErrorIs(t, err, ErrNoUsableServerKey)
	_, err = PickServerKey(nil)
	assert.ErrorIs(t, err, ErrNoUsableServerKey)
}

func TestNew(t *testing.T) {
	key := serverKey("sk-2026-10", now)
	text, obj, err := New(baseURL, "alice@example.com", ns, 30*time.Minute, &key, now)
	require.NoError(t, err)

	tok, err := credential.ParseOnboardingToken(text)
	require.NoError(t, err)
	assert.Equal(t, baseURL, tok.BaseURL())
	assert.Equal(t, key.Status.Fingerprint, tok.ServerKey().String())

	assert.Equal(t, tok.ID(), obj.Name)
	assert.Equal(t, ns, obj.Namespace)
	assert.Equal(t, "alice@example.com", obj.Spec.Owner)
	assert.Equal(t, now.Add(30*time.Minute), obj.Spec.ExpiresAt.Time)
	assert.Equal(t, tok.SecretHash().String(), obj.Spec.TokenHash)
	assert.Equal(t, "sk-2026-10", obj.Spec.ServerKey)
	assert.NotContains(t, obj.Spec.TokenHash, tok.RevealSecret(), "only the hash is stored")
}

func TestNewRefuses(t *testing.T) {
	key := serverKey("sk", now)
	_, _, err := New(baseURL, "", ns, time.Minute, &key, now)
	assert.Error(t, err, "no owner")
	_, _, err = New(baseURL, "alice", ns, 0, &key, now)
	assert.Error(t, err, "no ttl")
	_, _, err = New("http://wildwest.example.com", "alice", ns, time.Minute, &key, now)
	assert.ErrorIs(t, err, credential.ErrInvalidBaseURL)

	retired := serverKey("sk", now, retiring)
	_, _, err = New(baseURL, "alice", ns, time.Minute, &retired, now)
	assert.ErrorIs(t, err, ErrNoUsableServerKey)
}

func TestIssue(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	key := serverKey("sk-2026-10", now)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&key).Build()

	text, err := Issue(context.Background(), c, ns, baseURL, "alice@example.com", 30*time.Minute)
	require.NoError(t, err)
	tok, err := credential.ParseOnboardingToken(text)
	require.NoError(t, err)

	var obj sdkv1alpha1.OnboardingToken
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: tok.ID()}, &obj))
	assert.Equal(t, tok.SecretHash().String(), obj.Spec.TokenHash)

	empty := fake.NewClientBuilder().WithScheme(scheme).Build()
	_, err = Issue(context.Background(), empty, ns, baseURL, "alice", time.Minute)
	assert.ErrorIs(t, err, ErrNoUsableServerKey)
}
