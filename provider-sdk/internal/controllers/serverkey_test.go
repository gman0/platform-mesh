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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.platform-mesh.io/provider-protocol/fingerprint"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const ns = "wild-west-system"

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&sdkv1alpha1.ServerKey{}, &sdkv1alpha1.Connection{}, &sdkv1alpha1.OnboardingToken{}).
		WithObjects(objs...).Build()
}

func newServerKey(name string) *sdkv1alpha1.ServerKey {
	return &sdkv1alpha1.ServerKey{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

func reconcileKey(t *testing.T, c client.Client, name string) *sdkv1alpha1.ServerKey {
	t.Helper()
	r := &ServerKeyReconciler{Client: c, Namespace: ns}
	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	require.NoError(t, err)
	var key sdkv1alpha1.ServerKey
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &key))
	return &key
}

func readyReason(key *sdkv1alpha1.ServerKey) string {
	c := meta.FindStatusCondition(key.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady)
	if c == nil {
		return ""
	}
	return string(c.Status) + "/" + c.Reason
}

func secretFor(t *testing.T, name string, owner *sdkv1alpha1.ServerKey) (*corev1.Secret, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string][]byte{sdkv1alpha1.ServerKeyPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
	}
	if owner != nil {
		s.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: sdkv1alpha1.SchemeGroupVersion.String(), Kind: "ServerKey",
			Name: owner.Name, UID: owner.UID, Controller: ptr(true),
		}}
	}
	return s, priv
}

func ptr[T any](v T) *T { return &v }

func TestServerKeyGenerated(t *testing.T) {
	c := newClient(t, newServerKey("sk-1"))
	key := reconcileKey(t, c, "sk-1")
	assert.Equal(t, "True/AsExpected", readyReason(key))

	var secret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "sk-1"}, &secret))
	assert.True(t, metav1.IsControlledBy(&secret, key))
	signer, err := parsePrivateKey(secret.Data[sdkv1alpha1.ServerKeyPrivateKey])
	require.NoError(t, err)
	_, isECDSA := signer.(*ecdsa.PrivateKey)
	assert.True(t, isECDSA)

	pub, fp, err := publicKey(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, pub, key.Status.PublicKey)
	assert.Equal(t, fp, key.Status.Fingerprint)

	// Reconciling again changes nothing.
	again := reconcileKey(t, c, "sk-1")
	assert.Equal(t, key.Status.PublicKey, again.Status.PublicKey)
}

func TestServerKeyPublishedFromOwnedSecretAfterACrash(t *testing.T) {
	key := newServerKey("sk-1")
	key.UID = "uid-1"
	secret, priv := secretFor(t, "sk-1", key)
	c := newClient(t, key, secret)

	got := reconcileKey(t, c, "sk-1")
	want, err := fingerprint.OfPublicKey(priv.Public())
	require.NoError(t, err)
	assert.Equal(t, want.String(), got.Status.Fingerprint)
	assert.Equal(t, "True/AsExpected", readyReason(got))
}

func TestServerKeyRefusesForeignSecret(t *testing.T) {
	secret, _ := secretFor(t, "sk-1", nil)
	c := newClient(t, newServerKey("sk-1"), secret)
	got := reconcileKey(t, c, "sk-1")
	assert.Equal(t, "False/KeyMismatch", readyReason(got))
	assert.Empty(t, got.Status.PublicKey, "a key it doesn't own is never published")
}

func TestServerKeyNeverRegenerated(t *testing.T) {
	c := newClient(t, newServerKey("sk-1"))
	published := reconcileKey(t, c, "sk-1")

	var secret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "sk-1"}, &secret))
	require.NoError(t, c.Delete(context.Background(), &secret))

	got := reconcileKey(t, c, "sk-1")
	assert.Equal(t, "False/KeyMissing", readyReason(got))
	assert.Equal(t, published.Status.PublicKey, got.Status.PublicKey)
	err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "sk-1"}, &secret)
	assert.Error(t, err, "no new key under the same name")
}

func TestServerKeyMismatch(t *testing.T) {
	c := newClient(t, newServerKey("sk-1"))
	reconcileKey(t, c, "sk-1")

	other, _ := secretFor(t, "sk-1", nil)
	var secret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "sk-1"}, &secret))
	secret.Data = other.Data
	require.NoError(t, c.Update(context.Background(), &secret))

	assert.Equal(t, "False/KeyMismatch", readyReason(reconcileKey(t, c, "sk-1")))

	secret.Data = map[string][]byte{sdkv1alpha1.ServerKeyPrivateKey: []byte("garbage")}
	require.NoError(t, c.Update(context.Background(), &secret))
	assert.Equal(t, "False/KeyMismatch", readyReason(reconcileKey(t, c, "sk-1")))
}

func TestEnsureServerKey(t *testing.T) {
	c := newClient(t)
	require.NoError(t, EnsureServerKey(context.Background(), c, ns))
	require.NoError(t, EnsureServerKey(context.Background(), c, ns))
	var list sdkv1alpha1.ServerKeyList
	require.NoError(t, c.List(context.Background(), &list))
	assert.Len(t, list.Items, 1)
}

func TestKeyStore(t *testing.T) {
	c := newClient(t, newServerKey("sk-1"))
	key := reconcileKey(t, c, "sk-1")
	store := &KeyStore{Client: c, Namespace: ns}

	ik, err := store.Get(context.Background(), "sk-1")
	require.NoError(t, err)
	assert.Equal(t, key.Status.Fingerprint, ik.Fingerprint.String())

	again, err := store.Get(context.Background(), "sk-1")
	require.NoError(t, err)
	assert.Equal(t, ik.Certificate.Certificate, again.Certificate.Certificate, "cached")

	// A Secret that no longer matches is refused.
	other, _ := secretFor(t, "sk-1", nil)
	var secret corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "sk-1"}, &secret))
	secret.Data = other.Data
	require.NoError(t, c.Update(context.Background(), &secret))
	_, err = store.Get(context.Background(), "sk-1")
	assert.Error(t, err)

	_, err = store.Get(context.Background(), "missing")
	assert.Error(t, err)
}
