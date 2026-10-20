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

package kubeconfig

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	ns          = "wild-west-system"
	gatewayName = "provider-gateway.wild-west-system.svc"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func caSecret(t *testing.T, c client.Client) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: DefaultCASecretName}, &s))
	return &s
}

func TestEnsureCAGeneratesOnce(t *testing.T) {
	c := newClient(t)
	ca, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, now)
	require.NoError(t, err)
	assert.Equal(t, noExpiry, ca.cert.NotAfter, "never expires, never rotated")

	s := caSecret(t, c)
	assert.Equal(t, corev1.SecretTypeTLS, s.Type)
	assert.Equal(t, s.Data[corev1.TLSCertKey], s.Data[caBundleKey])
	assert.Equal(t, s.Data[caBundleKey], ca.Bundle())

	// Years later, it's the same CA.
	again, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, now.Add(50*365*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, ca.cert.Raw, again.cert.Raw)
}

func TestEnsureCAUsesAnExistingSecret(t *testing.T) {
	// e.g. written by an administrator, with a separate trust bundle.
	other := newClient(t)
	ca, err := EnsureCA(context.Background(), other, ns, DefaultCASecretName, now)
	require.NoError(t, err)
	s := caSecret(t, other)
	s.ResourceVersion = ""
	s.Data[caBundleKey] = append(append([]byte{}, s.Data[caBundleKey]...), s.Data[caBundleKey]...)

	c := newClient(t, s)
	loaded, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, now)
	require.NoError(t, err)
	assert.Equal(t, ca.cert.Raw, loaded.cert.Raw)
	assert.Equal(t, s.Data[caBundleKey], loaded.Bundle())
}

func TestEnsureCARefusesNonCA(t *testing.T) {
	c := newClient(t)
	ca, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, now)
	require.NoError(t, err)
	leaf, err := ca.Issue([]string{gatewayName}, now)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	require.NoError(t, err)

	s := caSecret(t, c)
	s.Data[corev1.TLSCertKey] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Leaf.Raw})
	s.Data[corev1.TLSPrivateKeyKey] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, c.Update(context.Background(), s))
	_, err = EnsureCA(context.Background(), c, ns, DefaultCASecretName, now)
	assert.ErrorContains(t, err, "isn't a CA")
}

func TestSelfSigned(t *testing.T) {
	c := newClient(t)
	ca, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, now)
	require.NoError(t, err)
	at := now
	s := &SelfSigned{CA: ca, Names: []string{gatewayName}, Now: func() time.Time { return at }}

	first, err := s.GetCertificate(nil)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	bundle, err := s.Bundle()
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(bundle))
	_, err = first.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: gatewayName, CurrentTime: at})
	assert.NoError(t, err, "verifies against the bundle, by the gateway's name")

	same, err := s.GetCertificate(nil)
	require.NoError(t, err)
	assert.Same(t, first, same, "cached")

	at = first.Leaf.NotAfter.Add(-servingRenewAt + time.Hour)
	renewed, err := s.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotSame(t, first, renewed, "reissued before expiry")
}

func TestFileSource(t *testing.T) {
	// A Secret as cert-manager writes it, mounted into a directory.
	c := newClient(t)
	ca, err := EnsureCA(context.Background(), c, ns, DefaultCASecretName, time.Now())
	require.NoError(t, err)
	leaf, err := ca.Issue([]string{gatewayName}, time.Now())
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Leaf.Raw}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), ca.Bundle(), 0o600))

	s, err := NewFileSource(dir)
	require.NoError(t, err)
	cert, err := s.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, leaf.Leaf.Raw, cert.Certificate[0])
	bundle, err := s.Bundle()
	require.NoError(t, err)
	assert.Equal(t, ca.Bundle(), bundle)
}
