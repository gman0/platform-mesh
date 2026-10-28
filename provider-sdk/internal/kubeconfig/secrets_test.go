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
	"crypto/tls"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const connID = "c-abcdefghijklmnopqrstuvwxyz"

type staticSource struct{ bundle []byte }

func (s *staticSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
func (s *staticSource) Bundle() ([]byte, error)                                      { return s.bundle, nil }

type writerFixture struct {
	t      *testing.T
	client client.Client
	source *staticSource
	w      *Writer
}

func newWriterFixture(t *testing.T) *writerFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, sdkv1alpha1.AddToScheme(scheme))
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: connID, Namespace: ns, UID: "uid-1"},
		Spec:       sdkv1alpha1.ConnectionSpec{Registration: sdkv1alpha1.ConnectionRegistration{Owner: "alice", ClusterName: "2x8k9abc"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdkv1alpha1.Connection{}).WithObjects(conn).Build()
	src := &staticSource{bundle: []byte("-----BEGIN CERTIFICATE-----\nca1\n-----END CERTIFICATE-----\n")}
	return &writerFixture{t: t, client: c, source: src, w: &Writer{
		Client: c, Namespace: ns, Source: src,
		ProxyHost: "provider-gateway.wild-west-system.svc:3128", ServerName: gatewayName,
	}}
}

func (f *writerFixture) conn() *sdkv1alpha1.Connection {
	f.t.Helper()
	var c sdkv1alpha1.Connection
	require.NoError(f.t, f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: connID}, &c))
	return &c
}

func (f *writerFixture) ensure() {
	f.t.Helper()
	require.NoError(f.t, f.w.Ensure(context.Background(), f.conn()))
}

func (f *writerFixture) secret() (*corev1.Secret, error) {
	var s corev1.Secret
	err := f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: SecretName(connID)}, &s)
	return &s, err
}

func TestEnsureWritesKubeconfig(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()

	s, err := f.secret()
	require.NoError(t, err)
	assert.Equal(t, connID, s.Labels[sdkv1alpha1.ConnectionLabel])
	assert.Equal(t, "2x8k9abc", s.Annotations[sdkv1alpha1.ClusterNameAnnotation])
	assert.True(t, metav1.IsControlledBy(s, f.conn()))

	cfg, err := clientcmd.Load(s.Data[sdkv1alpha1.KubeconfigKey])
	require.NoError(t, err)
	assert.Equal(t, connID, cfg.CurrentContext)
	cluster := cfg.Clusters[connID]
	require.NotNil(t, cluster)
	assert.Equal(t, "https://front-proxy.pm.invalid/clusters/2x8k9abc", cluster.Server)
	assert.Equal(t, gatewayName, cluster.TLSServerName)
	assert.Equal(t, f.source.bundle, cluster.CertificateAuthorityData)
	assert.Empty(t, cfg.AuthInfos[connID].Token, "no kcp credential")

	u, err := url.Parse(cluster.ProxyURL)
	require.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "provider-gateway.wild-west-system.svc:3128", u.Host)
	assert.Equal(t, connID, u.User.Username())
	credential, _ := u.User.Password()
	assert.True(t, CheckCredential(f.conn(), credential))
	assert.NotContains(t, f.conn().Status.ProxyCredentialHash, credential, "only the hash is stored")
}

func TestEnsureIsIdempotent(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()
	s1, err := f.secret()
	require.NoError(t, err)
	hash := f.conn().Status.ProxyCredentialHash

	f.ensure()
	s2, err := f.secret()
	require.NoError(t, err)
	assert.Equal(t, s1.ResourceVersion, s2.ResourceVersion, "nothing written")
	assert.Equal(t, hash, f.conn().Status.ProxyCredentialHash)
}

func TestEnsureFollowsTheBundle(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()
	hash := f.conn().Status.ProxyCredentialHash

	f.source.bundle = []byte("-----BEGIN CERTIFICATE-----\nca2\n-----END CERTIFICATE-----\n")
	f.ensure()
	s, err := f.secret()
	require.NoError(t, err)
	cfg, err := clientcmd.Load(s.Data[sdkv1alpha1.KubeconfigKey])
	require.NoError(t, err)
	assert.Equal(t, f.source.bundle, cfg.Clusters[connID].CertificateAuthorityData)
	assert.Equal(t, hash, f.conn().Status.ProxyCredentialHash, "the credential stays")
}

func TestEnsureRotatesTheCredential(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()
	s, err := f.secret()
	require.NoError(t, err)
	old := credentialIn(s.Data[sdkv1alpha1.KubeconfigKey], connID)

	c := f.conn()
	c.Annotations = map[string]string{sdkv1alpha1.AnnotationRotateProxyCredential: "2026-10-20"}
	require.NoError(t, f.client.Update(context.Background(), c))
	f.ensure()

	s, err = f.secret()
	require.NoError(t, err)
	current := credentialIn(s.Data[sdkv1alpha1.KubeconfigKey], connID)
	assert.NotEqual(t, old, current)
	c = f.conn()
	assert.True(t, CheckCredential(c, current))
	assert.True(t, CheckCredential(c, old), "the previous credential works during the rotation")
	assert.Equal(t, "2026-10-20", c.Status.ProxyCredentialRotation)

	// The same annotation value doesn't rotate again.
	f.ensure()
	s, err = f.secret()
	require.NoError(t, err)
	assert.Equal(t, current, credentialIn(s.Data[sdkv1alpha1.KubeconfigKey], connID))
}

func TestEnsureRecreatesALostSecret(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()
	s, err := f.secret()
	require.NoError(t, err)
	old := credentialIn(s.Data[sdkv1alpha1.KubeconfigKey], connID)
	require.NoError(t, f.client.Delete(context.Background(), s))

	f.ensure()
	s, err = f.secret()
	require.NoError(t, err)
	current := credentialIn(s.Data[sdkv1alpha1.KubeconfigKey], connID)
	assert.NotEqual(t, old, current, "a lost credential is replaced, never recovered")
	assert.True(t, CheckCredential(f.conn(), current))
	assert.False(t, CheckCredential(f.conn(), old))
}

func TestEnsureInItsOwnNamespace(t *testing.T) {
	f := newWriterFixture(t)
	f.w.Namespace = "wild-west-kubeconfigs"
	f.ensure()

	var s corev1.Secret
	require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{Namespace: f.w.Namespace, Name: SecretName(connID)}, &s))
	assert.Equal(t, connID, s.Labels[sdkv1alpha1.ConnectionLabel])
	assert.Empty(t, s.OwnerReferences, "owner references can't cross namespaces")
	_, err := f.secret()
	assert.Error(t, err, "nothing in the Connection's namespace")

	require.NoError(t, f.w.Delete(context.Background(), connID))
	err = f.client.Get(context.Background(), types.NamespacedName{Namespace: f.w.Namespace, Name: SecretName(connID)}, &s)
	assert.Error(t, err)
}

func TestDelete(t *testing.T) {
	f := newWriterFixture(t)
	f.ensure()
	require.NoError(t, f.w.Delete(context.Background(), connID))
	_, err := f.secret()
	assert.Error(t, err)
	require.NoError(t, f.w.Delete(context.Background(), connID), "deleting twice is harmless")
}

func TestCheckCredential(t *testing.T) {
	c := &sdkv1alpha1.Connection{}
	assert.False(t, CheckCredential(c, ""), "no hash, nothing matches")
	c.Status.ProxyCredentialHash = HashCredential("secret")
	assert.True(t, CheckCredential(c, "secret"))
	assert.False(t, CheckCredential(c, "other"))
	assert.False(t, CheckCredential(c, ""))
}
