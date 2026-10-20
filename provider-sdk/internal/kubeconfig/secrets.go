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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// FrontProxyPlaceholder is the host kubeconfigs use for the Provider
// Workspace. The Provider-side has no name for the front-proxy; this one is
// never resolved, and the Connector ignores it.
const FrontProxyPlaceholder = "front-proxy.pm.invalid"

// SecretName is the name of a Connection's kubeconfig Secret.
func SecretName(connectionID string) string { return "connection-" + connectionID }

// Writer writes the kubeconfig Secrets.
type Writer struct {
	Client    client.Client
	Namespace string
	// Source provides the trust bundle the kubeconfigs carry.
	Source Source
	// ProxyHost is the operator proxy's host:port, e.g.
	// provider-gateway.<namespace>.svc:3128.
	ProxyHost string
	// ServerName is the name the operator verifies the proxy's certificate
	// against, inside every tunnel too: tls-server-name.
	ServerName string
}

// Ensure makes the Connection's kubeconfig Secret match it, writing only
// what changed: a missing Secret, a new trust bundle, a requested credential
// rotation. The credential's hash is in the Connection's status; the
// credential itself only in the Secret.
func (w *Writer) Ensure(ctx context.Context, conn *sdkv1alpha1.Connection) error {
	bundle, err := w.Source.Bundle()
	if err != nil {
		return err
	}
	var secret corev1.Secret
	err = w.Client.Get(ctx, types.NamespacedName{Namespace: w.Namespace, Name: SecretName(conn.Name)}, &secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	exists := err == nil

	credential := ""
	if exists {
		credential = credentialIn(secret.Data[sdkv1alpha1.KubeconfigKey], conn.Name)
	}
	rotation := conn.Annotations[sdkv1alpha1.AnnotationRotateProxyCredential]
	rotate := rotation != "" && rotation != conn.Status.ProxyCredentialRotation
	if rotate || credential == "" || !matches(conn.Status.ProxyCredentialHash, credential) {
		if credential, err = w.newCredential(ctx, conn, rotate, rotation); err != nil {
			return err
		}
	}

	data, err := w.kubeconfig(conn, credential, bundle)
	if err != nil {
		return err
	}
	if exists && bytes.Equal(secret.Data[sdkv1alpha1.KubeconfigKey], data) {
		return nil
	}
	secret.Name, secret.Namespace = SecretName(conn.Name), w.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, w.Client, &secret, func() error {
		secret.Type = corev1.SecretTypeOpaque
		metav1.SetMetaDataLabel(&secret.ObjectMeta, sdkv1alpha1.ConnectionLabel, conn.Name)
		metav1.SetMetaDataLabel(&secret.ObjectMeta, "app.kubernetes.io/managed-by", "provider-gateway")
		metav1.SetMetaDataAnnotation(&secret.ObjectMeta, sdkv1alpha1.ClusterNameAnnotation, conn.Spec.Registration.ClusterName)
		secret.Data = map[string][]byte{sdkv1alpha1.KubeconfigKey: data}
		return controllerutil.SetControllerReference(conn, &secret, w.Client.Scheme())
	})
	return err
}

// newCredential records a new credential's hash in the Connection's status
// before it's written to the Secret, so a crash in between at worst leads to
// another new credential. On a rotation, the current hash stays accepted.
func (w *Writer) newCredential(ctx context.Context, conn *sdkv1alpha1.Connection, rotate bool, rotation string) (string, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	credential := base64.RawURLEncoding.EncodeToString(b)

	before := conn.DeepCopy()
	if rotate {
		conn.Status.PreviousProxyCredentialHash = conn.Status.ProxyCredentialHash
		conn.Status.ProxyCredentialRotation = rotation
	}
	conn.Status.ProxyCredentialHash = hashOf(credential)
	if err := w.Client.Status().Patch(ctx, conn, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return "", err
	}
	return credential, nil
}

func (w *Writer) kubeconfig(conn *sdkv1alpha1.Connection, credential string, bundle []byte) ([]byte, error) {
	proxy := url.URL{Scheme: "https", User: url.UserPassword(conn.Name, credential), Host: w.ProxyHost}
	cfg := clientcmdapi.NewConfig()
	cluster := clientcmdapi.NewCluster()
	cluster.Server = "https://" + FrontProxyPlaceholder + "/clusters/" + conn.Spec.Registration.ClusterName
	cluster.ProxyURL = proxy.String()
	cluster.TLSServerName = w.ServerName
	cluster.CertificateAuthorityData = bundle
	cfg.Clusters[conn.Name] = cluster
	// No credentials towards kcp: the Connector adds the SA token.
	cfg.AuthInfos[conn.Name] = clientcmdapi.NewAuthInfo()
	cfg.Contexts[conn.Name] = &clientcmdapi.Context{Cluster: conn.Name, AuthInfo: conn.Name}
	cfg.CurrentContext = conn.Name
	return clientcmd.Write(*cfg)
}

// Delete removes the Connection's kubeconfig Secret.
func (w *Writer) Delete(ctx context.Context, connectionID string) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: SecretName(connectionID), Namespace: w.Namespace}}
	return client.IgnoreNotFound(w.Client.Delete(ctx, secret))
}

// CheckCredential reports whether credential is the Connection's current
// proxy credential, or the previous one during a rotation.
func CheckCredential(conn *sdkv1alpha1.Connection, credential string) bool {
	return matches(conn.Status.ProxyCredentialHash, credential) ||
		matches(conn.Status.PreviousProxyCredentialHash, credential)
}

// credentialIn returns the proxy credential in a kubeconfig, if its user is
// the Connection.
func credentialIn(data []byte, connectionID string) string {
	cfg, err := clientcmd.Load(data)
	if err != nil {
		return ""
	}
	cluster := cfg.Clusters[connectionID]
	if cluster == nil {
		return ""
	}
	u, err := url.Parse(cluster.ProxyURL)
	if err != nil || u.User == nil || u.User.Username() != connectionID {
		return ""
	}
	p, _ := u.User.Password()
	return p
}

func hashOf(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func matches(hash, credential string) bool {
	if hash == "" || credential == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hash), []byte(hashOf(credential))) == 1
}
