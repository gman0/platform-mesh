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

// Package subroutines hosts access-operator-local helpers that don't fit
// into a specific subroutine subpackage. The kcp-admin plumbing here is
// a near-duplicate of the equivalent code in platform-mesh-operator.
//
// TODO(stage-5): extract into a shared module (golang-commons/kcp-admin
// or similar) so both operators consume one implementation.
package subroutines

import (
	"context"
	"fmt"

	"go.platform-mesh.io/access-operator/internal/config"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// BuildKubeconfigFromConfig builds a *rest.Config for the kcp admin
// plane out of the cluster-admin Secret in the operator's local cluster.
// Accepts either an Opaque Secret with a pre-built "kubeconfig" blob or
// a kubernetes.io/tls Secret with ca.crt + tls.crt + tls.key.
//
// kcpUrl overrides the server URL embedded in the Secret's kubeconfig.
func BuildKubeconfigFromConfig(ctx context.Context, cl ctrlruntimeclient.Client, kcpCfg *config.KCPConfig, kcpUrl string) (*rest.Config, error) {
	secret := &corev1.Secret{}
	err := cl.Get(ctx, types.NamespacedName{Name: kcpCfg.ClusterAdminSecretName, Namespace: kcpCfg.Namespace}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("cluster-admin secret %s/%s not found", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName)
		}
		return nil, fmt.Errorf("get cluster-admin secret %s/%s: %w", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName, err)
	}
	if secret.Data == nil {
		return nil, fmt.Errorf("cluster-admin secret %s/%s has no Data", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName)
	}

	// Opaque secret with a pre-built kubeconfig blob.
	if kubeconfigData, ok := secret.Data["kubeconfig"]; ok && len(kubeconfigData) > 0 {
		cfg, err := clientcmd.Load(kubeconfigData)
		if err != nil {
			return nil, fmt.Errorf("parse kubeconfig from secret %s/%s: %w", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName, err)
		}
		for _, cluster := range cfg.Clusters {
			cluster.Server = kcpUrl
		}
		return clientcmd.NewDefaultClientConfig(*cfg, nil).ClientConfig()
	}

	// kubernetes.io/tls secret with ca.crt + tls.crt + tls.key.
	caData, ok := secret.Data["ca.crt"]
	if !ok || len(caData) == 0 {
		return nil, fmt.Errorf("secret %s/%s missing both \"kubeconfig\" and \"ca.crt\" keys", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName)
	}
	tlsCrt, ok := secret.Data["tls.crt"]
	if !ok || len(tlsCrt) == 0 {
		return nil, fmt.Errorf("secret %s/%s missing or empty \"tls.crt\"", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName)
	}
	tlsKey, ok := secret.Data["tls.key"]
	if !ok || len(tlsKey) == 0 {
		return nil, fmt.Errorf("secret %s/%s missing or empty \"tls.key\"", kcpCfg.Namespace, kcpCfg.ClusterAdminSecretName)
	}

	raw := clientcmdapi.NewConfig()
	raw.Clusters = map[string]*clientcmdapi.Cluster{
		"kcp": {Server: kcpUrl, CertificateAuthorityData: caData},
	}
	raw.Contexts = map[string]*clientcmdapi.Context{
		"admin": {Cluster: "kcp", AuthInfo: "admin"},
	}
	raw.AuthInfos = map[string]*clientcmdapi.AuthInfo{
		"admin": {ClientCertificateData: tlsCrt, ClientKeyData: tlsKey},
	}
	raw.CurrentContext = "admin"
	return clientcmd.NewDefaultClientConfig(*raw, nil).ClientConfig()
}
