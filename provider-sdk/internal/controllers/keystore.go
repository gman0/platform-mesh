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
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.platform-mesh.io/provider-protocol/innertls"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// KeyStore loads Server Keys for the Inner TLS from their Secrets. A key is
// served only while its ServerKey is Ready and the Secret's key matches the
// published public key. Keys are cached until their Secret changes.
type KeyStore struct {
	Client    client.Client
	Namespace string

	mu    sync.Mutex
	cache map[string]cachedKey
}

type cachedKey struct {
	secretVersion string
	key           innertls.ServerKey
}

// Get returns the Server Key named name.
func (s *KeyStore) Get(ctx context.Context, name string) (innertls.ServerKey, error) {
	nn := types.NamespacedName{Namespace: s.Namespace, Name: name}
	var key sdkv1alpha1.ServerKey
	if err := s.Client.Get(ctx, nn, &key); err != nil {
		return innertls.ServerKey{}, err
	}
	if key.Status.PublicKey == "" || !meta.IsStatusConditionTrue(key.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady) {
		return innertls.ServerKey{}, fmt.Errorf("ServerKey %s isn't ready", name)
	}
	var secret corev1.Secret
	if err := s.Client.Get(ctx, nn, &secret); err != nil {
		return innertls.ServerKey{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cache[name]; ok && c.secretVersion == secret.ResourceVersion && secret.ResourceVersion != "" {
		return c.key, nil
	}
	signer, err := parsePrivateKey(secret.Data[sdkv1alpha1.ServerKeyPrivateKey])
	if err != nil {
		return innertls.ServerKey{}, fmt.Errorf("ServerKey %s: %w", name, err)
	}
	pub, _, err := publicKey(signer.Public())
	if err != nil || pub != key.Status.PublicKey {
		return innertls.ServerKey{}, fmt.Errorf("ServerKey %s: the private key doesn't match its public key", name)
	}
	ik, err := innertls.NewServerKey(signer)
	if err != nil {
		return innertls.ServerKey{}, err
	}
	if s.cache == nil {
		s.cache = map[string]cachedKey{}
	}
	s.cache[name] = cachedKey{secretVersion: secret.ResourceVersion, key: ik}
	return ik, nil
}
