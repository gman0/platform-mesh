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

// Package server implements the user-side /access HTTP handlers.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	pmaccessproto "go.platform-mesh.io/protocol/access"
	pmaccessv1 "go.platform-mesh.io/protocol/access/v1"
	accessv1alpha1 "go.platform-mesh.io/sdk/access/apis/v1alpha1"
	accessctrl "go.platform-mesh.io/sdk/access/internal/controller"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// KubeconfigSecretKey is the key under which the delivered kubeconfig
// is written into the owned Secret.
const KubeconfigSecretKey = "kubeconfig"

// Handler serves POST /v1/access against the user-side cluster. On a
// verified handshake it writes the delivered kubeconfig as a Secret
// owned by a freshly-created Access CR, and responds 200 empty.
//
// TLS and listener wiring live in the SDK binary; this type is a
// plain http.Handler mounted by the top-level mux at /v1/access.
type Handler struct {
	Client      ctrlruntimeclient.Client
	Scheme      *runtime.Scheme
	ReplayCache *pmaccessproto.ReplayCache
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		http.Error(w, "missing Bearer credential", http.StatusForbidden)
		return
	}
	jwt := auth[len(prefix):]

	// Peek sub to resolve which AccessIdentity this handshake is for.
	pre, err := pmaccessproto.ParseUnverified(jwt)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse credential: %v", err), http.StatusForbidden)
		return
	}

	identity, err := h.lookupIdentity(ctx, pre.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Load HMAC secret from the owned Secret's pma1 wire string.
	hmacSecret, err := h.loadHMACSecret(ctx, identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	claims, err := pmaccessproto.Verify(hmacSecret, jwt, body, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf("verify: %v", err), http.StatusForbidden)
		return
	}

	// Replay check.
	if h.ReplayCache != nil {
		if !h.ReplayCache.Seen(claims.Subject, claims.ID, claims.ExpiresAt.Time) {
			http.Error(w, "Replay", http.StatusForbidden)
			return
		}
	}

	// Manual accept mode is deferred to Stage 4.
	if identity.Spec.Accept == accessv1alpha1.AcceptModeManual {
		http.Error(w, "AcceptModeManualDeferred", http.StatusForbidden)
		return
	}

	// Parse delivery body.
	var payload pmaccessv1.HandshakeRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, fmt.Sprintf("parse body: %v", err), http.StatusForbidden)
		return
	}
	if payload.KcpURL == "" || payload.SAToken == "" {
		http.Error(w, "body missing kcpURL or saToken", http.StatusForbidden)
		return
	}

	if err := h.admit(ctx, identity, &payload); err != nil {
		// Admission mutates cluster state; signal 500 so the operator
		// retries rather than treating it as a terminal rejection.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) lookupIdentity(ctx context.Context, tokenID string) (*accessv1alpha1.AccessIdentity, error) {
	var list accessv1alpha1.AccessIdentityList
	if err := h.Client.List(ctx, &list, ctrlruntimeclient.MatchingFields{accessctrl.TokenIDIndex: tokenID}); err != nil {
		return nil, fmt.Errorf("lookup AccessIdentity: %w", err)
	}
	switch len(list.Items) {
	case 0:
		return nil, fmt.Errorf("UnknownIdentity")
	case 1:
		return &list.Items[0], nil
	default:
		return nil, fmt.Errorf("AmbiguousIdentity")
	}
}

func (h *Handler) loadHMACSecret(ctx context.Context, identity *accessv1alpha1.AccessIdentity) ([]byte, error) {
	secret := &corev1.Secret{}
	name := identity.Name + "-access-token"
	if err := h.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: identity.Namespace}, secret); err != nil {
		return nil, fmt.Errorf("get owned Secret %q: %w", name, err)
	}
	wire, ok := secret.Data[accessctrl.AccessTokenSecretKey]
	if !ok || len(wire) == 0 {
		return nil, fmt.Errorf("owned Secret %q has no access-token value", name)
	}
	parsed, err := pmaccessproto.ParseToken(string(wire))
	if err != nil {
		return nil, fmt.Errorf("owned Secret %q does not parse: %w", name, err)
	}
	return parsed.Secret, nil
}

// admit creates the Access CR, writes the kubeconfig Secret owned by
// that Access, and marks the Access Phase=Active. Idempotency is best
// effort via IsAlreadyExists tolerance; the replay cache is the
// primary guard against duplicate admission for the same jti.
func (h *Handler) admit(ctx context.Context, identity *accessv1alpha1.AccessIdentity, payload *pmaccessv1.HandshakeRequest) error {
	suffix, err := randSuffix()
	if err != nil {
		return fmt.Errorf("generate access suffix: %w", err)
	}
	accessName := identity.Name + "-" + suffix
	kubeconfigSecretName := accessName + "-kubeconfig"

	access := &accessv1alpha1.Access{
		ObjectMeta: metav1.ObjectMeta{Name: accessName, Namespace: identity.Namespace},
		Spec: accessv1alpha1.AccessSpec{
			IdentityRef:         corev1.LocalObjectReference{Name: identity.Name},
			KubeconfigSecretRef: &corev1.LocalObjectReference{Name: kubeconfigSecretName},
		},
	}
	if err := h.Client.Create(ctx, access); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create Access %q: %w", accessName, err)
	}

	kubeconfigBytes, err := buildKubeconfig(payload)
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}

	kcSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kubeconfigSecretName, Namespace: identity.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, h.Client, kcSecret, func() error {
		if err := controllerutil.SetControllerReference(access, kcSecret, h.Scheme); err != nil {
			return err
		}
		if kcSecret.Data == nil {
			kcSecret.Data = map[string][]byte{}
		}
		kcSecret.Data[KubeconfigSecretKey] = kubeconfigBytes
		return nil
	}); err != nil {
		return fmt.Errorf("upsert kubeconfig Secret %q: %w", kubeconfigSecretName, err)
	}

	access.Status.Phase = accessv1alpha1.AccessPhaseActive
	now := metav1.Now()
	access.Status.LastRefreshed = &now
	if err := h.Client.Status().Update(ctx, access); err != nil {
		return fmt.Errorf("update Access.status for %q: %w", accessName, err)
	}
	return nil
}

func buildKubeconfig(payload *pmaccessv1.HandshakeRequest) ([]byte, error) {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters = map[string]*clientcmdapi.Cluster{
		"pm-kcp": {
			Server:                   payload.KcpURL,
			CertificateAuthorityData: []byte(payload.KcpCABundle),
		},
	}
	cfg.AuthInfos = map[string]*clientcmdapi.AuthInfo{
		"pm-sa": {Token: payload.SAToken},
	}
	cfg.Contexts = map[string]*clientcmdapi.Context{
		"pm": {Cluster: "pm-kcp", AuthInfo: "pm-sa"},
	}
	cfg.CurrentContext = "pm"
	return clientcmd.Write(*cfg)
}

func randSuffix() (string, error) {
	var buf [4]byte // 6 base64url chars
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
