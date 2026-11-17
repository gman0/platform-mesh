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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-logr/logr"

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// KubeconfigSecretKey is the key under which the delivered kubeconfig
// is written into the owned Secret.
const KubeconfigSecretKey = "kubeconfig"

const AccessOperatorLabelKey = "access-sdk.platform-mesh.io/kubeconfig"

// maxRequestBodyBytes caps the handshake request body. The payload
// carries a URL, a PEM CA bundle, and a k8s SA token — well under
// this ceiling. The cap is a DoS bound, not a shape check.
const maxRequestBodyBytes = 64 << 10

// Handler serves POST /v1/access against the user-side cluster. On a
// verified handshake it writes the delivered kubeconfig as a Secret
// owned by a freshly-created Access CR, and responds 200 empty.
//
// TLS and listener wiring live in the SDK binary; this type is a
// plain http.Handler mounted by the top-level mux at /v1/access.
type Handler struct {
	Client      client.Client
	Scheme      *runtime.Scheme
	ReplayCache *pmaccessproto.ReplayCache
	Log         logr.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	jwt, err := parseBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, h.Log, err)
		return
	}
	handshake, err := h.doHandshake(r.Context(), jwt, body)
	if err != nil {
		writeError(w, h.Log, err)
		return
	}
	if err := h.doCommit(r.Context(), handshake); err != nil {
		writeError(w, h.Log, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// verifiedCredential is the output of verifyCredential: the resolved
// identity and the JWT's jti.
type verifiedCredential struct {
	identity *accessv1alpha1.AccessIdentity
	jti      string
}

// validatedHandshake bundles the outputs of the read-only handshake
// phase: the resolved identity, the decoded delivery payload, and the
// JWT's jti. doCommit consumes this to persist the request.
type validatedHandshake struct {
	identity *accessv1alpha1.AccessIdentity
	payload  *pmaccessv1.HandshakeRequest
	jti      string
}

// doHandshake runs the read-only checks: verify the credential, enforce
// the accept-mode gate, and decode the delivery body. All errors
// carry an *httpError with a 4xx code.
func (h *Handler) doHandshake(ctx context.Context, jwt string, body []byte) (*validatedHandshake, error) {
	cred, err := h.verifyCredential(ctx, jwt, body)
	if err != nil {
		return nil, err
	}
	if cred.identity.Spec.Accept != accessv1alpha1.AcceptModeAlways {
		return nil, httpErr(http.StatusNotImplemented, publicNotImplemented, nil)
	}
	payload, err := decodeDelivery(body)
	if err != nil {
		return nil, err
	}
	return &validatedHandshake{identity: cred.identity, payload: payload, jti: cred.jti}, nil
}

// verifyCredential resolves the identity named by the JWT's sub,
// loads its HMAC secret, verifies the signature over jwt+body, and
// records the jti in the replay cache.
func (h *Handler) verifyCredential(ctx context.Context, jwt string, body []byte) (*verifiedCredential, error) {
	// Read sub from the token to resolve which AccessIdentity this handshake is for.
	// We don't trust it yet, so all the code below, up until Verify(), treats it as such.
	pre, err := pmaccessproto.ParseUnverified(jwt)
	if err != nil {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, fmt.Errorf("parse credential: %w", err))
	}
	identity, err := h.findAccessIdentity(ctx, pre.Subject)
	if err != nil {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, err)
	}
	hmacSecret, err := h.findSecretForAccessIdentity(ctx, identity)
	if err != nil {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, err)
	}
	claims, err := pmaccessproto.Verify(hmacSecret, jwt, body, 0)
	if err != nil {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, fmt.Errorf("verify: %w", err))
	}
	if h.ReplayCache != nil && !h.ReplayCache.Seen(claims.Subject, claims.ID, claims.ExpiresAt.Time) {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, fmt.Errorf("replay for sub=%s jti=%s", claims.Subject, claims.ID))
	}
	return &verifiedCredential{identity: identity, jti: claims.ID}, nil
}

// doCommit mutates cluster state: creates the Access CR, writes the
// kubeconfig Secret owned by it, and marks the Access Active. The
// Access name is deterministic in (identity, jti) so that concurrent
// replicas racing on the same jti collapse to a single admission via
// AlreadyExists.
func (h *Handler) doCommit(ctx context.Context, handshake *validatedHandshake) error {
	accessName := buildAccessName(handshake.identity.Name, handshake.jti)
	kubeconfigSecretName := accessName + "-kubeconfig"

	access, err := h.createAccess(ctx, handshake.identity, accessName, kubeconfigSecretName)
	if err != nil {
		return httpErr(http.StatusInternalServerError, publicInternalError, err)
	}
	if err := h.writeKubeconfigSecret(ctx, access, kubeconfigSecretName, handshake.identity.Namespace, handshake.payload); err != nil {
		return httpErr(http.StatusInternalServerError, publicInternalError, err)
	}
	if err := h.markAccessActive(ctx, access); err != nil {
		return httpErr(http.StatusInternalServerError, publicInternalError, err)
	}
	return nil
}

// buildAccessName derives a deterministic Access CR name from an
// identity name and a jti. Collisions on different jtis are bounded
// by a 40-bit SHA-256 prefix (~2^-40).
func buildAccessName(identityName, jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return identityName + "-" + hex.EncodeToString(sum[:5])
}

func parseBearer(auth string) (string, error) {
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return "", httpErr(http.StatusForbidden, publicForbidden, fmt.Errorf("missing Bearer credential"))
	}
	return auth[len(prefix):], nil
}

func decodeDelivery(body []byte) (*pmaccessv1.HandshakeRequest, error) {
	var payload pmaccessv1.HandshakeRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, fmt.Errorf("parse body: %w", err))
	}
	if payload.KcpURL == "" || payload.SAToken == "" {
		return nil, httpErr(http.StatusForbidden, publicInvalidCredential, fmt.Errorf("body missing kcpURL or saToken"))
	}
	return &payload, nil
}

func (h *Handler) findAccessIdentity(ctx context.Context, tokenID string) (*accessv1alpha1.AccessIdentity, error) {
	var list accessv1alpha1.AccessIdentityList
	if err := h.Client.List(ctx, &list, client.MatchingFields{accessctrl.TokenIDIndex: tokenID}); err != nil {
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

func (h *Handler) findSecretForAccessIdentity(ctx context.Context, identity *accessv1alpha1.AccessIdentity) ([]byte, error) {
	secret := &corev1.Secret{}
	name := identity.Name + "-access-token"
	if err := h.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: identity.Namespace}, secret); err != nil {
		return nil, fmt.Errorf("get owned Secret %q: %w", name, err)
	}
	key, ok := secret.Data[accessctrl.AccessTokenSecretKey]
	if !ok || len(key) == 0 {
		return nil, fmt.Errorf("owned Secret %q has no access-token value", name)
	}
	parsed, err := pmaccessproto.ParseToken(string(key))
	if err != nil {
		return nil, fmt.Errorf("owned Secret %q does not parse: %w", name, err)
	}
	return parsed.Secret, nil
}

func (h *Handler) createAccess(ctx context.Context, identity *accessv1alpha1.AccessIdentity, accessName, kubeconfigSecretName string) (*accessv1alpha1.Access, error) {
	access := &accessv1alpha1.Access{
		ObjectMeta: metav1.ObjectMeta{Name: accessName, Namespace: identity.Namespace},
		Spec: accessv1alpha1.AccessSpec{
			IdentityRef:         corev1.LocalObjectReference{Name: identity.Name},
			KubeconfigSecretRef: &corev1.LocalObjectReference{Name: kubeconfigSecretName},
		},
	}
	if err := h.Client.Create(ctx, access); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create Access %q: %w", accessName, err)
	}
	return access, nil
}

func (h *Handler) writeKubeconfigSecret(ctx context.Context, access *accessv1alpha1.Access, name, namespace string, payload *pmaccessv1.HandshakeRequest) error {
	kubeconfigBytes, err := buildKubeconfig(payload)
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}

	kcSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, h.Client, kcSecret, func() error {
		if err := controllerutil.SetControllerReference(access, kcSecret, h.Scheme); err != nil {
			return err
		}
		if kcSecret.Labels == nil {
			kcSecret.Labels = map[string]string{}
		}
		kcSecret.Labels[AccessOperatorLabelKey] = "true"
		if kcSecret.Data == nil {
			kcSecret.Data = map[string][]byte{}
		}
		kcSecret.Data[KubeconfigSecretKey] = kubeconfigBytes
		return nil
	}); err != nil {
		return fmt.Errorf("upsert kubeconfig Secret %q: %w", name, err)
	}
	return nil
}

func (h *Handler) markAccessActive(ctx context.Context, access *accessv1alpha1.Access) error {
	access.Status.Phase = accessv1alpha1.AccessPhaseActive
	now := metav1.Now()
	access.Status.LastRefreshed = &now
	if err := h.Client.Status().Update(ctx, access); err != nil {
		return fmt.Errorf("update Access.status for %q: %w", access.Name, err)
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
