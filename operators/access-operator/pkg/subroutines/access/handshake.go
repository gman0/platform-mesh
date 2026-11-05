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

// Package access carries access-operator subroutines that drive the
// /access handshake against user-side access SDKs.
package access

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.platform-mesh.io/access-operator/internal/config"
	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"
	gcerrors "go.platform-mesh.io/golang-commons/errors"
	"go.platform-mesh.io/golang-commons/logger"
	pmaccessproto "go.platform-mesh.io/protocol/access"
	"go.platform-mesh.io/subroutines"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	AccessHandshakeSubroutineName = "AccessHandshakeSubroutine"

	// handshakeReadyConditionType is the Ready condition the handshake
	// writes reasons onto while it progresses.
	handshakeReadyConditionType = "Ready"

	// Retry cadences for the different non-terminal non-happy paths.
	// Picked to be long enough that a user noticing a misconfiguration
	// has time to fix it, short enough that transient network blips
	// resolve in seconds.
	retryUnreachable = 30 * time.Second
	retryRejected    = 60 * time.Second
	retry202         = 10 * time.Second
	retryOther       = 30 * time.Second

	// POST timeout per handshake attempt. Short — /access returns an
	// ack, not a stream.
	httpTimeout = 30 * time.Second
)

// SATokenMinter mints a ServiceAccount token via the TokenRequest
// subresource. Extracted as a function type so tests can stub it
// without needing fake-client subresource support.
type SATokenMinter func(ctx context.Context, cl ctrlruntimeclient.Client, saName, saNamespace string) (string, error)

// DefaultSATokenMinter is the production SATokenMinter. It POSTs a
// TokenRequest against the ServiceAccount's token subresource.
func DefaultSATokenMinter(ctx context.Context, cl ctrlruntimeclient.Client, saName, saNamespace string) (string, error) {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: saNamespace}}
	treq := &authenticationv1.TokenRequest{}
	if err := cl.SubResource("token").Create(ctx, sa, treq); err != nil {
		return "", err
	}
	return treq.Status.Token, nil
}

// AccessHandshakeSubroutine drives the /access POST for an AccessGrant.
// It reads the mirror access-token Secret, parses the pma1.<...> wire
// string, mints a ServiceAccount token via TokenRequest, signs a JWT
// call credential, and POSTs the handshake. On HTTP 200 it marks the
// AccessGrant Active; 202 / 403 / network failures stay Pending with a
// Ready-condition reason and retry.
//
// All kcp reads/writes go through the mc-runtime cluster client the
// manager hands in via getClusterClientFromContext — the AccessGrant
// and its Secret / ServiceAccount all live in the same Provider
// Workspace on PM's kcp.
type AccessHandshakeSubroutine struct {
	cfg                         *config.OperatorConfig
	httpClient                  *http.Client
	getClusterClientFromContext func(context.Context) (ctrlruntimeclient.Client, error)
	mintSAToken                 SATokenMinter
	readCABundle                func() ([]byte, error)
}

func NewAccessHandshakeSubroutine(
	cfg *config.OperatorConfig,
	getClusterClientFromContext func(context.Context) (ctrlruntimeclient.Client, error),
) *AccessHandshakeSubroutine {
	return &AccessHandshakeSubroutine{
		cfg:                         cfg,
		httpClient:                  &http.Client{Timeout: httpTimeout},
		getClusterClientFromContext: getClusterClientFromContext,
		mintSAToken:                 DefaultSATokenMinter,
		readCABundle: func() ([]byte, error) {
			if cfg.KCP.CABundlePath == "" {
				return nil, nil
			}
			return os.ReadFile(cfg.KCP.CABundlePath)
		},
	}
}

// WithHTTPClient overrides the http.Client used for /access POSTs.
// Intended for tests.
func (r *AccessHandshakeSubroutine) WithHTTPClient(c *http.Client) *AccessHandshakeSubroutine {
	r.httpClient = c
	return r
}

// WithSATokenMinter overrides the SA-token minter. Intended for tests
// that don't want to exercise the real TokenRequest subresource call.
func (r *AccessHandshakeSubroutine) WithSATokenMinter(m SATokenMinter) *AccessHandshakeSubroutine {
	r.mintSAToken = m
	return r
}

// WithCABundleReader overrides how the kcp CA bundle is loaded.
// Intended for tests.
func (r *AccessHandshakeSubroutine) WithCABundleReader(read func() ([]byte, error)) *AccessHandshakeSubroutine {
	r.readCABundle = read
	return r
}

func (r *AccessHandshakeSubroutine) GetName() string {
	return AccessHandshakeSubroutineName
}

// handshakeBody is the JSON payload posted to /access.
type handshakeBody struct {
	KcpURL      string `json:"kcpURL"`
	KcpCABundle string `json:"kcpCABundle"`
	SAToken     string `json:"saToken"`
}

func (r *AccessHandshakeSubroutine) Process(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	log := logger.LoadLoggerFromContext(ctx).ChildLogger("subroutine", r.GetName())
	grant := obj.(*pmaccessv1alpha1.AccessGrant)

	if grant.Status.Phase == pmaccessv1alpha1.AccessGrantPhaseActive {
		return subroutines.OK(), nil
	}
	if grant.Status.Phase == "" {
		grant.Status.Phase = pmaccessv1alpha1.AccessGrantPhasePending
	}

	if r.cfg.KCP.ExternalUrl == "" {
		// Misconfiguration — surface as a condition and refuse to attempt.
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			"MissingExternalKcpURL",
			"operator has no --kcp-external-url configured; refusing to perform /access handshake")
		return subroutines.StopWithRequeue(retryOther, "missing --kcp-external-url"), nil
	}

	ws, err := r.getClusterClientFromContext(ctx)
	if err != nil {
		return subroutines.OK(), err
	}

	// Read the mirror access-token Secret in the Provider Workspace.
	ref := grant.Spec.AccessTokenSecretRef
	key := ref.Key
	if key == "" {
		key = "accessToken"
	}
	tokenSecret := &corev1.Secret{}
	if err := ws.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: grant.Namespace}, tokenSecret); err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "get access-token Secret %s/%s", grant.Namespace, ref.Name)
	}
	rawToken, ok := tokenSecret.Data[key]
	if !ok || len(rawToken) == 0 {
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakeRejected,
			"mirror access-token Secret has no value at the expected key")
		return subroutines.StopWithRequeue(retryRejected, "token Secret missing key"), nil
	}

	parsed, err := pmaccessproto.ParseToken(string(rawToken))
	if err != nil {
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakeRejected,
			fmt.Sprintf("access token did not parse: %v", err))
		return subroutines.StopWithRequeue(retryRejected, "invalid access token"), nil
	}

	// Mint SA token against kcp for this workspace's SA.
	saToken, err := r.mintSAToken(ctx, ws, grant.Spec.SARef.Name, grant.Namespace)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "mint SA token for %s/%s", grant.Namespace, grant.Spec.SARef.Name)
	}

	caBundle, err := r.readCABundle()
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "read kcp CA bundle")
	}

	body := handshakeBody{
		KcpURL:      r.cfg.KCP.ExternalUrl,
		KcpCABundle: string(caBundle),
		SAToken:     saToken,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "marshal /access body")
	}

	jwt, err := pmaccessproto.SignCallCredential(parsed.Secret, parsed.TokenID, bodyBytes, 0)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "sign JWT call credential")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "build /access request")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	client, err := r.httpClientFor(grant.Spec.CABundle)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "build HTTP client for /access")
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Info().Err(err).Str("url", parsed.URL).Msg("/access dial failed")
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonAccessURLUnreachable,
			fmt.Sprintf("dial %s: %v", parsed.URL, err))
		return subroutines.StopWithRequeue(retryUnreachable, "/access dial failed"), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	switch resp.StatusCode {
	case http.StatusOK:
		grant.Status.Phase = pmaccessv1alpha1.AccessGrantPhaseActive
		setGrantReadyCondition(grant, metav1.ConditionTrue,
			pmaccessv1alpha1.AccessGrantReasonHandshakeSucceeded,
			"/access handshake completed")
		log.Info().Str("url", parsed.URL).Msg("/access handshake succeeded")
		return subroutines.OK(), nil
	case http.StatusAccepted:
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakePending,
			"user-side has queued the handshake for manual approval")
		return subroutines.StopWithRequeue(retry202, "manual approval pending"), nil
	case http.StatusForbidden:
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakeRejected,
			fmt.Sprintf("user-side rejected handshake: %s", trim(string(respBody))))
		return subroutines.StopWithRequeue(retryRejected, "handshake rejected"), nil
	default:
		setGrantReadyCondition(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonAccessURLUnreachable,
			fmt.Sprintf("unexpected %d from /access: %s", resp.StatusCode, trim(string(respBody))))
		return subroutines.StopWithRequeue(retryOther, "unexpected /access response"), nil
	}
}

func (r *AccessHandshakeSubroutine) Finalize(_ context.Context, _ ctrlruntimeclient.Object) (subroutines.Result, error) {
	return subroutines.OK(), nil
}

func (r *AccessHandshakeSubroutine) Finalizers(_ ctrlruntimeclient.Object) []string {
	return []string{}
}

// httpClientFor returns an http.Client that verifies the /access server
// certificate against caBundlePEM if non-empty, otherwise system CAs.
func (r *AccessHandshakeSubroutine) httpClientFor(caBundlePEM string) (*http.Client, error) {
	if caBundlePEM == "" {
		return r.httpClient, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caBundlePEM)) {
		return nil, fmt.Errorf("spec.caBundle: no valid certificates parsed")
	}
	// Clone transport to avoid mutating the shared one; fall back to a
	// fresh Transport{} if the default client has no custom transport.
	var baseTransport *http.Transport
	if rt, ok := r.httpClient.Transport.(*http.Transport); ok && rt != nil {
		baseTransport = rt.Clone()
	} else {
		baseTransport = &http.Transport{}
	}
	baseTransport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   r.httpClient.Timeout,
		Transport: baseTransport,
	}, nil
}

func setGrantReadyCondition(grant *pmaccessv1alpha1.AccessGrant, status metav1.ConditionStatus, reason, msg string) {
	apimeta.SetStatusCondition(&grant.Status.Conditions, metav1.Condition{
		Type:               handshakeReadyConditionType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: grant.Generation,
	})
}

func trim(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
