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

package accessgrant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"go.platform-mesh.io/access-operator/pkg/config"
	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"
	"go.platform-mesh.io/golang-commons/logger"
	pmaccessproto "go.platform-mesh.io/protocol/access"
	pmaccessv1 "go.platform-mesh.io/protocol/access/v1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	mccontext "sigs.k8s.io/multicluster-runtime/pkg/context"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"
)

const (
	// Retry cadences for the different non-terminal non-happy paths.
	// Picked to be long enough that a user noticing a misconfiguration
	// has time to fix it, short enough that transient network blips
	// resolve in seconds.
	retryUnreachable  = 30 * time.Second
	retryRejected     = 60 * time.Second
	retry202          = 10 * time.Second
	retryOther        = 30 * time.Second
	retrySATokenEmpty = 2 * time.Second

	// httpTimeout is the POST timeout per handshake attempt. Short —
	// /access returns an ack, not a stream.
	httpTimeout = 30 * time.Second
)

// Reconciler drives the /access handshake for an AccessGrant.
//
// It reads the mirror access-token Secret, parses the pma1.<...> wire
// string, ensures an SA-token Secret for the Provider Workspace's SA,
// signs a JWT call credential, and POSTs the handshake. On HTTP 200
// it marks the AccessGrant Connected; 202 / 403 / network failures
// stay unconnected with a Connected condition reason and a scheduled
// requeue.
//
// All kcp reads/writes go through the mc-runtime cluster client the
// manager hands in via mgr.ClusterFromContext — the AccessGrant and
// its Secret / ServiceAccount all live in the same Provider Workspace
// on PM's kcp.
type Reconciler struct {
	cfg          *config.OperatorConfig
	mgr          mcmanager.Manager
	httpClient   *http.Client
	mintSAToken  SATokenMinter
	readCABundle func() ([]byte, error)

	// versionCache memoizes the picked handshake version per base
	// URL, keyed by Token.URL. Populated by negotiateVersion on the
	// first handshake attempt to a given provider and invalidated
	// whenever a dial to the picked version fails.
	versionCacheMu sync.Mutex
	versionCache   map[string]string
}

// NewReconciler builds a Reconciler with production defaults. The
// options exposed via With* are for tests.
func NewReconciler(mgr mcmanager.Manager, cfg *config.OperatorConfig) *Reconciler {
	return &Reconciler{
		cfg:         cfg,
		mgr:         mgr,
		httpClient:  &http.Client{Timeout: httpTimeout},
		mintSAToken: defaultSATokenMinter,
		readCABundle: func() ([]byte, error) {
			if cfg.KCP.CABundlePath == "" {
				return nil, nil
			}
			return os.ReadFile(cfg.KCP.CABundlePath)
		},
		versionCache: map[string]string{},
	}
}

// WithHTTPClient overrides the http.Client used for /access POSTs.
// Intended for tests.
func (r *Reconciler) WithHTTPClient(c *http.Client) *Reconciler {
	r.httpClient = c
	return r
}

// WithSATokenMinter overrides the SA-token minter. Intended for tests
// that don't want to exercise the real TokenRequest subresource call.
func (r *Reconciler) WithSATokenMinter(m SATokenMinter) *Reconciler {
	r.mintSAToken = m
	return r
}

// WithCABundleReader overrides how the kcp CA bundle is loaded.
// Intended for tests.
func (r *Reconciler) WithCABundleReader(read func() ([]byte, error)) *Reconciler {
	r.readCABundle = read
	return r
}

func (r *Reconciler) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	ctx = mccontext.WithCluster(ctx, req.ClusterName)
	log := logger.LoadLoggerFromContext(ctx).ChildLogger("controller", "AccessGrant")

	cluster, err := r.mgr.ClusterFromContext(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve cluster from context: %w", err)
	}
	cl := cluster.GetClient()

	grant := &pmaccessv1alpha1.AccessGrant{}
	if err := cl.Get(ctx, req.NamespacedName, grant); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get AccessGrant: %w", err)
	}

	// Already connected — nothing to do until spec changes. A spec
	// change (e.g. fresh access token) bumps Generation and we re-run
	// the handshake.
	if isConnected(grant) && grant.Status.ObservedGeneration == grant.Generation {
		return ctrl.Result{}, nil
	}

	result, dialErr := r.reconcile(ctx, log, cl, grant)
	grant.Status.ObservedGeneration = grant.Generation

	if err := cl.Status().Update(ctx, grant); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update AccessGrant status: %w", err)
	}
	return result, dialErr
}

// reconcile performs validation and the /access dial, mutating grant's
// status conditions in-place. The returned ctrl.Result carries the
// requeue cadence; the error is for genuinely transient infra failures
// (API read/write issues the status update should not swallow).
func (r *Reconciler) reconcile(ctx context.Context, log *logger.Logger, cl ctrlruntimeclient.Client, grant *pmaccessv1alpha1.AccessGrant) (ctrl.Result, error) {
	if r.cfg.KCP.ExternalUrl == "" {
		setAccepted(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonMissingKcpURL,
			"operator has no --kcp-external-url configured; refusing to perform /access handshake")
		clearConnected(grant)
		return ctrl.Result{RequeueAfter: retryOther}, nil
	}

	ref := grant.Spec.AccessTokenSecretRef
	key := ref.Key
	if key == "" {
		key = "accessToken"
	}
	tokenSecret := &corev1.Secret{}
	if err := cl.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: grant.Namespace}, tokenSecret); err != nil {
		if apierrors.IsNotFound(err) {
			setAccepted(grant, metav1.ConditionFalse,
				pmaccessv1alpha1.AccessGrantReasonAccessTokenSecretMissing,
				fmt.Sprintf("Secret %s/%s not found", grant.Namespace, ref.Name))
			clearConnected(grant)
			return ctrl.Result{RequeueAfter: retryRejected}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get access-token Secret %s/%s: %w", grant.Namespace, ref.Name, err)
	}
	rawToken, ok := tokenSecret.Data[key]
	if !ok || len(rawToken) == 0 {
		setAccepted(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonAccessTokenSecretMissing,
			fmt.Sprintf("Secret %s/%s has no value at key %q", grant.Namespace, ref.Name, key))
		clearConnected(grant)
		return ctrl.Result{RequeueAfter: retryRejected}, nil
	}

	parsed, err := pmaccessproto.ParseToken(string(rawToken))
	if err != nil {
		setAccepted(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonInvalidAccessToken,
			fmt.Sprintf("access token did not parse: %v", err))
		clearConnected(grant)
		return ctrl.Result{RequeueAfter: retryRejected}, nil
	}

	setAccepted(grant, metav1.ConditionTrue,
		pmaccessv1alpha1.AccessGrantReasonAccepted,
		"spec validated; attempting /access handshake")

	// Ensure an SA-token Secret for the Provider Workspace's SA and
	// read back its populated token. Empty-string + nil-error means
	// the k8s SA-token controller hasn't populated the Secret yet;
	// requeue briefly.
	saToken, err := r.mintSAToken(ctx, cl, grant.Spec.SARef.Name, grant.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("mint SA token for %s/%s: %w", grant.Namespace, grant.Spec.SARef.Name, err)
	}
	if saToken == "" {
		setConnected(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonSATokenPending,
			"waiting for k8s SA-token controller to populate the SA-token Secret")
		return ctrl.Result{RequeueAfter: retrySATokenEmpty}, nil
	}

	caBundle, err := r.readCABundle()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("read kcp CA bundle: %w", err)
	}

	client, err := httpClientFor(r.httpClient, grant.Spec.CABundle)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build HTTP client for /access: %w", err)
	}

	version, cached := r.cachedVersion(parsed.URL)
	if !cached {
		picked, serverVersions, nerr := negotiateVersion(ctx, client, parsed.URL)
		if nerr != nil {
			log.Info().Err(nerr).Str("url", parsed.URL).Msg("/versions probe failed")
			setConnected(grant, metav1.ConditionFalse,
				pmaccessv1alpha1.AccessGrantReasonAccessURLUnreachable,
				fmt.Sprintf("probe %s/versions: %v", parsed.URL, nerr))
			return ctrl.Result{RequeueAfter: retryUnreachable}, nil
		}
		if picked == "" {
			setConnected(grant, metav1.ConditionFalse,
				pmaccessv1alpha1.AccessGrantReasonUnsupportedProtocolVersion,
				fmt.Sprintf("no mutually supported handshake version: provider offers %v, operator supports %v",
					serverVersions, pmaccessproto.SupportedVersions))
			return ctrl.Result{RequeueAfter: retryRejected}, nil
		}
		r.setCachedVersion(parsed.URL, picked)
		version = picked
	}

	body := pmaccessv1.HandshakeRequest{
		KcpURL:      r.cfg.KCP.ExternalUrl,
		KcpCABundle: string(caBundle),
		SAToken:     saToken,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("marshal /access body: %w", err)
	}

	jwt, err := pmaccessproto.SignCallCredential(parsed.Secret, parsed.TokenID, bodyBytes, 0)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("sign JWT call credential: %w", err)
	}

	accessURL, err := url.JoinPath(parsed.URL, pmaccessproto.AccessPath(version))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build /access URL: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, accessURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build /access request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Info().Err(err).Str("url", accessURL).Msg("/access dial failed")
		// Dial failure may mean the server dropped our cached version
		// (e.g. SDK upgraded past it). Invalidate so the next retry
		// re-probes /versions.
		r.invalidateCachedVersion(parsed.URL)
		setConnected(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonAccessURLUnreachable,
			fmt.Sprintf("dial %s: %v", accessURL, err))
		return ctrl.Result{RequeueAfter: retryUnreachable}, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	switch resp.StatusCode {
	case http.StatusOK:
		setConnected(grant, metav1.ConditionTrue,
			pmaccessv1alpha1.AccessGrantReasonHandshakeSucceeded,
			"/access handshake completed")
		log.Info().Str("url", accessURL).Msg("/access handshake succeeded")
		return ctrl.Result{}, nil
	case http.StatusAccepted:
		setConnected(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakePending,
			"user-side has queued the handshake for manual approval")
		return ctrl.Result{RequeueAfter: retry202}, nil
	case http.StatusForbidden:
		setConnected(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonHandshakeRejected,
			fmt.Sprintf("user-side rejected handshake: %s", trim(string(respBody))))
		return ctrl.Result{RequeueAfter: retryRejected}, nil
	default:
		setConnected(grant, metav1.ConditionFalse,
			pmaccessv1alpha1.AccessGrantReasonAccessURLUnreachable,
			fmt.Sprintf("unexpected %d from /access: %s", resp.StatusCode, trim(string(respBody))))
		return ctrl.Result{RequeueAfter: retryOther}, nil
	}
}

// isConnected reports whether the AccessGrant currently holds a
// Connected=True condition.
func isConnected(grant *pmaccessv1alpha1.AccessGrant) bool {
	c := apimeta.FindStatusCondition(grant.Status.Conditions, pmaccessv1alpha1.AccessGrantConditionConnected)
	return c != nil && c.Status == metav1.ConditionTrue
}

func setAccepted(grant *pmaccessv1alpha1.AccessGrant, status metav1.ConditionStatus, reason, msg string) {
	setCondition(grant, pmaccessv1alpha1.AccessGrantConditionAccepted, status, reason, msg)
}

func setConnected(grant *pmaccessv1alpha1.AccessGrant, status metav1.ConditionStatus, reason, msg string) {
	setCondition(grant, pmaccessv1alpha1.AccessGrantConditionConnected, status, reason, msg)
}

func clearConnected(grant *pmaccessv1alpha1.AccessGrant) {
	apimeta.RemoveStatusCondition(&grant.Status.Conditions, pmaccessv1alpha1.AccessGrantConditionConnected)
}

func setCondition(grant *pmaccessv1alpha1.AccessGrant, condType string, status metav1.ConditionStatus, reason, msg string) {
	apimeta.SetStatusCondition(&grant.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: grant.Generation,
	})
}

func (r *Reconciler) cachedVersion(baseURL string) (string, bool) {
	r.versionCacheMu.Lock()
	defer r.versionCacheMu.Unlock()
	v, ok := r.versionCache[baseURL]
	return v, ok
}

func (r *Reconciler) setCachedVersion(baseURL, version string) {
	r.versionCacheMu.Lock()
	defer r.versionCacheMu.Unlock()
	r.versionCache[baseURL] = version
}

func (r *Reconciler) invalidateCachedVersion(baseURL string) {
	r.versionCacheMu.Lock()
	defer r.versionCacheMu.Unlock()
	delete(r.versionCache, baseURL)
}
