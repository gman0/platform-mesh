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

package providers

import (
	"context"

	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"
	pmprovidersv1alpha1 "go.platform-mesh.io/apis/providers/v1alpha1"
	gcerrors "go.platform-mesh.io/golang-commons/errors"
	"go.platform-mesh.io/golang-commons/logger"
	"go.platform-mesh.io/platform-mesh-operator/internal/config"
	pmsubs "go.platform-mesh.io/platform-mesh-operator/pkg/subroutines"
	pmaccessproto "go.platform-mesh.io/protocol/access"
	"go.platform-mesh.io/subroutines"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	PARGrantSubroutineName = "PARGrantSubroutine"

	// Mirror-Secret key carrying the full pma1.<...> wire string in the
	// Provider Workspace.
	parAccessTokenSecretKey = "accessToken"
)

func providerAccessTokenSecretName(providerName string) string {
	return providerName + "-access-token"
}

func providerAccessGrantName(providerName string) string {
	return providerName + "-access-grant"
}

// PARGrantSubroutine implements the PAR's handshake-setup half:
//
//   - reads the PAR's access-token Secret from the user workspace,
//   - parses it via protocol/access.ParseToken,
//   - mirrors the token into a Secret in the Provider Workspace (name
//     "<provider>-access-token", key "accessToken"), and
//   - upserts the AccessGrant in the Provider Workspace that
//     access-operator will reconcile.
//
// On success it writes Provider.status.remote.{tokenID, accessURL} on
// the Provider living in the user workspace and marks the PAR
// Completed.
//
// par_resolve.go is expected to have run first, ensuring the Provider
// exists and has spec.remote set.
type PARGrantSubroutine struct {
	localClient                 ctrlruntimeclient.Client
	kcpHelper                   pmsubs.KcpHelper
	kcpCfg                      config.KCPConfig
	kcpUrl                      string
	getClusterClientFromContext func(context.Context) (ctrlruntimeclient.Client, error)
}

func NewPARGrantSubroutine(
	localClient ctrlruntimeclient.Client,
	kcpHelper pmsubs.KcpHelper,
	kcpCfg config.KCPConfig,
	kcpUrl string,
	getClusterClientFromContext func(context.Context) (ctrlruntimeclient.Client, error),
) *PARGrantSubroutine {
	return &PARGrantSubroutine{
		localClient:                 localClient,
		kcpHelper:                   kcpHelper,
		kcpCfg:                      kcpCfg,
		kcpUrl:                      kcpUrl,
		getClusterClientFromContext: getClusterClientFromContext,
	}
}

func (r *PARGrantSubroutine) GetName() string {
	return PARGrantSubroutineName
}

func (r *PARGrantSubroutine) Process(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	log := logger.LoadLoggerFromContext(ctx).ChildLogger("subroutine", r.GetName())
	par := obj.(*pmprovidersv1alpha1.ProviderAccessRequest)

	if isPARTerminalPhase(par) {
		return subroutines.OK(), nil
	}

	cl, err := r.getClusterClientFromContext(ctx)
	if err != nil {
		return subroutines.OK(), err
	}

	// Read the access-token Secret from the user workspace.
	secretRef := par.Spec.AccessTokenSecretRef
	key := secretRef.Key
	if key == "" {
		key = parAccessTokenSecretKey
	}
	srcSecret := &corev1.Secret{}
	if err := cl.Get(ctx, types.NamespacedName{Name: secretRef.Name, Namespace: secretRef.Namespace}, srcSecret); err != nil {
		if apierrors.IsNotFound(err) {
			setPARReadyCondition(par, metav1.ConditionFalse,
				pmprovidersv1alpha1.ProviderAccessRequestReasonInvalidAccessToken,
				"referenced access-token Secret does not exist")
		}
		return subroutines.OK(), gcerrors.Wrap(err, "get access-token Secret %s/%s", secretRef.Namespace, secretRef.Name)
	}
	rawToken, ok := srcSecret.Data[key]
	if !ok || len(rawToken) == 0 {
		log.Info().Str("secret", secretRef.Name).Str("key", key).Msg("Access-token Secret missing key; failing PAR")
		par.Status.Phase = pmprovidersv1alpha1.ProviderAccessRequestPhaseFailed
		setPARReadyCondition(par, metav1.ConditionFalse,
			pmprovidersv1alpha1.ProviderAccessRequestReasonInvalidAccessToken,
			"access-token Secret has no value at the expected key")
		return subroutines.OK(), nil
	}

	parsed, err := pmaccessproto.ParseToken(string(rawToken))
	if err != nil {
		log.Info().Err(err).Msg("Access token did not parse; failing PAR")
		par.Status.Phase = pmprovidersv1alpha1.ProviderAccessRequestPhaseFailed
		setPARReadyCondition(par, metav1.ConditionFalse,
			pmprovidersv1alpha1.ProviderAccessRequestReasonInvalidAccessToken,
			"access token does not parse as a pma1.<...> wire string")
		return subroutines.OK(), nil
	}

	// Fetch the referenced Provider from the user workspace so we can
	// (later) update its status.remote.
	provider := &pmprovidersv1alpha1.Provider{}
	if err := cl.Get(ctx, types.NamespacedName{Name: par.Spec.ProviderRef.Name}, provider); err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "get Provider %s", par.Spec.ProviderRef.Name)
	}

	// Build admin kcp config + a client scoped to the Provider Workspace.
	adminKcpRESTConfig, err := pmsubs.BuildKubeconfigFromConfig(r.localClient, &r.kcpCfg, r.kcpUrl)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "build kcp admin config")
	}
	wsPath := providerWorkspacePath(provider)
	providerWsClient, err := r.kcpHelper.NewKcpClient(adminKcpRESTConfig, wsPath)
	if err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "create kcp client for provider workspace %s", wsPath)
	}

	// Ensure the default namespace exists in the Provider Workspace.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: providerSANamespace}}
	if err := providerWsClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		return subroutines.OK(), gcerrors.Wrap(err, "ensure namespace %s in provider workspace", providerSANamespace)
	}

	// Mirror the access-token Secret into the Provider Workspace.
	mirrorName := providerAccessTokenSecretName(provider.Name)
	mirror := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: mirrorName, Namespace: providerSANamespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, providerWsClient, mirror, func() error {
		if mirror.Data == nil {
			mirror.Data = map[string][]byte{}
		}
		mirror.Data[parAccessTokenSecretKey] = rawToken
		return nil
	}); err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "upsert mirror access-token Secret %s", mirrorName)
	}

	// Upsert the AccessGrant in the Provider Workspace. access-operator
	// (PR 3) will reconcile it from Pending to Active.
	grant := &pmaccessv1alpha1.AccessGrant{ObjectMeta: metav1.ObjectMeta{Name: providerAccessGrantName(provider.Name), Namespace: providerSANamespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, providerWsClient, grant, func() error {
		grant.Spec.SARef = corev1.LocalObjectReference{Name: providerServiceAccountName(provider)}
		grant.Spec.AccessURL = parsed.URL
		grant.Spec.AccessTokenSecretRef = pmaccessv1alpha1.AccessTokenSecretRef{
			Name: mirrorName,
			Key:  parAccessTokenSecretKey,
		}
		grant.Spec.CABundle = provider.Spec.Remote.CABundle
		return nil
	}); err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "upsert AccessGrant %s", grant.Name)
	}

	// Write Provider.status.remote on the Provider living in the user
	// workspace. One-shot, same workspace as the PAR.
	if provider.Status.Remote == nil {
		provider.Status.Remote = &pmprovidersv1alpha1.ProviderRemoteStatus{}
	}
	provider.Status.Remote.TokenID = parsed.TokenID
	provider.Status.Remote.AccessURL = parsed.URL
	if err := cl.Status().Update(ctx, provider); err != nil {
		return subroutines.OK(), gcerrors.Wrap(err, "update Provider.status.remote for %s", provider.Name)
	}

	par.Status.Phase = pmprovidersv1alpha1.ProviderAccessRequestPhaseCompleted
	setPARReadyCondition(par, metav1.ConditionTrue,
		pmprovidersv1alpha1.ProviderAccessRequestReasonAccepted,
		"access token propagated to AccessGrant in provider workspace")

	log.Info().Str("provider", provider.Name).Str("workspace", wsPath).Msg("PAR accepted; AccessGrant created")
	return subroutines.OK(), nil
}

func (r *PARGrantSubroutine) Finalize(_ context.Context, _ ctrlruntimeclient.Object) (subroutines.Result, error) {
	return subroutines.OK(), nil
}

func (r *PARGrantSubroutine) Finalizers(_ ctrlruntimeclient.Object) []string {
	return []string{}
}
