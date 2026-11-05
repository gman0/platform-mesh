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
	"time"

	pmprovidersv1alpha1 "go.platform-mesh.io/apis/providers/v1alpha1"
	gcerrors "go.platform-mesh.io/golang-commons/errors"
	"go.platform-mesh.io/golang-commons/logger"
	"go.platform-mesh.io/subroutines"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	PARResolveSubroutineName = "PARResolveSubroutine"

	parProviderNotFoundRequeue = 10 * time.Second

	// parReadyConditionType is the condition type the resolve/grant
	// subroutines write reasons onto while the PAR progresses.
	parReadyConditionType = "Ready"
)

// PARResolveSubroutine validates the PAR's providerRef and the referenced
// Provider's remote-mode gate. It leaves terminal PARs untouched (no
// auto-retry), requeues while the Provider is missing, and transitions
// to Failed/ProviderNotRemoteMode when the Provider exists without
// spec.remote set. On success it returns OK and lets the next subroutine
// (par_grant.go) take over the handshake setup.
type PARResolveSubroutine struct {
	client ctrlruntimeclient.Client
}

func NewPARResolveSubroutine(cl ctrlruntimeclient.Client) *PARResolveSubroutine {
	return &PARResolveSubroutine{client: cl}
}

func (r *PARResolveSubroutine) GetName() string {
	return PARResolveSubroutineName
}

func (r *PARResolveSubroutine) Process(ctx context.Context, obj ctrlruntimeclient.Object) (subroutines.Result, error) {
	log := logger.LoadLoggerFromContext(ctx).ChildLogger("subroutine", r.GetName())
	par := obj.(*pmprovidersv1alpha1.ProviderAccessRequest)

	if isPARTerminal(par) {
		return subroutines.OK(), nil
	}
	if par.Status.Phase == "" {
		par.Status.Phase = pmprovidersv1alpha1.ProviderAccessRequestPhasePending
	}

	providerName := par.Spec.ProviderRef.Name
	provider := &pmprovidersv1alpha1.Provider{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: providerName}, provider); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info().Str("provider", providerName).Msg("Provider not found yet, requeuing")
			setPARReadyCondition(par, metav1.ConditionFalse,
				pmprovidersv1alpha1.ProviderAccessRequestReasonProviderNotFound,
				"referenced Provider does not exist yet")
			return subroutines.StopWithRequeue(parProviderNotFoundRequeue, "Provider not found yet"), nil
		}
		return subroutines.OK(), gcerrors.Wrap(err, "failed to get Provider %s", providerName)
	}

	if provider.Spec.Remote == nil {
		log.Info().Str("provider", providerName).Msg("Provider is not in remote mode; failing PAR")
		par.Status.Phase = pmprovidersv1alpha1.ProviderAccessRequestPhaseFailed
		setPARReadyCondition(par, metav1.ConditionFalse,
			pmprovidersv1alpha1.ProviderAccessRequestReasonProviderNotRemoteMode,
			"referenced Provider has no spec.remote set")
		return subroutines.OK(), nil
	}

	return subroutines.OK(), nil
}

func (r *PARResolveSubroutine) Finalize(_ context.Context, _ ctrlruntimeclient.Object) (subroutines.Result, error) {
	return subroutines.OK(), nil
}

func (r *PARResolveSubroutine) Finalizers(_ ctrlruntimeclient.Object) []string {
	return []string{}
}

// isPARTerminal reports whether the PAR has reached a terminal phase and
// should be left untouched on subsequent reconciles.
func isPARTerminal(par *pmprovidersv1alpha1.ProviderAccessRequest) bool {
	switch par.Status.Phase {
	case pmprovidersv1alpha1.ProviderAccessRequestPhaseCompleted,
		pmprovidersv1alpha1.ProviderAccessRequestPhaseFailed:
		return true
	}
	return false
}

// setPARReadyCondition sets the Ready condition on a PAR with the given
// status/reason/message. Observed generation is pinned to the PAR's
// current generation so stale conditions are visible as such.
func setPARReadyCondition(par *pmprovidersv1alpha1.ProviderAccessRequest, status metav1.ConditionStatus, reason, msg string) {
	apimeta.SetStatusCondition(&par.Status.Conditions, metav1.Condition{
		Type:               parReadyConditionType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: par.Generation,
	})
}
