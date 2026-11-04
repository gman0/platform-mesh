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
	"fmt"

	pmprovidersv1alpha1 "go.platform-mesh.io/apis/providers/v1alpha1"
	pmconfig "go.platform-mesh.io/golang-commons/config"
	"go.platform-mesh.io/golang-commons/controller/filter"
	"go.platform-mesh.io/golang-commons/controller/lifecycle/ratelimiter"
	"go.platform-mesh.io/platform-mesh-operator/internal/config"
	pmsubroutines "go.platform-mesh.io/platform-mesh-operator/pkg/subroutines"
	pmsubs "go.platform-mesh.io/platform-mesh-operator/pkg/subroutines/providers"
	"go.platform-mesh.io/subroutines"
	"go.platform-mesh.io/subroutines/conditions"
	"go.platform-mesh.io/subroutines/lifecycle"

	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"
)

const PARControllerName = "ProviderAccessRequestReconciler"

// PARReconciler reconciles ProviderAccessRequest objects. For each PAR it
// resolves the referenced Provider, parses the access token from the PAR's
// Secret, mirrors the token into the Provider Workspace alongside a freshly
// created AccessGrant, and marks the PAR Completed. One-shot per PAR;
// terminal states (Completed, Failed) are not auto-touched.
type PARReconciler struct {
	lifecycle   *lifecycle.Lifecycle
	rateLimiter workqueue.TypedRateLimiter[mcreconcile.Request]
}

func (r *PARReconciler) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	return r.lifecycle.Reconcile(ctx, req)
}

// SetupWithManager sets up the PAR controller with the Manager.
func (r *PARReconciler) SetupWithManager(mgr mcmanager.Manager, cfg *pmconfig.CommonServiceConfig,
	eventPredicates ...predicate.Predicate) error {
	opts := controller.TypedOptions[mcreconcile.Request]{
		MaxConcurrentReconciles: cfg.MaxConcurrentReconciles,
		RateLimiter:             r.rateLimiter,
	}
	predicates := append([]predicate.Predicate{filter.DebugResourcesBehaviourPredicate(cfg.DebugLabelValue)}, eventPredicates...)
	return mcbuilder.ControllerManagedBy(mgr).
		Named(PARControllerName).
		For(&pmprovidersv1alpha1.ProviderAccessRequest{}, mcbuilder.WithEngageWithProviderClusters(true)).
		WithOptions(opts).
		WithEventFilter(predicate.And(predicates...)).
		Complete(r)
}

func NewPARReconciler(mgr mcmanager.Manager, operatorCfg *config.OperatorConfig, commonCfg *pmconfig.CommonServiceConfig, localClient ctrlruntimeclient.Client) (*PARReconciler, error) {
	kcpUrl := operatorCfg.KCP.Url
	if kcpUrl == "" {
		kcpUrl = fmt.Sprintf("https://%s-front-proxy.%s:%s", operatorCfg.KCP.FrontProxyName, operatorCfg.KCP.Namespace, operatorCfg.KCP.FrontProxyPort)
	}

	rl, err := ratelimiter.NewStaticThenExponentialRateLimiter[mcreconcile.Request](ratelimiter.NewConfig())
	if err != nil {
		return nil, fmt.Errorf("creating rate limiter: %w", err)
	}

	kcpHelper := &pmsubroutines.Helper{}

	var subs []subroutines.Subroutine

	if operatorCfg.Subroutines.PAR.Resolve.Enabled {
		subs = append(subs, pmsubs.NewPARResolveSubroutine(
			func(ctx context.Context) (ctrlruntimeclient.Client, error) {
				cluster, err := mgr.ClusterFromContext(ctx)
				if err != nil {
					return nil, err
				}
				return cluster.GetClient(), nil
			},
		))
	}
	if operatorCfg.Subroutines.PAR.Grant.Enabled {
		subs = append(subs, pmsubs.NewPARGrantSubroutine(
			localClient,
			kcpHelper,
			operatorCfg.KCP,
			kcpUrl,
			func(ctx context.Context) (ctrlruntimeclient.Client, error) {
				cluster, err := mgr.ClusterFromContext(ctx)
				if err != nil {
					return nil, err
				}
				return cluster.GetClient(), nil
			},
		))
	}

	lc := lifecycle.New(mgr, PARControllerName, func() ctrlruntimeclient.Object {
		return &pmprovidersv1alpha1.ProviderAccessRequest{}
	}, subs...).WithConditions(conditions.NewManager())

	return &PARReconciler{
		lifecycle:   lc,
		rateLimiter: rl,
	}, nil
}
