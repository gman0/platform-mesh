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

package controller

import (
	"context"
	"fmt"

	"go.platform-mesh.io/access-operator/internal/config"
	accesssubs "go.platform-mesh.io/access-operator/pkg/subroutines/access"
	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"
	pmconfig "go.platform-mesh.io/golang-commons/config"
	"go.platform-mesh.io/golang-commons/controller/filter"
	"go.platform-mesh.io/golang-commons/controller/lifecycle/ratelimiter"
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

const AccessGrantControllerName = "AccessGrantReconciler"

// AccessGrantReconciler drives the /access handshake for AccessGrants
// in Pending state across Provider Workspaces. It is backed by an
// apiexport-provider on access.platform-mesh.io so events arrive via
// mc-runtime's cluster-from-context plumbing.
type AccessGrantReconciler struct {
	lifecycle   *lifecycle.Lifecycle
	rateLimiter workqueue.TypedRateLimiter[mcreconcile.Request]
}

func (r *AccessGrantReconciler) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	return r.lifecycle.Reconcile(ctx, req)
}

func (r *AccessGrantReconciler) SetupWithManager(mgr mcmanager.Manager, cfg *pmconfig.CommonServiceConfig,
	eventPredicates ...predicate.Predicate) error {
	opts := controller.TypedOptions[mcreconcile.Request]{
		MaxConcurrentReconciles: cfg.MaxConcurrentReconciles,
		RateLimiter:             r.rateLimiter,
	}
	predicates := append([]predicate.Predicate{filter.DebugResourcesBehaviourPredicate(cfg.DebugLabelValue)}, eventPredicates...)
	return mcbuilder.ControllerManagedBy(mgr).
		Named(AccessGrantControllerName).
		For(&pmaccessv1alpha1.AccessGrant{}, mcbuilder.WithEngageWithProviderClusters(true)).
		WithOptions(opts).
		WithEventFilter(predicate.And(predicates...)).
		Complete(r)
}

func NewAccessGrantReconciler(mgr mcmanager.Manager, operatorCfg *config.OperatorConfig, _ *pmconfig.CommonServiceConfig) (*AccessGrantReconciler, error) {
	rl, err := ratelimiter.NewStaticThenExponentialRateLimiter[mcreconcile.Request](ratelimiter.NewConfig())
	if err != nil {
		return nil, fmt.Errorf("creating rate limiter: %w", err)
	}

	var subs []subroutines.Subroutine
	if operatorCfg.Subroutines.Handshake.Enabled {
		subs = append(subs, accesssubs.NewAccessHandshakeSubroutine(
			operatorCfg,
			func(ctx context.Context) (ctrlruntimeclient.Client, error) {
				cluster, err := mgr.ClusterFromContext(ctx)
				if err != nil {
					return nil, err
				}
				return cluster.GetClient(), nil
			},
		))
	}

	lc := lifecycle.New(mgr, AccessGrantControllerName, func() ctrlruntimeclient.Object {
		return &pmaccessv1alpha1.AccessGrant{}
	}, subs...).WithConditions(conditions.NewManager())

	return &AccessGrantReconciler{
		lifecycle:   lc,
		rateLimiter: rl,
	}, nil
}
