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

	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// AccessGrantReconciler drives the /access handshake for AccessGrants
// in a Pending state. For this scaffold it is a no-op; the handshake
// subroutine (SA token mint + JWT call credential + POST /access) lands
// in Chunk C of PR 3, and the mc-runtime apiexport-provider wiring on
// access.platform-mesh.io lands alongside it.
type AccessGrantReconciler struct {
	Client ctrlruntimeclient.Client
	Scheme *runtime.Scheme
}

func (r *AccessGrantReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	// Chunk C will fill this in.
	return ctrl.Result{}, nil
}

func (r *AccessGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AccessGrantReconciler").
		For(&pmaccessv1alpha1.AccessGrant{}).
		Complete(r)
}
