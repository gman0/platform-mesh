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

package connapi

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/innertls"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

// serveSession handles GET /v1/connections/{id}/session. Unknown or deleted
// Connections are refused before the upgrade.
func (s *Server) serveSession(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	if credential.ValidateConnectionID(id) != nil {
		refuse(w, connectionsv1.ReasonConnectionUnknown, "", 0)
		return
	}
	conn, known := s.connection(ctx, id)
	if !known {
		refuse(w, connectionsv1.ReasonConnectionUnknown, "", 0)
		return
	}
	release, ok := s.limiter.acquire("c/" + id)
	if !ok {
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	defer release()

	key, err := s.sessionKey(ctx, conn)
	if err != nil {
		s.cfg.Log.Error(err, "no server key for a session", "connection", id)
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	err = s.cfg.Sessions.Accept(w, r, session.Accept{
		ConnectionID: id,
		ClusterName:  conn.Spec.Registration.ClusterName,
		Key:          key,
		Pinned:       func() *bundle.Bundle { return s.pinned(context.Background(), id) },
		Timeout:      s.cfg.HandshakeTimeout,
		Now:          s.cfg.Now,
	})
	if err != nil {
		// Logged and counted, never written anywhere.
		s.cfg.Log.V(1).Info("session refused", "connection", id, "reason", err.Error())
	}
}

// pinned reads the Connection's Pinned Bundle at handshake time.
func (s *Server) pinned(ctx context.Context, id string) *bundle.Bundle {
	conn, known := s.connection(ctx, id)
	if !known {
		return nil
	}
	b, err := bundle.ParseStored([]byte(conn.Spec.PinnedBundle))
	if err != nil {
		return nil
	}
	return b
}

// sessionKey is the newest announced Server Key the Connection's
// ProviderEndpoint lists: a Connection moves to a new key only once the
// PM-side pins it.
func (s *Server) sessionKey(ctx context.Context, conn *sdkv1alpha1.Connection) (innertls.ServerKey, error) {
	var list sdkv1alpha1.ServerKeyList
	if err := s.cfg.Client.List(ctx, &list, client.InNamespace(s.cfg.Namespace)); err != nil {
		return innertls.ServerKey{}, err
	}
	now := s.cfg.Now()
	keys := slices.DeleteFunc(list.Items, func(k sdkv1alpha1.ServerKey) bool {
		return !slices.Contains(conn.Status.ListedServerKeys, k.Name) ||
			!meta.IsStatusConditionTrue(k.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady) ||
			(k.Spec.RetireAt != nil && !now.Before(k.Spec.RetireAt.Time))
	})
	if len(keys) == 0 {
		return innertls.ServerKey{}, errors.New("no announced key listed for the Connection")
	}
	newest := slices.MaxFunc(keys, func(a, b sdkv1alpha1.ServerKey) int { return a.CreationTimestamp.Compare(b.CreationTimestamp.Time) })
	return s.cfg.Keys.Get(ctx, newest.Name)
}
