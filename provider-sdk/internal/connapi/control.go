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
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	"go.platform-mesh.io/provider-protocol/innertls"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

const (
	// lastSeenInterval is how often lastSeen is updated after the first time.
	lastSeenInterval = time.Hour
	// controlIdleTimeout ends a Control Session without calls.
	controlIdleTimeout = 2 * time.Minute
)

// serveControl handles GET /v1/connections/{id}/control.
func (s *Server) serveControl(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	if credential.ValidateConnectionID(id) != nil {
		refuse(w, connectionsv1.ReasonNotFound, "", 0)
		return
	}

	conn, known := s.connection(ctx, id)
	var release func()
	var ok bool
	if known {
		release, ok = s.limiter.acquire("c/" + id)
	} else {
		release, ok = s.unknown.acquire()
	}
	if !ok {
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	defer release()

	key, err := s.controlKey(ctx, r.Header.Get(connectionsv1.HeaderServerKey), conn)
	if err != nil {
		s.cfg.Log.Error(err, "no server key for a control session", "connection", id)
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}

	tc := accept(w, r, innertls.Server(key, []string{connectionsv1.ALPNControl}), s.cfg.HandshakeTimeout)
	if tc == nil {
		return
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Time{})
	release() // the handshake is over
	c := newInnerConn(tc)

	for {
		_ = tc.SetReadDeadline(time.Now().Add(controlIdleTimeout))
		req, err := c.read()
		if err != nil {
			return
		}
		if !s.controlCall(ctx, c, req, id) {
			return
		}
	}
}

// controlCall answers one Control Call; false closes the Control Session.
func (s *Server) controlCall(ctx context.Context, c *innerConn, req *http.Request, id string) bool {
	defer req.Body.Close()

	// Bound to the path's {id}: another Connection's path is what an Edge
	// rewriting paths causes, not an authentication failure.
	target, call, ok := parseControlPath(req.URL.Path)
	if !ok {
		_ = c.refuse(connectionsv1.ReasonNotFound, "", 0)
		return true
	}
	if target != id {
		_ = c.refuse(connectionsv1.ReasonConnectionMismatch, "", 0)
		return false
	}

	// "Unknown" only after an uncached read; if that fails, Unavailable.
	var conn sdkv1alpha1.Connection
	if err := s.cfg.APIReader.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: id}, &conn); err != nil {
		if apierrors.IsNotFound(err) {
			_ = c.refuse(connectionsv1.ReasonConnectionUnknown, "", 0)
		} else {
			_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		}
		return false
	}
	if conn.DeletionTimestamp != nil {
		_ = c.refuse(connectionsv1.ReasonConnectionUnknown, "", 0)
		return false
	}

	// The first failed authentication closes the Control Session, and
	// changes nothing.
	if !secretMatches(req, &conn) {
		_ = c.refuse(connectionsv1.ReasonUnauthorized, "", 0)
		return false
	}
	s.touchLastSeen(ctx, &conn)

	switch {
	case call == "" && req.Method == http.MethodGet:
		return s.status(ctx, c, &conn)
	case call == "" && req.Method == http.MethodDelete:
		if err := s.cfg.Client.Delete(ctx, &conn); err != nil && !apierrors.IsNotFound(err) {
			_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
			return false
		}
		_ = c.respond(http.StatusNoContent, nil)
		return false
	case call == "connector-ca-set" && req.Method == http.MethodPut:
		return s.putConnectorCASet(ctx, c, req, &conn)
	default:
		_ = c.refuse(connectionsv1.ReasonNotFound, "", 0)
		return true
	}
}

// parseControlPath splits /v1/connections/{id}[/{call}].
func parseControlPath(path string) (id, call string, ok bool) {
	rest, ok := strings.CutPrefix(path, connectionsv1.PathPrefix+"/")
	if !ok {
		return "", "", false
	}
	id, call, _ = strings.Cut(rest, "/")
	if credential.ValidateConnectionID(id) != nil || strings.Contains(call, "/") {
		return "", "", false
	}
	return id, call, true
}

func secretMatches(req *http.Request, conn *sdkv1alpha1.Connection) bool {
	bearer, err := connectionsv1.ParseBearer(req.Header.Get("Authorization"))
	if err != nil {
		return false
	}
	secret, err := credential.ParseConnectionSecret(bearer)
	if err != nil {
		return false
	}
	want, err := credential.ParseHash(conn.Status.SecretHash)
	return err == nil && want.Equal(secret.Hash())
}

func (s *Server) status(ctx context.Context, c *innerConn, conn *sdkv1alpha1.Connection) bool {
	pinned, err := bundle.ParseStored([]byte(conn.Spec.PinnedBundle))
	if err != nil {
		_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return false
	}
	announced, err := s.announcedKeys(ctx)
	if err != nil {
		_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return false
	}
	out := connectionsv1.ConnectionStatus{
		ServerKeys:   announced,
		PinnedBundle: bundleInfo(pinned),
	}
	if s.cfg.Status != nil {
		out.Workspace, out.VirtualWorkspaces = s.cfg.Status(conn.Name)
	}
	return c.respond(http.StatusOK, out) == nil
}

func (s *Server) putConnectorCASet(ctx context.Context, c *innerConn, req *http.Request, conn *sdkv1alpha1.Connection) bool {
	current, err := bundle.ParseStored([]byte(conn.Spec.PinnedBundle))
	if err != nil {
		_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return false
	}
	// Compare-and-swap: a missing or stale If-Match gets the current etag.
	if etag, err := connectionsv1.ParseIfMatch(req.Header.Get("If-Match")); err != nil || etag != current.ETag() {
		return c.writeError(connectionsv1.ErrorResponse{Reason: connectionsv1.ReasonPreconditionFailed, ETag: current.ETag()}) == nil
	}
	var body connectionsv1.ConnectorCASetUpdate
	if err := connectionsv1.ReadJSON(req.Body, connectionsv1.MaxBodySize, &body); err != nil {
		_ = c.refuse(connectionsv1.ReasonInvalidRequest, "", 0)
		return true
	}
	next, err := bundle.Parse([]byte(body.ConnectorCASet), s.cfg.Now())
	if err != nil {
		reason, _ := bundle.ReasonOf(err)
		_ = c.refuse(connectionsv1.ReasonBundleInvalid, string(reason), 0)
		return true
	}
	if next.Equal(current) {
		return c.respond(http.StatusNoContent, nil) == nil
	}
	// conn carries the resourceVersion it was read with, so a concurrent
	// replacement conflicts instead of being overwritten.
	conn.Spec.PinnedBundle = string(next.Encode())
	if err := s.cfg.Client.Update(ctx, conn); err != nil {
		if apierrors.IsConflict(err) {
			return c.writeError(connectionsv1.ErrorResponse{Reason: connectionsv1.ReasonPreconditionFailed, ETag: current.ETag()}) == nil
		}
		_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return false
	}
	return c.respond(http.StatusNoContent, nil) == nil
}

// connection reads a Connection from the cache: whether the ID is known
// decides which handshake limit applies.
func (s *Server) connection(ctx context.Context, id string) (*sdkv1alpha1.Connection, bool) {
	var conn sdkv1alpha1.Connection
	if err := s.cfg.Client.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: id}, &conn); err != nil || conn.DeletionTimestamp != nil {
		return nil, false
	}
	return &conn, true
}

// controlKey picks the Server Key a Control Session presents: the one the
// PM-side names in PM-Server-Key if this Provider-side has it, otherwise the
// Connection's newest listed key, otherwise the newest usable key.
func (s *Server) controlKey(ctx context.Context, header string, conn *sdkv1alpha1.Connection) (innertls.ServerKey, error) {
	var list sdkv1alpha1.ServerKeyList
	if err := s.cfg.Client.List(ctx, &list, client.InNamespace(s.cfg.Namespace)); err != nil {
		return innertls.ServerKey{}, err
	}
	ready := slices.DeleteFunc(list.Items, func(k sdkv1alpha1.ServerKey) bool {
		return k.Status.Fingerprint == "" || !meta.IsStatusConditionTrue(k.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady)
	})
	slices.SortFunc(ready, func(a, b sdkv1alpha1.ServerKey) int { return b.CreationTimestamp.Compare(a.CreationTimestamp.Time) })

	if want, err := fingerprint.ParseKind(header, fingerprint.KeySHA256); err == nil {
		for _, k := range ready {
			if k.Status.Fingerprint == want.String() {
				return s.cfg.Keys.Get(ctx, k.Name)
			}
		}
	}
	if conn != nil {
		for _, k := range ready {
			if slices.Contains(conn.Status.ListedServerKeys, k.Name) {
				return s.cfg.Keys.Get(ctx, k.Name)
			}
		}
	}
	if len(ready) > 0 {
		return s.cfg.Keys.Get(ctx, ready[0].Name)
	}
	return innertls.ServerKey{}, errors.New("no ready ServerKey")
}

// announcedKeys are every ready ServerKey not past its retireAt.
func (s *Server) announcedKeys(ctx context.Context) ([]connectionsv1.ServerKey, error) {
	var list sdkv1alpha1.ServerKeyList
	if err := s.cfg.Client.List(ctx, &list, client.InNamespace(s.cfg.Namespace)); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	slices.SortFunc(list.Items, func(a, b sdkv1alpha1.ServerKey) int { return a.CreationTimestamp.Compare(b.CreationTimestamp.Time) })
	var out []connectionsv1.ServerKey
	for _, k := range list.Items {
		if k.Status.PublicKey == "" || !meta.IsStatusConditionTrue(k.Status.Conditions, sdkv1alpha1.ServerKeyConditionReady) {
			continue
		}
		if k.Spec.RetireAt != nil && !now.Before(k.Spec.RetireAt.Time) {
			continue
		}
		out = append(out, connectionsv1.ServerKey{PublicKey: k.Status.PublicKey})
	}
	return out, nil
}

// touchLastSeen records an authenticated Control Call: the first at once,
// then at most every lastSeenInterval. Failures are only logged.
func (s *Server) touchLastSeen(ctx context.Context, conn *sdkv1alpha1.Connection) {
	now := s.cfg.Now()
	if conn.Status.LastSeen != nil && now.Sub(conn.Status.LastSeen.Time) < lastSeenInterval {
		return
	}
	patch := client.MergeFrom(conn.DeepCopy())
	t := metav1.NewTime(now)
	conn.Status.LastSeen = &t
	if err := s.cfg.Client.Status().Patch(ctx, conn, patch); err != nil {
		s.cfg.Log.Error(err, "updating lastSeen", "connection", conn.Name)
	}
}

func bundleInfo(b *bundle.Bundle) connectionsv1.PinnedBundleInfo {
	info := connectionsv1.PinnedBundleInfo{ETag: b.ETag()}
	for _, fp := range b.Fingerprints() {
		info.Fingerprints = append(info.Fingerprints, fp.String())
	}
	return info
}
