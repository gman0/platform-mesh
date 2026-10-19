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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/innertls"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/token"
)

// serveRegister handles GET /v1/connections/register/{tokenID}.
func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request, tokenID string) {
	ctx := r.Context()
	now := s.cfg.Now()

	// Before the upgrade: the token, and its Server Key.
	tok, refusal := s.lookupToken(ctx, tokenID, now)
	if refusal != "" {
		refuse(w, connectionsv1.ReasonTokenRefused, string(refusal), 0)
		return
	}
	key, err := s.cfg.Keys.Get(ctx, tok.Spec.ServerKey)
	if err != nil {
		s.cfg.Log.Error(err, "loading server key", "serverKey", tok.Spec.ServerKey)
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	release, ok := s.limiter.acquire("t/" + tokenID)
	if !ok {
		refuse(w, connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	defer release()

	conn := accept(w, r, innertls.Server(key, []string{connectionsv1.ALPNRegister}), s.cfg.HandshakeTimeout)
	if conn == nil {
		return
	}
	defer conn.Close()
	c := newInnerConn(conn)

	req, err := c.read()
	if err != nil {
		return
	}
	if req.Method != http.MethodPost || req.URL.Path != connectionsv1.RegistrationCreatePath {
		_ = c.refuse(connectionsv1.ReasonNotFound, "", 0)
		return
	}
	if !tokenSecretMatches(req, tok) {
		_ = c.refuse(connectionsv1.ReasonUnauthorized, "", 0)
		return
	}
	var body connectionsv1.RegistrationRequest
	if err := connectionsv1.ReadJSON(req.Body, connectionsv1.MaxBodySize, &body); err != nil || body.Validate() != nil {
		_ = c.refuse(connectionsv1.ReasonInvalidRequest, "", 0)
		return
	}
	pinned, err := bundle.Parse([]byte(body.ConnectorCASet), now)
	if err != nil {
		reason, _ := bundle.ReasonOf(err)
		_ = c.refuse(connectionsv1.ReasonBundleInvalid, string(reason), 0)
		return
	}

	if tok.Status.Registration != nil {
		s.answerRetry(c, tok, body)
		return
	}

	resp, err := s.register(ctx, tok, body, pinned, now)
	if err != nil {
		s.cfg.Log.Error(err, "registering", "token", tok.Name)
		_ = c.refuse(connectionsv1.ReasonUnavailable, "", connectionsv1.StandbyRetryAfter)
		return
	}
	_ = c.respond(http.StatusCreated, resp)
}

// lookupToken applies the checks before the upgrade. A spent token passes
// while its retry window is open, so a retry reaches RetryOutcome.
func (s *Server) lookupToken(ctx context.Context, tokenID string, now time.Time) (*sdkv1alpha1.OnboardingToken, connectionsv1.TokenRefusal) {
	if credential.ValidateTokenID(tokenID) != nil {
		return nil, connectionsv1.TokenUnknown
	}
	var tok sdkv1alpha1.OnboardingToken
	if err := s.cfg.Client.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: tokenID}, &tok); err != nil {
		return nil, connectionsv1.TokenUnknown
	}
	expires := tok.Spec.ExpiresAt.Time
	switch {
	case tok.Status.Registration != nil && !now.Before(expires.Add(s.cfg.RetryWindow)):
		return nil, connectionsv1.TokenSpent
	case tok.Status.Registration == nil && !now.Before(expires):
		return nil, connectionsv1.TokenExpired
	}
	var key sdkv1alpha1.ServerKey
	if err := s.cfg.Client.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: tok.Spec.ServerKey}, &key); err != nil || !token.Usable(&key) {
		return nil, connectionsv1.TokenKeyUnusable
	}
	return &tok, ""
}

func tokenSecretMatches(req *http.Request, tok *sdkv1alpha1.OnboardingToken) bool {
	bearer, err := connectionsv1.ParseBearer(req.Header.Get("Authorization"))
	if err != nil {
		return false
	}
	got, err := credential.HashTokenSecret(bearer)
	if err != nil {
		return false
	}
	want, err := credential.ParseHash(tok.Spec.TokenHash)
	return err == nil && want.Equal(got)
}

// answerRetry answers a Registration on a spent token: the stored response
// for the same attempt, a refusal otherwise.
func (s *Server) answerRetry(c *innerConn, tok *sdkv1alpha1.OnboardingToken, body connectionsv1.RegistrationRequest) {
	reg := tok.Status.Registration
	stored := connectionsv1.RegistrationRequest{IdempotencyKey: reg.IdempotencyKey, SecretHash: reg.SecretHash, ClusterName: reg.ClusterName}
	switch connectionsv1.RetryOutcome(stored, body) {
	case "":
		_ = c.respond(http.StatusCreated, s.response(tok, reg.ConnectionID, reg.ServerKeys))
	case connectionsv1.ReasonIdempotencyConflict:
		_ = c.refuse(connectionsv1.ReasonIdempotencyConflict, "", 0)
	default:
		_ = c.refuse(connectionsv1.ReasonTokenRefused, string(connectionsv1.TokenSpent), 0)
	}
}

// register creates the Connection, then spends the token by compare-and-swap.
// If another attempt spent it first, the Connection is deleted again and the
// caller retries into the spent-token path.
func (s *Server) register(ctx context.Context, tok *sdkv1alpha1.OnboardingToken, body connectionsv1.RegistrationRequest, pinned *bundle.Bundle, now time.Time) (*connectionsv1.RegistrationResponse, error) {
	var key sdkv1alpha1.ServerKey
	if err := s.cfg.Client.Get(ctx, types.NamespacedName{Namespace: s.cfg.Namespace, Name: tok.Spec.ServerKey}, &key); err != nil {
		return nil, err
	}
	unusedExpiresAt := metav1.NewTime(s.unusedExpiresAt(tok))
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       credential.NewConnectionID(),
			Namespace:  s.cfg.Namespace,
			Finalizers: []string{sdkv1alpha1.ConnectionFinalizer},
		},
		Spec: sdkv1alpha1.ConnectionSpec{
			Registration: sdkv1alpha1.ConnectionRegistration{
				Owner:           tok.Spec.Owner,
				ClusterName:     body.ClusterName,
				UnusedExpiresAt: &unusedExpiresAt,
			},
			PinnedBundle: string(pinned.Encode()),
		},
	}
	if err := s.cfg.Client.Create(ctx, conn); err != nil {
		return nil, err
	}
	conn.Status.SecretHash = body.SecretHash
	conn.Status.ListedServerKeys = []string{key.Name}
	if err := s.cfg.Client.Status().Update(ctx, conn); err != nil {
		return nil, s.undo(ctx, conn, err)
	}

	tok.Status.Registration = &sdkv1alpha1.TokenRegistration{
		ConnectionID:   conn.Name,
		IdempotencyKey: body.IdempotencyKey,
		SecretHash:     body.SecretHash,
		ClusterName:    body.ClusterName,
		ServerKeys:     []string{key.Status.PublicKey},
		At:             metav1.NewTime(now),
	}
	// tok carries the resourceVersion it was read with: a concurrent spend
	// makes this conflict.
	if err := s.cfg.Client.Status().Update(ctx, tok); err != nil {
		return nil, s.undo(ctx, conn, err)
	}

	if s.cfg.OnRegistered != nil {
		if err := s.cfg.OnRegistered(ctx, conn); err != nil {
			// The Connection exists and the token is spent; the controllers
			// complete what's missing.
			s.cfg.Log.Error(err, "after registration", "connection", conn.Name)
		}
	}
	return s.response(tok, conn.Name, tok.Status.Registration.ServerKeys), nil
}

// undo deletes a Connection whose Registration didn't complete.
func (s *Server) undo(ctx context.Context, conn *sdkv1alpha1.Connection, cause error) error {
	conn.Finalizers = nil
	if err := s.cfg.Client.Update(ctx, conn); err != nil && !apierrors.IsNotFound(err) {
		return errors.Join(cause, err)
	}
	if err := s.cfg.Client.Delete(ctx, conn); err != nil && !apierrors.IsNotFound(err) {
		return errors.Join(cause, err)
	}
	return cause
}

func (s *Server) unusedExpiresAt(tok *sdkv1alpha1.OnboardingToken) time.Time {
	return tok.Spec.ExpiresAt.Add(s.cfg.RetryWindow)
}

func (s *Server) response(tok *sdkv1alpha1.OnboardingToken, connectionID string, keys []string) *connectionsv1.RegistrationResponse {
	resp := &connectionsv1.RegistrationResponse{
		ConnectionID:    connectionID,
		UnusedExpiresAt: s.unusedExpiresAt(tok).UTC(),
	}
	for _, k := range keys {
		resp.ServerKeys = append(resp.ServerKeys, connectionsv1.ServerKey{PublicKey: k})
	}
	return resp
}
