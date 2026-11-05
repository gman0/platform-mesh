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

package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.platform-mesh.io/access-operator/internal/config"
	pmaccessv1alpha1 "go.platform-mesh.io/apis/access/v1alpha1"
	pmaccessproto "go.platform-mesh.io/protocol/access"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sch := runtime.NewScheme()
	if err := corev1.AddToScheme(sch); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := pmaccessv1alpha1.AddToScheme(sch); err != nil {
		t.Fatalf("add access/v1alpha1 to scheme: %v", err)
	}
	return sch
}

type testFixture struct {
	token   pmaccessproto.Token
	rawWire string
	grant   *pmaccessv1alpha1.AccessGrant
	secret  *corev1.Secret
}

func newFixture(t *testing.T, accessURL string) testFixture {
	t.Helper()
	tok := pmaccessproto.Token{
		URL:     accessURL,
		TokenID: "id-xyz",
		Secret:  []byte("hmac-secret-material"),
	}
	raw := tok.String()
	return testFixture{
		token:   tok,
		rawWire: raw,
		grant: &pmaccessv1alpha1.AccessGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "p-access-grant", Namespace: "default"},
			Spec: pmaccessv1alpha1.AccessGrantSpec{
				SARef:     corev1.LocalObjectReference{Name: "p-provider"},
				AccessURL: accessURL,
				AccessTokenSecretRef: pmaccessv1alpha1.AccessTokenSecretRef{
					Name: "p-access-token",
					Key:  "accessToken",
				},
			},
		},
		secret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "p-access-token", Namespace: "default"},
			Data:       map[string][]byte{"accessToken": []byte(raw)},
		},
	}
}

// newSubroutine builds a subroutine wired against the given httptest.Server,
// a fake cluster client seeded with the grant + token Secret, a stubbed
// SA-token minter, and a stubbed CA-bundle reader.
func newSubroutine(t *testing.T, srv *httptest.Server, fx testFixture) *AccessHandshakeSubroutine {
	t.Helper()
	sch := newTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(fx.grant, fx.secret).Build()

	cfg := &config.OperatorConfig{}
	cfg.KCP.ExternalUrl = "https://kcp.pm.example"

	return NewAccessHandshakeSubroutine(cfg, func(context.Context) (ctrlruntimeclient.Client, error) {
		return cl, nil
	}).
		WithHTTPClient(srv.Client()).
		WithSATokenMinter(func(context.Context, ctrlruntimeclient.Client, string, string) (string, error) {
			return "stub-sa-token", nil
		}).
		WithCABundleReader(func() ([]byte, error) { return []byte("stub-ca-bundle"), nil })
}

func TestHandshake_200_MarksActive(t *testing.T) {
	var gotBody handshakeBody
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fx := newFixture(t, srv.URL)
	s := newSubroutine(t, srv, fx)

	if _, err := s.Process(context.Background(), fx.grant); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if fx.grant.Status.Phase != pmaccessv1alpha1.AccessGrantPhaseActive {
		t.Errorf("Phase = %q, want Active", fx.grant.Status.Phase)
	}
	cond := apimeta.FindStatusCondition(fx.grant.Status.Conditions, handshakeReadyConditionType)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != pmaccessv1alpha1.AccessGrantReasonHandshakeSucceeded {
		t.Errorf("Ready condition = %+v, want True/HandshakeSucceeded", cond)
	}
	if gotAuth == "" || len(gotAuth) < len("Bearer ") || gotAuth[:7] != "Bearer " {
		t.Errorf("Authorization header = %q, want Bearer <jwt>", gotAuth)
	}
	if gotBody.KcpURL != "https://kcp.pm.example" {
		t.Errorf("kcpURL = %q, want https://kcp.pm.example", gotBody.KcpURL)
	}
	if gotBody.SAToken != "stub-sa-token" {
		t.Errorf("saToken = %q, want stub-sa-token", gotBody.SAToken)
	}
	if gotBody.KcpCABundle != "stub-ca-bundle" {
		t.Errorf("kcpCABundle = %q, want stub-ca-bundle", gotBody.KcpCABundle)
	}
}

func TestHandshake_403_StaysPendingWithReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("InvalidCredential"))
	}))
	defer srv.Close()

	fx := newFixture(t, srv.URL)
	s := newSubroutine(t, srv, fx)

	res, err := s.Process(context.Background(), fx.grant)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if fx.grant.Status.Phase == pmaccessv1alpha1.AccessGrantPhaseActive {
		t.Errorf("Phase must not be Active on 403")
	}
	if !res.IsStopWithRequeue() {
		t.Errorf("expected StopWithRequeue on 403, got %+v", res)
	}
	cond := apimeta.FindStatusCondition(fx.grant.Status.Conditions, handshakeReadyConditionType)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != pmaccessv1alpha1.AccessGrantReasonHandshakeRejected {
		t.Errorf("Ready condition = %+v, want False/HandshakeRejected", cond)
	}
}

func TestHandshake_202_StaysPendingWithReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	fx := newFixture(t, srv.URL)
	s := newSubroutine(t, srv, fx)

	res, err := s.Process(context.Background(), fx.grant)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if fx.grant.Status.Phase == pmaccessv1alpha1.AccessGrantPhaseActive {
		t.Errorf("Phase must not be Active on 202")
	}
	if !res.IsStopWithRequeue() {
		t.Errorf("expected StopWithRequeue on 202, got %+v", res)
	}
	cond := apimeta.FindStatusCondition(fx.grant.Status.Conditions, handshakeReadyConditionType)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != pmaccessv1alpha1.AccessGrantReasonHandshakePending {
		t.Errorf("Ready condition = %+v, want False/HandshakePending", cond)
	}
}

func TestHandshake_InvalidToken_SurfacesRejection(t *testing.T) {
	// Serve nothing — the request should never go out.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not be reached for invalid token")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	fx := newFixture(t, srv.URL)
	fx.secret.Data["accessToken"] = []byte("not-a-pma1-token")

	sch := newTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(fx.grant, fx.secret).Build()
	cfg := &config.OperatorConfig{}
	cfg.KCP.ExternalUrl = "https://kcp.pm.example"
	s := NewAccessHandshakeSubroutine(cfg, func(context.Context) (ctrlruntimeclient.Client, error) {
		return cl, nil
	}).WithHTTPClient(srv.Client()).
		WithSATokenMinter(func(context.Context, ctrlruntimeclient.Client, string, string) (string, error) {
			return "stub-sa-token", nil
		}).
		WithCABundleReader(func() ([]byte, error) { return nil, nil })

	if _, err := s.Process(context.Background(), fx.grant); err != nil {
		t.Fatalf("Process: %v", err)
	}
	cond := apimeta.FindStatusCondition(fx.grant.Status.Conditions, handshakeReadyConditionType)
	if cond == nil || cond.Reason != pmaccessv1alpha1.AccessGrantReasonHandshakeRejected {
		t.Errorf("Ready condition = %+v, want HandshakeRejected", cond)
	}
}

func TestHandshake_MissingExternalURL_Refuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not be reached when external URL is missing")
	}))
	defer srv.Close()

	fx := newFixture(t, srv.URL)
	sch := newTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(sch).WithObjects(fx.grant, fx.secret).Build()
	cfg := &config.OperatorConfig{} // ExternalUrl unset

	s := NewAccessHandshakeSubroutine(cfg, func(context.Context) (ctrlruntimeclient.Client, error) {
		return cl, nil
	})

	if _, err := s.Process(context.Background(), fx.grant); err != nil {
		t.Fatalf("Process: %v", err)
	}
	cond := apimeta.FindStatusCondition(fx.grant.Status.Conditions, handshakeReadyConditionType)
	if cond == nil || cond.Reason != "MissingExternalKcpURL" {
		t.Errorf("Ready condition = %+v, want MissingExternalKcpURL", cond)
	}
}
