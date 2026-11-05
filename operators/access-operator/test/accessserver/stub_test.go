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

package accessserver

import (
	"bytes"
	"net/http"
	"testing"

	pmaccessproto "go.platform-mesh.io/protocol/access"
)

func doRequest(t *testing.T, url, jwt string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/access", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestStub_Accepts_200(t *testing.T) {
	secret := []byte("s")
	body := []byte(`{"kcpURL":"https://kcp.example"}`)

	var accepted struct {
		tokenID string
		body    []byte
	}
	srv := New(Options{
		SecretLookup: StaticLookup(map[string][]byte{"id-xyz": secret}),
		OnAccepted: func(tokenID string, b []byte) {
			accepted.tokenID = tokenID
			accepted.body = b
		},
	}).NewHTTPTestServer()
	defer srv.Close()

	jwt, err := pmaccessproto.SignCallCredential(secret, "id-xyz", body, 0)
	if err != nil {
		t.Fatal(err)
	}

	resp := doRequest(t, srv.URL, jwt, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if accepted.tokenID != "id-xyz" {
		t.Errorf("OnAccepted tokenID = %q, want id-xyz", accepted.tokenID)
	}
	if !bytes.Equal(accepted.body, body) {
		t.Errorf("OnAccepted body mismatch")
	}
}

func TestStub_Rejects_UnknownIdentity(t *testing.T) {
	secret := []byte("s")
	srv := New(Options{
		SecretLookup: StaticLookup(map[string][]byte{"known": secret}),
	}).NewHTTPTestServer()
	defer srv.Close()

	// JWT signed for an unknown tokenID.
	jwt, err := pmaccessproto.SignCallCredential(secret, "unknown", []byte("b"), 0)
	if err != nil {
		t.Fatal(err)
	}
	resp := doRequest(t, srv.URL, jwt, []byte("b"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestStub_Rejects_BodyMismatch(t *testing.T) {
	secret := []byte("s")
	srv := New(Options{
		SecretLookup: StaticLookup(map[string][]byte{"id": secret}),
	}).NewHTTPTestServer()
	defer srv.Close()

	jwt, err := pmaccessproto.SignCallCredential(secret, "id", []byte("original"), 0)
	if err != nil {
		t.Fatal(err)
	}
	resp := doRequest(t, srv.URL, jwt, []byte("tampered"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on body tamper", resp.StatusCode)
	}
}

func TestStub_Rejects_Replay(t *testing.T) {
	secret := []byte("s")
	body := []byte("b")
	srv := New(Options{
		SecretLookup: StaticLookup(map[string][]byte{"id": secret}),
	}).NewHTTPTestServer()
	defer srv.Close()

	jwt, err := pmaccessproto.SignCallCredential(secret, "id", body, 0)
	if err != nil {
		t.Fatal(err)
	}

	resp1 := doRequest(t, srv.URL, jwt, body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first dial status = %d, want 200", resp1.StatusCode)
	}

	resp2 := doRequest(t, srv.URL, jwt, body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("replay dial status = %d, want 403", resp2.StatusCode)
	}
}
