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

package accessgrant

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// handshakeBody is the JSON payload posted to /access.
type handshakeBody struct {
	KcpURL      string `json:"kcpURL"`
	KcpCABundle string `json:"kcpCABundle"`
	SAToken     string `json:"saToken"`
}

// SATokenMinter mints a ServiceAccount token via the TokenRequest
// subresource. Extracted as a function type so tests can stub it
// without needing fake-client subresource support.
type SATokenMinter func(ctx context.Context, cl ctrlruntimeclient.Client, saName, saNamespace string) (string, error)

// defaultSATokenMinter is the production SATokenMinter. It POSTs a
// TokenRequest against the ServiceAccount's token subresource.
func defaultSATokenMinter(ctx context.Context, cl ctrlruntimeclient.Client, saName, saNamespace string) (string, error) {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: saNamespace}}
	treq := &authenticationv1.TokenRequest{}
	if err := cl.SubResource("token").Create(ctx, sa, treq); err != nil {
		return "", err
	}
	return treq.Status.Token, nil
}

// httpClientFor returns an http.Client that verifies the /access server
// certificate against caBundlePEM if non-empty, otherwise falls back to
// base. base must be non-nil.
func httpClientFor(base *http.Client, caBundlePEM string) (*http.Client, error) {
	if caBundlePEM == "" {
		return base, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caBundlePEM)) {
		return nil, fmt.Errorf("spec.caBundle: no valid certificates parsed")
	}
	// Clone transport to avoid mutating the shared one; fall back to a
	// fresh Transport{} if base has no custom transport.
	var baseTransport *http.Transport
	if rt, ok := base.Transport.(*http.Transport); ok && rt != nil {
		baseTransport = rt.Clone()
	} else {
		baseTransport = &http.Transport{}
	}
	baseTransport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   base.Timeout,
		Transport: baseTransport,
	}, nil
}

// trim truncates s for inclusion in a condition message.
func trim(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
