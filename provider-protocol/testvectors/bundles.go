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

package testvectors

import (
	"bytes"
	"encoding/pem"
	"testing"

	"go.platform-mesh.io/provider-protocol/bundle"
)

// BundleCase is a PEM bundle and the reason it's refused, empty if it's
// accepted at Now.
type BundleCase struct {
	Name   string
	PEM    []byte
	Reason bundle.Reason
}

// Bundles are Pinned Bundles, as received at Registration, in a push or a
// re-pin.
func Bundles(t testing.TB) []BundleCase {
	t.Helper()
	a, b := CA(t, "a", nil), CA(t, "b", nil)
	root := CA(t, "external root", nil)

	var many [][]byte
	for range bundle.MaxCertificates + 1 {
		many = append(many, CA(t, "many", nil).PEM())
	}

	return []BundleCase{
		{"one CA", a.PEM(), ""},
		{"two CAs", Join(a.PEM(), b.PEM()), ""},
		{"whitespace around and between", Join([]byte("\n \t\r\n"), a.PEM(), []byte("\n\n"), b.PEM(), []byte(" \n")), ""},
		{"an expired CA next to a valid one", Join(CA(t, "old", nil, Expired).PEM(), a.PEM()), ""},
		{"an intermediate under an external root", CA(t, "pm", &root).PEM(), ""},

		{"empty", nil, bundle.ReasonEmpty},
		{"whitespace only", []byte(" \n\t"), bundle.ReasonEmpty},
		{"malformed PEM", []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), bundle.ReasonMalformedPEM},
		{"malformed block before a good one", Join([]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), a.PEM()), bundle.ReasonMalformedPEM},
		{"non-CERTIFICATE block", Join(a.PEM(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})), bundle.ReasonNotCertificate},
		{"PEM headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a.Cert.Raw}), bundle.ReasonPEMHeaders},
		{"text between blocks", Join(a.PEM(), []byte("# b\n"), b.PEM()), bundle.ReasonTextOutsideBlocks},
		{"text after END", bytes.Replace(a.PEM(), []byte("-----END CERTIFICATE-----"), []byte("-----END CERTIFICATE----- x"), 1), bundle.ReasonMalformedPEM},
		{"duplicate certificate", Join(a.PEM(), b.PEM(), a.PEM()), bundle.ReasonDuplicate},
		{"non-CA certificate", Leaf(t, a).PEM(), bundle.ReasonNotCA},
		{"CA without keyCertSign", CA(t, "x", nil, NoCertSign).PEM(), bundle.ReasonNotCA},
		{"only expired certificates", Join(CA(t, "x", nil, Expired).PEM(), CA(t, "y", nil, Expired).PEM()), bundle.ReasonAllExpired},
		{"too many certificates", Join(many...), bundle.ReasonTooMany},
		{"too large", Join(a.PEM(), bytes.Repeat([]byte("\n"), bundle.MaxSize)), bundle.ReasonTooLarge},
	}
}

// SameSet returns one set of CAs as two bundles that differ only in order
// and whitespace: the same etag, and a push of one over the other is a
// no-op.
func SameSet(t testing.TB) (first, second []byte) {
	t.Helper()
	a, b := CA(t, "a", nil), CA(t, "b", nil)
	return Join(a.PEM(), b.PEM()), Join([]byte("\n"), b.PEM(), []byte("\r\n\n"), a.PEM())
}
