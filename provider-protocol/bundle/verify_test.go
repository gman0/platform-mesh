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

package bundle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/internal/testcerts"
)

func mustParse(t *testing.T, cas ...testcerts.Cert) *Bundle {
	t.Helper()
	var data []byte
	for _, c := range cas {
		data = append(data, c.PEM()...)
	}
	b, err := Parse(data, testcerts.Now)
	require.NoError(t, err)
	return b
}

func TestVerifyClient(t *testing.T) {
	ca := testcerts.CA(t, "current", nil)
	b := mustParse(t, ca)
	assert.NoError(t, b.VerifyClient(testcerts.Leaf(t, ca).Cert, testcerts.Now))
}

func TestVerifyClientWithPreviousCA(t *testing.T) {
	prev, cur := testcerts.CA(t, "previous", nil), testcerts.CA(t, "current", nil)
	b := mustParse(t, prev, cur)
	assert.NoError(t, b.VerifyClient(testcerts.Leaf(t, prev).Cert, testcerts.Now))
	assert.NoError(t, b.VerifyClient(testcerts.Leaf(t, cur).Cert, testcerts.Now))
}

func TestVerifyClientRefuses(t *testing.T) {
	ca := testcerts.CA(t, "pinned", nil)
	other := testcerts.CA(t, "unpinned", nil)
	intermediate := testcerts.CA(t, "intermediate", &ca)
	expiredCA := testcerts.CA(t, "expired", nil, testcerts.Expired)
	b := mustParse(t, ca, expiredCA)

	cases := map[string]struct {
		leaf testcerts.Cert
		want error
	}{
		"unpinned CA":          {testcerts.Leaf(t, other), nil},
		"expired leaf":         {testcerts.Leaf(t, ca, testcerts.Expired), nil},
		"pinned CA expired":    {testcerts.Leaf(t, expiredCA), nil},
		"through intermediate": {testcerts.Leaf(t, intermediate), nil},
		"no EKU":               {testcerts.Leaf(t, ca, testcerts.NoEKU), ErrClientUsage},
		"serverAuth only":      {testcerts.Leaf(t, ca, testcerts.ServerEKU), ErrClientUsage},
		"no digitalSignature":  {testcerts.Leaf(t, ca, testcerts.NoDigitalSignature), ErrClientUsage},
		"the CA itself":        {ca, ErrClientUsage},
	}
	for name, c := range cases {
		err := b.VerifyClient(c.leaf.Cert, testcerts.Now)
		if assert.Error(t, err, name) && c.want != nil {
			assert.ErrorIs(t, err, c.want, name)
		}
	}
}

func TestVerifyClientPinnedIntermediate(t *testing.T) {
	// With an external PKI, PM's CA is an intermediate, pinned as the
	// anchor: its leaves are issued directly by a pinned CA.
	root := testcerts.CA(t, "root", nil)
	intermediate := testcerts.CA(t, "intermediate", &root)
	b := mustParse(t, root, intermediate)
	assert.NoError(t, b.VerifyClient(testcerts.Leaf(t, intermediate).Cert, testcerts.Now))
}

func TestIssued(t *testing.T) {
	prev, cur, other := testcerts.CA(t, "previous", nil), testcerts.CA(t, "current", nil), testcerts.CA(t, "other", nil)
	both := mustParse(t, prev, cur)
	onlyCur := mustParse(t, cur)

	fromPrev := testcerts.Leaf(t, prev).Cert
	assert.True(t, both.Issued(fromPrev))
	assert.False(t, onlyCur.Issued(fromPrev), "dropping a CA ends its Sessions")
	assert.False(t, both.Issued(testcerts.Leaf(t, other).Cert))

	// Expiry doesn't count: an open Session outlives its certificate.
	assert.True(t, onlyCur.Issued(testcerts.Leaf(t, cur, testcerts.Expired).Cert))
	assert.NoError(t, onlyCur.VerifyClient(testcerts.Leaf(t, cur).Cert, testcerts.Now))
	assert.Error(t, onlyCur.VerifyClient(testcerts.Leaf(t, cur).Cert, testcerts.Now.Add(48*time.Hour)))
}

func TestIssuedSameNameDifferentKey(t *testing.T) {
	// A CA with the same subject but another key doesn't count as issuer.
	genuine, impostor := testcerts.CA(t, "connector-ca", nil), testcerts.CA(t, "connector-ca", nil)
	b := mustParse(t, genuine)
	assert.False(t, b.Issued(testcerts.Leaf(t, impostor).Cert))
}
