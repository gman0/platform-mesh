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
)

func mustParse(t *testing.T, cas ...issued) *Bundle {
	t.Helper()
	var data []byte
	for _, c := range cas {
		data = append(data, c.pem()...)
	}
	b, err := Parse(data, now)
	require.NoError(t, err)
	return b
}

func TestVerifyClient(t *testing.T) {
	ca := newCA(t, "current", nil)
	b := mustParse(t, ca)
	assert.NoError(t, b.VerifyClient(newLeaf(t, ca).cert, now))
}

func TestVerifyClientWithPreviousCA(t *testing.T) {
	prev, cur := newCA(t, "previous", nil), newCA(t, "current", nil)
	b := mustParse(t, prev, cur)
	assert.NoError(t, b.VerifyClient(newLeaf(t, prev).cert, now))
	assert.NoError(t, b.VerifyClient(newLeaf(t, cur).cert, now))
}

func TestVerifyClientRefuses(t *testing.T) {
	ca := newCA(t, "pinned", nil)
	other := newCA(t, "unpinned", nil)
	intermediate := newCA(t, "intermediate", &ca)
	expiredCA := newCA(t, "expired", nil, expired)
	b := mustParse(t, ca, expiredCA)

	cases := map[string]struct {
		leaf issued
		want error
	}{
		"unpinned CA":          {newLeaf(t, other), nil},
		"expired leaf":         {newLeaf(t, ca, expired), nil},
		"pinned CA expired":    {newLeaf(t, expiredCA), nil},
		"through intermediate": {newLeaf(t, intermediate), nil},
		"no EKU":               {newLeaf(t, ca, noEKU), ErrClientUsage},
		"serverAuth only":      {newLeaf(t, ca, serverEKU), ErrClientUsage},
		"no digitalSignature":  {newLeaf(t, ca, noDigitalSignature), ErrClientUsage},
		"the CA itself":        {ca, ErrClientUsage},
	}
	for name, c := range cases {
		err := b.VerifyClient(c.leaf.cert, now)
		if assert.Error(t, err, name) && c.want != nil {
			assert.ErrorIs(t, err, c.want, name)
		}
	}
}

func TestVerifyClientPinnedIntermediate(t *testing.T) {
	// With an external PKI, PM's CA is an intermediate, pinned as the
	// anchor: its leaves are issued directly by a pinned CA.
	root := newCA(t, "root", nil)
	intermediate := newCA(t, "intermediate", &root)
	b := mustParse(t, root, intermediate)
	assert.NoError(t, b.VerifyClient(newLeaf(t, intermediate).cert, now))
}

func TestIssued(t *testing.T) {
	prev, cur, other := newCA(t, "previous", nil), newCA(t, "current", nil), newCA(t, "other", nil)
	both := mustParse(t, prev, cur)
	onlyCur := mustParse(t, cur)

	fromPrev := newLeaf(t, prev).cert
	assert.True(t, both.Issued(fromPrev))
	assert.False(t, onlyCur.Issued(fromPrev), "dropping a CA ends its Sessions")
	assert.False(t, both.Issued(newLeaf(t, other).cert))

	// Expiry doesn't count: an open Session outlives its certificate.
	assert.True(t, onlyCur.Issued(newLeaf(t, cur, expired).cert))
	assert.NoError(t, onlyCur.VerifyClient(newLeaf(t, cur).cert, now))
	assert.Error(t, onlyCur.VerifyClient(newLeaf(t, cur).cert, now.Add(48*time.Hour)))
}

func TestIssuedSameNameDifferentKey(t *testing.T) {
	// A CA with the same subject but another key doesn't count as issuer.
	genuine, impostor := newCA(t, "connector-ca", nil), newCA(t, "connector-ca", nil)
	b := mustParse(t, genuine)
	assert.False(t, b.Issued(newLeaf(t, impostor).cert))
}
