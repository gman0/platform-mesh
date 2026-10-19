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

package testvectors_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
	"go.platform-mesh.io/provider-protocol/credential"
	"go.platform-mesh.io/provider-protocol/fingerprint"
	tv "go.platform-mesh.io/provider-protocol/testvectors"
)

func TestFixedToken(t *testing.T) {
	tok, err := credential.ParseOnboardingToken(tv.Token)
	require.NoError(t, err)
	assert.Equal(t, tv.TokenBaseURL, tok.BaseURL())
	assert.Equal(t, tv.TokenServerKeyFP, tok.ServerKey().String())
	assert.Equal(t, tv.TokenID, tok.ID())
	assert.Equal(t, tv.TokenSecretHash, tok.SecretHash().String())
	assert.Equal(t, tv.Token, tok.Reveal())
}

func TestFixedConnectionSecret(t *testing.T) {
	s, err := credential.ParseConnectionSecret(tv.ConnectionSecret)
	require.NoError(t, err)
	assert.Equal(t, tv.ConnectionSecretHash, s.Hash().String())
}

func TestOnboardingTokens(t *testing.T) {
	for _, c := range tv.OnboardingTokens() {
		_, err := credential.ParseOnboardingToken(c.Text)
		assertValid(t, c, err)
	}
}

func TestConnectionSecrets(t *testing.T) {
	for _, c := range tv.ConnectionSecrets() {
		_, err := credential.ParseConnectionSecret(c.Text)
		assertValid(t, c, err)
	}
}

func TestHashes(t *testing.T) {
	for _, c := range tv.Hashes() {
		_, err := credential.ParseHash(c.Text)
		assertValid(t, c, err)
	}
}

func TestFingerprints(t *testing.T) {
	for _, c := range tv.Fingerprints() {
		_, err := fingerprint.Parse(c.Text)
		assertValid(t, c, err)
	}
}

func TestBundles(t *testing.T) {
	for _, c := range tv.Bundles(t) {
		_, err := bundle.Parse(c.PEM, tv.Now)
		if c.Reason == "" {
			assert.NoError(t, err, c.Name)
			continue
		}
		r, ok := bundle.ReasonOf(err)
		if assert.True(t, ok, "%s: %v", c.Name, err) {
			assert.Equal(t, c.Reason, r, c.Name)
		}
	}
}

func TestSameSet(t *testing.T) {
	first, second := tv.SameSet(t)
	a, err := bundle.Parse(first, tv.Now)
	require.NoError(t, err)
	b, err := bundle.Parse(second, tv.Now)
	require.NoError(t, err)
	assert.Equal(t, a.ETag(), b.ETag())
	assert.True(t, a.Equal(b))
}

func TestHelloFrames(t *testing.T) {
	for _, c := range tv.HelloFrames() {
		_, err := connectionsv1.ReadHello(bytes.NewReader(c.Frame))
		if c.Err == nil {
			assert.NoError(t, err, c.Name)
		} else {
			assert.ErrorIs(t, err, c.Err, c.Name)
		}
	}
}

func TestHelloChecks(t *testing.T) {
	for _, c := range tv.HelloChecks() {
		err := c.Hello.Check(c.PathID, c.ClusterName)
		if c.Valid {
			assert.NoError(t, err, c.Name)
		} else {
			assert.ErrorIs(t, err, connectionsv1.ErrHelloMismatch, c.Name)
		}
	}
}

func assertValid(t *testing.T, c tv.TextCase, err error) {
	t.Helper()
	if c.Valid {
		assert.NoError(t, err, c.Name)
	} else {
		assert.Error(t, err, c.Name)
	}
}
