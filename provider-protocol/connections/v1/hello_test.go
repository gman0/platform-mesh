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

package v1

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/credential"
)

func validHello() Hello {
	return Hello{
		ConnectionID: "c-" + strings.Repeat("a", 26),
		ClusterName:  "2x8k9abc",
		Hosts:        []string{"nereus.kcp.example.com:443"},
		Sub:          "0f3a9c",
	}
}

// frame builds a Hello frame by hand: length, then body.
func frame(body string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

func TestHelloRoundTrip(t *testing.T) {
	h := validHello()
	var buf bytes.Buffer
	require.NoError(t, WriteHello(&buf, h))

	assert.Equal(t, uint16(buf.Len()-2), binary.BigEndian.Uint16(buf.Bytes()[:2]))
	assert.JSONEq(t, `{
		"connectionID": "c-aaaaaaaaaaaaaaaaaaaaaaaaaa",
		"clusterName": "2x8k9abc",
		"hosts": ["nereus.kcp.example.com:443"],
		"sub": "0f3a9c"
	}`, buf.String()[2:])

	got, err := ReadHello(&buf)
	require.NoError(t, err)
	assert.Equal(t, h, got)
}

func TestReadHelloLeavesTheStream(t *testing.T) {
	// yamux starts right after the Hello; nothing past it is consumed.
	var buf bytes.Buffer
	require.NoError(t, WriteHello(&buf, validHello()))
	buf.WriteString("yamux")

	_, err := ReadHello(&buf)
	require.NoError(t, err)
	assert.Equal(t, "yamux", buf.String())
}

func TestReadHelloIgnoresUnknownFields(t *testing.T) {
	h, err := ReadHello(bytes.NewReader(frame(
		`{"connectionID":"c-aaaaaaaaaaaaaaaaaaaaaaaaaa","clusterName":"2x8k9abc","hosts":["h"],"addedLater":1}`)))
	require.NoError(t, err)
	assert.Equal(t, []string{"h"}, h.Hosts)
}

func TestReadHelloSizes(t *testing.T) {
	_, err := ReadHello(bytes.NewReader([]byte{0, 0}))
	assert.ErrorIs(t, err, ErrHelloTooLarge, "empty")

	tooLarge := binary.BigEndian.AppendUint16(nil, MaxHelloSize+1)
	_, err = ReadHello(bytes.NewReader(append(tooLarge, make([]byte, MaxHelloSize+1)...)))
	assert.ErrorIs(t, err, ErrHelloTooLarge, "oversized")

	_, err = ReadHello(bytes.NewReader([]byte{0}))
	assert.Error(t, err, "truncated length")

	_, err = ReadHello(bytes.NewReader(frame(`{"connectionID":`)[:10]))
	assert.Error(t, err, "truncated body")
}

func TestReadHelloRefuses(t *testing.T) {
	id := "c-" + strings.Repeat("a", 26)
	cases := map[string]string{
		"not JSON":              `hello`,
		"array":                 `[]`,
		"two objects":           `{"connectionID":"` + id + `","clusterName":"x1","hosts":["h"]}{}`,
		"missing connectionID":  `{"clusterName":"2x8k9abc","hosts":["h"]}`,
		"token ID":              `{"connectionID":"t-` + strings.Repeat("a", 26) + `","clusterName":"2x8k9abc","hosts":["h"]}`,
		"missing clusterName":   `{"connectionID":"` + id + `","hosts":["h"]}`,
		"workspace path":        `{"connectionID":"` + id + `","clusterName":"root:providers:wildwest","hosts":["h"]}`,
		"system cluster":        `{"connectionID":"` + id + `","clusterName":"system:admin","hosts":["h"]}`,
		"missing hosts":         `{"connectionID":"` + id + `","clusterName":"2x8k9abc"}`,
		"empty hosts":           `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":[]}`,
		"hosts not a list":      `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":"h"}`,
		"host with scheme":      `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["https://h"]}`,
		"host with path":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h/services"]}`,
		"host uppercase":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["Nereus.kcp"]}`,
		"host empty":            `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":[""]}`,
		"host bad port":         `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h:0"]}`,
		"host port leading 0":   `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h:0443"]}`,
		"host bare IPv6":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["::1"]}`,
		"host duplicate":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h","h"]}`,
		"too many hosts":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["a","b","c","d","e"]}`,
		"sub with space":        `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h"],"sub":"a b"}`,
		"sub too long":          `{"connectionID":"` + id + `","clusterName":"2x8k9abc","hosts":["h"],"sub":"` + strings.Repeat("a", MaxHelloSubLength+1) + `"}`,
		"connectionID a number": `{"connectionID":1,"clusterName":"2x8k9abc","hosts":["h"]}`,
	}
	for name, body := range cases {
		_, err := ReadHello(bytes.NewReader(frame(body)))
		assert.ErrorIs(t, err, ErrHelloMalformed, name)
	}
}

func TestValidHosts(t *testing.T) {
	for _, h := range []string{
		"nereus.kcp.example.com",
		"nereus.kcp.example.com:443",
		"root-kcp.kcp-system.svc:6443",
		"10.0.0.1:443",
		"[2001:db8::1]:443",
		"localhost",
	} {
		assert.True(t, validHost(h), h)
	}
}

func TestWriteHelloValidates(t *testing.T) {
	h := validHello()
	h.Hosts = nil
	assert.ErrorIs(t, WriteHello(&bytes.Buffer{}, h), ErrHelloMalformed)
}

func TestHelloCheck(t *testing.T) {
	h := validHello()
	assert.NoError(t, h.Check(h.ConnectionID, h.ClusterName))
	assert.ErrorIs(t, h.Check(credential.NewConnectionID(), h.ClusterName), ErrHelloMismatch, "path rewritten to another Connection")
	assert.ErrorIs(t, h.Check(h.ConnectionID, "other1"), ErrHelloMismatch, "another Provider Workspace")
}

func TestValidateClusterName(t *testing.T) {
	assert.NoError(t, ValidateClusterName("2x8k9abc"))
	for _, s := range []string{"", "a", "A1", "root:providers:x", "system:admin", "system:", "-ab", "ab-", strings.Repeat("a", 64)} {
		assert.ErrorIs(t, ValidateClusterName(s), ErrInvalidClusterName, s)
	}
}
