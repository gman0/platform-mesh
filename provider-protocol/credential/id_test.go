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

package credential

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A Kubernetes object name (DNS-1123 label), which IDs must also be.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func TestNewIDs(t *testing.T) {
	tid := NewTokenID()
	cid := NewConnectionID()

	assert.NoError(t, ValidateTokenID(tid))
	assert.NoError(t, ValidateConnectionID(cid))
	assert.Len(t, tid, 28)
	assert.Len(t, cid, 28)
	assert.Regexp(t, dns1123Label, tid)
	assert.Regexp(t, dns1123Label, cid)

	assert.NotEqual(t, cid, NewConnectionID())
}

func TestIDKindsDontMix(t *testing.T) {
	assert.ErrorIs(t, ValidateTokenID(NewConnectionID()), ErrMalformedID)
	assert.ErrorIs(t, ValidateConnectionID(NewTokenID()), ErrMalformedID)
}

func TestValidateIDRefuses(t *testing.T) {
	ok := "c-" + strings.Repeat("a", 26)
	assert.NoError(t, ValidateConnectionID(ok))

	cases := map[string]string{
		"empty":          "",
		"prefix only":    "c-",
		"no prefix":      strings.Repeat("a", 28),
		"too short":      ok[:27],
		"too long":       ok + "a",
		"uppercase":      "c-" + strings.Repeat("A", 26),
		"digit 1":        "c-" + strings.Repeat("1", 26),
		"digit 8":        "c-" + strings.Repeat("8", 26),
		"slash":          "c-" + strings.Repeat("a", 25) + "/",
		"dot":            "c-" + strings.Repeat("a", 25) + ".",
		"percent":        "c-" + strings.Repeat("a", 25) + "%",
		"multibyte rune": "c-" + strings.Repeat("a", 24) + "é",
	}
	for name, id := range cases {
		assert.ErrorIs(t, ValidateConnectionID(id), ErrMalformedID, name)
	}
}
