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

package main

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetFromEnv(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	addr := fs.String("proxy-address", ":3128", "")
	window := fs.Duration("retry-window", time.Hour, "")
	ns := fs.String("namespace", "", "")
	t.Setenv("PROVIDER_GATEWAY_PROXY_ADDRESS", ":4000")
	t.Setenv("PROVIDER_GATEWAY_RETRY_WINDOW", "48h")
	t.Setenv("PROVIDER_GATEWAY_NAMESPACE", "from-env")

	require.NoError(t, fs.Parse([]string{"--namespace", "from-flag"}))
	require.NoError(t, setFromEnv(fs))
	assert.Equal(t, ":4000", *addr)
	assert.Equal(t, 48*time.Hour, *window)
	assert.Equal(t, "from-flag", *ns, "the command line wins")
}

func TestSetFromEnvInvalid(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Duration("retry-window", time.Hour, "")
	t.Setenv("PROVIDER_GATEWAY_RETRY_WINDOW", "a week")

	require.NoError(t, fs.Parse(nil))
	assert.ErrorContains(t, setFromEnv(fs), "PROVIDER_GATEWAY_RETRY_WINDOW")
}
