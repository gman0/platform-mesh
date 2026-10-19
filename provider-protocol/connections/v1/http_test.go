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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.platform-mesh.io/provider-protocol/bundle"
)

func TestIfMatch(t *testing.T) {
	etag := strings.Repeat("ab", 32)
	got, err := ParseIfMatch(FormatETag(etag))
	require.NoError(t, err)
	assert.Equal(t, etag, got)

	_, err = ParseIfMatch("")
	assert.ErrorIs(t, err, ErrNoIfMatch)

	for _, h := range []string{
		"*",
		etag,
		`W/"` + etag + `"`,
		`"` + etag + `", "other"`,
		`""`,
		`"a b"`,
		`"a"b"`,
		`"` + etag,
		` "` + etag + `"`,
	} {
		_, err := ParseIfMatch(h)
		assert.ErrorIs(t, err, ErrBadIfMatch, h)
	}
}

func TestBearer(t *testing.T) {
	got, err := ParseBearer(BearerHeader("pmc1_abc"))
	require.NoError(t, err)
	assert.Equal(t, "pmc1_abc", got)

	for _, h := range []string{"", "Bearer", "Bearer ", "bearer pmc1_abc", "Basic pmc1_abc", "Bearer  pmc1_abc", "Bearer pmc1 abc", "Bearer pmc1_abc\n"} {
		_, err := ParseBearer(h)
		assert.ErrorIs(t, err, ErrNoBearer, h)
	}
}

func TestWriteAndReadError(t *testing.T) {
	rec := httptest.NewRecorder()
	require.NoError(t, WriteError(rec, ErrorResponse{Reason: ReasonUnavailable, Message: "standby"}, 4500*time.Millisecond))
	resp := rec.Result()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "5", resp.Header.Get("Retry-After"), "rounded up")
	assert.Equal(t, ContentTypeJSON, resp.Header.Get("Content-Type"))

	e, retry, err := ReadError(resp, time.Now())
	require.NoError(t, err)
	assert.Equal(t, ReasonUnavailable, e.Reason)
	assert.Equal(t, "standby", e.Message)
	assert.Equal(t, 5*time.Second, retry)
}

func TestWriteErrorWithoutRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	require.NoError(t, WriteError(rec, ErrorResponse{Reason: ReasonPreconditionFailed, ETag: "e"}, 0))
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	assert.Empty(t, rec.Header().Get("Retry-After"))
}

func TestReadErrorRefusesForeignResponses(t *testing.T) {
	cases := map[string]*http.Response{
		"HTML challenge page": response(http.StatusForbidden, "text/html", "<html>Checking your browser</html>"),
		"JSON, unknown reason": response(http.StatusForbidden, ContentTypeJSON, `{"reason":"Bogus"}`),
		"JSON, wrong status":   response(http.StatusBadGateway, ContentTypeJSON, `{"reason":"Unavailable"}`),
		"JSON, not an object":  response(http.StatusServiceUnavailable, ContentTypeJSON, `"Unavailable"`),
		"too large":            response(http.StatusServiceUnavailable, ContentTypeJSON, `{"reason":"Unavailable","message":"`+strings.Repeat("a", MaxErrorBodySize)+`"}`),
	}
	for name, resp := range cases {
		_, _, err := ReadError(resp, time.Now())
		assert.ErrorIs(t, err, ErrNotProtocolResponse, name)
	}
}

func TestReadErrorKeepsRetryAfterOfForeignResponses(t *testing.T) {
	resp := response(http.StatusServiceUnavailable, "text/plain", "busy")
	resp.Header.Set("Retry-After", "7")
	_, retry, err := ReadError(resp, time.Now())
	assert.ErrorIs(t, err, ErrNotProtocolResponse)
	assert.Equal(t, 7*time.Second, retry)
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	d, ok := ParseRetryAfter("5", now)
	assert.True(t, ok)
	assert.Equal(t, 5*time.Second, d)

	d, ok = ParseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now)
	assert.True(t, ok)
	assert.Equal(t, 30*time.Second, d)

	d, ok = ParseRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now)
	assert.True(t, ok)
	assert.Equal(t, time.Duration(0), d, "a date in the past means now")

	for _, v := range []string{"", "-1", "1.5", "soon", "99999999999"} {
		_, ok := ParseRetryAfter(v, now)
		assert.False(t, ok, v)
	}
}

func TestReadJSON(t *testing.T) {
	var m ConnectorCASetUpdate
	require.NoError(t, ReadJSON(strings.NewReader(`{"connectorCASet":"pem","later":1}`), MaxBodySize, &m))
	assert.Equal(t, "pem", m.ConnectorCASet)

	assert.ErrorIs(t, ReadJSON(strings.NewReader(`{}{}`), MaxBodySize, &m), ErrInvalidRequest)
	assert.ErrorIs(t, ReadJSON(strings.NewReader(`nope`), MaxBodySize, &m), ErrInvalidRequest)
	assert.ErrorIs(t, ReadJSON(strings.NewReader(`{"connectorCASet":"`+strings.Repeat("a", 100)+`"}`), 50, &m), ErrBodyTooLarge)
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	require.NoError(t, WriteJSON(rec, http.StatusCreated, RegistrationResponse{ConnectionID: "c-1"}))
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), `"connectionID":"c-1"`)
}

func response(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestMaxBodySizeFitsTheLargestBundle(t *testing.T) {
	// A bundle's allowed whitespace doubles when escaped in JSON.
	assert.GreaterOrEqual(t, MaxBodySize, 2*bundle.MaxSize+4096)
}
