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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxBodySize bounds every request and response body: room for a
	// Registration with the largest Pinned Bundle.
	MaxBodySize = 128 * 1024
	// MaxErrorBodySize bounds how much of an error response is read.
	MaxErrorBodySize = 16 * 1024
)

var (
	// ErrNoIfMatch is returned for a Pinned Bundle replacement without
	// If-Match.
	ErrNoIfMatch = errors.New("missing If-Match")
	// ErrBadIfMatch is returned for an If-Match that isn't exactly one strong
	// entity tag.
	ErrBadIfMatch = errors.New("malformed If-Match")
	// ErrNoBearer is returned for a missing or malformed bearer.
	ErrNoBearer = errors.New("missing or malformed bearer")
	// ErrNotProtocolResponse is returned for an error response that isn't
	// the protocol's: not JSON, or without a known reason. Before an
	// upgrade, it's typically the Edge's.
	ErrNotProtocolResponse = errors.New("not a protocol response")
	// ErrBodyTooLarge is returned for a body beyond its limit.
	ErrBodyTooLarge = errors.New("body too large")
)

// FormatETag returns an etag as a strong entity tag, for If-Match.
func FormatETag(etag string) string { return `"` + etag + `"` }

// ParseIfMatch returns the etag of an If-Match header: exactly one strong
// entity tag. "*", lists and weak tags are refused.
func ParseIfMatch(h string) (string, error) {
	if h == "" {
		return "", ErrNoIfMatch
	}
	if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
		return "", ErrBadIfMatch
	}
	etag := h[1 : len(h)-1]
	// etagc = %x21 / %x23-7E (no quotes, no whitespace)
	if etag == "" || strings.ContainsFunc(etag, func(c rune) bool { return c < 0x21 || c == '"' || c > 0x7e }) {
		return "", ErrBadIfMatch
	}
	return etag, nil
}

const bearerPrefix = "Bearer "

// BearerHeader returns an Authorization header value for a secret.
func BearerHeader(secret string) string { return bearerPrefix + secret }

// ParseBearer returns the credential of an Authorization header: exactly
// "Bearer ", then a credential without whitespace. Its form is checked by
// the credential package.
func ParseBearer(h string) (string, error) {
	cred, ok := strings.CutPrefix(h, bearerPrefix)
	if !ok || cred == "" || strings.ContainsFunc(cred, func(c rune) bool { return c <= 0x20 || c > 0x7e }) {
		return "", ErrNoBearer
	}
	return cred, nil
}

// WriteJSON writes v as the response body with status.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}

// WriteError writes a refusal with its reason's status, and Retry-After when
// retryAfter is positive, in whole seconds, rounded up.
func WriteError(w http.ResponseWriter, e ErrorResponse, retryAfter time.Duration) error {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
	}
	return WriteJSON(w, e.Reason.HTTPStatus(), e)
}

// ReadJSON decodes one JSON object of at most limit bytes into v. Unknown
// fields are ignored; anything after the object is refused.
func ReadJSON(r io.Reader, limit int64, v any) error {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return ErrBodyTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: data after the object", ErrInvalidRequest)
	}
	return nil
}

// ReadError reads a refusal: its ErrorResponse and Retry-After (0 if none).
// It returns ErrNotProtocolResponse, with the Retry-After, for a response
// that isn't the protocol's.
func ReadError(resp *http.Response, now time.Time) (ErrorResponse, time.Duration, error) {
	retryAfter, _ := ParseRetryAfter(resp.Header.Get("Retry-After"), now)
	var e ErrorResponse
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), ContentTypeJSON) {
		return e, retryAfter, ErrNotProtocolResponse
	}
	if err := ReadJSON(resp.Body, MaxErrorBodySize, &e); err != nil || !e.Reason.Known() || e.Reason.HTTPStatus() != resp.StatusCode {
		return ErrorResponse{}, retryAfter, ErrNotProtocolResponse
	}
	return e, retryAfter, nil
}

// ParseRetryAfter parses a Retry-After value: delay-seconds or an HTTP date.
// The Edge may send either.
func ParseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if s, err := strconv.ParseUint(v, 10, 31); err == nil {
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}
