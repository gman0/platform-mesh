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

package proxy

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
)

// maxStatusLine bounds how much the sniffer looks at.
const maxStatusLine = 256

// statusSniffer reads the status line of a tunnel's first response as it
// passes, without changing or holding back any byte, and reports whether
// kcp was reached: the Connector answers 502 or 504 when it wasn't. Later
// responses on a reused connection aren't read; the signal is per host, and
// client-go opens a new tunnel per watch.
type statusSniffer struct {
	report func(reachable bool, msg string)

	mu   sync.Mutex
	buf  []byte
	done bool
}

// Write receives a copy of the bytes flowing back to the operator.
func (s *statusSniffer) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return len(b), nil
	}
	s.buf = append(s.buf, b[:min(len(b), maxStatusLine-len(s.buf))]...)
	if i := bytes.IndexByte(s.buf, '\n'); i >= 0 {
		s.finish(strings.TrimRight(string(s.buf[:i]), "\r"))
	} else if len(s.buf) >= maxStatusLine {
		s.finish(string(s.buf))
	}
	return len(b), nil
}

// end is called when the upstream side ends: no response at all means kcp
// wasn't reached.
func (s *statusSniffer) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.done = true
		s.report(false, "no response through the Connector")
	}
}

func (s *statusSniffer) finish(line string) {
	s.done = true
	s.buf = nil
	code, ok := statusCode(line)
	switch {
	case !ok:
		s.report(false, "malformed response through the Connector")
	case code == 502 || code == 504:
		s.report(false, "kcp not reached: "+strconv.Itoa(code)+" from the Connector")
	default:
		s.report(true, "")
	}
}

// statusCode parses "HTTP/1.1 200 OK".
func statusCode(line string) (int, bool) {
	proto, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.HasPrefix(proto, "HTTP/1.") {
		return 0, false
	}
	codeText, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}
