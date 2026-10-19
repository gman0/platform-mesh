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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/kcp-dev/logicalcluster/v3"

	"go.platform-mesh.io/provider-protocol/credential"
)

const (
	// MaxHelloSize bounds the Hello's JSON.
	MaxHelloSize = 4096
	// MaxHelloHosts bounds the hosts a Session serves.
	// A Session serves its shard's VW host, so normally a Hello message contains one host.
	// 4 is just to leave room just in case.
	MaxHelloHosts = 4
	// MaxHelloSubLength bounds the opaque audit ID.
	MaxHelloSubLength = 128
)

var (
	// ErrHelloTooLarge is returned for a Hello beyond MaxHelloSize, or empty.
	ErrHelloTooLarge = errors.New("hello size out of bounds")
	// ErrHelloMalformed is returned for a Hello that doesn't decode or has
	// invalid fields.
	ErrHelloMalformed = errors.New("malformed hello")
	// ErrHelloMismatch is returned when a Hello is for another Connection
	// than the Session's path, or another Provider Workspace than the
	// Connection's.
	ErrHelloMismatch = errors.New("hello doesn't match the connection")
)

// Hello is the Connector's first message inside a Session's Inner TLS,
// before yamux starts: a big-endian uint16 length, then this JSON object.
type Hello struct {
	// ConnectionID is the Connection the Session is for; it must equal the
	// Session path's ID.
	ConnectionID string `json:"connectionID"`

	// ClusterName is the Provider Workspace's logical cluster name; it must
	// equal the one stored at Registration.
	ClusterName string `json:"clusterName"`

	// Hosts are the virtual-workspace hosts (host or host:port) the Session
	// serves, besides the Provider Workspace, which every Session serves.
	// Routing only, not authority.
	Hosts []string `json:"hosts"`

	// Sub is an opaque Session-group ID, for audit.
	Sub string `json:"sub,omitempty"`
}

// WriteHello validates and writes a Hello.
func WriteHello(w io.Writer, h Hello) error {
	if err := h.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(body) > MaxHelloSize {
		return ErrHelloTooLarge
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(body)), uint16(len(body)))
	_, err = w.Write(append(frame, body...))
	return err
}

// ReadHello reads and validates a Hello. It doesn't check it against the
// Connection; see Hello.Check. The caller bounds the time it may take.
func ReadHello(r io.Reader) (Hello, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return Hello{}, fmt.Errorf("reading hello: %w", err)
	}
	n := binary.BigEndian.Uint16(size[:])
	if n == 0 || n > MaxHelloSize {
		return Hello{}, ErrHelloTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Hello{}, fmt.Errorf("reading hello: %w", err)
	}

	var h Hello
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&h); err != nil {
		return Hello{}, fmt.Errorf("%w: %v", ErrHelloMalformed, err)
	}
	if dec.More() {
		return Hello{}, fmt.Errorf("%w: data after the object", ErrHelloMalformed)
	}
	if err := h.Validate(); err != nil {
		return Hello{}, err
	}
	return h, nil
}

// Validate checks the Hello's fields on their own.
func (h Hello) Validate() error {
	if err := credential.ValidateConnectionID(h.ConnectionID); err != nil {
		return fmt.Errorf("%w: connectionID", ErrHelloMalformed)
	}
	if ValidateClusterName(h.ClusterName) != nil {
		return fmt.Errorf("%w: clusterName", ErrHelloMalformed)
	}
	if len(h.Hosts) == 0 || len(h.Hosts) > MaxHelloHosts {
		return fmt.Errorf("%w: hosts", ErrHelloMalformed)
	}
	seen := map[string]bool{}
	for _, host := range h.Hosts {
		if !validHost(host) || seen[host] {
			return fmt.Errorf("%w: hosts", ErrHelloMalformed)
		}
		seen[host] = true
	}
	if len(h.Sub) > MaxHelloSubLength || strings.ContainsFunc(h.Sub, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return fmt.Errorf("%w: sub", ErrHelloMalformed)
	}
	return nil
}

// Check is the Session's essential check: the Hello names the Connection of
// the Session's path and the Provider Workspace stored for it at
// Registration. One Connector Certificate serves every Connection of a PM
// Instance, so the Inner TLS alone doesn't say which Connection a Session is
// for.
func (h Hello) Check(pathConnectionID, clusterName string) error {
	if h.ConnectionID != pathConnectionID || h.ClusterName != clusterName {
		return ErrHelloMismatch
	}
	return nil
}

// ErrInvalidClusterName is returned for a name that isn't a Provider
// Workspace's logical cluster name.
var ErrInvalidClusterName = errors.New("invalid logical cluster name")

// ValidateClusterName checks that s is a logical cluster name as kcp assigns
// it to a workspace. Workspace paths (root:providers:...) and kcp's system
// logical clusters (system:...) are refused.
func ValidateClusterName(s string) error {
	if strings.HasPrefix(s, "system:") || !logicalcluster.Name(s).IsValid() {
		return ErrInvalidClusterName
	}
	return nil
}

// A DNS name of lowercase labels.
var hostnameRE = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)

// validHost accepts a lowercase DNS name or an IP address, with an optional
// port, as in an endpoint slice URL's host.
func validHost(s string) bool {
	if s == "" || len(s) > 253+6 {
		return false
	}
	host := s
	if h, port, err := net.SplitHostPort(s); err == nil {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return false
		}
		host = h
	} else if strings.Contains(s, ":") && !strings.HasPrefix(s, "[") {
		// A bare IPv6 address without brackets would be ambiguous.
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String() == host
	}
	return len(host) <= 253 && hostnameRE.MatchString(host)
}
