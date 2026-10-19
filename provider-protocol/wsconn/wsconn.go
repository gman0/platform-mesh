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

// Package wsconn carries the Inner TLS over a WebSocket, with the
// protocol's framing on Registration, Control Sessions and Sessions alike:
//
//   - binary messages only; a text message is a protocol error;
//   - at most connectionsv1.MaxMessageSize per message, in both directions;
//   - pings at the outer level, so Edge idle timeouts don't fire;
//   - a byte stream: message boundaries carry no meaning.
package wsconn

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
)

// ErrTextMessage is returned when the peer sends a text message.
var ErrTextMessage = errors.New("text message on a binary-only WebSocket")

// HandshakeTimeout bounds a WebSocket upgrade.
const HandshakeTimeout = 10 * time.Second

// closeTimeout bounds sending the close frame.
const closeTimeout = time.Second

// Dialer returns the PM-side's dialer for the Base URL. tlsConfig is the
// outer TLS (web PKI or the Provider's caBundle); netDial applies the egress
// rules. It never uses a proxy from the environment and doesn't compress:
// the payload is TLS ciphertext.
func Dialer(tlsConfig *tls.Config, netDial func(ctx context.Context, network, addr string) (net.Conn, error)) *websocket.Dialer {
	return &websocket.Dialer{
		NetDialContext:    netDial,
		TLSClientConfig:   tlsConfig,
		Proxy:             nil,
		HandshakeTimeout:  HandshakeTimeout,
		ReadBufferSize:    connectionsv1.MaxMessageSize,
		WriteBufferSize:   connectionsv1.MaxMessageSize,
		EnableCompression: false,
	}
}

// Upgrader returns the Provider-side's upgrader. The callers aren't browsers
// and send no Origin; the default origin check stays in place for any that
// do.
func Upgrader() *websocket.Upgrader {
	return &websocket.Upgrader{
		HandshakeTimeout:  HandshakeTimeout,
		ReadBufferSize:    connectionsv1.MaxMessageSize,
		WriteBufferSize:   connectionsv1.MaxMessageSize,
		EnableCompression: false,
	}
}

// Options tune a Conn; the zero value uses the protocol's values.
type Options struct {
	// PingInterval defaults to connectionsv1.PingInterval.
	PingInterval time.Duration
}

// Conn is a net.Conn over a WebSocket's binary messages. One goroutine may
// read while others write.
type Conn struct {
	ws *websocket.Conn

	readMu sync.Mutex
	r      io.Reader

	writeMu sync.Mutex

	closeOnce sync.Once
	done      chan struct{}
}

var _ net.Conn = (*Conn)(nil)

// New wraps an upgraded or dialled WebSocket and starts its pings.
func New(ws *websocket.Conn, o Options) *Conn {
	if o.PingInterval <= 0 {
		o.PingInterval = connectionsv1.PingInterval
	}
	ws.SetReadLimit(connectionsv1.MaxMessageSize)
	c := &Conn{ws: ws, done: make(chan struct{})}
	go c.ping(o.PingInterval)
	return c
}

// Read reads the next bytes, across message boundaries.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.r == nil {
			mt, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				_ = c.writeClose(websocket.CloseUnsupportedData)
				return 0, ErrTextMessage
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if errors.Is(err, io.EOF) {
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// Write writes p as one or more binary messages of at most
// connectionsv1.MaxMessageSize.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), connectionsv1.MaxMessageSize)
		if err := c.ws.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close sends a normal close frame, best effort, and closes the connection.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.writeClose(websocket.CloseNormalClosure)
		err = c.ws.Close()
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	return errors.Join(c.ws.SetReadDeadline(t), c.ws.SetWriteDeadline(t))
}
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

func (c *Conn) ping(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			// WriteControl may run concurrently with Write.
			if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(interval)); err != nil {
				return
			}
		}
	}
}

func (c *Conn) writeClose(code int) error {
	return c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(closeTimeout))
}
