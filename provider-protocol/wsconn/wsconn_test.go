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

package wsconn

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
)

// pair returns both ends of a WebSocket, unwrapped: the client end dialled
// with Dialer, the server end upgraded with Upgrader.
func pair(t *testing.T) (client, server *websocket.Conn) {
	t.Helper()
	upgraded := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := Upgrader().Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		upgraded <- ws
	}))
	t.Cleanup(srv.Close)

	ws, resp, err := Dialer(nil, nil).DialContext(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = ws.Close() })

	select {
	case s := <-upgraded:
		t.Cleanup(func() { _ = s.Close() })
		return ws, s
	case <-time.After(5 * time.Second):
		t.Fatal("no upgrade")
		return nil, nil
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestStreamAcrossMessages(t *testing.T) {
	cws, sws := pair(t)
	c, s := New(cws, Options{}), New(sws, Options{})

	data := randomBytes(t, 100*1024+7)
	go func() { _, _ = c.Write(data) }()

	got := make([]byte, len(data))
	_, err := io.ReadFull(s, got)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestMessagesAreBinaryAndCapped(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	data := randomBytes(t, 70*1024)
	go func() { _, _ = c.Write(data) }()

	var sizes []int
	var got []byte
	for len(got) < len(data) {
		mt, msg, err := sws.ReadMessage()
		require.NoError(t, err)
		assert.Equal(t, websocket.BinaryMessage, mt)
		sizes = append(sizes, len(msg))
		got = append(got, msg...)
	}
	assert.Equal(t, []int{32768, 32768, 6144}, sizes)
	assert.Equal(t, data, got)
}

func TestTextMessageRefused(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	require.NoError(t, sws.WriteMessage(websocket.TextMessage, []byte("hello")))
	_, err := c.Read(make([]byte, 16))
	assert.ErrorIs(t, err, ErrTextMessage)

	_, _, err = sws.ReadMessage()
	assert.True(t, websocket.IsCloseError(err, websocket.CloseUnsupportedData), "got %v", err)
}

func TestOversizedMessageRefused(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	require.NoError(t, sws.WriteMessage(websocket.BinaryMessage, make([]byte, connectionsv1.MaxMessageSize+1)))
	_, err := io.ReadAll(c)
	assert.ErrorIs(t, err, websocket.ErrReadLimit)

	_, _, err = sws.ReadMessage()
	assert.True(t, websocket.IsCloseError(err, websocket.CloseMessageTooBig), "got %v", err)
}

func TestMaxSizeMessageAccepted(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	data := randomBytes(t, connectionsv1.MaxMessageSize)
	require.NoError(t, sws.WriteMessage(websocket.BinaryMessage, data))
	got := make([]byte, len(data))
	_, err := io.ReadFull(c, got)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestPings(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{PingInterval: 20 * time.Millisecond})
	defer c.Close()

	var pings atomic.Int32
	sws.SetPingHandler(func(string) error {
		pings.Add(1)
		return nil
	})
	// Control frames are handled while reading.
	go func() {
		for {
			if _, _, err := sws.NextReader(); err != nil {
				return
			}
		}
	}()
	assert.Eventually(t, func() bool { return pings.Load() >= 3 }, 2*time.Second, 10*time.Millisecond)
}

func TestPeerPingsAnswered(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	pong := make(chan struct{}, 1)
	sws.SetPongHandler(func(string) error {
		pong <- struct{}{}
		return nil
	})
	go func() { _, _ = c.Read(make([]byte, 1)) }()
	go func() {
		for {
			if _, _, err := sws.NextReader(); err != nil {
				return
			}
		}
	}()
	require.NoError(t, sws.WriteControl(websocket.PingMessage, []byte("x"), time.Now().Add(time.Second)))

	select {
	case <-pong:
	case <-time.After(2 * time.Second):
		t.Fatal("no pong")
	}
}

func TestCloseSendsNormalClosure(t *testing.T) {
	cws, sws := pair(t)
	c := New(cws, Options{})

	require.NoError(t, c.Close())
	assert.NoError(t, c.Close(), "closing twice is harmless")

	_, _, err := sws.ReadMessage()
	assert.True(t, websocket.IsCloseError(err, websocket.CloseNormalClosure), "got %v", err)

	_, err = c.Write([]byte("x"))
	assert.Error(t, err)
}

func TestConcurrentWritesDontInterleave(t *testing.T) {
	cws, sws := pair(t)
	c, s := New(cws, Options{}), New(sws, Options{})

	const writers, size = 4, 50 * 1024
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Write(bytes.Repeat([]byte{byte('a' + i)}, size))
		}()
	}

	got := make([]byte, writers*size)
	_, err := io.ReadFull(s, got)
	require.NoError(t, err)
	wg.Wait()

	seen := map[byte]bool{}
	for i := 0; i < len(got); i += size {
		run := got[i : i+size]
		assert.Equal(t, bytes.Repeat(run[:1], size), run, "each Write arrives contiguous")
		assert.False(t, seen[run[0]])
		seen[run[0]] = true
	}
}

func TestReadDeadline(t *testing.T) {
	cws, _ := pair(t)
	c := New(cws, Options{})

	require.NoError(t, c.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	require.True(t, errors.As(err, &ne), "got %v", err)
	assert.True(t, ne.Timeout())
}

func TestDialerAndUpgraderSettings(t *testing.T) {
	d := Dialer(nil, nil)
	assert.Nil(t, d.Proxy, "never a proxy from the environment")
	assert.False(t, d.EnableCompression)
	assert.False(t, Upgrader().EnableCompression)
}
