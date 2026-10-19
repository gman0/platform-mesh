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

package connapi

import (
	"sync"
	"time"
)

// Limits bound handshakes in progress: from the upgrade until the Inner TLS
// handshake (and, for Registration, its one request) ends. There's no limit
// per source address: behind the Provider's Edge, callers share a few.
type Limits struct {
	// PerKey bounds handshakes per token or Connection. Default 4.
	PerKey int
	// Total bounds handshakes for known tokens and Connections. Default 64.
	Total int
	// UnknownTotal bounds Control Session handshakes for unknown Connection
	// IDs, which are accepted so "unknown" is answered inside the Inner TLS.
	// Default 2.
	UnknownTotal int
	// UnknownInterval is the least time between two of them. Default 1s.
	UnknownInterval time.Duration
}

func (l Limits) withDefaults() Limits {
	if l.PerKey <= 0 {
		l.PerKey = 4
	}
	if l.Total <= 0 {
		l.Total = 64
	}
	if l.UnknownTotal <= 0 {
		l.UnknownTotal = 2
	}
	if l.UnknownInterval <= 0 {
		l.UnknownInterval = time.Second
	}
	return l
}

type limiter struct {
	limits Limits
	mu     sync.Mutex
	perKey map[string]int
	total  int
}

func newLimiter(l Limits) *limiter {
	return &limiter{limits: l, perKey: map[string]int{}}
}

// acquire takes a slot for key; ok is false beyond the limits. release must
// be called once when the handshake ends.
func (l *limiter) acquire(key string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.limits.Total || l.perKey[key] >= l.limits.PerKey {
		return nil, false
	}
	l.total++
	l.perKey[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perKey[key]--; l.perKey[key] == 0 {
				delete(l.perKey, key)
			}
		})
	}, true
}

// unknownLimiter bounds handshakes for unknown Connection IDs: concurrent,
// and spaced in time.
type unknownLimiter struct {
	total    int
	interval time.Duration
	now      func() time.Time

	mu     sync.Mutex
	active int
	last   time.Time
}

func newUnknownLimiter(total int, interval time.Duration, now func() time.Time) *unknownLimiter {
	return &unknownLimiter{total: total, interval: interval, now: now}
}

func (l *unknownLimiter) acquire() (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.active >= l.total || (!l.last.IsZero() && now.Sub(l.last) < l.interval) {
		return nil, false
	}
	l.active++
	l.last = now
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active--
		})
	}, true
}
