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

package access

import (
	"sync"
	"time"
)

// ReplayCache is a bounded TTL map keyed by (tokenID, jti). It lets the
// user-side /access handler reject a call credential whose jti it has
// already seen within the credential's exp window.
//
// RFC 012 sizes the cache against the call-credential TTL
// (DefaultCallCredentialTTL + skew = ~90s), so the working-set is tiny
// per AccessIdentity. MaxEntries fails closed on overflow (treats new
// entries as replays) rather than evicting silently.
type ReplayCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
	now        func() time.Time
}

// NewReplayCache creates an empty cache. maxEntries <= 0 disables the
// bound (no cap); callers running with untrusted input should pass a
// positive cap.
func NewReplayCache(maxEntries int) *ReplayCache {
	return &ReplayCache{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Seen records (tokenID, jti) with the given expiry. Returns true if
// this is the first time the cache has seen the pair (the caller
// should accept the credential), false if it is a replay or the cache
// is full (the caller should reject with 403).
//
// Expired entries are treated as absent and evicted opportunistically.
func (c *ReplayCache) Seen(tokenID, jti string, exp time.Time) bool {
	key := tokenID + "|" + jti
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.entries[key]; ok {
		if existing.After(now) {
			return false // genuine replay within window
		}
		// Expired entry: fall through and overwrite below.
	}

	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		// Try one sweep before failing closed; keeps a steady-state
		// cache honest when entries expire faster than Seen is called.
		c.sweepLocked(now)
		if len(c.entries) >= c.maxEntries {
			return false
		}
	}

	c.entries[key] = exp
	return true
}

// Sweep drops expired entries. Called internally on overflow; callers
// running without a background janitor may invoke it periodically.
func (c *ReplayCache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
}

// Len returns the current number of live (non-expired) entries. Intended
// for tests and metrics; takes the lock.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
	return len(c.entries)
}

func (c *ReplayCache) sweepLocked(now time.Time) {
	for k, exp := range c.entries {
		if !exp.After(now) {
			delete(c.entries, k)
		}
	}
}
