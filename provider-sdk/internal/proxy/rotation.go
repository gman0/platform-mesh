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
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
)

// PreviousUnusedAfter is how long a rotated-out proxy credential stays
// accepted after its last use. Tunnels already open keep running.
const PreviousUnusedAfter = 10 * time.Minute

func (p *Proxy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Proxy) usedPrevious(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.previous == nil {
		p.previous = map[string]time.Time{}
	}
	p.previous[id] = p.now()
}

// DropUnusedPrevious clears a Connection's previous proxy credential once it
// hasn't been used for PreviousUnusedAfter. Usage is counted from when this
// replica first saw the rotation, so a failover restarts the wait.
func (p *Proxy) DropUnusedPrevious(ctx context.Context) error {
	var list sdkv1alpha1.ConnectionList
	if err := p.Client.List(ctx, &list, client.InNamespace(p.Namespace)); err != nil {
		return err
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.previous == nil {
		p.previous = map[string]time.Time{}
	}
	for i := range list.Items {
		conn := &list.Items[i]
		if conn.Status.PreviousProxyCredentialHash == "" {
			delete(p.previous, conn.Name)
			continue
		}
		last, seen := p.previous[conn.Name]
		if !seen {
			p.previous[conn.Name] = now
			continue
		}
		if now.Sub(last) < PreviousUnusedAfter {
			continue
		}
		before := conn.DeepCopy()
		conn.Status.PreviousProxyCredentialHash = ""
		if err := p.Client.Status().Patch(ctx, conn, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			p.Log.Error(err, "dropping the previous proxy credential", "connection", conn.Name)
			continue
		}
		delete(p.previous, conn.Name)
	}
	return nil
}

// Start runs DropUnusedPrevious every minute until ctx ends.
func (p *Proxy) Start(ctx context.Context) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.DropUnusedPrevious(ctx); err != nil {
				p.Log.Error(err, "checking previous proxy credentials")
			}
		}
	}
}
