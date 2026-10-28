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

package controllers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tv "go.platform-mesh.io/provider-protocol/testvectors"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

const connID = "c-abcdefghijklmnopqrstuvwxyz"

type connFixture struct {
	t        *testing.T
	client   client.Client
	r        *ConnectionReconciler
	recorder *record.FakeRecorder
	now      time.Time
	removed  []string
}

func newConnFixture(t *testing.T, mutate ...func(*sdkv1alpha1.Connection)) *connFixture {
	t.Helper()
	conn := &sdkv1alpha1.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: connID, Namespace: ns, Finalizers: []string{sdkv1alpha1.ConnectionFinalizer}},
		Spec: sdkv1alpha1.ConnectionSpec{
			Registration: sdkv1alpha1.ConnectionRegistration{Owner: "alice@example.com", ClusterName: "2x8k9abc"},
			PinnedBundle: string(tv.CA(t, "connector-ca", nil).PEM()),
		},
	}
	for _, m := range mutate {
		m(conn)
	}
	f := &connFixture{t: t, client: newClient(t, conn), recorder: record.NewFakeRecorder(100), now: tv.Now}
	f.r = &ConnectionReconciler{
		Client:    f.client,
		Sessions:  session.NewRegistry(),
		Recorder:  f.recorder,
		Now:       func() time.Time { return f.now },
		OnRemoved: func(_ context.Context, c *sdkv1alpha1.Connection) error { f.removed = append(f.removed, c.Name); return nil },
	}
	return f
}

func (f *connFixture) reconcile() reconcile.Result {
	f.t.Helper()
	res, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: connID}})
	require.NoError(f.t, err)
	return res
}

func (f *connFixture) get() (*sdkv1alpha1.Connection, error) {
	var conn sdkv1alpha1.Connection
	err := f.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: connID}, &conn)
	return &conn, err
}

func (f *connFixture) events() []string {
	var out []string
	for {
		select {
		case e := <-f.recorder.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestConnectionRegisteredOnce(t *testing.T) {
	f := newConnFixture(t)
	f.reconcile()
	f.reconcile()
	events := f.events()
	require.Len(t, events, 1)
	assert.True(t, strings.HasPrefix(events[0], "Normal Registered"))
}

func TestConnectionReadyAfterDelay(t *testing.T) {
	f := newConnFixture(t)
	res := f.reconcile()
	assert.Equal(t, resync, res.RequeueAfter)
	conn, err := f.get()
	require.NoError(t, err)
	assert.Nil(t, meta.FindStatusCondition(conn.Status.Conditions, sdkv1alpha1.ConnectionConditionReady),
		"a failure isn't reported before it lasts")

	f.now = f.now.Add(5 * time.Minute)
	f.reconcile()
	conn, err = f.get()
	require.NoError(t, err)
	c := meta.FindStatusCondition(conn.Status.Conditions, sdkv1alpha1.ConnectionConditionReady)
	require.NotNil(t, c)
	assert.Equal(t, metav1.ConditionFalse, c.Status)
	assert.Equal(t, sdkv1alpha1.ConnectionReasonNoSessions, c.Reason)
}

func TestConnectionOrphanExpiry(t *testing.T) {
	deadline := metav1.NewTime(tv.Now.Add(time.Hour))
	f := newConnFixture(t, func(c *sdkv1alpha1.Connection) { c.Spec.Registration.UnusedExpiresAt = &deadline })

	f.reconcile()
	conn, err := f.get()
	require.NoError(t, err)
	assert.Nil(t, conn.DeletionTimestamp, "not before the deadline")

	f.now = deadline.Add(time.Second)
	f.reconcile()
	conn, err = f.get()
	require.NoError(t, err)
	assert.NotNil(t, conn.DeletionTimestamp)
	assert.Equal(t, sdkv1alpha1.RemovalReasonUnused, conn.Annotations[sdkv1alpha1.AnnotationRemovalReason])
}

func TestConnectionUsedOnceNeverExpires(t *testing.T) {
	deadline := metav1.NewTime(tv.Now.Add(time.Hour))
	seen := metav1.NewTime(tv.Now)
	f := newConnFixture(t, func(c *sdkv1alpha1.Connection) {
		c.Spec.Registration.UnusedExpiresAt = &deadline
		c.Status.LastSeen = &seen
	})
	f.now = deadline.Add(30 * 24 * time.Hour)
	f.reconcile()
	conn, err := f.get()
	require.NoError(t, err)
	assert.Nil(t, conn.DeletionTimestamp)
}

func TestConnectionFinalizer(t *testing.T) {
	f := newConnFixture(t, func(c *sdkv1alpha1.Connection) {
		c.Annotations = map[string]string{sdkv1alpha1.AnnotationRemovalReason: sdkv1alpha1.RemovalReasonDeletedByPlatformMesh}
	})
	f.reconcile()
	f.events()

	conn, err := f.get()
	require.NoError(t, err)
	require.NoError(t, f.client.Delete(context.Background(), conn))
	f.reconcile()

	assert.Equal(t, []string{connID}, f.removed)
	_, err = f.get()
	assert.Error(t, err, "released")
	events := f.events()
	require.Len(t, events, 1)
	assert.Equal(t, "Normal Removed DeletedByPlatformMesh", events[0])
}

func TestConnectionPinnedBundleChanged(t *testing.T) {
	f := newConnFixture(t)
	f.reconcile()
	f.events()

	conn, err := f.get()
	require.NoError(t, err)
	conn.Spec.PinnedBundle = string(tv.Join([]byte(conn.Spec.PinnedBundle), tv.CA(t, "next", nil).PEM()))
	require.NoError(t, f.client.Update(context.Background(), conn))
	f.reconcile()

	events := f.events()
	require.Len(t, events, 1)
	assert.Equal(t, "Normal PinnedBundleChanged 2 CA(s) pinned, 0 Session(s) closed", events[0])

	f.reconcile()
	assert.Empty(t, f.events(), "no event without a change")
}

func TestConnectionUnparseableRepin(t *testing.T) {
	f := newConnFixture(t)
	f.reconcile()
	f.events()

	conn, err := f.get()
	require.NoError(t, err)
	conn.Spec.PinnedBundle = "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"
	require.NoError(t, f.client.Update(context.Background(), conn))
	f.reconcile()

	events := f.events()
	require.Len(t, events, 1)
	assert.True(t, strings.HasPrefix(events[0], "Warning PinnedBundleChanged"))
}

func TestConnectionGoneWithoutFinalizer(t *testing.T) {
	f := newConnFixture(t)
	conn, err := f.get()
	require.NoError(t, err)
	conn.Finalizers = nil
	require.NoError(t, f.client.Update(context.Background(), conn))
	require.NoError(t, f.client.Delete(context.Background(), conn))
	f.reconcile() // closes its Sessions, without error
}

func TestConnectionKubeconfigFromFirstSession(t *testing.T) {
	cases := map[string]struct {
		hash   string
		called bool
	}{
		"no Session yet":                 {"", false},
		"written for an earlier Session": {"sha256:" + strings.Repeat("ef", 32), true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newConnFixture(t, func(conn *sdkv1alpha1.Connection) { conn.Status.ProxyCredentialHash = c.hash })
			called := false
			f.r.EnsureKubeconfig = func(context.Context, *sdkv1alpha1.Connection) error { called = true; return nil }
			f.reconcile()
			assert.Equal(t, c.called, called)
		})
	}
}
