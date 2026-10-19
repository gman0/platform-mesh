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
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.platform-mesh.io/provider-protocol/bundle"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

const (
	// resync is how often a Connection is reconciled without changes:
	// Session state isn't a Kubernetes event.
	resync = 30 * time.Second
	// lastSeenInterval is how often lastSeen moves after the first time.
	lastSeenInterval = time.Hour
)

// ConnectionReconciler keeps a Connection's Sessions in line with it, and
// reports on it.
type ConnectionReconciler struct {
	Client client.Client
	// APIReader reads uncached, before an orphan is expired.
	APIReader client.Reader
	Sessions  *session.Registry
	Recorder  record.EventRecorder
	// ReadyDelay is how long a failure lasts before Ready reports it.
	// Default 5 minutes.
	ReadyDelay time.Duration
	// OnRemoved runs in the finalizer, e.g. to delete the kubeconfig
	// Secret. Optional.
	OnRemoved func(ctx context.Context, c *sdkv1alpha1.Connection) error
	// Now defaults to time.Now.
	Now func() time.Time

	mu             sync.Mutex
	etags          map[string]string
	unhealthySince map[string]time.Time
}

// Reconcile handles one Connection.
func (r *ConnectionReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.init()
	var conn sdkv1alpha1.Connection
	if err := r.Client.Get(ctx, req.NamespacedName, &conn); err != nil {
		if apierrors.IsNotFound(err) {
			// Gone without the finalizer running.
			r.Sessions.CloseConnection(req.Name)
			r.forget(req.Name)
		}
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if conn.DeletionTimestamp != nil {
		return reconcile.Result{}, r.finalize(ctx, &conn)
	}
	if !controllerutil.ContainsFinalizer(&conn, sdkv1alpha1.ConnectionFinalizer) {
		patch := client.MergeFrom(conn.DeepCopy())
		controllerutil.AddFinalizer(&conn, sdkv1alpha1.ConnectionFinalizer)
		if err := r.Client.Patch(ctx, &conn, patch); err != nil {
			return reconcile.Result{}, err
		}
	}

	if expired, err := r.expireOrphan(ctx, &conn); err != nil || expired {
		return reconcile.Result{}, err
	}

	r.checkBundle(&conn)

	before := conn.DeepCopy()
	if conn.Status.ObservedGeneration == 0 {
		r.Recorder.Event(&conn, corev1.EventTypeNormal, sdkv1alpha1.ConnectionEventRegistered,
			fmt.Sprintf("registered for %s", conn.Spec.Registration.Owner))
	}
	// At least 1, so it marks the Connection as seen even where the API
	// server leaves generation unset.
	conn.Status.ObservedGeneration = max(conn.Generation, 1)
	r.touchLastSeen(&conn)
	r.updateReady(&conn)
	if !equalStatus(before, &conn) {
		if err := r.Client.Status().Patch(ctx, &conn, client.MergeFrom(before)); err != nil {
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{RequeueAfter: r.requeueAfter(&conn)}, nil
}

func (r *ConnectionReconciler) init() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.etags == nil {
		r.etags = map[string]string{}
		r.unhealthySince = map[string]time.Time{}
	}
	if r.ReadyDelay <= 0 {
		r.ReadyDelay = 5 * time.Minute
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.APIReader == nil {
		r.APIReader = r.Client
	}
}

func (r *ConnectionReconciler) forget(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.etags, name)
	delete(r.unhealthySince, name)
}

// finalize closes the Connection's Sessions and cleans up, then lets it go.
func (r *ConnectionReconciler) finalize(ctx context.Context, conn *sdkv1alpha1.Connection) error {
	r.Sessions.CloseConnection(conn.Name)
	r.forget(conn.Name)
	if !controllerutil.ContainsFinalizer(conn, sdkv1alpha1.ConnectionFinalizer) {
		return nil
	}
	if r.OnRemoved != nil {
		if err := r.OnRemoved(ctx, conn); err != nil {
			return err
		}
	}
	reason := conn.Annotations[sdkv1alpha1.AnnotationRemovalReason]
	if reason == "" {
		reason = sdkv1alpha1.RemovalReasonDeleted
	}
	r.Recorder.Event(conn, corev1.EventTypeNormal, sdkv1alpha1.ConnectionEventRemoved, reason)

	patch := client.MergeFrom(conn.DeepCopy())
	controllerutil.RemoveFinalizer(conn, sdkv1alpha1.ConnectionFinalizer)
	return client.IgnoreNotFound(r.Client.Patch(ctx, conn, patch))
}

// expireOrphan deletes a Connection never used by its unusedExpiresAt,
// after an uncached read confirms it. A Connection used once never expires.
func (r *ConnectionReconciler) expireOrphan(ctx context.Context, conn *sdkv1alpha1.Connection) (bool, error) {
	deadline := conn.Spec.Registration.UnusedExpiresAt
	if deadline == nil || conn.Status.LastSeen != nil || r.Now().Before(deadline.Time) {
		return false, nil
	}
	var fresh sdkv1alpha1.Connection
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(conn), &fresh); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if fresh.Status.LastSeen != nil {
		return false, nil
	}
	patch := client.MergeFrom(fresh.DeepCopy())
	metav1.SetMetaDataAnnotation(&fresh.ObjectMeta, sdkv1alpha1.AnnotationRemovalReason, sdkv1alpha1.RemovalReasonUnused)
	if err := r.Client.Patch(ctx, &fresh, patch); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return true, client.IgnoreNotFound(r.Client.Delete(ctx, &fresh))
}

// checkBundle re-checks open Sessions when the Pinned Bundle changed.
func (r *ConnectionReconciler) checkBundle(conn *sdkv1alpha1.Connection) {
	b, err := bundle.ParseStored([]byte(conn.Spec.PinnedBundle))
	if err != nil {
		r.Recorder.Eventf(conn, corev1.EventTypeWarning, sdkv1alpha1.ConnectionEventPinnedBundleChanged,
			"the Pinned Bundle doesn't parse, Sessions can't open: %v", err)
		return
	}
	r.mu.Lock()
	previous, known := r.etags[conn.Name]
	r.etags[conn.Name] = b.ETag()
	r.mu.Unlock()

	if known && previous == b.ETag() {
		return
	}
	closed := r.Sessions.Recheck(conn.Name, b)
	if known {
		r.Recorder.Eventf(conn, corev1.EventTypeNormal, sdkv1alpha1.ConnectionEventPinnedBundleChanged,
			"%d CA(s) pinned, %d Session(s) closed", len(b.Certificates()), closed)
	}
}

// touchLastSeen records a verified Session: the first at once, then at most
// every lastSeenInterval.
func (r *ConnectionReconciler) touchLastSeen(conn *sdkv1alpha1.Connection) {
	if ws, _ := r.Sessions.Status(conn.Name); ws.Sessions == 0 {
		return
	}
	now := r.Now()
	if conn.Status.LastSeen != nil && now.Sub(conn.Status.LastSeen.Time) < lastSeenInterval {
		return
	}
	t := metav1.NewTime(now)
	conn.Status.LastSeen = &t
}

// updateReady sets Ready from the Sessions: a failure only once it has
// lasted ReadyDelay.
func (r *ConnectionReconciler) updateReady(conn *sdkv1alpha1.Connection) {
	reason, msg := health(r.Sessions, conn.Name)
	now := r.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if reason == sdkv1alpha1.ConnectionReasonAsExpected {
		delete(r.unhealthySince, conn.Name)
		r.setReady(conn, metav1.ConditionTrue, reason, msg)
		return
	}
	since, ok := r.unhealthySince[conn.Name]
	if !ok {
		since = now
		r.unhealthySince[conn.Name] = now
	}
	if now.Sub(since) >= r.ReadyDelay {
		r.setReady(conn, metav1.ConditionFalse, reason, msg)
	}
}

func (r *ConnectionReconciler) setReady(conn *sdkv1alpha1.Connection, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&conn.Status.Conditions, metav1.Condition{
		Type: sdkv1alpha1.ConnectionConditionReady, Status: status, Reason: reason, Message: msg,
		ObservedGeneration: conn.Generation,
	})
}

// health judges the Connection's Sessions: the workspace and every host the
// operator uses must have a Session that reaches kcp.
func health(sessions *session.Registry, name string) (string, string) {
	ws, vws := sessions.Status(name)
	if ws.Sessions == 0 {
		return sdkv1alpha1.ConnectionReasonNoSessions, "no Session serves the Provider Workspace"
	}
	for host, st := range vws {
		if st.Sessions == 0 {
			return sdkv1alpha1.ConnectionReasonNoSessions, "no Session serves " + host
		}
	}
	if !ws.KcpReachable {
		return sdkv1alpha1.ConnectionReasonKcpUnreachable, "the Provider Workspace isn't reached: " + ws.LastError
	}
	for host, st := range vws {
		if !st.KcpReachable {
			return sdkv1alpha1.ConnectionReasonKcpUnreachable, host + " isn't reached: " + st.LastError
		}
	}
	return sdkv1alpha1.ConnectionReasonAsExpected, ""
}

// requeueAfter is the resync, or sooner at an orphan's deadline.
func (r *ConnectionReconciler) requeueAfter(conn *sdkv1alpha1.Connection) time.Duration {
	if d := conn.Spec.Registration.UnusedExpiresAt; d != nil && conn.Status.LastSeen == nil {
		if wait := d.Sub(r.Now()); wait > 0 && wait < resync {
			return wait
		}
	}
	return resync
}

func equalStatus(a, b *sdkv1alpha1.Connection) bool {
	return a.Status.ObservedGeneration == b.Status.ObservedGeneration &&
		a.Status.LastSeen.Equal(b.Status.LastSeen) &&
		equalConditions(a.Status.Conditions, b.Status.Conditions)
}

func equalConditions(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Status != b[i].Status || a[i].Reason != b[i].Reason ||
			a[i].Message != b[i].Message || a[i].ObservedGeneration != b[i].ObservedGeneration {
			return false
		}
	}
	return true
}

// SetupWithManager watches Connections.
func (r *ConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&sdkv1alpha1.Connection{}).Complete(r)
}
