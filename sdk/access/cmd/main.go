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

// Binary platform-mesh-access runs the user-side Platform Mesh access
// SDK: an AccessIdentity controller and an HTTPS server exposing the
// unauthenticated /versions probe plus a handler per supported
// handshake version (currently /v1/access). Delivered as a single
// binary installed on the user-side (or portal) cluster.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	pmaccessproto "go.platform-mesh.io/protocol/access"
	accessv1alpha1 "go.platform-mesh.io/sdk/access/apis/v1alpha1"
	accessctrl "go.platform-mesh.io/sdk/access/internal/controller"
	accessserver "go.platform-mesh.io/sdk/access/internal/server"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)


// Bounds the replay cache. Call-credential JWTs live ~90s (60s TTL
// plus skew tolerance); well-behaved deployments see one entry per
// handshake per Identity. 1000 is generous for mid-size operations.
const replayCacheSize = 1000

// Startup grace for cache sync before the /access listener begins
// accepting traffic.
const cacheSyncTimeout = 2 * time.Minute

func main() {
	var (
		publicURL    string
		tlsCertFile  string
		tlsKeyFile   string
		accessListen string
		metricsAddr  string
		probeAddr    string
		leaderElect  bool
	)

	pflag.StringVar(&publicURL, "public-url", "", "External HTTPS URL for /access, encoded into minted access tokens. Required.")
	pflag.StringVar(&tlsCertFile, "tls-cert-file", "", "Path to PEM-encoded TLS cert for /access. Required.")
	pflag.StringVar(&tlsKeyFile, "tls-key-file", "", "Path to PEM-encoded TLS key for /access. Required.")
	pflag.StringVar(&accessListen, "access-listen", ":8443", "Listen address for the /access HTTPS server.")
	pflag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Metrics listen address.")
	pflag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe listen address.")
	pflag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election.")
	pflag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	setupLog := ctrl.Log.WithName("setup")

	for flag, val := range map[string]string{
		"--public-url":    publicURL,
		"--tls-cert-file": tlsCertFile,
		"--tls-key-file":  tlsKeyFile,
	} {
		if val == "" {
			setupLog.Error(fmt.Errorf("flag required"), flag+" is required")
			os.Exit(1)
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(accessv1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                leaderElect,
		LeaderElectionID:              "platform-mesh-access.access-sdk.platform-mesh.io",
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to build manager")
		os.Exit(1)
	}

	if err := (&accessctrl.AccessIdentityReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		PublicURL: publicURL,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to register AccessIdentityReconciler")
		os.Exit(1)
	}

	v1Handler := &accessserver.Handler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		ReplayCache: pmaccessproto.NewReplayCache(replayCacheSize),
	}

	// Honor any path prefix embedded in --public-url. Lets admins
	// front the SDK with an ingress that keeps a prefix on the way
	// through (e.g. https://host/platform-mesh/{versions,v1/access})
	// without configuring ingress rewrites. Empty prefix = flat mount.
	pathPrefix, err := publicURLPathPrefix(publicURL)
	if err != nil {
		setupLog.Error(err, "invalid --public-url")
		os.Exit(1)
	}

	// Mux routes: unauthenticated /versions probe + one /vN/access
	// handler per supported handshake version. When adding v2, mount
	// the v2 handler here and extend pmaccessproto.SupportedVersions.
	mux := http.NewServeMux()
	mux.Handle(pathPrefix+pmaccessproto.VersionsPath, accessserver.VersionsHandler())
	mux.Handle(pathPrefix+pmaccessproto.AccessPath(pmaccessproto.V1), v1Handler)

	if err := mgr.Add(&accessHTTPSRunnable{
		listen:   accessListen,
		certFile: tlsCertFile,
		keyFile:  tlsKeyFile,
		handler:  mux,
		cache:    mgr.GetCache(),
	}); err != nil {
		setupLog.Error(err, "unable to add /access HTTPS runnable")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up readyz")
		os.Exit(1)
	}

	setupLog.Info("starting access SDK", "publicURL", publicURL, "listen", accessListen)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager stopped with error")
		os.Exit(1)
	}
}

// accessHTTPSRunnable is a manager.Runnable that serves the /versions
// probe and the versioned /vN/access handlers over HTTPS. It waits
// for the shared cache to sync before accepting traffic so handler
// List/Get calls hit a populated cache.
type accessHTTPSRunnable struct {
	listen   string
	certFile string
	keyFile  string
	handler  http.Handler
	cache    cacheSyncer
}

// cacheSyncer narrows cache.Cache to the one method we need, so tests
// can swap it.
type cacheSyncer interface {
	WaitForCacheSync(ctx context.Context) bool
}

// Start implements manager.Runnable.
func (r *accessHTTPSRunnable) Start(ctx context.Context) error {
	syncCtx, cancel := context.WithTimeout(ctx, cacheSyncTimeout)
	defer cancel()
	if !r.cache.WaitForCacheSync(syncCtx) {
		return fmt.Errorf("/access server: cache failed to sync within %s", cacheSyncTimeout)
	}

	srv := &http.Server{
		Addr:    r.listen,
		Handler: r.handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS(r.certFile, r.keyFile)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// NeedLeaderElection returns false so the /access endpoint is served
// on every replica. Correctness isn't affected (replay cache is
// per-replica, but the AccessIdentity cluster-state guards against
// genuine replays via jti uniqueness).
func (r *accessHTTPSRunnable) NeedLeaderElection() bool { return false }

var _ manager.Runnable = (*accessHTTPSRunnable)(nil)
var _ manager.LeaderElectionRunnable = (*accessHTTPSRunnable)(nil)

// publicURLPathPrefix extracts the path prefix under which the SDK's
// endpoints should be mounted, derived from --public-url. The
// trailing slash is trimmed so callers can concatenate "/versions"
// and "/v1/access" directly. Root path returns "".
func publicURLPathPrefix(publicURL string) (string, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", fmt.Errorf("parse --public-url %q: %w", publicURL, err)
	}
	p := strings.TrimRight(u.Path, "/")
	return p, nil
}
