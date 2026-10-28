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

// Package gateway runs provider-gateway: the Connection API on every
// replica, and the controllers, Sessions and operator proxy on the elected
// one.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	sdkv1alpha1 "go.platform-mesh.io/provider-sdk/api/v1alpha1"
	"go.platform-mesh.io/provider-sdk/internal/connapi"
	"go.platform-mesh.io/provider-sdk/internal/controllers"
	"go.platform-mesh.io/provider-sdk/internal/endpoint"
	"go.platform-mesh.io/provider-sdk/internal/kubeconfig"
	"go.platform-mesh.io/provider-sdk/internal/metrics"
	"go.platform-mesh.io/provider-sdk/internal/proxy"
	"go.platform-mesh.io/provider-sdk/internal/session"
)

// ensureServerKeyInterval is how often creating the first ServerKey is
// retried.
const ensureServerKeyInterval = 5 * time.Second

// Run runs provider-gateway until ctx ends.
func Run(ctx context.Context, cfg *rest.Config, o Options) error {
	if err := o.Complete(); err != nil {
		return err
	}
	log := ctrl.Log.WithName("provider-gateway")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := sdkv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	servingTLS, err := o.servingTLS(ctx, cfg, scheme)
	if err != nil {
		return fmt.Errorf("serving TLS: %w", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                        scheme,
		Cache:                         cache.Options{DefaultNamespaces: map[string]cache.Config{o.Namespace: {}}},
		Metrics:                       metricsserver.Options{BindAddress: o.MetricsAddress},
		HealthProbeBindAddress:        o.HealthAddress,
		LeaderElection:                o.LeaderElection,
		LeaderElectionID:              o.LeaderElectionID,
		LeaderElectionNamespace:       o.Namespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return err
	}
	isLeader := func() bool {
		select {
		case <-mgr.Elected():
			return true
		default:
			return false
		}
	}

	c := mgr.GetClient()
	m, err := metrics.New(ctrlmetrics.Registry)
	if err != nil {
		return err
	}
	registry := session.NewRegistry()
	registry.Metrics = m
	if err := ctrlmetrics.Registry.Register(&metrics.State{Client: c, Namespace: o.Namespace, Sessions: registry.Counts}); err != nil {
		return err
	}
	recorder := mgr.GetEventRecorderFor("provider-gateway")
	writer := &kubeconfig.Writer{
		Client:     c,
		Namespace:  o.Namespace,
		Source:     servingTLS,
		ProxyHost:  o.ProxyHost,
		ServerName: o.Names[0],
	}

	// Controllers. The kubeconfig Secret is written on the Connection's
	// first verified Session, not at Registration.
	if err := (&controllers.ServerKeyReconciler{Client: c, Namespace: o.Namespace}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&controllers.ConnectionReconciler{
		Client:           c,
		APIReader:        mgr.GetAPIReader(),
		Sessions:         registry,
		Recorder:         recorder,
		ReadyDelay:       o.ReadyDelay,
		EnsureKubeconfig: writer.Ensure,
		OnRemoved: func(ctx context.Context, conn *sdkv1alpha1.Connection) error {
			return writer.Delete(ctx, conn.Name)
		},
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&controllers.OnboardingTokenReconciler{Client: c, RetryWindow: o.RetryWindow}).SetupWithManager(mgr); err != nil {
		return err
	}
	endpoints := endpoint.NewManager(c, o.Namespace, registry, recorder, log.WithName("endpoint"))

	api := connapi.New(connapi.Config{
		Client:      c,
		APIReader:   mgr.GetAPIReader(),
		Namespace:   o.Namespace,
		Keys:        &controllers.KeyStore{Client: c, Namespace: o.Namespace},
		Sessions:    registry,
		RetryWindow: o.RetryWindow,
		IsLeader:    isLeader,
		Metrics:     m,
		Log:         log.WithName("connection-api"),
	})
	apiTLS, err := o.connectionAPITLS(mgr)
	if err != nil {
		return fmt.Errorf("connection API TLS: %w", err)
	}

	px := &proxy.Proxy{
		Client:    c,
		Namespace: o.Namespace,
		Sessions:  registry,
		TLS:       servingTLS,
		Log:       log.WithName("proxy"),
		Metrics:   m,
	}

	// Runnables without NeedLeaderElection run on the elected replica only.
	runnables := []manager.Runnable{
		// Standbys answer upgrades with 503 and Retry-After.
		&server{name: "connection API", addr: o.ConnectionAPIAddress, handler: api, tls: apiTLS},
		&server{name: "operator proxy", addr: o.ProxyAddress, handler: px, tls: serverTLS(servingTLS.GetCertificate), leader: true},
		manager.RunnableFunc(px.Start),
		manager.RunnableFunc(func(ctx context.Context) error {
			<-ctx.Done()
			endpoints.Stop()
			return nil
		}),
		manager.RunnableFunc(func(ctx context.Context) error {
			ensureServerKey(ctx, c, o.Namespace, log)
			return nil
		}),
	}
	if fs, ok := servingTLS.(*kubeconfig.FileSource); ok {
		runnables = append(runnables, fs)
	}
	for _, r := range runnables {
		if err := mgr.Add(r); err != nil {
			return err
		}
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	// Standbys aren't ready, so the operator proxy's Service reaches only
	// the elected replica.
	if err := mgr.AddReadyzCheck("elected", func(*http.Request) error {
		if !isLeader() {
			return errors.New("standby")
		}
		return nil
	}); err != nil {
		return err
	}

	log.Info("starting", "namespace", o.Namespace, "servingTLS", o.ServingTLS, "proxyHost", o.ProxyHost)
	return mgr.Start(ctx)
}

// servingTLS returns the operator proxy's TLS. The self-signed CA is
// loaded, or created once, before the manager starts, with an uncached
// client; any replica may create it.
func (o *Options) servingTLS(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme) (kubeconfig.Source, error) {
	if o.ServingTLS == ServingTLSCertManager {
		return kubeconfig.NewFileSource(o.ServingTLSDir)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	ca, err := kubeconfig.EnsureCA(ctx, c, o.Namespace, o.CASecretName, time.Now())
	if err != nil {
		return nil, err
	}
	return &kubeconfig.SelfSigned{CA: ca, Names: o.Names}, nil
}

// connectionAPITLS returns nil for plain HTTP, or the TLS of the
// Connection API's listener from ConnectionAPITLSDir, reloaded on change.
func (o *Options) connectionAPITLS(mgr manager.Manager) (*tls.Config, error) {
	if o.ConnectionAPITLSDir == "" {
		return nil, nil
	}
	w, err := certwatcher.New(
		filepath.Join(o.ConnectionAPITLSDir, corev1.TLSCertKey),
		filepath.Join(o.ConnectionAPITLSDir, corev1.TLSPrivateKeyKey),
	)
	if err != nil {
		return nil, err
	}
	if err := mgr.Add(anyReplica{w}); err != nil {
		return nil, err
	}
	return serverTLS(w.GetCertificate), nil
}

// ensureServerKey creates the first ServerKey if there's none, retrying
// until it succeeds or ctx ends.
func ensureServerKey(ctx context.Context, c client.Client, namespace string, log logr.Logger) {
	_ = wait.PollUntilContextCancel(ctx, ensureServerKeyInterval, true, func(ctx context.Context) (bool, error) {
		if err := controllers.EnsureServerKey(ctx, c, namespace); err != nil {
			log.Error(err, "creating the first ServerKey")
			return false, nil
		}
		return true, nil
	})
}
