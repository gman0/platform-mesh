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

package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"go.platform-mesh.io/access-operator/internal/controller"
	accesssubs "go.platform-mesh.io/access-operator/pkg/subroutines"
	pmcontext "go.platform-mesh.io/golang-commons/context"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcmultiprovider "sigs.k8s.io/multicluster-runtime/providers/multi"

	mcapiexportprovider "github.com/kcp-dev/multicluster-provider/apiexport"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Run the access-operator",
	Run:   RunController,
}

const defaultWaitForKcpAdminKubeconfigPeriod = 15 * time.Second

func RunController(_ *cobra.Command, _ []string) { // coverage-ignore
	ctrl.SetLogger(log.ComponentLogger("controller-runtime").Logr())

	log.Info().Msg("Starting access-operator")
	defer log.Info().Msg("Shutting down access-operator")

	ctx, _, shutdown := pmcontext.StartContext(log, operatorCfg, defaultCfg.ShutdownTimeout)
	defer shutdown()

	disableHTTP2 := func(c *tls.Config) {
		log.Info().Msg("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}
	var tlsOpts []func(*tls.Config)
	if !defaultCfg.EnableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	restCfg := ctrl.GetConfigOrDie()
	runtimeClient, err := ctrlruntimeclient.New(restCfg, ctrlruntimeclient.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create local-cluster client")
		os.Exit(1)
	}

	var leaderCfg *rest.Config
	if defaultCfg.LeaderElectionEnabled {
		leaderCfg, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("unable to get in-cluster config")
		}
	}

	mgr, err := mcmanager.New(restCfg, mcmultiprovider.New(mcmultiprovider.Options{}), mcmanager.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   defaultCfg.Metrics.BindAddress,
			SecureServing: defaultCfg.Metrics.Secure,
			TLSOpts:       tlsOpts,
		},
		BaseContext:                   func() context.Context { return ctx },
		HealthProbeBindAddress:        defaultCfg.HealthProbeBindAddress,
		LeaderElection:                defaultCfg.LeaderElectionEnabled,
		LeaderElectionID:              "access-operator.platform-mesh.io",
		LeaderElectionConfig:          leaderCfg,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	go startAccessProvider(ctx, runtimeClient, mgr)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("problem running manager")
	}
}

// startAccessProvider waits for kcp admin reachability, builds the
// apiexport-provider on access.platform-mesh.io, registers the
// AccessGrant reconciler, and wires the provider into the manager's
// multi-provider.
func startAccessProvider(ctx context.Context, runtimeCl ctrlruntimeclient.Client, mgr mcmanager.Manager) { // coverage-ignore
	multiProvider := mgr.GetProvider().(*mcmultiprovider.Provider)

	kcpUrl := operatorCfg.KCP.Url
	if kcpUrl == "" {
		kcpUrl = fmt.Sprintf("https://%s-front-proxy.%s:%s",
			operatorCfg.KCP.FrontProxyName, operatorCfg.KCP.Namespace, operatorCfg.KCP.FrontProxyPort)
	}
	kcpUrl += fmt.Sprintf("/clusters/%s", operatorCfg.Access.EndpointSliceWorkspace)

	var kcpCfg *rest.Config
	err := wait.PollUntilContextCancel(ctx, defaultWaitForKcpAdminKubeconfigPeriod, true, func(ctx context.Context) (bool, error) {
		var err error
		kcpCfg, err = accesssubs.BuildKubeconfigFromConfig(ctx, runtimeCl, &operatorCfg.KCP, kcpUrl)
		if err != nil {
			setupLog.Error(err, "waiting for kcp admin kubeconfig")
		}
		return err == nil, nil
	})
	if err != nil {
		setupLog.Error(err, "failed to retrieve kcp admin config")
		os.Exit(1)
	}

	setupLog.Info("starting apiexport-access.platform-mesh.io provider")
	var provider *mcapiexportprovider.Provider
	err = wait.PollUntilContextCancel(ctx, defaultWaitForKcpAdminKubeconfigPeriod, true, func(ctx context.Context) (bool, error) {
		var err error
		provider, err = mcapiexportprovider.New(kcpCfg, operatorCfg.Access.EndpointSliceName, mcapiexportprovider.Options{
			Scheme: scheme,
		})
		if err != nil {
			setupLog.Error(err, "failed to create apiexport provider", "apiexportendpointslice",
				fmt.Sprintf("%s:%s", operatorCfg.Access.EndpointSliceWorkspace, operatorCfg.Access.EndpointSliceName))
		}
		return err == nil, nil
	})
	if err != nil {
		setupLog.Error(err, "failed to create apiexport provider")
		os.Exit(1)
	}

	rec, err := controller.NewAccessGrantReconciler(mgr, &operatorCfg, defaultCfg)
	if err != nil {
		setupLog.Error(err, "failed to create AccessGrant reconciler")
		os.Exit(1)
	}
	if err := rec.SetupWithManager(mgr, defaultCfg); err != nil {
		setupLog.Error(err, "failed to set up AccessGrant reconciler")
		os.Exit(1)
	}

	if err := multiProvider.AddProvider("apiexport-access-platform-mesh", provider); err != nil {
		setupLog.Error(err, "failed to register apiexport provider")
		os.Exit(1)
	}

	setupLog.Info("apiexport-access.platform-mesh.io provider engaged")
}
