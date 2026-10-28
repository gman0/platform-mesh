## Repository Description
- `provider-sdk` lets a service provider offer its APIs on any number of Platform Mesh instances, which reach it from outside and hand it no credentials of theirs.
- It builds `provider-gateway` (image; chart in `pm-helm-charts`), the Provider-side of the Connection API, and holds a token helper for portals and test support.
- The wire contract is in `provider-protocol`; this module implements it and adds nothing to it.
- Read the org-wide [AGENTS.md](https://github.com/platform-mesh/.github/blob/main/AGENTS.md) for general conventions.

## Core Principles
- Security-relevant: every refusal is tested, with `provider-protocol`'s test vectors where they apply.
- The Kubernetes API is the only source of truth; memory holds caches and live Sessions only.
- A failed authentication changes nothing in any resource and isn't an Event; it's logged and counted.
- Never log or print secret values.

## Project Structure
- `api/v1alpha1`: `Connection`, `OnboardingToken`, `ServerKey` (`provider-sdk.platform-mesh.io`).
- `config/crd/bases`: generated CRDs.
- `pmtest`: a fake PM-side for tests: Registration, Control Sessions, Sessions.
- `token`: Onboarding Tokens for portals: `PickServerKey`, `New`, `Issue`.
- `internal/connapi`: the Connection API server: routing, handshake limits, Registration, Control Sessions, Session upgrades.
- `internal/session`: accepting Sessions (mutual Inner TLS, Hello, yamux) and the registry of live Sessions: Streams by host, status, re-checks, closing.
- `internal/controllers`: reconcilers for the SDK's resources (`ServerKey`, `Connection`, `OnboardingToken`) and `KeyStore`, which loads Server Keys for the Inner TLS.
- `internal/endpoint`: one `ProviderEndpoint` watch per Connection with a Session, over its Streams; applies `pendingSecretHash` and `serverKeys`.
- `internal/kubeconfig`: the operator proxy's serving TLS (cert-manager's mounted certificate by default, a self-generated CA otherwise); the kubeconfig Secrets and proxy credentials.
- `internal/metrics`: Prometheus metrics: nil-safe event counters passed into `connapi`, `session` and `proxy`, and `State`, gauges read at scrape time. No `connectionID` labels. `metricstest` reads them in tests.
- `internal/gateway`: wires `provider-gateway`: options, one controller-runtime manager, the listeners; the Connection API on every replica, everything else on the elected one.
- `cmd/provider-gateway`: flags (or `PROVIDER_GATEWAY_*` env) into `gateway.Run`.
- `internal/proxy`: the operator proxy: `CONNECT` with a per-Connection credential, a Stream per tunnel, TLS inside the tunnel, first-response status sniffing, dropping unused previous credentials.

## Commands
- `task generate` — CRDs and deepcopy for `api/`.
- `task docker-build` — the `provider-gateway` image (context: the repository root).
- `task test` — unit tests.
- `task lint` — golangci-lint.

## Do Not
- Hand-edit generated files (`zz_generated.*`, `config/crd`).
- Change anything on the wire here; that's `provider-protocol`.
