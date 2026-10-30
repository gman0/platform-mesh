# Remote Providers: development plan

Working plan for implementing RFC 011 (`pm-architecture/rfc/011-remote-provider-flow.md`, published 2026-10-28) in this monorepo, on branch `remote-providers`. Not a design document. It records what's done, what was decided along the way, and exactly what's next, so work can resume from this file alone.

## How to resume

1. Read this file top to bottom.
2. The design: `/workspace/pm-architecture/rfc/`:
   - `xxx-notes-011-v5-impl-00-overview.md` and its documents 01–10 (01 protocol, 02 APIs, 03 operator, 04 Connector CA, 05 Connector, 07 SDK, 08 quickstart, 09 deployment, 10 testing), plus `xxx-notes-011-v5-impl-todo.md`;
   - the v5 notes (`xxx-notes-011-provider-onboarding-flow-improvements-v5.md`) and `xxx-notes-011-v5-connection-gateway.md`.

   Where this file and the docs differ, this file records the newer decision; "Doc fixes pending" lists what still has to be written back.
3. Each module has an `AGENTS.md` with its package map: `provider-protocol/AGENTS.md`, `provider-sdk/AGENTS.md`.
4. Continue at "Next step".

## Working rules

- One package (or one concern) per step; stop after each for review.
- Changes stay uncommitted; the author commits.
- The assistant runs no Go tooling (`go build`, `go test`, `go vet`, `gofmt`, `go mod tidy`); it writes code and tests, and says what to run.
- No hand-written generated code (deepcopy, CRD YAML, clients): add markers, the author runs the generators.
- Ask when a choice is the author's; propose options with a recommendation.
- Docs and comments lean; no over-explaining. First lines of READMEs say what a thing is for, not which components it has.
- Tests: certificates from `testvectors` are valid around `testvectors.Now` (2026-10-19 12:00 UTC, ±1 h / +23 h for leaves): every check against them must use that clock, never `time.Now`. Channel reads in tests use timeouts, never block. Fake listeners must make `Close` unblock `Accept` (`http.Server.Close` waits for `Serve`). Use loopback TCP, not `net.Pipe`, where both ends may write at once (TLS alerts).

## Decisions

### Protocol (`provider-protocol/`, `go.platform-mesh.io/provider-protocol`)

- **Its own module**, imported by `provider-sdk` and the PM-side. Registered in `go.work`, the root `Taskfile.yaml` (`COMPONENTS`, `LIBRARIES`), `.github/workflows/provider-protocol.yml`, `cmd/release/const.go`.
- **Versioning**: what's negotiated per connection (paths, messages, reasons, ALPN names, the Hello) is in `connections/v1` (package `v1`, imported as `connectionsv1`); ALPN names are tied to it (`pm-register/1`, `pm-control/1`, `pm-session/1`); any wire change except adding a field is a new `connections/vN`. Persisted formats (tokens, secrets, hashes, fingerprints, bundles) carry their own version prefix and stay unversioned.
- **Libraries**: gorilla/websocket (the monorepo's pseudo-version), `github.com/kcp-dev/logicalcluster/v3`, hashicorp/yamux v0.1.2 (MPL-2.0, accepted), testify.
- **Wire choices**:
  - `ServerKey` is `{"publicKey": "<PEM SPKI>"}`.
  - Reason → status: `TokenRefused` 403, `ConnectionUnknown` 404, `NotFound` 404, `Unavailable` 503, `Unauthorized` 401, `ConnectionMismatch` 409, `IdempotencyConflict` 409, `InvalidRequest` 400, `BundleInvalid` 422, `PreconditionFailed` 412, `RateLimited` 429. `TokenRefusal` sub-reasons (`Unknown`, `Expired`, `Spent`, `KeyUnusable`) in `ErrorResponse.Detail`; `BundleInvalid`'s detail is the `bundle.Reason`.
  - Registration is `POST /v1/connections` inside the Registration Session; inner requests' Host is irrelevant (routing by path).
  - Fingerprints and hashes: lowercase only, one text form. `keyfp` in the token is hex only.
  - Token hash covers `tokenSecret` only; Connection Secret hash covers the whole `pmc1_…`.
  - IDs: `t-`/`c-` + 26 lowercase base32 characters, valid Kubernetes names.
  - Base URL: `https`, canonical, no user info, query, fragment or dot segments, ≤ 2 KB.
  - Pinned Bundle: ≤ 32 certificates, ≤ 64 KB. `etag` plain hex in JSON, quoted in `If-Match`.
  - Hello: big-endian uint16 length + JSON, ≤ 4 KB; 1–4 lowercase hosts (one, two during a rename); `sub` optional; `clusterName` via `logicalcluster`, never `system:`.
  - `MaxBodySize` 256 KB (a 64 KB bundle's whitespace doubles when JSON-escaped; a test pins `≥ 2 × bundle.MaxSize + 4 KB`), `MaxErrorBodySize` 16 KB.
  - Bearer scheme exactly `Bearer` (case-sensitive).
  - yamux: the Provider-side is the client (it opens Streams), the PM-side the server.
- **Liveness and timeouts**: outer WebSocket pings only keep the Edge's idle timers busy (pongs may come from the Edge): no pong deadline in `wsconn`. Liveness between the ends is end to end, by yamux keepalives inside the Inner TLS. Every handshake and call has a timeout, on both sides (see "Open items").

### PM-side APIs (`apis/providers/v1alpha1`)

- Go types and markers only; the author handles CRDs, `APIResourceSchema`s, exports and generation (done).
- `Provider` phases replaced for both kinds: `Pending`, `Provisioning`, `Ready`, `Degraded`, `Deleting`. `ProvisioningWorkspace`/`ProvisioningKubeconfig` were removed: `operators/platform-mesh-operator`'s `workspace.go` and `scoped_kubeconfig.go` don't compile until the operator step.
- Schema validation: protocol formats as patterns (copied as literal regexes, so `apis` doesn't import `provider-protocol`), CEL for https and immutability, bounds everywhere; deep checks (strict PEM) in the operator.
- `ProviderOnboardingRequest` is cluster-scoped; `tokenSecretRef` carries a namespace.

### SDK (`provider-sdk/`, `go.platform-mesh.io/provider-sdk`, builds `provider-gateway`)

- The SDK's kinds live in this module (`api/v1alpha1`, group `provider-sdk.platform-mesh.io`). The chart lives in this repository: `provider-gateway-chart/`, `provider-gateway-crds-chart/` (see "Chart and release").
- `provider-protocol` via a local `replace` in `go.mod` until its first tag.
- **Serving TLS of the operator proxy**: the standard setup, a long-lived CA clients trust and short-lived serving certificates; no rotation code in the SDK. Default: cert-manager (a `SelfSigned` Issuer, a long-lived CA `Certificate`, a CA Issuer, a serving `Certificate` for the gateway's Service names), mounted and reloaded with `certwatcher`. Fallback (a chart value): a CA generated once, never expiring, serving certificates issued in memory. Changing the CA is rare and deliberate; overlap is trust-manager's job.
- **`ProviderEndpoint`**: followed by a client-go watch per Connection over its Streams (not polling); decoded as unstructured (no dependency on `apis`); Server Keys matched by `key-sha256` fingerprint, not PEM text.
- **Operator proxy**: no tunnel cap; first response's status line per tunnel only (simplification of 07's per-response bookkeeping).
- **Kubeconfig `Secret`s in a namespace of their own** (decided 2026-10-28): `--kubeconfig-namespace` (default `--namespace`; the chart's default `<release namespace>-kubeconfigs`, created by the chart, and it refuses the release namespace). The Provider's operator gets `get`/`list`/`watch` on Secrets there only (chart value `kubeconfigSecrets.readers`), never on the namespace with the Server Keys' and CAs' keys. No owner reference across namespaces: the `Connection`'s finalizer deletes the `Secret`, and the `Connection` controller finds `Secret`s by their Connection label. The cache watches Secrets in both namespaces, everything else in the gateway's.
- **Retry window and GC**: spent tokens pass the pre-upgrade check until `expiresAt` + retry window, and are garbage-collected at that same time (not `registration.at` + window).

### From the published RFC 011 (2026-10-28)

The notes (00–10) were brought in line with the RFC. What it changes in code, done or to do:
- **Connection Export**: `providerendpoints.platform-mesh.io`, in `:root:platform-mesh-system` (was `connections.providers.platform-mesh.io` in `:root:providers:system`). Done in `apis` (`ConnectionExportName`); to do: regenerate, and the kcp manifests (09).
- **Its binding comes from the Provider Workspaces' `WorkspaceType`** (a default binding), not from `platform-mesh-operator`; no `ConnectionBinding` step or condition. Done: `ProviderConditionConnectionBinding` and `ConnectionExportBindingName` removed (unreferenced). Verified in kcp (`pkg/reconciler/tenancy/initialization/apibinder_initializer_reconcile.go`): the default-binding initializer accepts all of the export's permission claims. Caveat: only at a workspace's initialization; Provider Workspaces that already exist get no binding. Handle at the kcp-bootstrap step (create it for existing ones, or document recreating them).
- **Kubeconfig `Secret` on the first verified Session**, not at Registration (07, "Kubeconfig per Connection", "Session server"): the proxy credential and `Secret` are created then; a deleted `Secret` is recreated with a new credential. Done: `ConnectionReconciler` calls `EnsureKubeconfig` only while a Session is open or once `proxyCredentialHash` is set, and watches its `Secret`s; `OnRegistered` stays unwired.
- **"No Session" is a `503` with a message** ("no Session for Connection c-…"), so the operator's logs say what it is (07, "Operator proxy"). Done in `internal/proxy`.
- **Spent tokens stay in the Owner's `Secret`**: `platform-mesh-operator` never writes to it (02, 03 "Declined").
- **On-demand Connection Secret rotation is optional** (an open question in the RFC): keep `AnnotationRotateConnectionSecret`, implement it last.
- **Connector**: the flag `--virtual-workspace-url`; the group `system:platform-mesh:providers-connectors` (05, 09).
- **Not adopted from the RFC's examples**: the RFC names the `ProviderEndpoint` `self` and the kubeconfig `Secret` `c-…-kubeconfig`; the notes and code keep `default` and `connection-c-…` until decided.

## Done

### `provider-protocol`

| Package | Content |
|---|---|
| `connections/v1` | `constants.go` (paths, ALPN, `PM-Server-Key`, framing limits, `StandbyRetryAfter`), `reasons.go`, `messages.go`, `hello.go` (`WriteHello`, `ReadHello`, `Validate`, `Check`, `ValidateClusterName`), `registration.go` (`RegistrationRequest.Validate`, `RetryOutcome`), `http.go` (`FormatETag`, `ParseIfMatch`, `BearerHeader`, `ParseBearer`, `WriteJSON`, `WriteError`, `ReadJSON`, `ReadError` + `ErrNotProtocolResponse`, `ParseRetryAfter`), `SPEC.md` (normative v1 spec, names the Go symbols) |
| `fingerprint` | `cert-sha256:`/`key-sha256:`: `OfCertificate`, `OfCertificateKey`, `OfPublicKey`, `Parse`, `ParseKind`, `Hex`, text/JSON |
| `credential` | `OnboardingToken` (`NewOnboardingToken`, `ParseOnboardingToken`, `Reveal`, `RevealSecret`, `SecretHash`), `HashTokenSecret`, `ConnectionSecret` (`New…`, `Parse…`, `Hash`, `Reveal`), `Hash`, IDs (`New/ValidateTokenID`, `New/ValidateConnectionID`), `ValidateBaseURL`; secrets never in `String`/`GoString`; canonical base64 only |
| `bundle` | `Parse(data, now)` (strict, stable `Reason`s), `ParseStored` (no expiry rule, for stored bundles), `ETag`, `Equal`, `Contains`, `Encode`, `VerifyClient` (direct issuance, `clientAuth`, `digitalSignature`, CA valid), `Issued` (issuer only) |
| `innertls` | `NewServerKey(signer)`, `Server`, `SessionServer(key, pinned, protos, now)`, `Client(ClientOptions)`, `PeerServerKey`, `ClientCertificate`; TLS 1.3 only, ALPN required both ways, no resumption; refusals send `bad_certificate` |
| `wsconn` | `Conn` (binary only, ≤ 32 KB, 1003 on text, 1009 oversized, pings, close 1000), `Dialer(tlsConfig, netDial)` (no proxy, no compression), `Upgrader()`, `HandshakeTimeout` 10 s |
| `testvectors` | certificate factory (`CA`, `Leaf`, options, `Now`); `Handshake` (loopback TCP); fixed token and Connection Secret; vectors: tokens, secrets, hashes, fingerprints, bundles (+ `SameSet`), Hello frames and checks, Inner TLS client certificates, Server Keys, ALPN, Registration requests and retries, `StreamPaths` for the Connector (not self-tested here) |
| `internal/testcerts` | the factory `testvectors` re-exports |

### `apis/providers/v1alpha1`

`ProviderOnboardingRequest` (spec `providerRef`, `tokenSecretRef`, `tokenID`, immutable; status `phase`, `connectionID`, condition `Registered` with reason constants), `Provider` changes (`spec.remote.caBundle`; CEL against local fields and local↔remote switches; `status.lastReadyTime`, `status.connection`; condition, label and annotation constants; `RemoteProviderServiceAccount`; printer column fix), `ProviderEndpointRegistration` (+ `ConnectionSecretName`, keys `secret`/`pendingSecret`), `ProviderEndpoint` (name `default`; `ProviderEndpointName`, `ConnectionExportName`), `ConnectorCASet` (singleton `default`, `distrust`, status, enums). Generated, except the RFC changes of 2026-10-28 (export name; `ConnectionExportBindingName`, `ProviderConditionConnectionBinding` removed): regenerate, and update the export's manifests.

### `provider-sdk`

| Package | Content | Key API |
|---|---|---|
| `api/v1alpha1` | `Connection` (named by connectionID), `OnboardingToken` (named by token ID; `status.registration` stores the request and response for retries), `ServerKey`; constants: finalizer, Events, `ConnectionLabel`, `ClusterNameAnnotation`, `KubeconfigKey`, `AnnotationRotateProxyCredential`, `AnnotationRemovalReason` + `RemovalReason*`, `ServerKeyPrivateKey` | generated by the author |
| `pmtest` | fake PM-side | `New(t)`, `PM.OuterRoots`, `Register`, `Control` → `ControlSession{Status, PutConnectorCASet, Delete, Do, Close}`, `OpenSession` → `Session{Serve, GoAway, Done, NumStreams, Close}`, `UpgradeError`, `CallError`, `ReasonOf` |
| `providertest` | Provider-side for PM-side tests (S12) | `New(t, WithClock, WithNamespace, WithRetryWindow, WithProviderEndpointWatch)` → `*Provider{BaseURL, OuterRoots, Client, Namespace, Metrics}`: `SetLeader`, `AddServerKey` (real `ServerKeyReconciler`), `RetireServerKey`, `ServerKeys`, `ServerKeyFingerprints`, `IssueToken`, `AddConnection(ConnectionSpec)`, `Connection`, `DeleteConnection`, `Reconcile` (Connection and token controllers once), `Sessions(id, host)`, `WaitSessions`, `OpenStream`, `RoundTrip`. `ControlClient`/`ControlSession` (+ optional `Doer`) adapt the client under test; `ControlScenarios`/`RunControlScenarios`: status, first wrong secret closes, `If-Match` missing, stale then current, same-set no-op, unknown inside the Inner TLS (also after a Provider-side delete), standby isn't unknown, delete, `ConnectionMismatch` (with `Doer`). Self-tested with `pmtest` |
| `token` | portal helper | `Usable`, `PickServerKey`, `New` (pure), `Issue` (client) |
| `internal/connapi` | the Connection API | `New(Config)` → `http.Handler`. `Config`: `Client`, `APIReader`, `Namespace`, `Keys`, `Sessions *session.Registry`, `Status` (defaults to the registry's), `RetryWindow` (7 d), `HandshakeTimeout` (10 s), `Limits{PerKey 4, Total 64, UnknownTotal 2, UnknownInterval 1 s}`, `IsLeader`, `OnRegistered`, `Now`, `Log`. Routes `…/register/{tokenID}`, `…/{id}/control`, `…/{id}/session` below `/v1/connections/` wherever it sits; standbys `503` + `Retry-After: 5`. DELETE annotates `DeletedByPlatformMesh` |
| `internal/session` | Sessions | `NewRegistry()`; `Registry.Accept(w, r, Accept{…})`, `OpenStream(conn, host)`, `Has`, `Recheck(conn, bundle)`, `CloseConnection`, `Report`, `Status`, `Grace` (30 s), `OnChange`; `WorkspaceHost` (""), `ErrNoSession` |
| `internal/controllers` | reconcilers | `ServerKeyReconciler`, `EnsureServerKey`, `KeyStore` (implements `connapi.Keys`), `ConnectionReconciler{Client, APIReader, Sessions, Recorder, ReadyDelay 5 min, EnsureKubeconfig, OnRemoved, Now}`, `OnboardingTokenReconciler{Client, RetryWindow, Now}`; each has `SetupWithManager` |
| `internal/endpoint` | `ProviderEndpoint` watch | `NewManager(client, ns, registry, recorder, log)` (subscribes to `registry.OnChange`), `Sync`, `Stop` |
| `internal/kubeconfig` | serving TLS and kubeconfig Secrets | `Source` (`GetCertificate`, `Bundle`); `NewFileSource(dir)` + `Start(ctx)`; `EnsureCA(ctx, c, ns, name, now)` + `SelfSigned{CA, Names, Now}`; `DefaultCASecretName`; `Writer{Client, Namespace, Source, ProxyHost, ServerName}.Ensure/Delete`; `SecretName`, `FrontProxyPlaceholder`, `CheckCredential`, `HashCredential`, `MatchesHash` |
| `internal/gateway` | wiring (S11) | `Options` (+ `Complete`), `Run(ctx, cfg, o)`: one manager, cache in the namespace, leader election; Connection API listener on all replicas (plain HTTP, optional TLS dir via `certwatcher`); controllers, `endpoint.Manager`, operator proxy listener (TLS from the `Source`, HTTP/1.1), `proxy.Start`, first `ServerKey` (retried every 5 s) on the elected one; self-signed CA via `EnsureCA` with an uncached client before the manager starts; readiness = elected |
| `internal/metrics` | metrics (S11b) | `New(reg)` → `*Metrics` (nil-safe): `AuthenticationFailed(endpoint)`, `ConnectionMismatch`, `RegistrationRefused(reason)`, `PushRefused(reason, detail)`, `HandshakeRefused(endpoint, reason)`, `SessionClosed(reason)`, `TunnelOpened`/`Closed`/`Refused(reason)`; `State{Client, Namespace, Sessions}` collector (Sessions by state, Connections, `server_key_connections`, `server_key_retire_at_seconds`); `metricstest.New`, `Value`. Hooks: `connapi.Config.Metrics`, `session.Registry.Metrics` (+ `Counts`, `ErrUpgrade`, close reasons), `proxy.Proxy.Metrics`; registered on controller-runtime's registry in `gateway` |
| `cmd/provider-gateway` | binary | flags, each also `PROVIDER_GATEWAY_<FLAG>`; namespace defaults to the pod's; zap logging; `Dockerfile` (repo-root context), `task docker-build` |
| `internal/proxy` | operator proxy | `Proxy{Client, Namespace, Sessions, TLS, HandshakeTimeout, Log, Now}` as `http.Handler` (CONNECT); `DropUnusedPrevious`, `Start(ctx)` (every minute); `PreviousUnusedAfter` 10 min |

### Chart and release (S13)

Both charts live in this repository (moved from `pm-helm-charts` on 2026-10-28, to keep the plan's work in one place, in line with moving all charts here): `provider-gateway-chart/` and `provider-gateway-crds-chart/`, with license headers for the boilerplate check. To use `pm-helm-charts`' tasks (`task update-changed`, `task docs`, `ct lint`), symlink them into its `charts/` under the same directory names, since `provider-gateway-chart` depends on `file://../provider-gateway-crds-chart`:
`ln -s ../../platform-mesh/provider-gateway-chart pm-helm-charts/charts/provider-gateway-chart` (and the same for `provider-gateway-crds-chart`).

- `provider-gateway-chart` (chart `provider-gateway`, 0.1.0): Deployment (2 replicas, leader election required with more than one, preferred anti-affinity, read-only root, probes on `health`), Services: `provider-gateway` (Connection API, `publishNotReadyAddresses`), `provider-gateway-operator-proxy` (ready = elected), `provider-gateway-metrics` (all replicas); `--names` = the proxy Service's DNS names (`.svc` first, the kubeconfigs' `tls-server-name`); Role in the namespace (SDK kinds, status, finalizers, Secrets, Leases, Events); cert-manager by default (SelfSigned Issuer → CA `Certificate` 10 y, `revisionHistoryLimit: 10` → CA Issuer → serving `Certificate` 90 d over the names; `issuerRef` value to use another issuer), `self-signed` mode; optional `ServiceMonitor` and `PrometheusRule` (`ProviderGatewayServerKeyRotationIncomplete`), in the chart since Providers install it outside PM's observability stack; no PodDisruptionBudget (only the leader is ready, so `minAvailable: 1` would block draining its node). helm-unittest suite `tests/snapshot_test.yaml`.
- `provider-gateway-crds-chart` (chart `provider-gateway-crds`, 0.1.0): `crds/` is filled by `task generate` in `provider-sdk`, which copies `config/crd/bases` there.
- `platform-mesh`: root `_image` names the `provider-sdk` image `provider-gateway`; `.github/workflows/provider-sdk.yml` (from `backup-operator.yml`: lint/test, PR build, `:latest`, tag `provider-sdk/v*` → image, cosign, SBOM, release, chart bump of `provider-gateway`, OCM `github.com/platform-mesh/images/provider-gateway`; no envtest job); `cmd/release` entry `provider-sdk` (an image component; add to `libraryComponents` once `platform-mesh-operator` imports `providertest`).

### Repo and docs

- `remote-providers-devplan.md` (this file).
- `provider-sdk/providertest` for `platform-mesh-operator` and Connector tests: it makes their modules require `provider-sdk` (test-only use).
- `pm-architecture/rfc` updated during implementation: 07, 08, 10, v5 notes and gateway notes for the serving TLS (cert-manager by default).

## Test status

Reported passing by the author (after fixes): `provider-protocol/credential`, `bundle`, `innertls`, `connections/v1` (`MaxBodySize` test), `provider-sdk/pmtest`, `internal/connapi` (registration), `internal/endpoint`. Not confirmed yet: `wsconn` (written without local gorilla sources), `testvectors`, the rest of `connapi` (control, session), `controllers`, `kubeconfig`, `proxy`, `token`. Run before S11: `go test ./provider-protocol/... ./provider-sdk/...` and `task lint` in both modules.

Kubeconfig namespace (2026-10-28, passing): `kubeconfig` (`TestEnsureInItsOwnNamespace`), `controllers` (`TestConnectionKubeconfigSecretMapsToConnection`), `gateway` (`TestOptionsKubeconfigNamespace`, invalid case); chart tests (own namespace, readers, release namespace refused).

S13 chart (2026-10-28, passing): `task generate` in `provider-sdk` (fills the CRD chart); then, through the symlinks in `pm-helm-charts`: `task update-changed` (dependencies, docs, snapshot), `helm unittest charts/provider-gateway-chart`, `task lint`. Check: with the license header, a template whose condition is false renders a comment-only document; if helm-unittest counts it (`hasDocuments: count: 0` in the self-signed and default-monitoring tests), skip the chart templates in `hack/boilerplate/skip.txt` instead of the headers. `task boilerplate` here.

`apis` RFC changes (2026-10-28), not yet run: regenerate in `apis`; `go build ./...` in modules importing `apis/providers/v1alpha1` (nothing referenced the removed names).

S12 `providertest` (2026-10-28, passing): `providertest` (`TestControlScenarios`, `TestRegistration`, `TestStandby`, `TestSessions`, `TestServerKeyRotation`). Adds `session.Registry.Count(id, host)`.

S11b metrics (2026-10-28, passing): `internal/metrics` (`TestNilCountsNothing`, `TestCounters`, `TestState`), `connapi` (`TestMetricsRegistrationRefused`, `TestMetricsControl`, `TestMetricsSessions`), `proxy` (`TestConnectRefusals`, `TestConnectWithoutSessions` extended, `TestTunnelsOpenGauge`). `go mod tidy`: `prometheus/client_golang` becomes direct.

S11 wiring (2026-10-28, passing): `internal/gateway` (`TestOptions*`, `TestServer*`, `TestLeaderElection`), `cmd/provider-gateway` (`TestSetFromEnv*`), `controllers` (`TestConnectionKubeconfigFromFirstSession`). The open-Session branch of the kubeconfig gate has no test yet (`providertest` writes no kubeconfigs): add one with a real Session when the kind e2e comes.

Registration retries on spent tokens (2026-10-28, passing): `connapi` fixed so a spent token's key needs only to be present, not deleting and `Ready` (`keyServes`; `retireAt` ignored), and a retry's Connector CA Set is no longer parsed (it got `BundleInvalid` instead of the stored answer). Tests: `TestRegisterRetryRetiredKey`, `TestRegisterKeyNotServing`, `TestRegisterRetryIgnoresConnectorCASet`, and `unusedExpiresAt` = `expiresAt` + window in `TestRegister`.

## Next step: S14, Connector CA derivation (proposed, awaiting the author's go)

Docs for Provider authors are skipped for now (author, 2026-10-28); see "Later". Build order from here: Connector CA and kcp bootstrap (04, 09); `platform-mesh-operator` (03) and the Connector (05); quickstart (08); deployment and e2e (09, 10).

S14: package `operators/platform-mesh-operator/internal/connectorca`, doc 04's Connector CA Set rules as pure functions: no client, no cert-manager types, so it's unit-testable and compiles while the rest of the operator doesn't (old phases removed). cert-manager v1.21.1 is already in the operator's `go.mod`; the controller mapping cert-manager objects to the inputs comes in a later step.
- **Input**: the CA's `CertificateRequest`s (revision, ready time, certificate PEM; empty if pending or failed); each shard's current Connector Certificate; `spec.distrust`; whether the current CA has converged; the clock; the previous `ConnectorCASet` status (see the question below).
- **`Derive(input) → State`**: validates each CA; current CA = newest valid by revision; states `Current`, `Previous`, `DistrustPending`, `Distrusted`, `Dropped`; drop time = successor issued + 48 h; leaf gate (no drop while a Connector Certificate chains to it); distrust results (`Pending`, `Applied`, `Unmatched`), key reuse (`DistrustedKeyReused`); never-empty guard; `Valid` and its reason; Platform Mesh's unexpired CAs for the tamper check.
- **`State.SetFor(connectionID, now)`**: the bundle one Connection pins, with a per-Connection spread derived from the connectionID: up to 6 h on drops, 15 min after a distrust's gate is met.
- **`State.Status(previous)`**: the `ConnectorCASet` status.
- **Tests**: rollover timeline; two issuances within 48 h; an invalid newest CA; pending and failed requests; leaf gate; distrust gated, `immediate`, unmatched, never empty, rollback, key reused; spread determinism.

**Open question for the author** (asked, not answered yet): "the operator stores nothing" conflicts with two timestamps 04 needs: when a distrust's gate was met (starts the 15 min spread) and `distrust.since` in the status. Recommendation: take the previous `ConnectorCASet` status as input and carry them forward; losing it only restarts a distrust's spread, in line with 04's "losing it costs nothing". The alternative, recomputing from cert-manager's timestamps, works for the gate mostly but not for `since` (when the entry was added exists nowhere else).

## Later

- **Docs for Provider authors** (07 work breakdown 13; skipped for now), in `provider-sdk` (README and `docs/`): installing the chart behind an Edge (08's checklist) and the values that matter (`--names`, serving TLS, `kubeconfigSecrets`); the kubeconfig `Secret`s (namespace, `readers`, contents, watching them, the "no Session" 503, the shared-transport optimisation); consumer-data rules (07 "Requirements on Providers"); runbooks (Server Key rotation with the alert, proxy credential rotation, re-pinning, changing the CA, removing a Connection); the metrics.
- **RFC names not adopted** (`self` for the `ProviderEndpoint`, `c-…-kubeconfig` for the Secret): decide before the docs.

## Open items

- **Deadlines everywhere**: before the first release, re-check every call on both sides for a context with a deadline: dials and upgrades, Inner TLS handshakes, Hello reads and writes, Registration and Control Calls, Stream opens, kcp requests through Sessions (including the `ProviderEndpoint` watch's list), Kubernetes API calls in handlers (`connapi` uses the request context: confirm it ends when the WebSocket does), outbound HTTP anywhere. The Connector and `platform-mesh-operator` must time out the upgrade (`wsconn.HandshakeTimeout`), the Inner TLS handshake, the Hello write, and every Registration and Control Call; an early close after the handshake counts as a refused Session (TLS 1.3: the client's handshake completes before the server checks its certificate).
- **Not yet in `provider-sdk`**: per-Owner rate limits on Registration; the Event `AdministrativeChange` (unused so far).
- **Lint in `provider-sdk`**: the root `.golangci.yaml` wants `sigs.k8s.io/controller-runtime/pkg/client` imported as `ctrlruntimeclient` and `go.platform-mesh.io` imports grouped before `k8s.io`/`sigs.k8s.io`; the module (new files included, for consistency) does neither. One mechanical pass when `task lint` is first run; check `provider-protocol` too.
- **`provider-sdk`'s first tag needs `provider-protocol` tagged first**: consumers ignore `provider-sdk`'s `replace`, so its `require go.platform-mesh.io/provider-protocol v0.0.0` must name a real tag before `provider-sdk/v0.1.0`.
- **Readiness isn't per port**: Kubernetes readiness is per pod, so "standbys fail readiness on the operator proxy's port" (07) means a standby is out of every Service. `provider-gateway` reports ready only when elected. The chart sets `publishNotReadyAddresses: true` on the Connection API Service (a value), so standbys still answer upgrades with `503` + `Retry-After`. Fix 07's wording.
- **First kubeconfig `Secret` latency**: it's written on the `Connection`'s next reconcile after its first Session, within the 30 s resync. `registry.OnChange` is taken by `endpoint.Manager`; a fan-out to a channel source on the `Connection` controller would make it immediate.
- **Metrics choices to confirm** (S11b): `providersdk_server_key_connections{key, listed}` counts only Connections seen in the last day (`metrics.RecentlySeen`), the population the rotation alert needs; `providersdk_server_key_retire_at_seconds{key}` was added so the alert can test "within a day of `retireAt`". Registration refusals use the token refusal (`Unknown`, `Expired`, `Spent`, `KeyUnusable`) or the protocol reason (`Unauthorized`, `InvalidRequest`, `BundleInvalid`, `IdempotencyConflict`) as `reason`. A failed Hello or Connector Certificate counts as a Session authentication failure; a failed Inner TLS handshake on Registration or Control as `handshakes_refused{reason="tls"}` (e.g. PM not accepting the Server Key). A Connector's go-away is only seen when a Stream is opened, so an idle Session it replaces counts as `disconnected`. Write the alert rule with the chart (S13).
- **Chart publishing**: the charts are in this repository now, but publishing (OCI, OCM) still runs from `pm-helm-charts`, and `provider-sdk.yml`'s `update-version` job bumps `charts/provider-gateway` there, which doesn't exist (a symlink to this repository doesn't resolve in its CI). Settle with the plan to move all charts here; until then, the tag release fails at that job. The chart isn't referenced by the platform's installation, which is right: Providers install it.
- **`provider-protocol` repo integration**: path triggers (`'provider-protocol/**'`) in the workflows of modules that import it; check the `go.platform-mesh.io` vanity import serves the new path; remove the `replace` in `provider-sdk/go.mod` after the first tag.
- **Refused upgrades** are classified by the caller from the `*http.Response` gorilla returns (`connectionsv1.ReadError`); the Connector's metrics label Session refusals by TLS alert (`bad_certificate`).
- **Registration retries, PM-side** (operator step, 03 "Registration"): `TokenRefused` (before the upgrade or inside the Inner TLS) and `IdempotencyConflict` fail the request; a lost response or crash before persisting retries with the same token, idempotency key, hash and `clusterName`. The Provider-side was checked against the docs on 2026-10-28 (see "Test status").
- **CA management** (author's note): the SDK shouldn't reimplement certificate management; revisit at the chart step that cert-manager is the default and the self-signed CA only the fallback.

## Doc fixes pending in `pm-architecture/rfc`

- 07: `OnboardingToken.status.registration` also stores `secretHash`, `clusterName`, `serverKeys`; `Connection.status` has `previousProxyCredentialHash` and `proxyCredentialRotation`; the token helper is `token.New`/`token.Issue`; first-response status sniffing; removal reasons.
- 01: refusals send TLS alert `bad_certificate` (it says e.g. `unknown_ca`); `MaxBodySize` 256 KB.
- 02: `ProviderOnboardingRequest` is cluster-scoped and `tokenSecretRef` has a namespace.
- 07: kubeconfig `Secret`s in their own namespace (see "Decisions"; "Kubeconfig per Connection" still says the SDK's namespace and has the operator's Role there); "readiness per port" (see "Open items"); metric names and labels as implemented (`internal/metrics`), `server_key_connections` over recently seen Connections, `server_key_retire_at_seconds`.
