# Dev plan: remote access baseline (RFC 012)

Working notes for the PoC implementation of [RFC 012 — Remote access: baseline](../pm-architecture/rfc/012-remote-access-baseline.md).

Scope for this iteration: **Stages 0–2** (end-to-end happy path for the direct deployment model; customer runs the SDK on their own cluster).

Later stages (3–7) and follow-ups live in [`xxx-devplan-later-stages.md`](./xxx-devplan-later-stages.md) as thin checkbox skeletons.

Companion RFCs:
- [RFC 012 — baseline](../pm-architecture/rfc/012-remote-access-baseline.md)
- [RFC 013 — tunnel mode](../pm-architecture/rfc/013-remote-access-tunnel.md) *(not implemented in this iteration)*
- [Overview / working notes](../pm-architecture/rfc/xxx-notes-remote-access-overview.md)

---

## Shaping (settled)

| Area | Decision |
|---|---|
| **access-operator binary location** | `platform-mesh/operators/access-operator/` |
| **access SDK binary + library location** | `platform-mesh/sdk/access/` (new top-level `sdk/` dir) |
| **Shared protocol library** | `platform-mesh/protocol/access/` (new top-level `protocol/` dir) |
| **PM-side CRD types** | Split by domain: `ProviderAccessRequest` lives in `platform-mesh/apis/providers/v1alpha1/` (same group as `Provider`, since it's an Owner-facing intent object on Providers). `AccessGrant` lives in `platform-mesh/apis/access/v1alpha1/` (group `access.platform-mesh.io/v1alpha1`, access-plane infrastructure). |
| **User-side CRD types** | `platform-mesh/sdk/access/apis/v1alpha1/` — separate group `access-sdk.platform-mesh.io/v1alpha1` to keep the PM-facing (`access`) and user-facing (`access-sdk`) surfaces clearly disjoint |
| **Provider extension** | Edit existing `platform-mesh/apis/providers/v1alpha1/provider_types.go` |
| **PAR reconciler** | Add alongside existing provider controllers in `platform-mesh/operators/platform-mesh-operator/internal/controller/providers/` |
| **PoC scope** | Stages 0–2 (end-to-end happy path on test harness) |
| **Deployment model demoed** | Direct (customer runs SDK on own cluster) |
| **Team** | Working together (user + Claude) |
| **kcp version** | BYO — we rely on whatever we need |
| **JWT library** | `golang-jwt/jwt/v5` |
| **Test harness** | Reuse existing kind-based e2e pattern (see `operators/platform-mesh-operator/Taskfile.yaml` and `test/e2e/kind/`). Envtest for unit-integration. |

---

## Code layout

```
platform-mesh/
├── apis/
│   ├── access/v1alpha1/                       # NEW: PM-side access-plane CRDs
│   │   └── accessgrant_types.go
│   └── providers/v1alpha1/                    # EXTEND
│       ├── provider_types.go                  # + Remote spec/status
│       └── provideraccessrequest_types.go     # NEW (PAR lives next to Provider)
├── protocol/
│   └── access/                                # NEW: shared library
│       ├── token.go                           # pma1 parse/serialize
│       ├── callcredential.go                  # JWT HS256 sign/verify
│       └── replaycache.go                     # (tokenID, jti) → exp
├── sdk/
│   └── access/                                # NEW: user-side
│       ├── apis/v1alpha1/
│       │   ├── accessidentity_types.go
│       │   └── access_types.go
│       ├── cmd/                               # access SDK binary
│       └── internal/
│           ├── controller/                    # AccessIdentity reconciler
│           └── server/                        # /access HTTP handler
└── operators/
    ├── access-operator/                       # NEW: PM-side operator
    │   ├── cmd/
    │   └── internal/controller/               # AccessGrant reconciler
    └── platform-mesh-operator/                # EXTEND
        └── internal/controller/providers/
            ├── par_controller.go              # NEW
            ├── provider_controller.go         # EDIT for spec.remote
            └── managedprovider_controller.go  # (existing, untouched)
```

---

## Stages

Legend: ☐ not started · ◐ in progress · ☑ done

### Stage 0 — Foundations (shared, unblocks everything)

- ☑ `apis/providers/v1alpha1/provideraccessrequest_types.go` — `ProviderAccessRequest` CRD
- ☑ `apis/providers/v1alpha1/groupversion_info.go` — register new type in SchemeBuilder (edit existing)
- ☑ `apis/access/v1alpha1/accessgrant_types.go` — `AccessGrant` CRD (+ `groupversion_info.go` for new `access.platform-mesh.io` group)
- ☑ `apis/providers/v1alpha1/provider_types.go` — extend with `Remote` spec/status
- ☑ `sdk/access/apis/v1alpha1/accessidentity_types.go` — `AccessIdentity` CRD
- ☑ `sdk/access/apis/v1alpha1/access_types.go` — `Access` CRD (+ `groupversion_info.go` for new `access-sdk.platform-mesh.io` group)
- ☑ `sdk/Taskfile.yaml` — added so `task sdk:generate` emits deepcopy for the sdk module
- ☑ `protocol/access/token.go` — `pma1` parse/serialize + tests
- ☑ `protocol/access/callcredential.go` — JWT HS256 sign/verify + tests
  - Claims: `sub` (= tokenID), `iat`, `exp`, `jti`, `body_sha256`.
  - Reject non-`HS256` algorithms.
- ☑ `protocol/access/replaycache.go` — bounded TTL map + tests
- ☑ `protocol/Taskfile.yaml` — standard component Taskfile for the new module
- ☑ Root `Taskfile.yaml` — `protocol` + `sdk` registered in `COMPONENTS` + `LIBRARIES`
- ◐ CRD manifests via `controller-gen` — `providers.*` already regenerates through `operators/platform-mesh-operator/Taskfile.yaml manifests` (picks up new PAR + extended Provider); `access-sdk.*` wired through `sdk/Taskfile.yaml generate` into new chart `charts/platform-mesh-access-sdk-crds/`. `access.*` (AccessGrant) CRD + apigen are deferred to Stage 1 where they'll live next to the new `operators/access-operator/` that owns the type's semantics — pm-operator only *creates* AccessGrants (via PAR reconciler), doesn't reconcile them.
- ◐ CEL validation rules — `Provider.spec.remote` immutability landed on `provider_types.go`; `AccessIdentity.spec.accept` enum landed via `+kubebuilder:validation:Enum=Always;Manual`. Nothing else needed for Stage 0.
- ☐ CI green

**Deliverable**: types + protocol library. No behavior yet.

### Stage 1 — PM-side happy path (against a stub SDK)

- ☑ `operators/platform-mesh-operator/.../providers/par_controller.go` — PAR reconciler
  - Resolve `providerRef`; wait in `Pending` if missing.
  - `Failed` reasons: `ProviderNotRemoteMode`, `InvalidAccessToken` (PAR invariant enforcement deferred — see note below).
  - Parse access token from PAR's Secret, mirror the Secret into the Provider Workspace, upsert `AccessGrant` there.
  - Write `Provider.status.remote.{tokenID, accessURL}` (local, same workspace as the PAR).
  - Mark PAR `Completed`.
- ☑ Edit `provider_controller.go` — handle `spec.remote`
  - `ScopedKubeconfigSubroutine` now early-returns after SA + CRB + token-Secret when `inst.Spec.Remote != nil`. Keeps SA bootstrap unconditional per RFC. TODO(stage-5): refactor into `provider_identity.go` + local-only kubeconfig subroutine.
  - No `AccessGrant` watch; no `Connected` condition. See PoC note below.

**PoC notes carried into PR 2:**

- **One-active-PAR invariant.** RFC 012 requires enforcement ("new PARs arriving while an older non-terminal PAR exists for the same Provider go `Failed` with `AnotherPARActive`; oldest wins"). Deferred for the PoC — rely on Owner discipline. Re-add in Stage 5 (hardening) with a list-and-compare check in `par_resolve.go`, plus deterministic tie-breaking on `(creationTimestamp, name)`.
- **No cross-workspace status reflection.** `AccessGrant.status` (phase, conditions) lives in the Provider Workspace and is not mirrored onto `Provider.status`. The Owner observes connection health with `kubectl get accessgrant` inside the Provider Workspace directly — they already have RBAC there from the Workspace bootstrap. `Provider.status.remote.{tokenID, accessURL}` is populated by the PAR reconciler from the parsed token (one-shot, no sync). Rationale: cross-workspace reads from pm-operator would be a new access pattern inconsistent with the rest of the codebase; the information is one `kubectl` away where it rightfully lives. Follow-up for Stage 5+ is UX aggregation (plugin or UI), not reconciler plumbing.
- ☑ `operators/access-operator/` — new binary
  - Standalone Go module `go.platform-mesh.io/access-operator`, in `go.work` + root `Taskfile.yaml` COMPONENTS.
  - mc-runtime manager + `mcapiexportprovider` on `access.platform-mesh.io`.
  - Lifecycle-based `AccessGrantReconciler` wires in `AccessHandshakeSubroutine`.
  - `AccessHandshakeSubroutine` (in `pkg/subroutines/access/handshake.go`) parses token, mints SA token via `TokenRequest`, signs JWT via `protocol/access`, POSTs `/access`, dispatches 200/202/403. Covered by unit tests against `httptest.Server`.
  - Taskfile `manifests` + `apigen` for AccessGrant CRD → `config/crd/` + `manifests/kcp/01-platform-mesh-system/`.
  - Dockerfile at `operators/access-operator/Dockerfile` + chart at `charts/platform-mesh-access-operator/` (Deployment + SA + RBAC; mounts kcp CA bundle Secret; values `kcp.externalUrl` required). CA bundle defaults to `root-merged-ca-bundle` with key `tls.crt` — the Secret kcp-operator's RootShard controller produces (`internal/resources/rootshard/ca_bundle.go` in kcp-operator). In the standard PM install, `charts/infra/values.yaml` deploys kcp to `platform-mesh-system`, so access-operator (also in `platform-mesh-system`) reads the Secret natively. kcp-operator does not expose a dedicated "CA publisher" CR or cross-namespace mirror — the `Kubeconfig` CR issues admin-level kubeconfigs (overkill for CA-only consumers), and RootShard's `CABundleSecretRef` is an input, not an output. If access-operator ever needs to run outside `platform-mesh-system`, add a Secret-reflector dependency (kyverno / stakater) or a one-shot copy Job in the chart. Not needed for the standard install.
  - **Manifest output.** `task apigen` in access-operator writes `apiexport-access.platform-mesh.io.yaml` + `apiresourceschema-accessgrants.access.platform-mesh.io.yaml` directly into `apis/static-assets/kcp/01-platform-mesh-system/` (the shared embed tree consumed by pm-operator's `KcpsetupSubroutine`). This follows pm-operator's own `apigen` pattern (seeds output from committed manifests to preserve schema hash names, applies yaml-patches) rather than the resources/ + hand-curated kcp/ pattern most components use, because every APIExport access-operator produces ships to kcp verbatim — no curation decision. See `apis/static-assets/README.md` for the tree layout. Also note: `apis/static-assets/kcp/02-root/workspace-type-provider.yaml` now includes `access.platform-mesh.io` in `defaultAPIBindings`, so each Provider Workspace gets the APIBinding automatically.
  - **TODO(stage-5): access-operator must not run as kcp cluster-admin.** The current PoC ctor path calls `BuildKubeconfigFromConfig` with the shared `kcp-cluster-admin-client-cert` Secret — convenient but wildly over-privileged. Idiomatic replacement: a dedicated `access-operator` SA with narrow RBAC — just enough to (a) engage the `access.platform-mesh.io` APIExportEndpointSlice as a virtual-workspace client, and (b) mint SA tokens (`TokenRequest` subresource) against the Provider Workspace SAs the AccessGrants reference. Credential should mount from its own Secret, not the cluster-admin one.
  - **TODO(stage-5): factor `BuildKubeconfigFromConfig` out of both pm-operator and access-operator.** Currently duplicated; should live in `golang-commons/kcp-admin` or similar.
  - Host AccessGrant CRD + apigen here (CRD lives with the operator that owns its semantics). Add `/access/...` to the operator's `manifests` task and `access.platform-mesh.io_accessgrants.yaml` to its apigen list, producing `apiexport-access.platform-mesh.io.yaml` + `apiresourceschema-accessgrants.access.platform-mesh.io.yaml` under its `manifests/kcp/...` tree.
  - `internal/controller/accessgrant_controller.go`:
    - Watch `AccessGrant` in `Pending`.
    - Mint SA token via `TokenRequest` for `spec.saRef`.
    - Sign call-credential JWT via `protocol/access`.
    - `POST /access` with Authorization + body `{kcpURL, kcpCABundle, saToken}`; TLS verify against `spec.caBundle` (or system CAs).
    - On 200: mark `AccessGrant` `Active`.
    - On 202: requeue for retry.
    - On 403: surface failure reason on `AccessGrant` status.
- ☑ Stub `/access` server for Stage 1 integration tests — shipped as `operators/access-operator/test/accessserver/`, a Go library (verifier + replay cache, injectable `SecretLookup`). Covered by unit tests.
- ☐ ~~Kind-based integration test~~ — **deferred** to Stage 2 e2e (PR 5) once the real user-side SDK exists. Rationale: the devplan acceptance criteria ("Provider.status reflects Connected") no longer applies (we removed cross-workspace status reflection); a stub-based kind harness would be throwaway work with Stage 2 landing shortly after.

**Deliverable**: PM-side chain compiles + unit-tested. Live validation deferred to PR 5 e2e.

### Stage 2 — User-side happy path (paired with Stage 1)

- **TODO(stage-5 revisit): `Access.spec.identityRef` may need to go.** AccessIdentity can be deleted while Access keeps running; a dangling ref is informational at best. Any Identity-side detail the Customer or operator needs to see from an Access (PM instance labels, audit tags, the Identity's public tokenID at admission time) must be *copied* into Access's own fields at creation time, not resolved by ref. Revisit when Stage 5 polishing lands and the UX requirements are clearer.
- ☑ `sdk/access/cmd/main.go` — SDK binary entry (controller + HTTPS server). Flags: `--public-url`, `--tls-cert-file`, `--tls-key-file`, `--access-listen`, standard controller-runtime flags. Serves `/access` on a dedicated HTTPS listener with ALPN `pm-access/1` enforced via `tls.Config.VerifyConnection` (rejects bare-curl handshakes).
- ☑ `sdk/access/internal/controller/accessidentity_controller.go`
  - On create: generate `(tokenID, hmacSecret)`, build `pma1` with configured public URL, write owned Secret `<accessidentity-name>-access-token`.
  - Field indexer on `status.tokenID` registered in `SetupWithManager` as const `TokenIDIndex`, consumed by the `/access` handler for sub-claim lookup.
  - `Ready=False, Reason=TokenSecretMissing` if the owned Secret is deleted externally (can't re-mint — HMAC secret lives in the Secret).
- ☑ `sdk/access/internal/server/` — HTTP `POST /access` handler
  - Resolves `sub` → `AccessIdentity` via the field indexer, loads HMAC secret from the owned Secret's pma1 wire string.
  - Verifies via `protocol/access.Verify`, runs replay cache.
  - `spec.accept: Always`: builds kubeconfig (clientcmdapi), creates `Access`, writes `<access>-kubeconfig` owned by the Access, sets `status.phase=Active`, responds 200 empty.
  - `spec.accept: Manual`: deferred to Stage 4; currently 403 with reason `AcceptModeManualDeferred`.
  - Owner chain: `<identity>-access-token` → `AccessIdentity`; `Access` is **not** owned by the Identity (rotating the Identity must not kill existing tunnels); `<access>-kubeconfig` → `Access`.
  - Covered by 5 unit tests: 200 happy path, unknown identity, wrong HMAC, replay, Manual deferred.
- ☑ Chart + Dockerfile for the SDK binary.
  - `sdk/access/Dockerfile` — multi-stage build, context at repo root, mirrors access-operator's pattern.
  - `charts/platform-mesh-access-sdk/` — Deployment + Service + SA + RBAC + cert-manager Certificate (optional via `tls.issuerRef`). Depends on `charts/common`. Values: `publicUrl` (required), `tls.{secretName,dnsNames,issuerRef}`, `service.type`, `image.*`, `operator.leaderElect`.
- ☐ E2E test: AccessIdentity on one kind cluster, PM-side on another (or two workspaces in one kind) — full chain, kubeconfig lands, dummy operator can use it. **This is PR 5**, depends on PR 2+3+4 and the SDK chart/Dockerfile if we want kind deployment.

**Deliverable**: full RFC 012 happy path works for the `Always` accept mode.

---

## Out of scope for this iteration

Deferred to later stages (not part of Stages 0–2):

- SA token renewal loop (Stage 3)
- CA bundle rotation + well-known object (Stage 3)
- Offboarding detection (Stage 3)
- `spec.accept: Manual` mode (Stage 4)
- Full error-path matrix + status transitions (Stage 5)
- Re-onboarding flow + teardown cascade (Stage 6)
- Hardening: metrics, admission validation, RBAC tightening, docs (Stage 7)
- Multi-tenant portal deployment demo (follow-up)
- Anything from RFC 013 (tunnel, session tokens, reconnect auth plane)

---

## Open points to resolve during implementation

Small clarifications we'll pin down as we go; none are blockers.

- ☐ Secret naming conventions
  - Proposal: `<accessidentity-name>-access-token` (pma1 Secret); `<access-name>-kubeconfig` (delivered kubeconfig Secret). Call out in RFC 012 once settled.
- ☐ CA-bundle well-known ConfigMap schema (Stage 3 concern)
- ☐ Default `pendingTTL` on `AccessIdentity.spec.accept: Manual` (Stage 4 concern)
- ☐ `AccessIdentity` indexing by `tokenID` — controller-runtime index? label-based? In-memory map?
  - Controller-runtime field indexer is the standard answer.
- ☐ PAR API group placement (deferred by RFC 012); we've landed on `access.platform-mesh.io/v1alpha1` above — confirm no conflicts.

---

## PR plan

1. **PR 1 — Stage 0 foundations.** All types + protocol library + CRD manifests + unit tests. Sequential; everything else depends.
2. **PR 2 — Stage 1 PM-side provider controllers.** PAR reconciler + Provider extension handling. Depends on PR 1.
3. **PR 3 — Stage 1 access-operator.** New binary + AccessGrant reconciler + stub test server. Depends on PR 1; developable in parallel with PR 2.
4. **PR 4 — Stage 2 user-side SDK.** AccessIdentity reconciler + `/access` handler. Depends on PR 1; developable in parallel with PRs 2+3.
5. **PR 5 — Stage 2 e2e.** Full integration test exercising PRs 2+3+4 together.

Working-together workflow: PR 1 is sequential (nail the shapes). PRs 2+3+4 can be interleaved. PR 5 ties the knot.

---

## Status

**Current stage:** mid-Stage 0 (types).

**Done so far:**

- `apis/providers/v1alpha1/provideraccessrequest_types.go` — written. Secret-ref'd `AccessToken`, phases `Pending | Completed | Failed`, no `Reason`/`Message` top-level fields, no short name, printer columns `Provider / Phase / Age` only. `AccessTokenSecretRef` type local to this file with `Key` defaulting to `"accessToken"`. Conditions carry reasons. The `providers.platform-mesh.io/v1alpha1` group was chosen over a new `access.*` group because PAR is an Owner-facing intent object on Providers and lives next to `Provider`.
- `apis/providers/v1alpha1/groupversion_info.go` — edited to register `ProviderAccessRequest{}` and `ProviderAccessRequestList{}` in `addKnownTypes`.
- `apis/providers/v1alpha1/provider_types.go` — extended:
  - `ProviderSpec.Remote *ProviderRemoteSpec` (presence opts into remote mode).
  - `ProviderRemoteSpec{CABundle string}` — inline PEM, not a Secret ref; CA bundles aren't actually secret, kept inline for simplicity.
  - `ProviderSpec` carries a kubebuilder `XValidation` rule making `spec.remote` presence immutable (CEL: `has(self.remote) == has(oldSelf.remote)`).
  - `ProviderStatus.Remote *ProviderRemoteStatus`.
  - `ProviderRemoteStatus{TokenID, AccessURL}` — informational only; live connection state lives in `status.conditions` per v5 pattern (`Connected`, `Ready`, etc.).
  - Added printer column `AccessURL` at `priority=1` (shows only with `-o wide`).
  - Minor doc update on `ProviderKubeconfigSecretRef` noting "local mode only".

**Open decisions made during Stage 0 (no need to re-litigate):**

- PAR lives in the `providers` group, not a new `access` group. `AccessGrant` goes in `apis/access/v1alpha1/` (PM-facing access-plane infrastructure CRD, group `access.platform-mesh.io`). User-side `AccessIdentity` + `Access` go in `sdk/access/apis/v1alpha1/` under a separate group `access-sdk.platform-mesh.io`.
- `AccessToken` is a Secret reference, not inline.
- `CABundle` on `Provider.spec.remote` is inline, not a Secret ref.
- No `Reconciling` phase on PAR — just `Pending → Completed | Failed`.
- No top-level `Reason`/`Message` on PAR status; use conditions.
- No short name on PAR; use full `providerAccessRequests`.
- `AccessTokenSecretRef.Key` defaults to `"accessToken"`.
- When we add `AccessGrant.spec.caBundle`, the SDK's Secret for a delivered kubeconfig will key it `"kubeconfig"` (TBD; just capturing the naming direction).
- `AccessGrant.spec.accessTokenSecretRef` is a same-namespace Secret ref (not inline). Reason: HMAC secret sensitivity is identical to PAR's; keep symmetric credential handling and stay inside Secret-encryption-at-rest. `CABundle` stays inline (not secret).

**Next action:** continue Stage 0 types. Remaining files:

1. `apis/access/v1alpha1/accessgrant_types.go` — new file. `AccessGrant` CRD, group `access.platform-mesh.io/v1alpha1`. Lives in the Provider Workspace on the PM cluster. Namespaced; access-operator watches cluster-wide. Spec: `SARef` (same-namespace SA), `AccessURL`, `AccessTokenSecretRef` (same-namespace Secret; the provider reconciler creates/updates an owned Secret in the Provider Workspace propagated from the PAR's Secret — kept as a Secret ref rather than inline to match the credential-handling symmetry with PAR and to stay inside the Secret-at-rest encryption path), `CABundle` (inline — CA bundles aren't secret, propagated from `Provider.spec.remote.CABundle`). Status: `Phase` (`Pending | Active`), `Conditions`. Match the v5 phase/conditions pattern.
2. `apis/access/v1alpha1/groupversion_info.go` — new file for the new access group. Mirrors `apis/providers/v1alpha1/groupversion_info.go` structure. Register `AccessGrant{}` + `AccessGrantList{}`.
3. `sdk/access/apis/v1alpha1/` — new tree. User-side CRDs in group `access-sdk.platform-mesh.io/v1alpha1`:
   - `accessidentity_types.go` — `AccessIdentitySpec{Accept, MaxPending, PendingTTL}`, `AccessIdentityStatus{TokenID, PendingConnections}`.
   - `access_types.go` — `AccessSpec{IdentityRef, KubeconfigSecretRef}`, `AccessStatus{Phase, LastRefreshed, Conditions}`. Include the commented-out `PMInstance` follow-up field.
   - `groupversion_info.go` — group `access-sdk.platform-mesh.io/v1alpha1`.
4. `protocol/access/` — new tree:
   - `token.go` — parse/serialize `pma1.<base64url(URL)>.<tokenID>.<secret>`.
   - `callcredential.go` — JWT HS256 sign/verify using `golang-jwt/jwt/v5`; claims `sub`, `iat`, `exp`, `jti`, `body_sha256`; reject non-HS256.
   - `replaycache.go` — bounded TTL map keyed by `(tokenID, jti)`.
   - Unit tests for each.

**Working mode:**

- One file (or one small group of files) at a time.
- User reviews each proposed snippet before I write.
- **Do not run `go build` / `go fmt` / `go test` / `controller-gen` — user runs those locally.**
- Assume files land into the existing monorepo; no Go module changes without asking.

---

## Decision log (for future conversation restart)

Key architectural decisions already settled in RFC 012 / RFC 013 (so a future conversation can be restarted without re-litigating):

- Access token wire format: `pma1.<base64url(URL)>.<tokenID>.<secret>`. Prefix `pma1` is wire-only; prose everywhere says "access token."
- Call credential: JWT HS256 signed with the access token's HMAC secret. Claims `sub`/`iat`/`exp`/`jti`/`body_sha256`. 60 s TTL default. Reject non-`HS256`.
- Protocol versioning: ALPN `pm-access/1`. Additive extensions within v1. Bump to `/2` only on a real shape break.
- TLS trust: `Provider.spec.remote.caBundle` optional, propagated to `AccessGrant.spec.caBundle`; system CAs when unset.
- Status: `Provider.status.phase` + `status.conditions` (v5 pattern). `status.remote.{tokenID, accessURL}` for informational fields only. `NeedsReonboarding` is a *reason* on `Connected=False`, not a separate condition.
- PAR: one-shot, cluster-scoped; order-independent with Provider; one active PAR per Provider; terminal states `Completed`/`Failed`; cascade on Provider deletion.
- AccessGrant lives in Provider Workspace; removed when Workspace is torn down.
- Session tokens, signing keys, jti tracking, grace window, reconnect: all RFC 013, not in this PoC.
