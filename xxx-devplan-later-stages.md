# Dev plan: later stages (RFC 012)

Companion to [`xxx-devplan.md`](./xxx-devplan.md). Captures Stages 3–7 as thin checkbox skeletons; details will be fleshed out when we actually reach each stage. Expect this file to drift ahead of reality — treat the bullets as a forward-looking map, not a commitment.

Legend: ☐ not started · ◐ in progress · ☑ done

---

## Stage 3 — Lifecycle on the user side

After Stage 2, the kubeconfig arrives once and sits static. Stage 3 keeps it alive.

- ☐ **SA token renewal loop** in access SDK
  - Periodic `TokenRequest` against kcp for each `Access`'s SA.
  - Rewrite kubeconfig Secret on each renewal.
  - Backoff + retry on `TokenRequest` failures.
- ☐ **CA-bundle well-known object (PM side)**
  - Define schema. Proposal: `ConfigMap kcp-ca-bundle` at a well-known name in each Provider Workspace, with keys `caBundle` (PEM) and `kcpURL`.
  - `access-operator` (or a dedicated controller) maintains it; watches the PM-side CA source; handles old/new overlap window.
  - Where this lives: likely a new sub-controller in `access-operator`, or extracted into its own controller.
- ☐ **CA-bundle polling (user side)**
  - access SDK polls the well-known ConfigMap on a timer via the SA kubeconfig.
  - On change, rewrite the delivered kubeconfig's `certificate-authority-data`.
- ☐ **Offboarding detection**
  - access SDK monitors kubeconfig usage outcomes (401s against kcp).
  - `401` after JWT `exp` → expired; renew via step above.
  - Persistent `401` before `exp` (including repeated renewal failures) → SA revoked PM-side. Delete Secret + `Access`, emit Pod Event, reflect on `Access.status`.
  - `403` / 5xx / network errors are not counted as offboarding.
- ☐ Integration tests
  - SA rotation propagates.
  - CA rotation propagates.
  - PM-side SA deletion propagates to user-side cleanup within a bounded window.

---

## Stage 4 — Manual accept mode

- ☐ **`AccessIdentity.spec.accept: Manual` in `/access` handler**
  - On incoming handshake: add entry to `AccessIdentity.status.pendingConnections` with `tokenID`, `pendingAt`, `expiresAt`. Return `202`.
  - `spec.maxPending` cap (reject with `429` or similar once full? TBD).
  - Pending TTL: default decision needed. Proposal: 1 h.
- ☐ **access-operator retry loop under 202**
  - Exponential backoff with cap; keep retrying until `200`, `403`, or external PAR timeout.
  - Surface `Pending` state on `AccessGrant` and reflect to `Provider.status`.
- ☐ **Approval path**
  - Provider patches `AccessIdentity.status.pendingConnections[i]` to approved. On next retry the handshake proceeds.
  - Need a clear approval API: patch the status field, or a dedicated subresource? TBD.
- ☐ **Denial / expiry path**
  - Provider marks an entry denied → next retry returns `403 Denied`.
  - TTL elapses → entry removed; next retry returns `403 PendingExpired`.
- ☐ Integration tests
  - Approve path.
  - Deny path.
  - TTL expiry path.
  - `maxPending` hit.

---

## Stage 5 — Error paths and status

Full matrix of observable states, surfaced consistently.

- ☐ **PAR rejection reasons** on `ProviderAccessRequest.status`
  - `ProviderNotFound` (transient, waits).
  - `ProviderNotRemoteMode` (terminal).
  - `AnotherPARActive: <older-par-name>` (terminal).
  - Malformed access token (terminal).
- ☐ **`/access` rejection reasons** on `AccessGrant.status` (and reflected on `Provider.status.conditions[Connected]`)
  - `UnknownIdentity` (tokenID not found on user-side).
  - `InvalidCredential` (JWT signature / claims).
  - `BodyMismatch` (body_sha256 check).
  - `Replay` (jti cache hit).
  - `Denied` (Manual mode).
  - `PendingExpired` (Manual mode TTL).
  - `TunnelDenied` (RFC 013, not in this iteration).
- ☐ **`Provider.status` transitions**
  - Phase: `Pending` → `Provisioning` → `Ready` ⇄ `Degraded`, plus `Deleting`.
  - Conditions: `WorkspaceReady`, `Connected`, `Ready` (aggregate).
  - `Connected=False` reason enum covering all the above.
  - `status.lastReadyTime` populated on first `Ready`; `Degraded` requires it per v5.
- ☐ **Reconciler event emission** for every state transition (standard `EventRecorder`).
- ☐ Observability wiring (structured logs with correlation IDs — `AccessGrant` UID, `tokenID`, PAR UID).

---

## Stage 6 — Re-onboarding and teardown cascade

- ☐ **PAR-driven re-onboarding**
  - New PAR with same `providerRef` and a fresh access token → `AccessGrant.spec.accessToken` updated by the reconciler.
  - `access-operator` detects `AccessGrant.spec.accessToken` change → fresh initial handshake.
  - User-side access SDK receives the new handshake and may issue a new kubeconfig Secret (or reuse existing one if the identity hasn't changed).
- ☐ **Provider deletion cascade**
  - Deleting `Provider` → Provider Workspace torn down → `AccessGrant` disappears → `access-operator` observes and stops.
  - User side notices tunnel-equivalent close (connection close in direct mode) → access SDK deletes `Access` + kubeconfig Secret.
  - PAR objects removed as part of Provider cascade.
- ☐ **`AccessIdentity` deletion (user side)**
  - Stops accepting new `/access` dials under this identity.
  - Does NOT cascade to existing `Access` objects (per Decision 7).
  - Operator keeps using existing kubeconfig until SA revocation or `Access` deletion.
- ☐ **`Access` deletion (user side)**
  - Direct teardown lever for one PM connection.
  - access SDK deletes kubeconfig Secret via ownerRef cascade.
  - Operator Pod loses credentials; stops reconciling.
- ☐ Integration tests
  - Re-onboarding after PM-side SA revocation.
  - Full `Provider` deletion → clean on both sides.
  - Per-`Access` deletion isolates one connection.

---

## Stage 7 — Hardening (production prep)

Nothing below is architectural; it's all operational polish.

- ☐ **Metrics**
  - access-operator: `/access` dial outcome counter (by reason), handshake latency histogram, SA-token mint latency.
  - access SDK: `/access` serve outcome counter, SA renewal latency, CA poll cadence, kubeconfig write count.
  - provider reconciler: PAR reconcile outcome counter.
- ☐ **Admission validation** (reconciler-side; no webhooks)
  - PAR: `providerRef` non-empty, `accessToken` parseable, well-formed `pma1`.
  - Provider extension: immutability of `spec.remote` presence after creation.
  - AccessIdentity: `spec.accept` enum, `maxPending` > 0.
- ☐ **RBAC tightening**
  - access-operator: least-privilege (watch AccessGrant, TokenRequest on specific SAs, update AccessGrant.status).
  - access SDK (user side): watch AccessIdentity, write Secret in same namespace, create Access objects; TokenRequest on its own SA; read CA ConfigMap.
  - PAR controller: watch PAR + Provider; write AccessGrant in Provider Workspace.
- ☐ **Observability**
  - Structured logs (JSON) with consistent fields: `providerRef`, `accessGrantUID`, `tokenID`, `jti`.
  - Trace spans on `/access` request lifecycle; propagate via standard headers.
- ☐ **Documentation**
  - Deployment guide (direct mode first; portal later).
  - Troubleshooting runbook (state → likely cause → next action).
  - Operator-facing docs: "I got a `NeedsReonboarding` — what do I do?"
- ☐ **Upgrade story**
  - CRD migration path (v1alpha1 → future versions).
  - Access-operator / access SDK rolling upgrade semantics.
  - Protocol-version negotiation already handled by ALPN but worth exercising.
- ☐ **Security review**
  - Replay cache sizing + DoS resistance.
  - HMAC secret storage + access.
  - CA bundle rotation old/new overlap window correctness.
  - Access token minimum entropy; tokenID collision resistance.

---

## Follow-ups outside the staged plan

Work that's planned but doesn't fit neatly into the stages above.

- ☐ **Multi-tenant portal deployment demo** — same protocol, different deployment shape. Write a reference portal that creates `AccessIdentity` + emits `pma1` to a customer.
- ☐ **RFC 013 implementation** — tunnel mode, session tokens, reconnect auth plane. Separate dev plan when we get there.
- ☐ **PMInstance field** on `Access` (currently commented out in RFC 012) — spec + implement when the single-PM assumption breaks.
- ☐ **OIDC call credential** — RFC 012 future work; separate design.
- ☐ **In-place session-signing-key rotation** — RFC 013 future work; multi-generation key sets.
- ☐ **User-initiated flow** — deferred in overview; design is sketched, implementation is distant.
