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

## Commands
- `task generate` — CRDs and deepcopy for `api/`.
- `task test` — unit tests.
- `task lint` — golangci-lint.

## Do Not
- Hand-edit generated files (`zz_generated.*`, `config/crd`).
- Change anything on the wire here; that's `provider-protocol`.
