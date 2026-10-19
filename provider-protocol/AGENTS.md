## Repository Description
- `provider-protocol` is the wire contract between the PM-side (`platform-mesh-operator`, the Connectors) and the Provider-side (`provider-gateway`) of a Connection.
- It's a Go library module, not a runnable service. Both sides import it.
- Read the org-wide [AGENTS.md](https://github.com/platform-mesh/.github/blob/main/AGENTS.md) for general conventions.

## Core Principles
- The protocol is security-relevant. Every check that refuses input is tested with negative cases, and the shared test vectors cover them.
- Messages are forward-compatible: decoders ignore unknown fields; never reuse a field name with a different meaning.
- Adding a field is compatible; changing or removing anything on the wire (a path, a field, a status, a reason, a limit) is a new `connections/vN` package.
- Versioned packages hold what's negotiated per connection; persisted formats (tokens, secrets, hashes, fingerprints, bundles) carry their own version prefix and stay unversioned.
- No Kubernetes types, no controllers, no I/O beyond what a package's purpose needs.

## Project Structure
- `connections/v1`: version 1 of the contract: paths, ALPN names, headers, limits, reasons, messages.
- `fingerprint`: `cert-sha256:` and `key-sha256:` fingerprints.
- `credential`: Onboarding Token and Connection Secret formats, their hashes, token and Connection IDs.
- `bundle`: the strict Pinned Bundle parser, its `etag`, and Connector Certificate checks against it.
- `innertls`: `tls.Config`s of the Inner TLS: Server Keys, key pinning, Connector Certificate verification.
- `wsconn`: a `net.Conn` over WebSocket binary messages, with the protocol's framing; the dialer and upgrader settings.
- `internal/testcerts`: CAs and Connector Certificates for tests.

## Commands
- `task test` — run the unit tests.
- `task lint` — run golangci-lint.
- `go test ./<pkg>` — targeted package verification.

## Code Conventions
- Add or update `_test.go` files alongside behavior changes.
- Compare secrets in constant time; never log or format secret values.
- Parse strictly: refuse anything not explicitly allowed, with a stable reason.

## Do Not
- Add dependencies on PM-side or Provider-side code.
- Relax a parser or a limit without updating the test vectors.
