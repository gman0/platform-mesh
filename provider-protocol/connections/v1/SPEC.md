# Connection API, version 1

The wire contract between a Platform Mesh instance (the **PM-side**: `platform-mesh-operator` and the Connectors) and a Remote Provider (the **Provider-side**: `provider-gateway`). Both sides implement exactly this document. Names in code formatting are Go symbols of this module unless stated otherwise.

## Channels

All endpoints are relative to the Provider's **Base URL**, from the Onboarding Token.

| Channel | Upgrade path | Caller | ALPN | Inner TLS client | Credential inside |
|---|---|---|---|---|---|
| Registration | `GET /v1/connections/register/{tokenID}` | `platform-mesh-operator` | `pm-register/1` | no certificate | token secret, bearer |
| Control Session | `GET /v1/connections/{id}/control` | `platform-mesh-operator` | `pm-control/1` | no certificate | Connection Secret, bearer |
| Session | `GET /v1/connections/{id}/session` | Connector | `pm-session/1` | Connector Certificate | none |

Each channel is:
1. **Outer TLS** to the Base URL, verified with web PKI or the Provider's CA bundle. It's terminated by the Provider's Edge and isn't the trust anchor.
2. **A WebSocket upgrade**, a plain `GET` without credentials, cookies or subprotocols.
3. **The Inner TLS** inside the WebSocket.
4. **The channel's protocol** inside the Inner TLS.

## WebSocket framing

Package `wsconn`. On every channel:
- binary messages only; a text message is a protocol error, closed with 1003;
- at most `MaxMessageSize` (32 KB) per message, both directions; larger is closed with 1009;
- the Inner TLS is a byte stream over the messages; boundaries carry no meaning;
- WebSocket pings at the outer level every `PingInterval` (30 s); pings are answered;
- no compression, no proxy from the environment.

## Inner TLS

Package `innertls`. TLS 1.3 only; no session resumption; no hostname checks on either side.

- **Server**: the Provider-side presents a self-signed certificate for one of its Server Keys. The PM-side accepts it only if the key's `key-sha256` fingerprint is pinned for the channel: the token's `keyfp` at Registration, the Connection's Server Keys otherwise.
- **Client, Sessions only**: exactly one certificate, the Connector Certificate. It must be issued directly by a CA in the Connection's Pinned Bundle (no intermediates), be valid, with that CA valid too, and have key usage `digitalSignature` and EKU `clientAuth`.
- **ALPN** is required on both sides and must be the channel's protocol.

## Formats

| Value | Format | Package |
|---|---|---|
| Onboarding Token | `pm1.<base64url(Base URL)>.<keyfp>.<tokenID>.<tokenSecret>`, at most 4 KB; `keyfp` is 64 lowercase hex digits | `credential` |
| Token secret, Connection Secret body | 256 random bits, base64url without padding, canonical | `credential` |
| Connection Secret | `pmc1_` + 256 random bits | `credential` |
| Hash | `sha256:<64 lowercase hex>`; over the token secret, or over the whole Connection Secret | `credential` |
| Token ID, Connection ID | `t-` or `c-` + 26 lowercase base32 characters | `credential` |
| Base URL | `https`, canonical, no user info, query, fragment or dot segments, at most 2 KB | `credential` |
| Fingerprint | `cert-sha256:<hex>` (certificate DER) or `key-sha256:<hex>` (SubjectPublicKeyInfo DER), lowercase | `fingerprint` |
| Cluster name | a logical cluster name, never a workspace path or `system:…` | `ValidateClusterName` |
| Pinned Bundle | PEM; see below | `bundle` |
| Server Key | `{"publicKey": "<PEM SubjectPublicKeyInfo>"}` | `ServerKey` |

**Pinned Bundle**:
- **Content**: only `CERTIFICATE` blocks without PEM headers, and only whitespace outside them.
- **Certificates**: every one a CA (`CA:true`, `keyCertSign`), no duplicates.
- **Count**: at least one certificate, at least one unexpired when received, at most 32 certificates and 64 KB.
- **Refusals** carry a stable `bundle.Reason`.
- **`etag`**: the hex SHA-256 over its sorted `cert-sha256` fingerprints, one per line. Bundles with the same set of certificates are equal, whatever their order or formatting.

## Before the upgrade

The Provider-side may refuse an upgrade with a JSON `ErrorResponse`:
- `register`: `TokenRefused` with a `TokenRefusal` detail. The token must be known, unexpired and its Server Key usable. A spent token passes while its retry window (7 days by default) is open;
- `session`: `ConnectionUnknown` for an unknown or deleted Connection;
- all three: `Unavailable` with `Retry-After`, beyond the handshake limits or from a standby replica (`StandbyRetryAfter`, 5 s).

`control` accepts unknown Connection IDs, within a small separate limit, so that "unknown" is answered inside the Inner TLS.

**Trust**: nothing before the upgrade is trusted, because the Edge could have produced it. A response that isn't the protocol's (`ReadError` returns `ErrNotProtocolResponse`) is the Edge's.

## Registration

Inside the Inner TLS: one request, then the channel closes.

```
POST /v1/connections
Authorization: Bearer <tokenSecret>
{ "idempotencyKey": "...", "clusterName": "...", "secretHash": "sha256:...", "connectorCASet": "<PEM>" }

201 { "connectionID": "c-...", "serverKeys": [ { "publicKey": "..." } ], "unusedExpiresAt": "<RFC 3339>" }
```

- **Validation**: `RegistrationRequest.Validate`; the Connector CA Set must be a valid Pinned Bundle (`BundleInvalid` otherwise).
- **Spent token** (`RetryOutcome`):
  - the same idempotency key, hash and cluster name returns the stored response; a changed Connector CA Set is ignored;
  - another hash or cluster name gets `IdempotencyConflict`;
  - another idempotency key gets `TokenRefused` (`Spent`).
- **Orphans**: a Connection with neither an authenticated Control Call nor a verified Session by `unusedExpiresAt` is removed.

## Control Sessions

**Opening**: the upgrade carries `PM-Server-Key: key-sha256:<hex>`, the Server Key the PM-side expects; the Provider-side presents it if it has it.

**Inside**: HTTP/1.1 with keep-alive. Every request carries `Authorization: Bearer <Connection Secret>`, exactly `BearerHeader`/`ParseBearer`.

| Call | Success | Refusals |
|---|---|---|
| `GET /v1/connections/{id}` | `200 ConnectionStatus` | |
| `PUT /v1/connections/{id}/connector-ca-set` with `If-Match: "<etag>"`, body `ConnectorCASetUpdate` | `204`; a bundle with the same set is a no-op | `412 PreconditionFailed` with the current `etag` for a missing or stale `If-Match`; `422 BundleInvalid` |
| `DELETE /v1/connections/{id}` | `204` | |

**On every call**:
- **Path binding**: the path's `{id}` must be the upgrade path's; otherwise `ConnectionMismatch`, and the Control Session closes.
- **Authentication**: a wrong Connection Secret gets `Unauthorized`, without detail, and the Control Session closes. Every guess costs a new handshake.
- **Unknown Connection**: `ConnectionUnknown`, inside the Inner TLS. That's the only trusted "unknown". If the Provider-side can't read its state, it answers `Unavailable` instead.
- **A replaced Pinned Bundle** is also accepted when every pinned CA has expired.
- **No call changes the Connection Secret.**

**Changing the Connection Secret**:
1. The PM-side writes the new secret's hash into the Connection's `ProviderEndpoint.spec.pendingSecretHash`.
2. The Provider-side reads the `ProviderEndpoint` over a Session, and applies the hash only if the `ProviderEndpoint`'s `connectionID` is its own. The old secret stops working.
3. The PM-side confirms with a Control Call using the new secret.

## Sessions

**Hello**: after the Inner TLS, the Connector sends one Hello: a big-endian uint16 length, then a JSON `Hello`, at most `MaxHelloSize` (4 KB).
- **Validation**: `Hello.Validate`.
- **The essential check**: `Hello.Check`. `connectionID` must equal the path's `{id}`, and `clusterName` the one stored at Registration. Otherwise the Provider-side closes the Session.
- **Hosts**: `hosts` are the virtual-workspace hosts the Session serves, besides the Provider Workspace, which every Session serves. They're routing, not authority.

**Multiplexer**: then yamux.
- Only the Provider-side opens Streams; the Connector refuses others.
- Each Stream carries HTTP/1.1 from its first byte.
- Flow control applies per Stream.
- Either side may send go-away. The Provider-side then stops opening Streams on that Session, and the Connector reconnects at once.

**When the Pinned Bundle changes**, the Provider-side re-checks each open Session's Connector Certificate with `bundle.Bundle.Issued`, which ignores expiry. Sessions it no longer covers get go-away, a short grace period, then close.

## Errors

**Body**: every refusal is an `ErrorResponse` with a `Reason`, sent with `Reason.HTTPStatus`.

**`Retry-After`**: in whole seconds. Callers also accept an HTTP date.

**Backoff**:
- `Retry-After` is the lower bound of the caller's normal reconnect backoff;
- `429` and `5xx` are retried with backoff and jitter;
- a graceful close by the Provider-side is reconnected at once.

## Versioning

**This document is `v1`.** Every channel negotiates its version per connection through ALPN; nothing is stored. Implementations support the current and the previous version.

**What counts as a change**:
- adding a message field is compatible, and decoders ignore unknown fields;
- any other change on the wire is a new `connections/vN`, with new ALPN names for all three channels.

## Limits

| Limit | Value |
|---|---|
| WebSocket message | 32 KB |
| Ping interval | 30 s |
| Request or response body | 256 KB (`MaxBodySize`) |
| Error body read | 16 KB (`MaxErrorBodySize`) |
| Hello | 4 KB, 1–4 hosts, `sub` ≤ 128 printable ASCII |
| Pinned Bundle | 32 certificates, 64 KB |
| Onboarding Token | 4 KB; Base URL 2 KB |
| Idempotency key | 128 printable ASCII |

## Test vectors

Package `testvectors`, run by both sides' tests: tokens, secrets, hashes, fingerprints, Pinned Bundles, Hellos, Inner TLS client certificates, Server Keys and ALPN, Registration requests and retries, and Stream request paths for the Connector.
