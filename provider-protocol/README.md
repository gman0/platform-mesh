# Platform Mesh - provider-protocol

## Description

provider-protocol is the wire contract between a Platform Mesh instance and Remote Providers: the Connection API that `provider-gateway` serves under a Provider's Base URL, and that `platform-mesh-operator` and the Connectors call. Both sides import this module, so they implement exactly the same contract.

- **Endpoints and versions**: paths, ALPN protocol names, headers, framing limits
- **Messages**: Registration, status, Pinned Bundle replacement, errors with stable reasons
- **Credentials**: Onboarding Token and Connection Secret formats, fingerprints
- **Pinned Bundles**: the strict parser and its `etag`
- **Sessions**: the Hello, the Inner TLS configuration, WebSocket framing
- **Test vectors**, shared by both sides' tests

It holds no Kubernetes types and no controllers.

## Getting started

```
go get go.platform-mesh.io/provider-protocol
```
