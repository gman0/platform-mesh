# Platform Mesh - provider-sdk

## Description

provider-sdk lets a service provider offer its APIs on any number of Platform Mesh instances, which reach it from outside and hand it no credentials of theirs.

It's delivered as `provider-gateway`, an image and a Helm chart installed next to the Provider's operator. The operator stays unchanged: it gets one ordinary kubeconfig per Platform Mesh instance and talks to it through `provider-gateway`.

- **Connection API**: Registration, Control Sessions and Sessions under the Provider's Base URL ([provider-protocol](../provider-protocol))
- **Operator proxy**: an in-cluster forward proxy and one kubeconfig `Secret` per Connection
- **Resources**: `Connection`, `OnboardingToken` and `ServerKey` in `provider-sdk.platform-mesh.io`
- **For portals**: a token helper
- **For tests**: a fake PM-side and a test Provider-side server

## Getting started

```
go get go.platform-mesh.io/provider-sdk
```
