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

// Package v1 is version 1 of the Connection API: paths, ALPN names, headers,
// limits, reasons and messages.
//
// All endpoints are WebSocket upgrades under the Provider's Base URL, without
// credentials; everything else runs inside the Inner TLS:
//
//   - Registration (RegisterPath): one request, with the token secret.
//   - Control Sessions (ControlPath): Control Calls, with the Connection
//     Secret.
//   - Sessions (SessionPath): mutual TLS, the Hello, then yamux.
package v1
