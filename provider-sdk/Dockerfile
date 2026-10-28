# Copyright The Platform Mesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build provider-gateway.
#
# NOTE: the build context is the repository ROOT, not this directory:
# provider-sdk uses the in-repo provider-protocol module (go.mod replace and
# the root go.work).
#   docker build -f provider-sdk/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.26.7@sha256:dc2521c2a906db43073b8b4d99f491b6341cf15610b6ebbab187c45153f9959e AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.work go.work
COPY go.work.sum go.work.sum
COPY provider-protocol/ provider-protocol/
COPY provider-sdk/ provider-sdk/

# Drop every workspace module except the ones copied above.
RUN for m in $(go work edit -json | sed -n 's/.*"DiskPath": "\(.*\)".*/\1/p'); do \
      case "$m" in \
        ./provider-protocol|./provider-sdk) ;; \
        *) go work edit -dropuse "$m" ;; \
      esac; \
    done

WORKDIR /workspace/provider-sdk

# cache deps before building so that source changes don't invalidate the layer
RUN go mod download

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -ldflags '-w -s' -o /workspace/provider-gateway ./cmd/provider-gateway

FROM scratch
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV USER_UID=1001
ENV GROUP_UID=1001
COPY --from=builder --chown=${USER_UID}:${GROUP_UID} /workspace/provider-gateway /provider-gateway

USER ${USER_UID}:${GROUP_UID}
ENTRYPOINT ["/provider-gateway"]
