#!/usr/bin/env sh

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

# Build a container image from a context + Dockerfile and load it into the
# kind cluster. Wrapper used from Tiltfile custom_build; works with both
# docker and podman.
#
# Usage:
#   build-and-load.sh REF CONTEXT DOCKERFILE
#
# The caller (Tilt) is expected to tag the image exactly as REF so it
# matches what the chart renders.

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 REF CONTEXT DOCKERFILE" >&2
    exit 2
fi
ref="$1"
context="$2"
dockerfile="$3"

cluster="${KIND_CLUSTER_NAME:-platform-mesh}"
kind="${KIND:-kind}"

installed() { command -v "$1" > /dev/null 2>&1; }

if installed docker && docker info > /dev/null 2>&1; then
    runtime=docker
elif installed podman && podman info > /dev/null 2>&1; then
    runtime=podman
else
    echo "build-and-load.sh: neither docker nor podman is usable" >&2
    exit 1
fi

echo ">>> building $ref with $runtime"
"$runtime" build -t "$ref" -f "$dockerfile" "$context"

echo ">>> loading $ref into kind cluster $cluster"
case "$runtime" in
    docker)
        "$kind" load docker-image "$ref" --name "$cluster"
        ;;
    podman)
        # kind only knows docker tarballs via image-archive. podman save
        # emits a compatible OCI/docker archive; pipe it into kind.
        tmp="$(mktemp --suffix=.tar)"
        trap 'rm -f "$tmp"' EXIT
        "$runtime" save --format docker-archive -o "$tmp" "$ref"
        "$kind" load image-archive "$tmp" --name "$cluster"
        ;;
esac
