#!/usr/bin/env bash

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

# Manages the kind cluster used for local development and e2e tests: the
# Tilt environment goes through this script.
#
#   hack/kind.sh up   [--name N] [--kubeconfig PATH] [--config FILE] [--image IMG]
#   hack/kind.sh down [--name N] [--kubeconfig PATH]
#
# up is idempotent:
# - creates the cluster if absent (--config and --image only apply then)
# - when --config declares a hostPort, verifies the kind node publishes it
# - exports its kubeconfig (to PATH when --kubeconfig is given, otherwise to
#   kind's default, $KUBECONFIG or ~/.kube/config)
# - runs a local image registry on the kind network and points containerd at it
# - makes CoreDNS answer *.sslip.io with the node's InternalIP
#
# Environment:
#   KIND               kind binary (default: kind on PATH)
#   KUBECTL            kubectl binary (default: kubectl on PATH)
#   KIND_CLUSTER_NAME  default for --name (default: platform-mesh)
#   REGISTRY_NAME      local registry container name (default: kind-registry;
#                      empty disables the registry)
#   REGISTRY_PORT      host port for the local registry (default: 5001)

set -euo pipefail

log() { echo ">>> $*"; }
die() { echo "$@" >&2; exit 1; }
installed() { command -v "$1" > /dev/null 2>&1; }

usage() {
    cat >&2 << 'USAGE'
usage: hack/kind.sh up   [--name N] [--kubeconfig PATH] [--config FILE] [--image IMG]
       hack/kind.sh down [--name N] [--kubeconfig PATH]
USAGE
    exit 2
}

kind="${KIND:-kind}"
kubectl="${KUBECTL:-kubectl}"
registry_name="${REGISTRY_NAME-kind-registry}"
registry_port="${REGISTRY_PORT:-5001}"

cluster_exists() {
    "$kind" get clusters 2> /dev/null | grep -qx "$cluster_name"
}

# kubectl against the cluster, through the exported kubeconfig.
kc() {
    "$kubectl" ${kubeconfig_args[@]+"${kubeconfig_args[@]}"} --context "kind-$cluster_name" "$@"
}

# Prints the first container runtime (docker or podman) that responds to
# `info`, or returns 1.
container_runtime() {
    for rt in docker podman; do
        if installed "$rt" && "$rt" info > /dev/null 2>&1; then
            echo "$rt"
            return 0
        fi
    done
    return 1
}

# When a --config file declares a hostPort, verify the kind node actually
# publishes it on the host. Catches a cluster that was created before the
# port mapping was added to the config.
check_hostport_published() {
    [[ -n "$config" ]] || return 0
    local node_port
    node_port="$(grep -o 'hostPort: [0-9]\{1,\}' "$config" | head -n1 | cut -d ' ' -f2)" || true
    [[ -n "$node_port" ]] || return 0

    local rt node
    rt="$(container_runtime)" || return 0
    node="$("$kind" get nodes --name "$cluster_name" 2> /dev/null | head -n 1)"
    [[ -n "$node" ]] || return 0
    "$rt" inspect "$node" > /dev/null 2>&1 || return 0
    [[ -n "$("$rt" port "$node" "${node_port}/tcp" 2> /dev/null || true)" ]] || die \
        "kind cluster $cluster_name publishes no host port $node_port; recreate it: $kind delete cluster --name $cluster_name"
}

# Local image registry. Tilt pushes to localhost:${registry_port}; each kind
# node resolves that via /etc/containerd/certs.d/localhost:${registry_port}/hosts.toml
# to the registry container on the kind network.
# See https://kind.sigs.k8s.io/docs/user/local-registry/.
setup_local_registry() {
    [[ -n "$registry_name" ]] || return 0

    local rt
    rt="$(container_runtime)" || die "need docker or podman for the local registry"

    if ! "$rt" inspect -f '{{.State.Running}}' "$registry_name" 2> /dev/null | grep -qx true; then
        log "starting local registry $registry_name on localhost:$registry_port"
        "$rt" rm -f "$registry_name" > /dev/null 2>&1 || true
        "$rt" run -d --restart=always \
            -p "127.0.0.1:${registry_port}:5000" \
            --network kind \
            --name "$registry_name" docker.io/library/registry:2 > /dev/null \
            || die "starting $registry_name failed"
    fi

    # Write the per-node hosts.toml once per run. The directory name must match
    # the host:port Tilt pushes to so containerd picks it up.
    local node
    for node in $("$kind" get nodes --name "$cluster_name"); do
        "$rt" exec "$node" sh -c "
            mkdir -p /etc/containerd/certs.d/localhost:${registry_port} &&
            printf '[host.\"http://%s:5000\"]\n' '${registry_name}' > /etc/containerd/certs.d/localhost:${registry_port}/hosts.toml
        " || die "writing hosts.toml on node $node failed"
    done

    # Advertise per the local-registry discovery KEP (https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry).
    kc apply -f - > /dev/null <<EOF || die "applying local-registry-hosting configmap failed"
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${registry_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

# A for sslip.io is answered with the node IP, which routes to the gateway so
# pm.<node-ip-dashed>.sslip.io resolves within the cluster without hostaliases.
# From the host it resolves to 127.0.0.1 via sslip.io itself.
# AAAA is answered empty since the cluster has no IPv6.
patch_coredns() {
    local node_ip sslip_block corefile stripped patched tmp
    node_ip="$(kc get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')" \
        || die "reading the node InternalIP of $cluster_name failed"
    case "$node_ip" in
        ""|*" "*) die "the kind node of $cluster_name needs exactly one InternalIP, got '$node_ip'";;
    esac

    sslip_block='sslip.io:53 {
    errors
    template IN A sslip.io {
        match "[.]sslip[.]io[.]$"
        answer "{{ .Name }} 60 IN A '"$node_ip"'"
    }
    template IN AAAA sslip.io {
        rcode NOERROR
    }
}'

    corefile="$(kc -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')" \
        || die "reading coredns Corefile failed"

    # Drop any earlier sslip.io block rather than leaving it in front of this
    # one: CoreDNS refuses to serve a zone twice, and a prior block may answer
    # a stale node IP.
    stripped="$(echo "$corefile" | awk '
        /^sslip[.]io:53 \{/ {skip = 1; next}
        skip && /^\}/       {skip = 0; next}
        skip                {next}
                            {print}')"

    patched="$(printf '%s\n%s' "$sslip_block" "$stripped")"
    if [[ "$patched" == "$corefile" ]]; then
        log "coredns already resolves sslip.io to $node_ip"
        return 0
    fi

    log "making coredns resolve sslip.io to $node_ip"
    tmp="$(mktemp -d)" || die "mktemp failed"
    # shellcheck disable=SC2064 # expand $tmp now
    trap "rm -rf '$tmp'" EXIT INT

    printf '%s\n' "$patched" > "$tmp/Corefile" || die "writing Corefile failed"
    kc -n kube-system create configmap coredns \
        --from-file=Corefile="$tmp/Corefile" --dry-run=client -o yaml \
        | kc apply -f - || die "updating coredns configmap failed"
    kc -n kube-system rollout restart deployment/coredns || die "restarting coredns failed"
    kc -n kube-system rollout status deployment/coredns --timeout=180s || die "coredns did not become ready"
}

cmd_up() {
    installed "$kubectl" || die "$kubectl not found"

    if cluster_exists; then
        log "kind cluster $cluster_name exists"
    else
        log "creating kind cluster $cluster_name"
        local args=(create cluster --name "$cluster_name" ${kubeconfig_args[@]+"${kubeconfig_args[@]}"})
        if [[ -n "$config" ]]; then args+=(--config "$config"); fi
        if [[ -n "$image" ]]; then args+=(--image "$image"); fi
        "$kind" "${args[@]}" || die "kind create cluster failed"
    fi

    check_hostport_published
    "$kind" export kubeconfig --name "$cluster_name" ${kubeconfig_args[@]+"${kubeconfig_args[@]}"} || die "kind export kubeconfig failed"
    setup_local_registry
    patch_coredns
}

cmd_down() {
    if ! cluster_exists; then
        log "kind cluster $cluster_name does not exist"
        return 0
    fi
    log "deleting kind cluster $cluster_name"
    "$kind" delete cluster --name "$cluster_name" ${kubeconfig_args[@]+"${kubeconfig_args[@]}"} || die "kind delete cluster failed"
}

[[ $# -ge 1 ]] || usage
action="$1"
shift

cluster_name="${KIND_CLUSTER_NAME:-platform-mesh}"
kubeconfig=""
config=""
image=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) [[ $# -ge 2 ]] || usage; cluster_name="$2"; shift 2 ;;
        --name=*) cluster_name="${1#*=}"; shift ;;
        --kubeconfig) [[ $# -ge 2 ]] || usage; kubeconfig="$2"; shift 2 ;;
        --kubeconfig=*) kubeconfig="${1#*=}"; shift ;;
        --config) [[ $# -ge 2 ]] || usage; config="$2"; shift 2 ;;
        --config=*) config="${1#*=}"; shift ;;
        --image) [[ $# -ge 2 ]] || usage; image="$2"; shift 2 ;;
        --image=*) image="${1#*=}"; shift ;;
        -h | --help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

kubeconfig_args=()
if [[ -n "$kubeconfig" ]]; then kubeconfig_args=(--kubeconfig "$kubeconfig"); fi

installed "$kind" || die "$kind not found"

case "$action" in
    up) cmd_up ;;
    down) cmd_down ;;
    *) usage ;;
esac
