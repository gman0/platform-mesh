# Thin runtime image for hot-reloaded components. The host builds the linux
# binary (see component_binary in helpers.py); Tilt live_update-syncs it into
# this image, so a code change never triggers a full docker build.
#
# NOT distroless, deliberately. Tilt implements live_update by exec'ing `tar`
# inside the running container, and the restart_process extension additionally
# needs `sh`, `touch`, `chmod` and `date` to arm its restart trigger. A
# distroless/scratch base has none of them, and every sync dies with
#
#   OCI runtime exec failed: exec: "tar": executable file not found in $PATH
#
# (https://github.com/tilt-dev/tilt/issues/4303). busybox-via-alpine supplies
# the lot for ~8MB. This image only ever runs in the kind dev cluster; the
# images a real install pulls are built by each component's own Dockerfile and
# stay distroless.
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

# The build context is ./bin/<component>: the binary as `entrypoint` plus any
# payload directories the component reads at runtime (component_binary's
# extra_dirs). It lands in a directory owned by the runtime user, NOT at `/`:
# the live_update sync runs as the container's user, and replacing a file
# means writing to its parent directory. Rooted at `/` that needs root, which
# would mean giving up the nonroot parity the production image has.
COPY . /app/
RUN chown -R 65532:65532 /app

# Restart wrapper, baked into the image so we don't depend on the
# restart_process Tilt extension (which requires a local docker/podman API
# the user may not have). The wrapper execs /app/entrypoint, waits on a
# trigger file, and re-execs on change. live_update in helpers.py syncs
# the binary and `touch`es /tmp/.tilt_restart to trigger the re-exec.
RUN apk add --no-cache inotify-tools \
 && printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'trigger=/tmp/.tilt_restart' \
    'mkdir -p "$(dirname "$trigger")"' \
    ': > "$trigger"' \
    'while true; do' \
    '    /app/entrypoint "$@" &' \
    '    pid=$!' \
    '    inotifywait -qq -e close_write,delete_self "$trigger" || true' \
    '    kill "$pid" 2>/dev/null || true' \
    '    wait "$pid" 2>/dev/null || true' \
    'done' \
    > /app/.restart-wrapper \
 && chmod +x /app/.restart-wrapper \
 && chown 65532:65532 /app/.restart-wrapper /tmp

USER 65532:65532
ENTRYPOINT ["/app/.restart-wrapper"]
