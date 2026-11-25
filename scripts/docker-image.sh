#!/usr/bin/env bash
# scripts/docker-image.sh [TAG]: build the AnvilID container image and enforce the size gate.
#
#   scripts/docker-image.sh            # tag anvilid:ci
#   scripts/docker-image.sh anvilid:dev
#   TARGET=aarch64-unknown-linux-musl PREBUILT=1 scripts/docker-image.sh anvilid:arm64
#
# Environment:
#   TARGET    musl target whose binary goes into the image (default x86_64-unknown-linux-musl);
#             the image platform follows from it (linux/amd64 or linux/arm64). A non-native
#             platform needs QEMU binfmt (docker/setup-qemu-action) for the smoke test.
#   PREBUILT  1 = use target/$TARGET/release/anvilid as is (release workflow: the binary was built
#             by an earlier job); fail if it is missing instead of building it.
#
# 1. Builds the static musl binary (scripts/build-musl.sh) unless it exists and is newer than
#    every source file (or PREBUILT=1).
# 2. `docker build` from the prebuilt binary (Dockerfile, distroless static nonroot).
# 3. Fails if the image is 50 MB (52428800 bytes) or larger. Prints the size and appends it to
#    $GITHUB_STEP_SUMMARY when set.
# 4. Smoke test: zero-config `docker run`, wait for /health/live, assert the setup URL is logged.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TAG=${1:-anvilid:ci}
TARGET=${TARGET:-x86_64-unknown-linux-musl}
case "$TARGET" in
    x86_64-unknown-linux-musl) PLATFORM=linux/amd64 ;;
    aarch64-unknown-linux-musl) PLATFORM=linux/arm64 ;;
    *)
        echo "error: unsupported TARGET $TARGET" >&2
        exit 2
        ;;
esac
BIN="target/$TARGET/release/anvilid"
LIMIT=52428800
SMOKE_PORT=${SMOKE_PORT:-18080}

needs_build() {
    [[ -x "$BIN" ]] || return 0
    # Any tracked input newer than the binary triggers a rebuild.
    local newer
    newer=$(find crates themes Cargo.toml Cargo.lock rust-toolchain.toml \
        -path '*/target' -prune -o -type f -newer "$BIN" -print -quit 2>/dev/null || true)
    [[ -n "$newer" ]]
}

if [[ "${PREBUILT:-0}" == "1" ]]; then
    if [[ ! -x "$BIN" ]]; then
        echo "error: PREBUILT=1 but $BIN is missing or not executable" >&2
        exit 1
    fi
    echo "using prebuilt $BIN"
elif needs_build; then
    scripts/build-musl.sh "$TARGET"
else
    echo "using existing $BIN (newer than the sources)"
fi

# Empty directory copied to /data with nonroot ownership (distroless has no shell to mkdir).
mkdir -p target/docker/data
find target/docker/data -mindepth 1 -delete

docker build --platform "$PLATFORM" -t "$TAG" .

size=$(docker image inspect -f '{{.Size}}' "$TAG")
size_mb=$(awk -v s="$size" 'BEGIN { printf "%.1f", s / 1048576 }')
echo "image $TAG ($PLATFORM) size: $size bytes ($size_mb MiB), limit $LIMIT bytes"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "Container image \`$TAG\` ($PLATFORM): $size bytes ($size_mb MiB), limit $LIMIT bytes" >>"$GITHUB_STEP_SUMMARY"
fi
if ((size >= LIMIT)); then
    echo "error: image $TAG is $size bytes, which is not under the $LIMIT byte limit" >&2
    exit 1
fi

user=$(docker image inspect -f '{{.Config.User}}' "$TAG")
if [[ "$user" != "nonroot" ]]; then
    echo "error: image $TAG runs as '$user', expected nonroot" >&2
    exit 1
fi

# --- Smoke test: zero configuration, setup URL in the logs. ---
cid=$(docker run -d --platform "$PLATFORM" -p "127.0.0.1:$SMOKE_PORT:8080" "$TAG")
cleanup() { docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok=0
for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$SMOKE_PORT/health/live" >/dev/null 2>&1; then
        ok=1
        break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$cid")" != "true" ]]; then
        break
    fi
    sleep 0.5
done
if ((ok == 0)); then
    echo "error: container did not become live on port $SMOKE_PORT" >&2
    docker logs "$cid" >&2 || true
    exit 1
fi
if ! docker logs "$cid" 2>&1 | grep -q 'Setup URL: http://localhost:8080/setup?token='; then
    echo "error: container logs do not contain the setup URL" >&2
    exit 1
fi
echo "smoke test passed: live on :$SMOKE_PORT, setup URL logged, user nonroot"
