#!/usr/bin/env bash
# scripts/build-musl.sh TARGET: static musl release build of `anvilid` inside the official Rust
# alpine image (native per-arch build: the image runs on the host architecture, so TARGET's
# architecture must match `uname -m`; CI uses native arm64 runners for aarch64).
#
#   scripts/build-musl.sh x86_64-unknown-linux-musl
#   scripts/build-musl.sh aarch64-unknown-linux-musl   # on an arm64 host
#
# Output: target/$TARGET/release/anvilid (asserted statically linked).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET=${1:-}
if [[ -z "$TARGET" ]]; then
    echo "usage: $0 <x86_64-unknown-linux-musl|aarch64-unknown-linux-musl>" >&2
    exit 2
fi
case "$TARGET" in
    *-unknown-linux-musl) ;;
    *)
        echo "error: $TARGET is not a linux musl target" >&2
        exit 2
        ;;
esac

target_arch=${TARGET%%-*}
host_arch=$(uname -m)
[[ "$host_arch" == "arm64" ]] && host_arch=aarch64
if [[ "$target_arch" != "$host_arch" ]]; then
    echo "error: $TARGET needs a native $target_arch host (this host is $host_arch)." >&2
    echo "       Cross-arch builds are not supported; CI builds each arch on its own runner." >&2
    exit 2
fi

TOOLCHAIN=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml)
if [[ -z "$TOOLCHAIN" ]]; then
    echo "error: could not read the toolchain channel from rust-toolchain.toml" >&2
    exit 1
fi
IMAGE="rust:${TOOLCHAIN}-alpine"

mkdir -p .cargo-home
echo "building anvilid for $TARGET in $IMAGE"
start=$(date +%s)
# RUSTUP_TOOLCHAIN overrides rust-toolchain.toml so rustup inside the image does not try to
# install clippy/rustfmt. SQLX_OFFLINE is also set by .cargo/config.toml; pass it explicitly.
# Always an explicit --target: a host-target build would not be static (static-pie needs it).
docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e CARGO_HOME=/src/.cargo-home \
    -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
    -e SQLX_OFFLINE=true \
    -v "$ROOT":/src \
    -w /src \
    "$IMAGE" \
    sh -c "cargo build --release --locked -p anvilid --target $TARGET"
end=$(date +%s)

BIN="target/$TARGET/release/anvilid"
if [[ ! -x "$BIN" ]]; then
    echo "error: build produced no binary at $BIN" >&2
    exit 1
fi
desc=$(file "$BIN")
if ! grep -Eq 'static-pie linked|statically linked' <<<"$desc"; then
    echo "error: $BIN is not statically linked: $desc" >&2
    exit 1
fi
echo "$desc"
echo "build time: $((end - start))s"
echo "$BIN"
