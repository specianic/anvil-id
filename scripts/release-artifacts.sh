#!/usr/bin/env bash
# scripts/release-artifacts.sh BIN TARGET VERSION [OUTDIR]: package a built `anvilid` binary as a
# release archive plus a SHA-256 checksum file.
#
#   scripts/release-artifacts.sh target/x86_64-unknown-linux-musl/release/anvilid \
#       x86_64-unknown-linux-musl 0.1.0 dist
#
# Output (OUTDIR defaults to dist/):
#   anvilid-VERSION-TARGET.tar.gz         anvilid, LICENSE, README.md in anvilid-VERSION-TARGET/
#   anvilid-VERSION-TARGET.tar.gz.sha256  "<hex>  <archive name>" (sha256sum -c / shasum -a 256 -c)
#
# Runs on Linux and macOS (uses sha256sum or shasum, whichever exists).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BIN=${1:-}
TARGET=${2:-}
VERSION=${3:-}
OUTDIR=${4:-dist}
if [[ -z "$BIN" || -z "$TARGET" || -z "$VERSION" ]]; then
    echo "usage: $0 <binary> <target triple> <version> [outdir]" >&2
    exit 2
fi
if [[ ! -f "$BIN" ]]; then
    echo "error: binary $BIN does not exist" >&2
    exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9A-Za-z.+-]+$ ]]; then
    echo "error: version '$VERSION' contains unexpected characters" >&2
    exit 2
fi
if [[ ! "$TARGET" =~ ^[0-9A-Za-z_-]+$ ]]; then
    echo "error: target '$TARGET' contains unexpected characters" >&2
    exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    echo "error: neither sha256sum nor shasum is available" >&2
    exit 1
fi

NAME="anvilid-${VERSION}-${TARGET}"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir "$STAGE/$NAME"
cp "$BIN" "$STAGE/$NAME/anvilid"
chmod 0755 "$STAGE/$NAME/anvilid"
cp "$ROOT/LICENSE" "$ROOT/README.md" "$STAGE/$NAME/"

ARCHIVE="$NAME.tar.gz"
tar -C "$STAGE" -czf "$OUTDIR/$ARCHIVE" "$NAME"
(cd "$OUTDIR" && sha256 "$ARCHIVE" >"$ARCHIVE.sha256")

# Self-check: the checksum file verifies and the archive lists the binary.
(cd "$OUTDIR" && sha256 -c "$ARCHIVE.sha256" >/dev/null)
listing=$(tar -tzf "$OUTDIR/$ARCHIVE")
if ! grep -qx "$NAME/anvilid" <<<"$listing"; then
    echo "error: $ARCHIVE does not contain $NAME/anvilid" >&2
    exit 1
fi

echo "$OUTDIR/$ARCHIVE"
cat "$OUTDIR/$ARCHIVE.sha256"
