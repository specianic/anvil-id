#!/usr/bin/env bash
# scripts/measure-idle.sh BIN TARGET: binary size and idle memory of `anvilid serve`.
#
# Runs BIN from an empty temp directory (so a served /assets/anvil.css that matches the repo
# file proves the asset is embedded), with a file SQLite database, then reports size,
# VmRSS/VmHWM (/proc/PID/status) and Pss (/proc/PID/smaps_rollup) after 5 s idle.
#
# Output: a markdown table row on stdout (and in $GITHUB_STEP_SUMMARY when set) and
# ${MEASURE_OUT:-target/measure}/measure-$TARGET.json.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <path/to/anvilid> <target-triple>" >&2
    exit 2
fi
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
TARGET=$2
OUT_DIR=${MEASURE_OUT:-target/measure}
[[ "$OUT_DIR" = /* ]] || OUT_DIR="$ROOT/$OUT_DIR"
REPO_CSS="$ROOT/themes/default/static/anvil.css"

[[ -x "$BIN" ]] || { echo "error: $BIN is not an executable" >&2; exit 1; }
[[ -f "$REPO_CSS" ]] || { echo "error: $REPO_CSS missing" >&2; exit 1; }

TOOLCHAIN=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' "$ROOT/rust-toolchain.toml")
COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)

WORK=$(mktemp -d)
PID=
cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
BASE="http://127.0.0.1:$PORT"
mkdir -p "$WORK/run" "$WORK/data"
cd "$WORK/run" # empty directory: nothing to serve from disk

# Zero-config SQLite in a temp data dir; loopback public URL (dev mode); no breach-check traffic.
"$BIN" serve --listen "127.0.0.1:$PORT" --public-url "$BASE" --data-dir "$WORK/data" \
    --breach-check off >"$WORK/anvilid.log" 2>&1 &
PID=$!

for _ in $(seq 1 100); do
    if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "error: anvilid exited during startup:" >&2
        cat "$WORK/anvilid.log" >&2
        exit 1
    fi
    sleep 0.1
done
curl -fsS "$BASE/healthz" >/dev/null || { echo "error: anvilid not healthy" >&2; cat "$WORK/anvilid.log" >&2; exit 1; }

curl -fsS "$BASE/.well-known/openid-configuration" -o "$WORK/discovery.json"
grep -q "\"issuer\":\"$BASE\"" "$WORK/discovery.json" || { echo "error: unexpected discovery document" >&2; exit 1; }

curl -fsS "$BASE/assets/anvil.css" -o "$WORK/anvil.css"
served=$(sha256sum "$WORK/anvil.css" | cut -d' ' -f1)
expected=$(sha256sum "$REPO_CSS" | cut -d' ' -f1)
if [[ "$served" != "$expected" ]]; then
    echo "error: served /assets/anvil.css ($served) differs from the repo file ($expected)" >&2
    exit 1
fi
echo "embedded asset OK (sha256 $served)"

sleep 5

vmrss_kb=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status")
vmhwm_kb=$(awk '/^VmHWM:/{print $2}' "/proc/$PID/status")
pss_kb=$(awk '/^Pss:/{print $2}' "/proc/$PID/smaps_rollup")
size_bytes=$(stat -c %s "$BIN")

kill "$PID"
wait "$PID" 2>/dev/null || true
PID=

row="| $TARGET | $size_bytes ($(awk "BEGIN{printf \"%.2f\", $size_bytes/1048576}") MiB) | $vmrss_kb | $vmhwm_kb | $pss_kb | $TOOLCHAIN | $COMMIT |"
header="| target | binary size (bytes) | VmRSS kB | VmHWM kB | Pss kB | toolchain | commit |
|---|---|---|---|---|---|---|"
printf '%s\n%s\n' "$header" "$row"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '### Idle footprint (%s)\n\n%s\n%s\n\n' "$TARGET" "$header" "$row" >>"$GITHUB_STEP_SUMMARY"
fi

mkdir -p "$OUT_DIR"
cat >"$OUT_DIR/measure-$TARGET.json" <<EOF
{"target":"$TARGET","size_bytes":$size_bytes,"vmrss_kb":$vmrss_kb,"vmhwm_kb":$vmhwm_kb,"pss_kb":$pss_kb,"rust_toolchain":"$TOOLCHAIN","commit":"$COMMIT"}
EOF
echo "wrote $OUT_DIR/measure-$TARGET.json"
