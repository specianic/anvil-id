#!/usr/bin/env bash
# scripts/fuzz.sh: cargo-fuzz entry points (SEC-07). Needs a nightly toolchain and cargo-fuzz 0.13.2:
#   rustup toolchain install nightly --profile minimal
#   cargo install cargo-fuzz --version 0.13.2 --locked
#
#   scripts/fuzz.sh smoke                    every target for 10 000 iterations (PR smoke budget)
#   scripts/fuzz.sh run <target> [seconds]   one target for a time budget (default 300 s, nightly CI)
#   scripts/fuzz.sh list                     print the target names
#
# The fuzz crate lives in fuzz/ with its own workspace and Cargo.lock (not part of the main
# workspace). A crash exits non-zero and prints the reproducer path under fuzz/artifacts/.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
FUZZ_DIR="$ROOT/fuzz"
SMOKE_RUNS=10000

targets() {
  (cd "$ROOT" && cargo +nightly fuzz list --fuzz-dir "$FUZZ_DIR")
}

# run_target <target> <libFuzzer args...>
run_target() {
  local target=$1 log status
  shift
  mkdir -p "$FUZZ_DIR/artifacts/$target"
  log=$(mktemp)
  echo "==> fuzz $target $*"
  set +e
  (cd "$ROOT" && cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- "$@") 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  set -e
  if ((status != 0)); then
    echo "FUZZ FAILURE: target $target exited with status $status" >&2
    local artifacts
    artifacts=$(grep -oE "artifact_prefix='[^']*'; Test unit written to [^ ]+" "$log" | sed 's/.*written to //' || true)
    if [[ -n $artifacts ]]; then
      echo "reproducer: $artifacts" >&2
      echo "replay with: cargo +nightly fuzz run --fuzz-dir fuzz $target $artifacts" >&2
    else
      echo "no crash artifact was written (build or setup failure?); see the output above" >&2
    fi
    rm -f "$log"
    return "$status"
  fi
  rm -f "$log"
}

smoke() {
  local t failed=0
  local list
  list=$(targets)
  for t in $list; do
    run_target "$t" "-runs=$SMOKE_RUNS" || failed=1
  done
  if ((failed != 0)); then
    echo "fuzz smoke FAILED" >&2
    return 1
  fi
  echo "fuzz smoke OK ($(wc -w <<<"$list") targets x $SMOKE_RUNS runs)"
}

run_one() {
  local target=${1:?usage: $0 run <target> [seconds]} seconds=${2:-300}
  if ! targets | grep -qx -- "$target"; then
    echo "unknown fuzz target: $target (known: $(targets | tr '\n' ' '))" >&2
    return 64
  fi
  if ! [[ $seconds =~ ^[0-9]+$ ]] || ((seconds == 0)); then
    echo "seconds must be a positive integer, got: $seconds" >&2
    return 64
  fi
  run_target "$target" "-max_total_time=$seconds"
}

case "${1:-}" in
  smoke) smoke ;;
  run) shift; run_one "$@" ;;
  list) targets ;;
  *) echo "usage: $0 smoke | run <target> [seconds] | list" >&2; exit 64 ;;
esac
