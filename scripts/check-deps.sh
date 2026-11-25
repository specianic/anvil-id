#!/usr/bin/env bash
# scripts/check-deps.sh: FND-02 crate dependency rules (ARCHITECTURE.md §4).
#
#   scripts/check-deps.sh              check the workspace, exit non-zero on any violation
#   scripts/check-deps.sh --self-test  prove the checker rejects forbidden NORMAL dependencies
#                                      and accepts dev-dependencies
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${CHECK_DEPS_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}

check() {
  echo "dependency rules not implemented" >&2
  return 2
}

# --- self-test -------------------------------------------------------------------------------
# Copies the workspace (minus target/ and .git/) into a temp dir, applies one mutation per case
# with `cargo add --offline`, runs this checker against the copy and asserts the exit status.
# Offline works because every crate involved is already in Cargo.lock.
self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064 # expand $tmp now
  trap "rm -rf '$tmp'" EXIT

  # Make sure every registry crate in the lock is in the local cache before going offline.
  (cd "$ROOT" && cargo fetch --locked -q)

  mkdir -p "$tmp/pristine" "$tmp/ws"
  tar -C "$ROOT" --exclude=./target --exclude=./.git -cf - . | tar -C "$tmp/pristine" -xf -

  local failures=0
  # case <name> <expected: pass|fail> <cargo add args...>
  run_case() {
    local name=$1 expected=$2
    shift 2
    rm -rf "$tmp/ws"
    cp -a "$tmp/pristine" "$tmp/ws"
    if ! (cd "$tmp/ws" && cargo add --offline -q "$@") >"$tmp/add.log" 2>&1; then
      echo "FAIL $name: could not apply mutation (cargo add $*)"
      sed 's/^/    /' "$tmp/add.log"
      failures=$((failures + 1))
      return
    fi
    local actual=pass
    CHECK_DEPS_ROOT="$tmp/ws" CARGO_NET_OFFLINE=true "$SCRIPT_DIR/check-deps.sh" >"$tmp/check.log" 2>&1 || actual=fail
    if [[ $actual == "$expected" ]]; then
      echo "PASS $name (checker: $actual, expected: $expected)"
    else
      echo "FAIL $name (checker: $actual, expected: $expected)"
      sed 's/^/    /' "$tmp/check.log"
      failures=$((failures + 1))
    fi
  }

  run_case "A: anvil-core gains normal dep tokio" fail \
    -p anvil-core tokio
  run_case "B: anvil-web gains normal dep anvil-storage-sqlite" fail \
    -p anvil-web anvil-storage-sqlite --path crates/anvil-storage-sqlite
  run_case "C: anvil-web gains dev dep anvil-storage-sqlite" pass \
    -p anvil-web anvil-storage-sqlite --path crates/anvil-storage-sqlite --dev
  run_case "D: anvil-storage-sqlite gains normal dep anvil-web" fail \
    -p anvil-storage-sqlite anvil-web --path crates/anvil-web

  if ((failures > 0)); then
    echo "dependency checker self-test FAILED ($failures case(s))"
    return 1
  fi
  echo "dependency checker self-test OK"
}

case "${1:-}" in
  "") check ;;
  --self-test) self_test ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 64 ;;
esac
