#!/usr/bin/env bash
# scripts/check-deps.sh: FND-02 crate dependency rules (ARCHITECTURE.md §4).
#
#   scripts/check-deps.sh              check the workspace, exit non-zero on any violation
#   scripts/check-deps.sh --self-test  prove the checker rejects forbidden NORMAL dependencies
#                                      and accepts dev-dependencies
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${CHECK_DEPS_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}

# --- checker ---------------------------------------------------------------------------------
# Per-package resolution (`cargo tree -p`), never unified `cargo metadata`: workspace feature
# unification would attribute other crates' features and deps to the crate under test.
# Only normal + build edges are followed, so dev-dependencies are ignored by construction:
# the rules apply to NORMAL dependencies only (tests may use concrete backends).

# All crates reachable from $1 over normal+build edges, on every target.
deps_of() {
  (cd "$ROOT" && cargo tree --locked -q -p "$1" -e normal,build --target all --prefix none --format '{p}') |
    awk '{print $1}' | sort -u
}

# Direct normal dependencies of $1, on every target.
direct_of() {
  (cd "$ROOT" && cargo tree --locked -q -p "$1" -e normal --target all --depth 1 --prefix none --format '{p}') |
    awk 'NR>1{print $1}' | sort -u
}

fail=0

# forbid <crate> <forbidden...>: none of the forbidden crates may be reachable from <crate>.
forbid() {
  local crate=$1 all bad
  shift
  all=$(deps_of "$crate")
  for bad in "$@"; do
    if grep -qx -- "$bad" <<<"$all"; then
      echo "RULE VIOLATION: $crate depends (directly or transitively) on $bad"
      fail=1
    fi
  done
}

# allow_direct <crate> <allowed...>: every direct normal dependency of <crate> must be listed.
allow_direct() {
  local crate=$1 direct d
  shift
  direct=$(direct_of "$crate")
  for d in $direct; do
    if ! printf '%s\n' "$@" | grep -qx -- "$d"; then
      echo "RULE VIOLATION: $crate has non-allowlisted direct dependency $d"
      fail=1
    fi
  done
}

check() {
  local io=(tokio mio hyper axum tower reqwest sqlx sqlx-core libsqlite3-sys tokio-postgres)
  local store_impls=(anvil-storage-sqlite anvil-storage-postgres)

  # anvil-core: pure domain + ports, no I/O.
  allow_direct anvil-core anvil-jose serde serde_json time uuid url thiserror async-trait
  forbid anvil-core "${io[@]}" anvil-storage "${store_impls[@]}" anvil-web anvil-cache anvil-mail

  # anvil-storage (contract suite) stays driver-free.
  forbid anvil-storage sqlx sqlx-core "${store_impls[@]}" anvil-web

  # Backends never see the web layer or each other.
  forbid anvil-storage-sqlite anvil-web anvil-storage-postgres
  forbid anvil-storage-postgres anvil-web anvil-storage-sqlite

  # Only anvilid knows concrete storage implementations.
  local c
  for c in anvil-web anvil-jose anvil-cache anvil-mail; do
    forbid "$c" "${store_impls[@]}" sqlx sqlx-core
  done

  if ((fail == 0)); then
    echo "dependency rules OK"
  fi
  return "$fail"
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
  (cd "$ROOT" && cargo fetch --locked -q) >"$tmp/fetch.log" 2>&1 || {
    cat "$tmp/fetch.log"
    return 1
  }

  mkdir -p "$tmp/pristine" "$tmp/ws"
  tar -C "$ROOT" --exclude=./target --exclude=./.git --exclude=./suite --exclude=./conformance-results -cf - . | tar -C "$tmp/pristine" -xf -

  local failures=0
  # case <name> <expected: pass|fail> <cargo add args...>
  run_case() {
    local name=$1 expected=$2
    shift 2
    rm -rf "$tmp/ws"
    cp -a "$tmp/pristine" "$tmp/ws"
    if (($# > 0)) && ! (cd "$tmp/ws" && cargo add --offline -q "$@") >"$tmp/add.log" 2>&1; then
      echo "FAIL $name: could not apply mutation (cargo add $*)"
      sed 's/^/    /' "$tmp/add.log"
      failures=$((failures + 1))
      return
    fi
    local actual=pass
    CHECK_DEPS_ROOT="$tmp/ws" CARGO_NET_OFFLINE=true "$SCRIPT_DIR/check-deps.sh" >"$tmp/check.log" 2>&1 || actual=fail
    # A failure only counts if it is a rule violation, not e.g. a cargo resolution error.
    if [[ $actual == fail ]] && ! grep -q '^RULE VIOLATION: ' "$tmp/check.log"; then
      actual=error
    fi
    if [[ $actual == "$expected" ]]; then
      echo "PASS $name (checker: $actual, expected: $expected)"
    else
      echo "FAIL $name (checker: $actual, expected: $expected)"
      sed 's/^/    /' "$tmp/check.log"
      failures=$((failures + 1))
    fi
  }

  run_case "0: unmodified workspace" pass
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
