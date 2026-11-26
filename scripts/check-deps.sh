#!/usr/bin/env bash
# scripts/check-deps.sh: FND-02 crate dependency rules (ARCHITECTURE.md §4).
#
#   scripts/check-deps.sh              check the workspace, exit non-zero on any violation
#   scripts/check-deps.sh --self-test  prove the checker rejects forbidden NORMAL dependencies,
#                                      accepts dev-dependencies, rejects base64 outside
#                                      anvil-jose and a second locked aws-lc version
#
# Also enforces "one implementation per concern" for base64 (CLAUDE.md): only anvil-jose may
# depend on the base64 crate (any dependency kind), and no Rust source under crates/ outside
# crates/anvil-jose/src may call `base64::` or carry a hand-rolled base64 alphabet. Everything
# else uses anvil_jose::encoding::{b64url, b64url_decode, b64std, b64std_decode}.
#
# One aws-lc (ARCHITECTURE.md §4, 06-01): exactly one aws-lc-rs and one aws-lc-sys version in
# Cargo.lock (distinct `version` values of the `[[package]]` entries with that name; zero or more
# than one is a violation). A version listed twice by `cargo tree -d` because of a host/target
# feature split is not a duplicate, so the rule reads the lockfile instead of `cargo tree`.
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

  # First: a lockfile that no longer matches the manifests makes the `cargo tree --locked` calls
  # below exit (set -e), and this rule's violation must already be in the output by then.
  check_single_aws_lc

  # anvil-core: pure domain + ports, no I/O.
  # psl + idna: domain normalisation and public-suffix data (policy::home_realm); pure, no I/O.
  allow_direct anvil-core anvil-jose secrecy serde serde_json time uuid url thiserror async-trait psl idna
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

  check_base64

  if ((fail == 0)); then
    echo "dependency rules OK"
  fi
  return "$fail"
}

# One aws-lc: exactly one locked version each of aws-lc-rs and aws-lc-sys.
check_single_aws_lc() {
  local lock="$ROOT/Cargo.lock" crate versions count
  if [[ ! -f $lock ]]; then
    echo "RULE VIOLATION: no Cargo.lock at ${lock}"
    fail=1
    return
  fi
  for crate in aws-lc-rs aws-lc-sys; do
    # name/version of each [[package]] block; a block ends at the next table header.
    versions=$(awk -v want="$crate" '
      /^\[/ { name = ""; inpkg = ($0 == "[[package]]"); next }
      inpkg && /^name = "/ { name = $3; gsub(/"/, "", name); next }
      inpkg && /^version = "/ && name == want { v = $3; gsub(/"/, "", v); print v }
    ' "$lock" | sort -uV | paste -sd' ' -)
    if [[ -z $versions ]]; then
      count=0
    else
      count=$(wc -w <<<"$versions")
    fi
    if ((count != 1)); then
      echo "RULE VIOLATION: Cargo.lock has $count versions of $crate (${versions:-none})"
      fail=1
    fi
  done
}

# One base64 implementation: anvil_jose::encoding.
check_base64() {
  local manifest hits
  # Any dependency kind (normal, dev, build, target-specific) on the base64 crate.
  for manifest in "$ROOT"/crates/*/Cargo.toml; do
    [[ $manifest == "$ROOT/crates/anvil-jose/Cargo.toml" ]] && continue
    if grep -Eq '^[[:space:]]*base64[[:space:]]*(=|\.)' "$manifest"; then
      echo "RULE VIOLATION: ${manifest#"$ROOT/"} depends on base64 (use anvil_jose::encoding)"
      fail=1
    fi
  done
  # Direct calls into the crate or a hand-rolled alphabet table (standard or URL-safe).
  hits=$(cd "$ROOT" && grep -rnE --include='*.rs' \
    -e 'base64::' -e 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' \
    crates | grep -v '^crates/anvil-jose/src/' || true)
  if [[ -n $hits ]]; then
    while IFS= read -r line; do
      echo "RULE VIOLATION: base64 outside anvil-jose (use anvil_jose::encoding): $line"
    done <<<"$hits"
    fail=1
  fi
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
  # or   <name> <expected> --append <file> <text>  (appends a line of source to <file>)
  run_case() {
    local name=$1 expected=$2
    shift 2
    rm -rf "$tmp/ws"
    cp -a "$tmp/pristine" "$tmp/ws"
    if [[ ${1:-} == --append ]]; then
      if [[ ! -f "$tmp/ws/$2" ]]; then
        echo "FAIL $name: could not apply mutation (no file $2)"
        failures=$((failures + 1))
        return
      fi
      printf '%s\n' "$3" >>"$tmp/ws/$2"
    elif (($# > 0)) && ! (cd "$tmp/ws" && cargo add --offline -q "$@") >"$tmp/add.log" 2>&1; then
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
  run_case "E: anvil-web gains dev dep base64" fail \
    -p anvil-web base64 --dev
  run_case "F: anvil-web source calls base64::" fail \
    --append crates/anvil-web/src/lib.rs \
    'fn _b(x: &[u8]) -> String { base64::Engine::encode(&base64::engine::general_purpose::STANDARD, x) }'
  run_case "G: anvil-mail test code hand-rolls a base64 alphabet" fail \
    --append crates/anvil-mail/tests/templates.rs \
    'const _T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";'
  run_case "H: base64:: inside anvil-jose/src is allowed" pass \
    --append crates/anvil-jose/src/encoding.rs \
    'const _E: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;'
  run_case "I: Cargo.lock gains a second aws-lc-sys version" fail \
    --append Cargo.lock $'\n[[package]]\nname = "aws-lc-sys"\nversion = "0.99.0"'

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
