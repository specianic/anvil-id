#!/usr/bin/env bash
# scripts/check-release-graph.sh: SEC-06, release builds contain no test-only code.
#
#   scripts/check-release-graph.sh              check the workspace, exit non-zero on any violation
#   scripts/check-release-graph.sh --self-test  prove the gate rejects a test crate in the anvilid
#                                               dependency graph and a test-only item in production
#                                               source, and accepts the unmodified workspace
#
# Check 1 (dependency graph): the crates reachable from anvilid over normal+build edges, on every
# target, must not include a test crate, nor anvil-storage (the storage contract suite is a
# dev-dependency only). Dev-dependencies are ignored by construction (`-e normal,build`).
#
# Check 2 (source): production source (crates/*/src, minus #[cfg(test)] modules) must not contain
# test-only cfg branches or test hooks:
#   - `#[cfg(test)]` on anything but a `mod` (inline block or file module);
#   - `cfg(feature = "test...")`, `cfg(any(test`, `cfg(all(test`, `cfg(not(test`;
#   - the markers ANVILID_TEST, CapturingTransport, TestClock, allow_insecure_test.
# Code inside a `#[cfg(test)] mod name { ... }` block (closed by a `}` at the block's own
# indentation, as rustfmt lays it out) and files of `#[cfg(test)] mod name;` are skipped; tests/
# directories are never scanned.
#
# Every finding prints one `RELEASE GRAPH VIOLATION:` line.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${CHECK_RELEASE_GRAPH_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}

# Crates that exist only to test. None may reach the release binary.
FORBIDDEN_CRATES=(wiremock testcontainers testcontainers-modules proptest insta tempfile axum-test anvil-storage)

fail=0

violation() {
  echo "RELEASE GRAPH VIOLATION: $*"
  fail=1
}

# --- check 1: dependency graph ---------------------------------------------------------------
check_graph() {
  local all bad
  all=$( (cd "$ROOT" && cargo tree --locked -q -p anvilid -e normal,build --target all --prefix none --format '{p}') |
    awk '{print $1}' | sort -u)
  if [[ -z $all ]]; then
    violation "cargo tree returned no dependency graph for anvilid"
    return
  fi
  for bad in "${FORBIDDEN_CRATES[@]}"; do
    if grep -qx -- "$bad" <<<"$all"; then
      violation "anvilid depends (directly or transitively, normal/build edge) on test crate $bad"
    fi
  done
}

# --- check 2: production source --------------------------------------------------------------
# Scans one file. Prints `VIOLATION <line> <message>` and `TESTMOD <name>` (a `#[cfg(test)] mod
# name;` whose file must be skipped).
scan_file() {
  awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function indent(s) { match(s, /^[ \t]*/); return substr(s, 1, RLENGTH) }
    # Called for the first non-attribute line after #[cfg(test)].
    function after_cfg_test(line, rest,   name) {
      rest = trim(line)
      if (rest ~ /^(pub(\([a-z]+\))? )?mod [A-Za-z0-9_]+[ \t]*;/) {
        name = rest; sub(/^(pub(\([a-z]+\))? )?mod /, "", name); sub(/[ \t]*;.*$/, "", name)
        print "TESTMOD " name
        return
      }
      if (rest ~ /^(pub(\([a-z]+\))? )?mod [A-Za-z0-9_]+[ \t]*\{/) {
        # Single-line block: nothing to skip.
        if (rest ~ /\}[ \t]*$/ && gsub(/\{/, "{", rest) == gsub(/\}/, "}", rest)) return
        skip = indent(line) "}"
        skipping = 1
        return
      }
      print "VIOLATION " NR " #[cfg(test)] on a non-module item: " rest
    }
    function markers(line, t) {
      t = line
      if (t ~ /cfg\(feature *= *"test/)   print "VIOLATION " NR " test feature cfg: " trim(t)
      if (t ~ /cfg\((any|all|not)\(test/) print "VIOLATION " NR " test cfg branch: " trim(t)
      if (t ~ /ANVILID_TEST/)             print "VIOLATION " NR " test hook marker ANVILID_TEST"
      if (t ~ /CapturingTransport/)       print "VIOLATION " NR " test double CapturingTransport"
      if (t ~ /TestClock/)                print "VIOLATION " NR " test double TestClock"
      if (t ~ /allow_insecure_test/)      print "VIOLATION " NR " test hook allow_insecure_test"
    }
    {
      line = $0
      if (skipping) {
        if (line == skip || (line ~ /^[ \t]*\}[ \t]*$/ && indent(line) "}" == skip && trim(line) == "}")) skipping = 0
        next
      }
      if (pending) {
        if (trim(line) ~ /^#\[/ || trim(line) ~ /^\/\//) next
        pending = 0
        after_cfg_test(line)
        next
      }
      t = trim(line)
      if (t ~ /^#\[cfg\(test\)\]/) {
        rest = t; sub(/^#\[cfg\(test\)\][ \t]*/, "", rest)
        if (rest == "") { pending = 1; next }
        after_cfg_test(indent(line) rest)
        next
      }
      markers(line)
    }
    END { if (skipping) print "VIOLATION " NR " unterminated #[cfg(test)] module (expected a closing brace at its indentation)" }
  ' "$1"
}

# Directory holding the child modules of file $1 (`foo.rs` -> `foo/`, `mod.rs`/`lib.rs`/`main.rs` -> `.`).
child_dir() {
  case "$(basename "$1")" in
    mod.rs | lib.rs | main.rs) dirname "$1" ;;
    *) echo "${1%.rs}" ;;
  esac
}

check_source() {
  local files f rel out kind rest lineno msg
  local -a skipped=()
  mapfile -t files < <(cd "$ROOT" && find crates/*/src -type f -name '*.rs' | sort)
  if ((${#files[@]} == 0)); then
    violation "no production source found under crates/*/src"
    return
  fi
  # Pass 1: collect file modules declared under #[cfg(test)].
  for f in "${files[@]}"; do
    while read -r kind rest; do
      [[ $kind == TESTMOD ]] || continue
      skipped+=("$(child_dir "$f")/$rest.rs" "$(child_dir "$f")/$rest/")
    done < <(scan_file "$ROOT/$f")
  done
  # Pass 2: report violations outside skipped files.
  for f in "${files[@]}"; do
    local skip=0 s
    for s in "${skipped[@]+"${skipped[@]}"}"; do
      if [[ $f == "$s" || ($s == */ && $f == "$s"*) ]]; then
        skip=1
        break
      fi
    done
    ((skip == 0)) || continue
    while read -r kind lineno msg; do
      [[ $kind == VIOLATION ]] || continue
      rel=$f
      violation "$rel:$lineno: $msg"
    done < <(scan_file "$ROOT/$f")
  done
}

check() {
  check_graph
  check_source
  if ((fail == 0)); then
    echo "release graph OK (no test crates reachable from anvilid, no test-only code in crates/*/src)"
  fi
  return "$fail"
}

# --- self-test -------------------------------------------------------------------------------
# Copies the workspace (minus target/, .git/ and local tooling dirs) into a temp dir, applies one
# mutation per case, runs this gate against the copy and asserts the outcome. Only
# `RELEASE GRAPH VIOLATION:` output counts as a rejection (not e.g. a cargo resolution error).
self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064 # expand $tmp now
  trap "rm -rf '$tmp'" EXIT

  # Every registry crate in the lock must be cached before going offline.
  (cd "$ROOT" && cargo fetch --locked -q) >"$tmp/fetch.log" 2>&1 || {
    cat "$tmp/fetch.log"
    return 1
  }

  mkdir -p "$tmp/pristine"
  tar -C "$ROOT" --exclude=./target --exclude=./.git --exclude=./suite --exclude=./conformance-results \
    --exclude=./fuzz --exclude=./node_modules --exclude=./tests/e2e/node_modules -cf - . | tar -C "$tmp/pristine" -xf -

  local failures=0
  # run_case <name> <expected: pass|fail> <mutation function or "">
  run_case() {
    local name=$1 expected=$2 mutate=$3
    rm -rf "$tmp/ws"
    cp -a "$tmp/pristine" "$tmp/ws"
    if [[ -n $mutate ]] && ! (cd "$tmp/ws" && "$mutate") >"$tmp/mutate.log" 2>&1; then
      echo "FAIL $name: could not apply mutation ($mutate)"
      sed 's/^/    /' "$tmp/mutate.log"
      failures=$((failures + 1))
      return
    fi
    local actual=pass
    CHECK_RELEASE_GRAPH_ROOT="$tmp/ws" CARGO_NET_OFFLINE=true "$SCRIPT_DIR/check-release-graph.sh" >"$tmp/check.log" 2>&1 || actual=fail
    if [[ $actual == fail ]] && ! grep -q '^RELEASE GRAPH VIOLATION: ' "$tmp/check.log"; then
      actual=error
    fi
    if [[ $actual == "$expected" ]]; then
      echo "PASS $name (gate: $actual, expected: $expected)"
      grep '^RELEASE GRAPH VIOLATION: ' "$tmp/check.log" | sed 's/^/    /' || true
    else
      echo "FAIL $name (gate: $actual, expected: $expected)"
      sed 's/^/    /' "$tmp/check.log"
      failures=$((failures + 1))
    fi
  }

  add_wiremock() { cargo add --offline -q -p anvilid wiremock; }
  add_dev_wiremock() { cargo add --offline -q -p anvilid wiremock --dev; }
  add_backdoor() { printf '\n#[cfg(test)] pub fn backdoor() {}\n' >>crates/anvilid/src/main.rs; }
  add_marker() { printf '\npub struct TestClock;\n' >>crates/anvil-core/src/clock.rs; }
  add_test_module() { printf '\n#[cfg(test)]\nmod release_graph_probe {\n    struct TestClock;\n}\n' >>crates/anvilid/src/main.rs; }

  run_case "0: unmodified workspace" pass ""
  run_case "A: anvilid gains normal dep wiremock" fail add_wiremock
  run_case "B: #[cfg(test)] pub fn appended to anvilid main.rs" fail add_backdoor
  run_case "C: anvilid gains dev dep wiremock" pass add_dev_wiremock
  run_case "D: test double inside a #[cfg(test)] module" pass add_test_module
  run_case "E: test double TestClock in production source" fail add_marker

  if ((failures > 0)); then
    echo "release graph self-test FAILED ($failures case(s))"
    return 1
  fi
  echo "release graph self-test OK"
}

case "${1:-}" in
  "") check ;;
  --self-test) self_test ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 64 ;;
esac
