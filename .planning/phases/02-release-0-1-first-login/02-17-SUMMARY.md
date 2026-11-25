---
phase: 02-release-0-1-first-login
plan: 17
subsystem: security-gates
tags: [fuzzing, cargo-fuzz, libfuzzer, release-graph, sec-06, sec-07]
requires:
  - phase: 02-01
    provides: justfile recipes (fuzz-smoke, fuzz, release-graph), fuzz.yml and ci.yml release-graph job
  - phase: 02-07
    provides: anvil-core authorize_request parse_raw/validate, redirect_matches
  - phase: 02-08
    provides: client_auth parse_basic, anvil-jose client assertion verification
provides:
  - fuzz/ cargo-fuzz crate (own workspace + Cargo.lock) with jwt_decode, client_assertion, authorize_parse, redirect_match
  - scripts/fuzz.sh (smoke | run <target> [seconds] | list)
  - scripts/check-release-graph.sh (SEC-06 gate) with --self-test
affects: [ci, fuzz.yml, every later phase touching parsers]
tech-stack:
  added: [libfuzzer-sys 0.4.13 (fuzz crate only), arbitrary 1.5 (fuzz crate only), cargo-fuzz 0.13.2 (tool), nightly toolchain (tool)]
  patterns: [model-based fuzz oracle for claim validation, security-invariant assertions in fuzz targets, copy-and-mutate self-test for gates]
key-files:
  created:
    - fuzz/Cargo.toml
    - fuzz/Cargo.lock
    - fuzz/.gitignore
    - fuzz/fuzz_targets/jwt_decode.rs
    - fuzz/fuzz_targets/client_assertion.rs
    - fuzz/fuzz_targets/authorize_parse.rs
    - fuzz/fuzz_targets/redirect_match.rs
    - scripts/fuzz.sh
    - scripts/check-release-graph.sh
  modified: []
key-decisions:
  - "Fuzz targets assert security invariants, not only absence of panics: client assertions are checked against an independent RFC 7523 model, authorize errors/successes only redirect to URIs that redirect_matches the registered list, public clients always carry PKCE"
  - "fuzz/Cargo.lock seeded from the main Cargo.lock so shared crates resolve to the same versions; main Cargo.lock untouched"
  - "Release-graph source check skips #[cfg(test)] mod blocks by rustfmt indentation (closing brace at the block's indent) and #[cfg(test)] mod name; files; also flags cfg(all(test / cfg(not(test"
  - "http-body-util is NOT on the forbidden list: it is a legitimate normal dependency of axum in the anvilid graph"
requirements-completed: []
duration: 30min
completed: 2026-11-25
---

# Phase 2 Plan 17: Fuzzing and Release-Graph Gate Summary

**Four cargo-fuzz targets (JWS, client assertion + Basic, authorize request, redirect matching) with invariant/model oracles, plus a SEC-06 gate proving no test crates or test-only code reach the anvilid release graph.**

## Performance

- **Duration:** about 30 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files created:** 9

## Accomplishments

- `fuzz/` crate outside the main workspace (own `[workspace]` table and Cargo.lock), path-depending on anvil-jose and anvil-core.
- `jwt_decode`: arbitrary tokens through `decode_header`/`verify_jwt` (no panic); arbitrary JSON objects signed with a fixed RS256 key must verify and round-trip the claims exactly, and be rejected when RS256 is not allowed.
- `client_assertion`: structured claims (iss/sub/aud/exp/nbf/iat/jti/typ choices) signed with the client key; the `verify_client_assertion` verdict must equal an independent model of the RFC 7523 rules. Also fuzzes `parse_basic` on raw headers and on well-formed headers built from arbitrary credentials (must round-trip).
- `authorize_parse`: `parse_raw` then `validate` against no client (always an error page), a confidential web client and a public native client with `require_pkce = false` (PKCE still required). Every success or error redirect targets a registered URI.
- `redirect_match`: web clients exact-match only; native extra matches are loopback IP literals only.
- `scripts/fuzz.sh smoke` runs all four targets for 10 000 iterations each (passes in a few seconds); `run <target> <seconds>` for the nightly matrix. Each target also ran 60 s locally without findings (107k to 2.7M executions).
- `scripts/check-release-graph.sh`: graph check (cargo tree, normal+build edges, all targets) and source check; `--self-test` with six cases (pristine pass, normal wiremock dep fail, appended `#[cfg(test)] pub fn` fail, dev wiremock dep pass, TestClock inside a test module pass, TestClock in production source fail).

## Task Commits

1. **Task 1: Fuzz crate, four targets, scripts/fuzz.sh** - `965bff4` (feat)
2. **Task 2: SEC-06 release-graph gate with self-test** - `914fb84` (feat)

## Files Created/Modified

- `fuzz/Cargo.toml`, `fuzz/Cargo.lock`, `fuzz/.gitignore` - standalone fuzz crate
- `fuzz/fuzz_targets/{jwt_decode,client_assertion,authorize_parse,redirect_match}.rs` - targets
- `scripts/fuzz.sh` - smoke/run entry points behind `just fuzz-smoke` and `just fuzz`
- `scripts/check-release-graph.sh` - SEC-06 gate behind `just release-graph`

## Decisions Made

See key-decisions in the frontmatter.

## Deviations from Plan

### Additions (within scope)

**1. Extra self-test cases**
- Added case D (test double inside a `#[cfg(test)]` module is accepted) and case E (TestClock in production source is rejected) besides the two required rejections, so the module-skipping and marker checks are proven too.

**2. Extra test-cfg patterns**
- The source check also flags `cfg(all(test` and `cfg(not(test`, which are test-dependent branches of the same kind as `cfg(any(test`.

**3. must_haves listed "http-body-util test helpers" as forbidden**
- http-body-util is a normal dependency of axum and is legitimately in the anvilid graph, so it can't be forbidden by crate name. The task action list (which omits it) was followed. No test-helper crate built on it is present.

Otherwise the plan was executed as written. The real tree passed the gate with no findings, so no other plan's code needed fixing.

## Issues Encountered

- None. The nightly toolchain and cargo-fuzz 0.13.2 were installed locally without problems.

## Next Phase Readiness

- The fuzz.yml (PR smoke + nightly matrix) and ci.yml release-graph jobs from 02-01 now have working scripts behind them.
- If a new parser or a test double is added, it can be added to the fuzz targets and to the marker list in check-release-graph.sh.

## Self-Check: PASSED
