---
phase: 02-release-0-1-first-login
plan: 21
subsystem: quality-gates
tags: [qual-01, security-tests, ci, docs, fuzz, conformance, phase-gate]
requires:
  - phase: 02-17
    provides: fuzz targets + release-graph gate
  - phase: 02-19
    provides: conformance Basic + Config OP over TLS
  - phase: 02-20
    provides: container image, QUAL-04 script, Playwright e2e
provides:
  - "scripts/check-security-tests.sh: QUAL-01 control -> test map (107 pairs) with --self-test"
  - "`just ci` = fmt-check lint deny deps test test-pg release-graph security-tests"
  - "ARCHITECTURE §8.1/§10/§11/§13/§16 synced with the built 0.1 system"
  - "All five workflows green on GitHub for main @ f16e726"
affects: [phase-2-verification, phase-3]
tech-stack:
  added: []
  patterns:
    - "Security-test map checks `fn` exists in the named file AND the owning test binary lists it (`cargo test --workspace --color never -- --list`), so a lost #[test] attribute is caught"
key-files:
  created:
    - scripts/check-security-tests.sh
  modified:
    - justfile
    - .github/workflows/ci.yml
    - docs/ARCHITECTURE.md
    - .planning/REQUIREMENTS.md
    - scripts/measure-idle.sh
    - scripts/fuzz.sh
    - Cargo.toml
    - fuzz/Cargo.toml
    - crates/anvil-jose/src/jws.rs
key-decisions:
  - "Security-test map lives in the script as `control|file|fn` rows; owning binary derived from the path (tests/<t>.rs, src/** unit tests, anvil-storage contract -> anvil-storage-sqlite contract test). Rate limiting, SSRF guard and SEC-06 are documented as intentionally unmapped in 0.1"
  - "serde_json float_roundtrip enabled workspace-wide (fuzz finding: f64 claims did not round-trip through sign + verify)"
  - "scripts/fuzz.sh pins --target to the nightly host triple (prebuilt cargo-fuzz defaults to musl, which ASan cannot link)"
  - "PRD unchanged: the only requirement-wording deviation (OIDC-1, C1) was already applied in 02-19"
  - "REQUIREMENTS checkboxes not ticked here (left to phase verification); traceability note added for the OIDC-14 subset (C2) and the OIDC-01 amendment"
duration: 80min
completed: 2026-11-25
---

# Phase 2 Plan 21: Phase gate Summary

**QUAL-01 control→test map (107 control/test pairs, self-tested) wired into `just ci` and CI, docs synced with the built 0.1 system, and every workflow (ci, conformance, e2e, release-build, fuzz) green on GitHub for main @ f16e726. Getting there took three CI-only fixes and one real fuzz finding.**

## Performance

- Duration: about 80 min (most of it waiting on CI)
- Tasks: 3 (Task 2's push checkpoint was approved in advance by the orchestrator)
- Files: 1 created, 9 modified

## Accomplishments

- `scripts/check-security-tests.sh` maps every in-scope ARCHITECTURE §11 / RFC 9700 control to `file::test_fn` (107 rows covering redirect, PKCE + downgrade, code binding/reuse/concurrency, refresh rotation/reuse, response/grant types, client auth, private_key_jwt, JWS alg/typ confusion, RFC 9207 iss, ID token claims, bearer handling, 303, CSP/frame-ancestors/Referrer-Policy/HSTS, CSRF, cookies, secrets at rest on both backends, Debug redaction, tenant isolation, enumeration, Argon2 pool/dummy hash, setup token, admin scopes, no-store). It checks that each fn exists in the named file and is registered in the owning test binary. `--self-test` renames a fn in a scratch copy and expects a failure, checks that a non-test helper is rejected, and checks that the real map passes.
- `just ci` now runs `fmt-check lint deny deps test test-pg release-graph security-tests`, and new `just security-tests-selftest` runs the self-test. The CI `tests (sqlite)` job runs the map and its self-test after `just test`.
- ARCHITECTURE: §8.1 (how anvil-jose uses `jsonwebtoken::crypto::{sign,verify}`, PKCS#8→PEM, RS256-only signing in 0.1), §10.1 (both discovery path forms, `/authorize/continue`, the 0.1 surface and advertised metadata), §10.2 (0.1 UI pages, `/setup`), §10.3 (installation-level admin API, scopes as built), §11 (CSRF Fetch-Metadata rules 1–3, exemptions), §13 (config keys, secrets env/file only, `--insecure-http`, KEK policy incl. Postgres, `serve.lock`, logs to stderr, 0.1 CLI commands), §16 (`ANVILID_TEST_DB` matrix, security-test map).
- REQUIREMENTS traceability: OIDC-14 row notes the Phase 2 subset, plus a "Partial pull-ins" note (OIDC-14 subset per C2, OIDC-01 amendment per C1).

## CI evidence (main @ f16e726)

| Workflow | Result | Run |
|---|---|---|
| ci | success | https://github.com/specianic/anvil-id/actions/runs/45547127756 |
| conformance | success | https://github.com/specianic/anvil-id/actions/runs/45547127850 |
| e2e | success | https://github.com/specianic/anvil-id/actions/runs/45547127808 |
| release-build | success | https://github.com/specianic/anvil-id/actions/runs/45547127890 |
| fuzz (workflow_dispatch, 4 targets x 300 s) | success | https://github.com/specianic/anvil-id/actions/runs/45547147420 |

- **Conformance:** Basic OP + Config OP: 31 PASSED, 4 REVIEW (screenshot modules), 1 SKIPPED (the reviewed request-object skip), 0 expected failures, "All tests ran to completion".
- **Handshake interruptions:** "Remote host terminated the handshake" appeared **0 times** in all three conformance runs on GitHub's Linux runners (837596a, 145a211, f16e726, each 36/36 modules completed, none INTERRUPTED). This supports the 02-19 diagnosis that the interruptions are a Docker Desktop/WSL2 environment issue, not an anvilid defect. No expected-failure entries were added.
- **Container image:** 19 274 086 bytes (18.4 MiB), limit 50 MiB, runs as nonroot, smoke test passed.
- **QUAL-04:** sqlite 4 s, postgres 10 s (limit 120 s).
- **Playwright e2e:** 3/3 passed on sqlite and on postgres.
- **Static musl binaries (idle):** x86_64 16.12 MiB, 44.4 MB RSS. aarch64 13.04 MiB, 41.7 MB RSS.
- **Local:** `just ci` passed (1091 tests across `test` + `test-pg`, 0 failed), security-tests + self-test OK, `scripts/sqlx.sh check` OK.

## Task Commits

1. **Task 1: security-test map, `just ci` gates, docs/traceability:** `837596a` (feat)
2. **Task 2: push approval:** pre-resolved by the orchestrator (push to origin/main authorized)
3. **Task 3: push and get CI green:** `145a211` (fix), `32c0384` (fix), `f16e726` (fix)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Security-test map parsed no tests on CI**
- **Found during:** Task 3 (ci run 45544241436)
- **Issue:** CI sets `CARGO_TERM_COLOR=always`. ANSI codes in cargo's `Running` lines stopped the awk parser from matching them, so the gate reported "cargo test --list returned no tests" (it failed closed, as intended).
- **Fix:** `cargo test ... --color never -- --list`. Reproduced locally with `CARGO_TERM_COLOR=always`.
- **Files:** scripts/check-security-tests.sh. **Commit:** 145a211

**2. [Rule 1 - Bug] release-build idle measurement used removed Phase 1 flags**
- **Found during:** Task 3 (release-build was already failing on main before this plan, run 45538155407)
- **Issue:** `scripts/measure-idle.sh` started `anvilid serve --issuer … --database-url …`. Those flags were removed in 02-18.
- **Fix:** `--public-url --data-dir --breach-check off`. Verified locally.
- **Files:** scripts/measure-idle.sh. **Commit:** 145a211

**3. [Rule 3 - Blocking] Fuzz targets could not build on CI**
- **Found during:** Task 3 (fuzz run 45544285873)
- **Issue:** The prebuilt cargo-fuzz installed by taiki-e/install-action defaults `--target` to its own musl triple. ASan then fails with "sanitizer is incompatible with statically linked libc".
- **Fix:** `scripts/fuzz.sh` passes `--target "$(rustc +nightly -vV | host)"`.
- **Files:** scripts/fuzz.sh. **Commit:** 32c0384

**4. [Rule 1 - Bug] Fuzz finding: float claims did not round-trip through sign + verify**
- **Found during:** Task 3 (first real nightly run of jwt_decode on GitHub, run 45545634507)
- **Issue:** The JSON number `24442` followed by 48 `2`s came back as 2.444222222222222e52 instead of 2.4442222222222216e52. serde_json's default float parser is not correctly rounded. Not a security issue: protocol claims are integers or strings. But the harness invariant "verify returns exactly the signed claims" was broken.
- **Fix:** enabled serde_json `float_roundtrip` (workspace + fuzz crate; lockfiles unchanged) and added the input as the unit test `jws::tests::float_claims_round_trip_exactly`, which fails without the feature and passes with it. Replayed the crash artifact locally, ran jwt_decode clean for 60 s locally and for 300 s in CI.
- **Files:** Cargo.toml, fuzz/Cargo.toml, crates/anvil-jose/src/jws.rs. **Commit:** f16e726

### Orchestrator overrides

- The plan asked for a branch + PR. The orchestrator authorized pushing directly to `main`, so no PR was opened.
- The plan asked to mark Phase 2 IDs Complete in REQUIREMENTS.md. Per the orchestrator, checkboxes and Complete statuses are left to phase verification. Only the traceability notes were added.
- STATE.md's Current Position block was rewritten by hand in the bold-field format gsd-tools parses (`**Current Phase:**`, `**Current Plan:**`, `**Total Plans in Phase:**`, `**Status:**`, `**Last Activity:**`, `**Progress:**`). This was inferred from `stateExtractField` in gsd-tools' state.cjs.

## Issues Encountered

- Before this plan, `e2e` and `release-build` were already red on main (5b88fdc and earlier). The e2e failures were missing scripts, fixed by the 02-20 commits included in this push. The release-build failure is fix 2 above.

## Notes for verification / Phase 3

- `just ci` now needs Docker (test-pg). The security-test map must gain rows when Phase 3 adds controls (rate limiting, SSRF guard once jwks_uri fetching exists).
- The fuzz `smoke` job runs only on PRs. Direct pushes to main don't run fuzz unless dispatched; the nightly schedule covers it.

## Self-Check: PASSED
