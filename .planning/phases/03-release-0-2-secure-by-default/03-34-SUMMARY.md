---
phase: 03-release-0-2-secure-by-default
plan: 34
subsystem: security
tags: [base64, one-implementation, ci-guard, tidy-up, gap-closure]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: anvil_jose::encoding strict base64url (03-32), check-deps.sh (Phase 1)
provides:
  - anvil_jose::encoding::{b64std, b64std_decode} (strict standard alphabet)
  - check-deps.sh base64 guard (manifests + sources under crates/) with self-test cases E-H
affects: [anvil-core client_auth, anvil-mail tester, anvil-web captcha, anvil-web tests]
tech-stack:
  added: []
  patterns:
    - "All base64 goes through anvil_jose::encoding; check-deps.sh rejects any other base64 dependency, `base64::` call or alphabet table under crates/"
key-files:
  created: []
  modified:
    - crates/anvil-jose/src/encoding.rs
    - crates/anvil-core/src/service/client_auth.rs
    - crates/anvil-mail/src/tester.rs
    - crates/anvil-web/src/adapters/captcha.rs
    - crates/anvil-web/Cargo.toml
    - crates/anvil-web/tests/{admin_api,flow_passkey,passkey_adapter,security_client_auth,security_setup}.rs
    - crates/anvil-web/tests/token_support/mod.rs
    - scripts/check-deps.sh
    - crates/anvil-cache/Cargo.toml
    - Cargo.toml
    - Cargo.lock
    - crates/anvil-core/src/flow/engine.rs
key-decisions:
  - "b64std_decode accepts fully padded or fully unpadded input only (canonical bits, no partial or excess padding), keeping the Phase 2 Basic-auth decoder's behaviour exactly"
  - "CAPTCHA secret_sealed is now decoded with the strict b64url_decode (the lenient '=' trim is gone); the writer has always used b64url"
  - "The base64 guard covers every crate under crates/ (src and tests, any dependency kind); the separate fuzz workspace is deferred"
requirements-completed: [SEC-04]
duration: 40min
completed: 2026-11-25
---

# Phase 3 Plan 34: Single base64 implementation + tidy-ups Summary

**All base64 in the workspace now goes through `anvil_jose::encoding`, which gains strict standard-alphabet `b64std`/`b64std_decode`. `check-deps.sh` rejects base64 anywhere else in crates/, and three manifest and doc tidy-ups from verification are done.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 18

## Accomplishments

- `b64std` (padded) and `b64std_decode` were added to `anvil_jose::encoding`. The decoder accepts canonical input that is either fully padded or fully unpadded. It rejects the URL alphabet, whitespace, partial or excess padding, padding inside the data and non-zero trailing bits. Tests: RFC 4648 §10 vectors, strictness negatives and a round-trip proptest.
- Call sites moved to the shared code:
  - `client_auth::parse_basic` now uses `b64std_decode`. The hand-rolled `b64_std_decode` is deleted. A new test proves Basic still accepts both padded and unpadded input and rejects non-canonical, URL-alphabet, partially padded and over-padded input with `invalid_client`.
  - The SMTP tester redaction now uses `b64std`. The hand-rolled `fn base64` is deleted, and its RFC vectors moved to anvil-jose.
  - The CAPTCHA `open_secret` now uses `b64url_decode`, without the lenient `=` trim. A test now shows a padded value is rejected as `CaptchaError::Config`.
- `base64` is no longer a dependency of anvil-web. Its integration tests use `anvil_jose::encoding` instead.
- `scripts/check-deps.sh` now runs a base64 check that fails on any of these:
  - a `base64` dependency of any kind in a `crates/*/Cargo.toml` other than anvil-jose
  - a `base64::` call in `*.rs` under crates/ outside `crates/anvil-jose/src`
  - a hand-rolled alphabet table under crates/ outside `crates/anvil-jose/src`

  It runs from `just deps` / `just ci` and in CI. `--self-test` gained cases E–H: a dev dependency, a source call and a test-code alphabet are rejected, and `base64::` inside anvil-jose is allowed. All 9 cases pass.
- Tidy-ups:
  - `tokio` was removed from anvil-cache `[dependencies]` and kept as a dev-dependency.
  - The unused `anvilid` workspace dependency entry was removed.
  - The `FlowEngine::initial` doc and error text now say that Settings and Consent have their own state machines. They no longer say "not implemented".

## Task Commits

1. **Task 1: Single base64 implementation + guard**: `9b206b5` (fix)
2. **Task 2: Tidy-ups**: `d5c8415` (chore)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] anvil-web integration tests used the base64 crate through the normal dependency**
- **Found during:** Task 1
- **Issue:** Removing `base64` from anvil-web would have broken 6 test files: admin_api, flow_passkey, passkey_adapter, security_client_auth, security_setup and token_support. Those files would also have tripped the new guard.
- **Fix:** They now use `anvil_jose::encoding::{b64url, b64url_decode, b64std}`.
- **Files modified:** crates/anvil-web/tests/*.rs (listed above)
- **Commit:** 9b206b5

**2. [Rule 1 - Behaviour preservation] Padding handling of b64std_decode**
- **Found during:** Task 1
- **Issue:** The plan wording was "canonical-only, padded". The Phase 2 Basic decoder also accepted unpadded input, and it rejected partial padding such as `YQ=`. The crate's `Indifferent` padding mode accepts `YQ=`.
- **Fix:** The decoder now chooses between two engines. Input containing `=` must have canonical padding, and input without `=` must have none. Basic-auth behaviour is exactly as before.
- **Commit:** 9b206b5

Also: the error text of `FlowEngine::initial` for Settings/Consent changed from "not implemented" to "not started by the flow engine". It is the same `CoreError::Internal`, and no test matches the text.

## Deferred Issues

Logged in `deferred-items.md`:
- The fuzz workspace (`fuzz/fuzz_targets/client_assertion.rs`) still uses `base64::` directly. It is outside this plan's files and has its own lock file.
- `cargo build --workspace` without dev-deps warns that anvil-storage does not use anvil-core, because its code is all behind the `contract` feature. This was already the case before this plan.

## Verification

- `cargo test -p anvil-jose -p anvil-mail -p anvil-core`: green
- `cargo test -p anvil-web --lib --test captcha --test security_client_auth --test security_setup --test admin_api --test passkey_adapter --test flow_passkey`: green
- `cargo test --workspace --locked --exclude anvil-storage-postgres --no-fail-fast`: no failures
- `scripts/check-deps.sh` OK; `--self-test` OK (9 cases)
- `scripts/check-security-tests.sh` OK (230 pairs)
- `cargo clippy --workspace --all-targets -- -D warnings`: exit 0, and the `anvilid` and anvil-cache `tokio` manifest warnings are gone
- `cargo build --workspace --locked`, `cargo deny --locked check`: OK

## CI

ci run 45627156784 on d5c8415: all 8 jobs green (fmt + clippy, dependency rules, release graph, cargo deny, sqlx metadata, tests sqlite, tests postgres, admin console).

## Self-Check: PASSED

- FOUND: 9b206b5, d5c8415
- FOUND: 03-34-SUMMARY.md and every modified file listed
