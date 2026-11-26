---
phase: 07-release-1-0-certification
plan: 09
subsystem: password-hashing
tags: [password-import, dispatcher, argon2, bcrypt, scrypt, firebase, pbkdf2, sha2, dos-caps, ADM-08]
requires: ["07-01 legacy verifiers", "07-02 parse_stored/check_stored_caps", "07-03 PasswordHasher::verify(profile)"]
provides:
  - "anvil_web::adapters::PasswordDispatcher (adapters::password::PasswordDispatcher): the one production PasswordHasher"
  - "Argon2Pool::{run_bounded, run_verification, verify_dummy, verify_argon2} (crate-visible), Argon2Pool::permits()"
  - "Verify-time caps for every stored scheme, Argon2 PHC parameters included"
affects: [07-14 (core passes Some(profile) for Firebase hashes), 07-23 (gate)]
tech-stack:
  added: []
  patterns:
    - "parse -> caps (fail closed, no hashing) -> route -> run inside the pool's one semaphore + spawn_blocking"
    - "Legacy schemes are an owned LegacyJob enum (one arm per scheme), so bcrypt/scrypt/Firebase arms can be removed independently if the 07-01 crypto exception is rejected"
key-files:
  created: []
  modified:
    - crates/anvil-web/src/adapters/password/mod.rs
    - crates/anvil-web/src/adapters/argon2.rs
    - crates/anvil-web/src/adapters/mod.rs
    - crates/anvilid/src/startup.rs
    - crates/anvilid/src/main.rs
    - crates/anvil-web/tests/support/mod.rs
    - crates/anvil-web/tests/ui_helpers/mod.rs
key-decisions:
  - "Over-cap, refused ($2x$) and Firebase-without-profile hashes fail closed with NO hashing at all (verifications counter unchanged, not even a dummy). Unknown, garbled and None take the dummy (counter +1)"
  - "A hash profile passed with a non-Firebase hash is ignored (core resolves profiles only for $anvil-firebase-scrypt$ strings); Argon2Pool's own impl ignores it too (the TRANSITIONAL(07-09) refusal is removed)"
  - "Firebase profile parameters are checked with check_scrypt_params(mem_cost, rounds, 1) before hashing"
  - "Argon2Pool keeps its own PasswordHasher impl for Argon2-only direct use: caps-checked Argon2, anything else takes the dummy path"
metrics:
  duration: ~70min (including waits for other wave-2 plans' in-progress files to compile)
  completed: 2026-11-26
---

# Phase 7 Plan 09: Password scheme dispatcher Summary

`PasswordDispatcher` wraps the bounded `Argon2Pool` and is now the only `PasswordHasher` wired in production. It
applies the import caps before any hashing (Argon2 parameters read from stored PHC strings included), routes each
stored scheme to the Argon2 path or a 07-01 legacy verifier inside the one permit pool, and asks for a rehash
after every legacy match.

## Dispatcher API

```rust
pub struct PasswordDispatcher { argon2: Argon2Pool }      // Debug: "PasswordDispatcher { permits: N }"
impl PasswordDispatcher {
    pub fn new(argon2: Argon2Pool) -> Self;
    pub fn verifications(&self) -> u64;                    // Argon2 + dummy + legacy
}
impl PasswordHasher for PasswordDispatcher { hash -> Argon2id; verify(stored, password, profile) }

// Argon2Pool additions (pub(crate) unless noted)
pub fn permits(&self) -> usize;
async fn run_bounded<F, R>(&self, f: F) -> Result<R, CoreError>;        // permit + spawn_blocking
async fn run_verification<F, R>(&self, f: F) -> Result<R, CoreError>;   // same, counted
async fn verify_dummy(&self, password: &str) -> Result<PasswordCheck, CoreError>;
async fn verify_argon2(&self, phc: &str, password: &str) -> Result<PasswordCheck, CoreError>;
```

`verify` flow: `None` -> dummy. `parse_stored` error: `RefusedVariant` -> fail closed; anything else (unknown or
garbled) -> dummy plus an error log with the reason code only. `check_stored_caps` error -> fail closed (one
warn log with `scheme` and `reason`). Firebase without material, or with material over the scrypt cap -> fail
closed. Then Argon2 goes to `verify_argon2` (parameter-based `needs_rehash`), and the legacy schemes become a
`LegacyJob` that runs in `run_verification` with the password copied into `Zeroizing<Vec<u8>>`. A
`LegacyVerifyError` -> `valid = false` plus a warn log with the reason code. A legacy match -> `valid = true,
needs_rehash = true`. Fail-closed paths take no permit, so they answer even when the pool is saturated.

## Tests (`cargo test -p anvil-web --lib adapters::`: 123 passed)

Dispatcher (`adapters::password::dispatcher_tests`):
- KATs via `format_stored`: `dispatcher_verifies_bcrypt_openwall_vector`, `dispatcher_verifies_scrypt_rfc7914_vector`
  (N=1024), `dispatcher_verifies_firebase_vector_with_profile` (hunter2 + published profile),
  `dispatcher_verifies_pbkdf2_sha1_4096_vector`, `dispatcher_verifies_sha256_suffix_vector`. Each one checks the right
  password (valid, rehash) and a wrong one (invalid, no rehash).
- Argon2: `dispatcher_argon2_fresh_hash_keeps_todays_behaviour` (current params: no rehash; other params: rehash),
  `dispatcher_verifies_phc_readme_argon2i_vector` (valid, needs_rehash = true).
- Negative: `dispatcher_argon2_over_cap_fails_closed_without_hashing` (m=4194304, t=11, p=9),
  `dispatcher_scrypt_over_cap_fails_closed_without_hashing` (1 GiB, p=64, r*p overflow),
  `dispatcher_pbkdf2_over_cap_fails_closed` (5,000,001 iterations, u32::MAX, block-multiplied work),
  `dispatcher_bcrypt_over_cap_fails_closed` (cost 17), `dispatcher_refuses_bcrypt_2x`,
  `dispatcher_unknown_scheme_takes_dummy_path` (`$6$…`, `garbage`, `""`, garbled argon2 and `$anvil-pbkdf2$`, and
  None; counter +1 each), `dispatcher_firebase_without_profile_fails_closed`,
  `dispatcher_firebase_profile_over_cap_fails_closed`, `dispatcher_legacy_match_requests_rehash`,
  `dispatcher_ignores_profile_for_non_firebase_hashes`, `dispatcher_overloaded_when_queue_full` (1 permit held: Argon2,
  bcrypt, SHA-2, garbage, None and hash all return Overloaded; the counter does not move),
  `dispatcher_serialises_legacy_and_argon2_on_one_permit` (PBKDF2 3M iterations holds the permit -> Argon2
  Overloaded; the 64 MiB Argon2 vector holds it -> legacy Overloaded; about 0.5 s and 1 s of hashing against a
  100 ms acquire window, 5/5 repeated runs green), `dispatcher_debug_redacts`.
- Over-cap tests assert `valid = false`, an unchanged counter (no hashing, not even the dummy) and < 200 ms.

Argon2Pool: `argon2_pool_refuses_profile_material` replaced by `argon2_pool_ignores_profile_material`; new
`argon2_pool_over_cap_phc_fails_closed_without_hashing` and `non_argon2_stored_value_takes_the_dummy_path`.

## Mutation checks

| Mutation | Result |
|---|---|
| Dispatcher caps call replaced by `Ok(())` (run under `ulimit -v 3 GiB` so the 4 GiB Argon2 case cannot exhaust host memory) | 4 failed: argon2 (counter), scrypt, pbkdf2, bcrypt over-cap (time/counter); reverted |
| Unknown scheme returns `Ok(INVALID)` without the dummy | `dispatcher_unknown_scheme_takes_dummy_path` failed (counter); reverted |

## Wiring sites

- `crates/anvilid/src/startup.rs` (AppDeps/BootstrapService `hasher`) and `crates/anvilid/src/main.rs` (setup-url
  command): `PasswordDispatcher::new(Argon2Pool::new(Argon2Pool::owasp_params(), …)?)`.
- `crates/anvil-web/tests/support/mod.rs` (TestApp deps) and `crates/anvil-web/tests/ui_helpers/mod.rs`
  (`OwnApp.hasher: Arc<PasswordDispatcher>`, `verifications()` unchanged for security_enumeration).
- Other test files that build `Argon2Pool` directly keep it (Argon2-only use; not this plan's files).

## Verification

- `cargo test -p anvil-web --locked --no-fail-fast`: 1486 passed, 0 failed (security_enumeration and the dummy-hash
  timing tests included).
- `cargo test -p anvilid --locked --no-fail-fast`: 153 passed, 0 failed.
- `cargo clippy -p anvil-web -p anvilid --all-targets --locked -- -D warnings`: clean.
- `grep -rn 'TRANSITIONAL(07-09)' crates/`: no matches.
- `scripts/check-release-graph.sh`: OK (after fix commit 2c8ff75, see below).
- Postgres-backed runs not done (no Docker); left for CI.

## Task Commits

1. Task 1: `aaab694` feat(07-09): PasswordDispatcher with verify-time caps, scheme routing and the shared bounded pool
2. Fix: `2c8ff75` fix(07-09): move the test-only permit accessor into a cfg(test) module
3. Task 2: `cd72b1b` feat(07-09): wire PasswordDispatcher in the binary and the shared test harnesses

## Deviations from Plan

**1. [Rule 1 - Release-graph gate] Test-only accessor moved into a cfg(test) module.** Commit aaab694 had
`#[cfg(test)] fn available_permits` on an impl item, which `check-release-graph.sh` forbids (the orchestrator
reported it). Now it lives in `argon2::test_support` (a `#[cfg(test)] mod` holding an `impl Argon2Pool` block).
Commit 2c8ff75.

**2. [Rule 2] Extra negative tests beyond the plan's list:** bcrypt cost over the cap, Firebase profile over the
scrypt cap, profile ignored for non-Firebase hashes, and Argon2Pool's own over-cap and non-Argon2 paths.

No files outside files_modified were touched. The 07-01 crypto exception is still awaiting owner approval; the
bcrypt, scrypt and Firebase arms are separate `LegacyJob` variants and `StoredHash` match arms, so they can be
removed on their own.

## Self-Check: PASSED

- FOUND: commits aaab694, 2c8ff75, cd72b1b on main
- FOUND: `impl PasswordHasher for PasswordDispatcher` in crates/anvil-web/src/adapters/password/mod.rs
- FOUND: `PasswordDispatcher` in crates/anvilid/src/startup.rs
