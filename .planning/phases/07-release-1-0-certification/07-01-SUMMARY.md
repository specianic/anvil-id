---
phase: 07-release-1-0-certification
plan: 01
subsystem: password-import-crypto
tags: [crypto, deny, bcrypt, scrypt, firebase, pbkdf2, sha2, ADM-08]
status: complete
requires: []
provides:
  - "Workspace deps scrypt 0.12.0 (default-features = false) and bcrypt 0.19.3 (default-features = false, alloc), anvil-web only"
  - "deny.toml [bans] deny: blowfish via wrappers [bcrypt], salsa20 via wrappers [scrypt]"
  - "anvil_web::adapters::password::{bcrypt,scrypt,firebase,pbkdf2,sha2}::verify + LegacyVerifyError (signatures exactly as in the plan interfaces)"
  - "ARCHITECTURE §2 fourth crypto exception paragraph (owner review pending)"
affects: [07-09 (dispatcher calls these verifiers), 07-14 (import tests), 07-22 (ARCHITECTURE wording after approval), 07-23 (gate)]
tech-stack:
  added: ["bcrypt 0.19.3", "blowfish 0.10.0 (via bcrypt)", "scrypt 0.12.0 (was already in the lock via pkcs5; now a direct dependency)"]
  patterns:
    - "Legacy verifiers are pure sync functions over primitive arguments; caps/floors live only in anvil_core::policy::password_import"
    - "KDF verifiers derive max(stored length, floor) bytes and ct_eq against the stored value, so a stored hash shorter than the floor never verifies"
key-files:
  created:
    - crates/anvil-web/src/adapters/password/mod.rs
    - crates/anvil-web/src/adapters/password/bcrypt.rs
    - crates/anvil-web/src/adapters/password/scrypt.rs
    - crates/anvil-web/src/adapters/password/firebase.rs
    - crates/anvil-web/src/adapters/password/pbkdf2.rs
    - crates/anvil-web/src/adapters/password/sha2.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - fuzz/Cargo.lock
    - deny.toml
    - crates/anvil-web/Cargo.toml
    - crates/anvil-web/src/adapters/mod.rs
    - docs/ARCHITECTURE.md
key-decisions:
  - "PBKDF2 derived length = max(stored length, PRF output length); scrypt = max(stored length, 16). A stored hash shorter than the floor returns Ok(false) (the plan's 'truncated expected -> false'). Longer stored values verify their own length, as PBKDF2/scrypt outputs are stored"
  - "Stored derived keys and Firebase signer keys are capped at 1024 bytes (InvalidParameters) to bound KDF output work; these are size sanity limits, not the import policy caps (07-02)"
  - "scrypt parameters are validated before calling the crate (log_n = 0, r = 0, p = 0, r*p overflow or >= 2^30 -> InvalidParameters), because scrypt::Params::new computes r*p in u32 and would panic in debug on overflow"
  - "bcrypt CostNotAllowed -> InvalidParameters; any other crate error -> Malformed; $2x$ refused before the crate is called"
metrics:
  duration: ~50min (including waits for the shared tree to build)
  completed: 2026-11-26 (tasks 1-2; task 3 awaits the owner)
---

# Phase 7 Plan 01: Legacy password-hash crypto exception Summary

RustCrypto scrypt 0.12.0 and bcrypt 0.19.3 added as a deny-scoped, verification-only exception, five constant-time
legacy verifiers (bcrypt, scrypt, Firebase scrypt on scrypt + aws-lc AES-256-CTR, PBKDF2 and salted SHA-2 on
aws-lc-rs) passing primary-source known-answer vectors. The plan stops at the owner's approve/reject checkpoint.

## Tasks

| Task | Name | Commit | Status |
|------|------|--------|--------|
| 1 | Dependencies and the scoped deny exception | 3a2a3dc | done |
| 2 | Verifier modules with KATs, ARCHITECTURE §2 | e26daf3 | done |
| 3 | Owner approves or rejects the exception | - | **awaiting owner** |

## Dependency delta

- `Cargo.toml` `[workspace.dependencies]` (new "Phase 7" block): `scrypt = { version = "0.12.0", default-features = false }`,
  `bcrypt = { version = "0.19.3", default-features = false, features = ["alloc"] }`.
- `crates/anvil-web/Cargo.toml`: `bcrypt`, `scrypt`, `subtle` (`subtle` was not yet a direct dependency).
- `Cargo.lock`: `git diff --stat` = 25 insertions; new packages **bcrypt 0.19.3, blowfish 0.10.0** only (scrypt 0.12.0,
  salsa20 0.11.0, pbkdf2, sha2, byteorder, base64 0.23, getrandom 0.4 were already locked).
- `fuzz/Cargo.lock`: `cargo update -p bcrypt` answered "did not match any packages", so `cargo check --manifest-path
  fuzz/Cargo.toml` added them once: 31 insertions, new packages **bcrypt, blowfish, byteorder** (byteorder was already
  in the root lock) plus the `bcrypt`, `scrypt`, `subtle` entries in anvil-web's dependency list. No upgrades.
- `deny.toml` `[bans] deny`:
  ```toml
  # Legacy password-hash verification only (ADM-08): ... Owner review pending (07-01 checkpoint). ARCHITECTURE.md §2.
  { crate = "blowfish", wrappers = ["bcrypt"], reason = "bcrypt verification of imported hashes only (ADM-08)" },
  { crate = "salsa20", wrappers = ["scrypt"], reason = "scrypt verification of imported hashes only (ADM-08)" },
  ```
  No global allow, licence exception or skip added.

## cargo tree outputs

```
$ cargo tree -i blowfish --target all
blowfish v0.10.0
└── bcrypt v0.19.3
    └── anvil-web v0.0.0
        └── anvilid v1.0.0-beta.1

$ cargo tree -i salsa20 --target all
salsa20 v0.11.0
└── scrypt v0.12.0
    ├── anvil-web v0.0.0
    │   └── anvilid v1.0.0-beta.1
    └── pkcs5 v0.8.1            (pre-existing parent of scrypt, not of salsa20)
        └── pkcs8 v0.11.0
            ├── crypto-glue v0.2.2 -> webauthn-attestation-ca / webauthn-rs-core -> webauthn-rs -> anvil-web
            └── elliptic-curve v0.14.3 ...

$ cargo tree -i ring --target all
warning: nothing to print.

$ cargo tree -i scrypt --target all
scrypt v0.12.0
├── anvil-web v0.0.0 -> anvilid
└── pkcs5 v0.8.1 -> pkcs8 v0.11.0 -> crypto-glue / elliptic-curve ...   (already in the lock before this plan)

$ cargo tree -i bcrypt --target all
bcrypt v0.19.3
└── anvil-web v0.0.0
    └── anvilid v1.0.0-beta.1
```

salsa20's only parent is scrypt, so the wrapper list did not need widening (no decision checkpoint required). scrypt
itself already had the parent `pkcs5` (webauthn-rs -> crypto-glue -> pkcs8 -> pkcs5) before this plan.

`cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok` (exit 0; only the existing
`multiple-versions = "warn"` duplicates; bcrypt joins the existing base64 0.23 / getrandom 0.4 entries, no new
duplicate crate). `just deps`: `dependency rules OK` (one aws-lc-rs, one aws-lc-sys).

## Known-answer tests (33 tests, `cargo test -p anvil-web --lib adapters::password`: 33 passed)

| Module | Vectors (source) | Negative tests |
|---|---|---|
| scrypt | RFC 7914 §12: ("", "", N=16, r=1, p=1, 64) and ("password", "NaCl", N=1024, r=8, p=16, 64) | flipped byte, wrong password, stored hash below 16-byte floor -> false; log_n=0, r=0, p=0, r*p overflow, empty / >1024-byte expected -> InvalidParameters |
| firebase | firebase/scrypt README (`user1password` -> `lSrfV15cpx95…`) and tests/01-known-value.sh (`hunter2` -> `70k8Vg5B…`) | wrong password, wrong / empty separator, flipped byte -> false; empty signer key, rounds=0, mem_cost=0 -> InvalidParameters |
| pbkdf2 | RFC 6070 SHA1 c=1 and c=4096 (20 bytes); RFC 7914 §11 SHA256 c=1 (64 bytes); SHA512 wiring round trip against aws-lc derive (no primary-source vector) | flipped byte, truncated (19 of 20 bytes), wrong iterations, wrong PRF -> false; iterations=0, empty expected -> InvalidParameters |
| sha2 | FIPS 180-4 "abc": salt "a" + pw "bc" (Prefix), pw "ab" + salt "c" (Suffix), SHA-256 and SHA-512 | swapped position (all four), flipped byte, wrong digest, truncated -> false |
| bcrypt | Openwall crypt_blowfish `$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW` with `U*U`; same with `$2b$`, `$2y$` | `U*V` -> false; `bcrypt_refuses_2x_variant`; 59 chars, empty, `$1a$` -> Malformed; cost 03 -> InvalidParameters; 72-byte truncation asserted (bytes after 72 ignored, byte 72 counts) |
| mod | `legacy_verify_error_debug_has_no_input` (Debug = variant name, Display = reason code), `ct_eq_folds_length_into_the_result` | |

## Mutation check

- `ct_eq` replaced with a function that always returns true: 14 tests failed (every flipped-byte, wrong-password,
  wrong-separator, truncated, swapped-position test in scrypt, firebase, pbkdf2, sha2, plus the ct_eq unit test).
- `$2x$` guard disabled: `bcrypt_refuses_2x_variant` failed (the crate returns Ok(true) for `$2x$`).
- Both reverted; the suite is 33/33 green again.

## Verification run

- `cargo test -p anvil-web --lib adapters::password`: 33 passed.
- `cargo clippy -p anvil-web --all-targets --locked -- -D warnings`: no findings in this plan's files; the run
  fails on `crates/anvil-web/src/ui/flow_driver.rs:659` (large_enum_variant), another wave-1 plan's in-progress file.
- `cargo build --workspace --all-targets --locked`: Finished (green) at the time of the run.
- `cargo deny --locked check`, `just deps`: green (above). `scripts/check-release-graph.sh`: OK.
- `just fuzz-check`: the fuzz lock resolves with `--locked` and anvil-web compiles, but the run fails in
  `fuzz/fuzz_targets/authorize_parse.rs:40` (missing new `Client` fields `client_kind`, `headless_native`,
  `require_pushed_authorization_requests` added by 07-03). Not this plan's file; recorded for the orchestrator.

## Deviations from Plan

- [Rule 2 - Correctness] scrypt parameters are pre-validated (r*p overflow) so a hostile stored parameter cannot
  panic the verifier; derived-key and signer-key length capped at 1024 bytes. Files: scrypt.rs, firebase.rs,
  pbkdf2.rs, mod.rs. Commit e26daf3.
- Fuzz lock: `cargo update -p bcrypt` could not run (package not yet in the fuzz lock), so the plan's fallback
  `cargo check --manifest-path fuzz/Cargo.toml` was used.

## Owner checkpoint (Task 3): APPROVED (2026-11-27)

Decision asked: approve RustCrypto scrypt 0.12.0 and bcrypt 0.19.3 (blowfish and salsa20 scoped through deny
wrappers) as a verification-only exception to "single crypto backend: aws-lc-rs"? Options: **approve** or
**reject** (reject -> the orchestrator creates a gap plan that removes the crates, the bcrypt/scrypt/Firebase
verifiers and import paths, re-words ADM-08 with the owner's sign-off and documents the drop).

Owner decision (verbatim): "I approve"

Reminder: the chrono exception review (06-01, D4/Q2) is still pending and is decided in 07-26, not here.

## Self-Check: PASSED

- All six created files exist; commits 3a2a3dc and e26daf3 are on main.
