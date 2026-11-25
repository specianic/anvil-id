---
phase: 03-release-0-2-secure-by-default
plan: 01
subsystem: crypto, dependencies
tags: [jose, ed25519, es256, totp, recovery-codes, cargo-deny, webauthn-rs]
requires: []
provides:
  - "Frozen Phase 3 dependency graph (webauthn-rs, totp-rs, qrcodegen, governor, moka, ipnet; rust-embed interpolate-folder-path; minijinja fuel)"
  - "anvil-jose: Alg::Ed25519, generate_es256/generate_ed25519/generate(alg), OKP JWKs + thumbprints"
  - "anvil-jose: verify_op_token_algs (explicit allow-list); token_hash(alg, value)"
  - "anvil-jose: TotpSecret, otpauth_uri, check_code; generate_recovery_codes, normalize_recovery_code, recovery_code_hash; Kek::derive_key"
affects: [03-09, 03-10, 03-12, 03-16, 03-23, 03-24]
tech-stack:
  added: [webauthn-rs 0.6.2, totp-rs 6.0.0, qrcodegen 1.8, governor 0.10.4, moka 0.12.16, ipnet 2.12]
  patterns:
    - "JOSE header always serialised in-crate; jsonwebtoken only produces/verifies signature bytes (Ed25519 -> Algorithm::EdDSA)"
    - "KEK subkeys via Kek::derive_key(info) with a salt separate from the AEAD data keys"
key-files:
  created:
    - crates/anvil-jose/src/hash.rs
    - crates/anvil-jose/src/otp.rs
    - crates/anvil-jose/src/recovery_code.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - deny.toml
    - crates/anvil-jose/Cargo.toml
    - crates/anvil-web/Cargo.toml
    - crates/anvil-cache/Cargo.toml
    - crates/anvilid/Cargo.toml
    - crates/anvil-jose/src/keys.rs
    - crates/anvil-jose/src/jwk.rs
    - crates/anvil-jose/src/jws.rs
    - crates/anvil-jose/src/op_token.rs
    - crates/anvil-jose/src/kek.rs
    - crates/anvil-jose/src/lib.rs
decisions:
  - "Ed25519 uses the RFC 9864 name `Ed25519` in headers and JWKs; `EdDSA` is neither emitted nor accepted (closes ARCHITECTURE §8.1 'decided in Phase 3')"
  - "deny.toml: rsa allowed only via crypto-glue; RUSTSEC-2023-0071 ignored with reason (fixed rsa 0.10.0 unreachable: crypto-glue 0.2.2 needs the rc-only `sha2` feature); MPL-2.0 accepted per crate (webauthn-rs x4, crypto-glue, option-ext), not globally"
  - "verify_op_token stays RS256-only (existing security test unchanged); verify_op_token_algs takes an explicit allow-list for 03-10"
  - "Kek::derive_key uses HKDF salt anvilid/derive/v1 (info as given), so derived peppers never equal an AEAD data key"
  - "Recovery-code normalisation maps no lookalikes; ':' in otpauth issuer/account is replaced with a space"
metrics:
  duration: 13min
  completed: 2026-11-25
  tasks: 3
  files: 16
---

# Phase 3 Plan 01: Phase 3 dependencies and anvil-jose crypto primitives Summary

All Phase 3 crates declared once (cargo-deny clean with a crypto-glue-scoped `rsa` exception), and anvil-jose now signs and verifies RS256/ES256/Ed25519 (RFC 9864 `Ed25519` header, never `EdDSA`), publishes OKP JWKs with RFC 7638/8037 thumbprints, computes per-alg `at_hash`/`c_hash`, and provides TOTP (totp-rs) and KEK-peppered recovery codes.

## Tasks

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Declare all Phase 3 dependencies; scope the rsa ban | e6fcf86 |
| 2 | ES256/Ed25519 keys, Ed25519 JWS, OKP thumbprints, per-alg token hash | 6613897 |
| 3 | TOTP and recovery-code primitives | ab78764 |

## deny.toml diff (summary)

- `bans.deny`: `{ crate = "rsa", reason = "RUSTSEC-2023-0071 (Marvin), no fix" }` plus the "webauthn-rs (M2) will need" comment
  replaced by `{ crate = "rsa", wrappers = ["crypto-glue"], reason = "...public keys only (ARCHITECTURE.md §2)" }`.
- `advisories.ignore`: `RUSTSEC-2023-0071` with reason. cargo-deny reports `warning[patched]` (rsa 0.10.0 fixes it), but
  `cargo update -p rsa --precise 0.10.0` fails: crypto-glue 0.2.2 enables `rsa/sha2`, which only the rc releases have.
  Remove the ignore when crypto-glue moves to rsa 0.10 stable.
- `[[licenses.exceptions]]` MPL-2.0 for webauthn-rs, webauthn-rs-core, webauthn-rs-proto, webauthn-attestation-ca,
  crypto-glue and option-ext (from rust-embed `interpolate-folder-path` -> shellexpand -> dirs, build-time proc-macro).
  MPL-2.0 is not added to the global allow list.
- No other ban loosened. openssl, native-tls, ring and chrono do not appear on any active edge (`cargo tree -i` prints nothing; the
  pre-existing lock entries for ring/chrono belong to inactive features).

## Duplicate-version warnings (multiple-versions = warn, no skips added)

argon2 (0.5 via crypto-glue, 0.6 ours), password-hash, blake2, digest, block-buffer, crypto-common, cpufeatures, getrandom,
rand, rand_chacha, rand_core (3), sha1, base64 (3), hashbrown (3), nom, syn, synstructure, thiserror/thiserror-impl, untrusted.
Most come from the RustCrypto rc stack under webauthn-rs.

## EdDSA decision

`Alg::Ed25519` serialises as `"Ed25519"` (RFC 9864 fully-specified). `"EdDSA".parse::<Alg>()` fails, so a token whose header says
`EdDSA` is rejected with `UnsupportedAlg` even if its signature verifies under a published Ed25519 key (test
`ed25519_token_with_eddsa_header_rejected`). jsonwebtoken's `Algorithm::EdDSA` is used for signature bytes only.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] cargo-deny needed an advisory ignore and MPL-2.0 license exceptions**
- **Found during:** Task 1
- **Issue:** The research expected only the rsa ban to fail. cargo-deny also failed on the RUSTSEC-2023-0071 advisory (rsa is in the
  graph now) and on MPL-2.0 licenses (webauthn-rs crates, crypto-glue, option-ext).
- **Fix:** A scoped advisory ignore with reason and per-crate MPL-2.0 exceptions (no global allow). ARCHITECTURE §2 already accepts
  webauthn-rs, and these are the minimum entries that let it in.
- **Files modified:** deny.toml
- **Commit:** e6fcf86

**2. [Rule 2 - API compatibility] verify_op_token kept RS256-only; added verify_op_token_algs**
- **Found during:** Task 2
- **Issue:** The plan says verify_op_token should verify Ed25519, and also that the public API must stay source-compatible. The existing
  `only_rs256_accepted` test asserts the RS256-only behaviour.
- **Fix:** `verify_op_token` delegates to a new `verify_op_token_algs(token, published, allowed, ...)`. 03-10 can switch callers to the
  tenant's signing algs.
- **Commit:** 6613897

**3. [Rule 2 - Security] Kek::derive_key uses its own HKDF salt**
- **Found during:** Task 3
- **Issue:** Without a different salt, `derive_key(x)` would equal the AES key used by `seal(x, ..)`.
- **Fix:** Salt `anvilid/derive/v1`, with the info string exactly as specified (`anvilid/recovery-code/v1`). A test asserts the separation.
- **Commit:** ab78764

### Notes

- anvil-mail, storage crates: unchanged (fuel is a workspace feature; both storage crates already have dev-dep anvil-jose).
- Cargo now reports `unused dependency` manifest warnings for crates declared ahead of use (webauthn-rs, qrcodegen, anvil-cache,
  anvil-mail in anvil-web; governor, moka, tokio, anvil-core in anvil-cache). These are cargo warnings, not rustc/clippy, so they do
  not fail `-D warnings`. They go away as 03-09/03-23/03-24 use the crates.
- TDD: each task's tests and implementation went into one commit (no separate RED commit).
- Workspace-wide build was checked in a temporary worktree (target/wt-03-01, since removed), because another plan's in-progress
  anvil-core changes in the main tree do not compile yet.

## Verification

- `cargo build --workspace --all-targets --locked` (clean worktree at ab78764): OK
- `cargo deny --locked check`: advisories ok, bans ok, licenses ok, sources ok
- `scripts/check-deps.sh`: dependency rules OK (anvil-core manifest unchanged)
- `scripts/check-release-graph.sh`: OK
- `cargo test -p anvil-jose`: 82 passed; `cargo clippy -p anvil-jose --all-targets -- -D warnings`: clean
- `cargo tree -p anvilid -i image|ring|openssl`: nothing

## Self-Check: PASSED
