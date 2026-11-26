---
phase: 07-release-1-0-certification
plan: 02
subsystem: auth
tags: [password-import, bcrypt, scrypt, firebase, pbkdf2, argon2, sha2, fuzz, ADM-08]

requires: []
provides:
  - "anvil_core::policy::password_import: stored legacy-hash encoding ($anvil-scrypt/firebase-scrypt/pbkdf2/sha2), Argon2 PHC and bcrypt MCF recognition"
  - "caps (check_stored_caps, check_scrypt_params) and floors (check_import_floors) with reason codes"
  - "vendor import conversion: ImportPassword, parse_import_value, convert_import, Converted"
  - "fuzz target password_hash_parse (fuzz/Cargo.toml + nightly matrix)"
affects: [07-09 dispatcher, 07-14 import service, 07-17 admin import route, docs/IMPORT-EXPORT.md]

tech-stack:
  added: []
  patterns:
    - "Vendor formats converted once at import into a canonical $anvil-… string; the login path parses only the stored encoding"
    - "Same caps at import (refuse) and verify (fail closed) through one function"

key-files:
  created:
    - crates/anvil-core/src/policy/password_import.rs
    - fuzz/fuzz_targets/password_hash_parse.rs
  modified:
    - crates/anvil-core/src/policy.rs
    - fuzz/Cargo.toml
    - .github/workflows/fuzz.yml

key-decisions:
  - "PBKDF2 cap counts work, not just iterations: iterations x ceil(hash_len / PRF block) <= 5,000,000 (a long derived key multiplies the cost)"
  - "Extra floors/caps beyond the plan's list: scrypt/Firebase need a non-empty salt; scrypt/Firebase/PBKDF2 hashes >= 16 bytes; salt <= 256 bytes, hash <= 128 bytes, strings <= 1,024 chars"
  - "MD5 and plain SHA-1: unknown_scheme when named as a scheme (no such import scheme), weak_parameters when named as the digest of a salted_sha2 import"
  - "Argon2, scrypt and Firebase scrypt are never flagged weak; salted SHA-2 always is"
  - "The $anvil-… grammar is canonical (fixed parameter order, no leading zeros, lowercase UUID, unpadded canonical base64), so format_stored(parse_stored(s)) == s"

patterns-established:
  - "Redacting Debug: every type that holds hash/salt bytes prints lengths only; errors are unit variants"

requirements-completed: []  # ADM-08 contributes here; only the gate plan 07-23 ticks REQUIREMENTS.md

duration: 75min
completed: 2026-11-26
---

# Phase 7 Plan 02: Password-import policy Summary

**One pure core module, `policy::password_import`, now owns imported password hashes: the canonical `$anvil-…$`
stored encoding, the memory/CPU caps (enforced at import and verify), the weak-data floors with reason codes, and
the conversion of bcrypt, Argon2, scrypt, Firebase scrypt, PBKDF2 (generic, Django, passlib) and salted SHA-2
import inputs. It has 32 unit/property tests and a new fuzz target.**

## Performance

- **Duration:** about 75 min
- **Tasks:** 2 (TDD, RED and GREEN commits for each)
- **Files modified:** 5

## Public API as built

```rust
pub enum HashPolicyError { UnknownScheme, WeakParameters, OverCap, RefusedVariant, Malformed } // serde snake_case, .reason()
pub enum Prf { Sha1, Sha256, Sha512 }            // serde lowercase, block_len()
pub enum ShaAlg { Sha256, Sha512 }               // digest_len()
pub enum SaltPosition { Prefix, Suffix }         // prefix = H(salt‖pw), suffix = H(pw‖salt)
pub enum StoredHash<'a> { Argon2{phc,m_kib,t,p}, Bcrypt{mcf,cost}, Scrypt{log_n,r,p,salt,hash},
                          FirebaseScrypt{profile,salt,hash}, Pbkdf2{prf,iterations,salt,hash},
                          Sha2{alg,position,salt,hash} }   // Debug: parameters + lengths only
pub fn parse_stored(s: &str) -> Result<StoredHash<'_>, HashPolicyError>;
pub fn format_stored(h: &StoredHash<'_>) -> String;
pub fn check_stored_caps(h: &StoredHash<'_>) -> Result<(), HashPolicyError>;
pub fn check_import_floors(h: &StoredHash<'_>) -> Result<bool /* weak */, HashPolicyError>;
pub fn check_scrypt_params(log_n: u8, r: u32, p: u32) -> Result<(), HashPolicyError>; // also for Firebase profiles (p = 1)
pub enum ByteField { Hex(String), Base64(String) }        // {"hex": ..} | {"base64": ..}
pub enum SaltedDigest { Md5, Sha1, Sha256, Sha512 }
pub enum ImportPassword { Bcrypt{hash}, Argon2{hash}, Scrypt{salt,hash,log_n,r,p}, FirebaseScrypt{salt,hash,profile},
                          Pbkdf2{prf,iterations,salt,hash}, DjangoPbkdf2{hash}, PasslibPbkdf2{hash},
                          SaltedSha2{alg,position,salt: Option<_>,hash} } // tag "scheme", deny_unknown_fields
pub const IMPORT_SCHEMES: [&str; 8];
pub fn parse_import_value(v: serde_json::Value) -> Result<ImportPassword, HashPolicyError>;
pub struct Converted { pub stored: String, pub weak: bool }  // Debug redacts stored
pub fn convert_import(input: &ImportPassword) -> Result<Converted, HashPolicyError>;
pub const FIREBASE_PROFILE_PREFIX: &str = "$anvil-firebase-scrypt$";
```

`ImportPassword` is an enum (the interface sketch said `struct`; the plan's action describes the tagged enum).

## Constants

| Constant | Value | Kind |
|---|---|---|
| `SCRYPT_MAX_MEMORY_BYTES` | 64 MiB (`128·N·r·p`, checked u64) | cap |
| `ARGON2_MAX_M_KIB` / `ARGON2_MAX_T` / `ARGON2_MAX_P` | 262,144 / 10 / 8 | cap |
| `PBKDF2_MAX_ITERATIONS` | 5,000,000 (x output blocks) | cap |
| `BCRYPT_MAX_COST` | 16 | cap |
| `MAX_SALT_BYTES` / `MAX_HASH_BYTES` / `MAX_ENCODED_LEN` | 256 / 128 / 1,024 | cap |
| `BCRYPT_MIN_COST` / `BCRYPT_WEAK_BELOW_COST` | 4 / 10 | floor |
| `PBKDF2_MIN_ITERATIONS` / `PBKDF2_WEAK_BELOW_ITERATIONS` | 1,000 / 100,000 | floor |
| `MIN_SALT_BYTES` | 8 (PBKDF2, salted SHA-2) | floor |
| `MIN_HASH_BYTES` | 16 (scrypt, Firebase, PBKDF2) | floor |

## Accepted input shapes

The module docs hold the full table, which 07-14 copies into docs/IMPORT-EXPORT.md. Byte fields are `{"hex": …}` or
`{"base64": …}`.
`bcrypt {hash}` (MCF, as is), `argon2 {hash}` (PHC, as is), `scrypt {salt, hash, log_n, r, p}`,
`firebase_scrypt {salt, hash, profile}`, `pbkdf2 {prf, iterations, salt, hash}`,
`django_pbkdf2 {hash: "pbkdf2_sha256$<i>$<salt>$<b64>"}` (also `pbkdf2_sha1`),
`passlib_pbkdf2 {hash: "$pbkdf2-sha256$<i>$<ab64 salt>$<ab64 hash>"}` (also `$pbkdf2$`, `$pbkdf2-sha512$`),
`salted_sha2 {alg, position, salt, hash}`.

## Task Commits

1. **Task 1 RED:** `c0e623e` test(07-02): failing tests for the stored encoding, caps and floors
2. **Task 1 GREEN:** `6403b9e` feat(07-02): stored legacy-hash encoding, caps and floors
3. **Task 2 RED:** `8b459c4` test(07-02): failing tests for vendor import conversion
4. **Task 2 GREEN:** `6f5b204` feat(07-02): vendor import conversion and password_hash_parse fuzz target

## Verification

- `cargo test -p anvil-core --lib policy::password_import`: 32 passed. This includes the proptests for the
  round-trip, total parsing, mutation survival, import totality and converted-output parsing.
- `cargo clippy -p anvil-core --lib --tests`: no warnings in the module. `scripts/check-deps.sh`: OK (no new
  dependency; base64 only through `anvil_jose::encoding`). `scripts/check-release-graph.sh`: OK.
- `cargo check --manifest-path fuzz/Cargo.toml --locked --bin password_hash_parse`: OK; the 07-01 lock had landed.
  The full `--bins` check (`just fuzz-check`) currently fails in `fuzz_targets/authorize_parse.rs`, which is not this
  plan's file: 07-03 added `Client` fields (`client_kind`, `headless_native`,
  `require_pushed_authorization_requests`) that the existing target's initializer lacks.
- Fuzz smoke: `scripts/fuzz.sh run password_hash_parse 60` (nightly, local) ran 2,943,312 runs in 61 s with no crash and exit 0.

## Mutation checks

| Mutation | Result |
|---|---|
| `SCRYPT_MAX_MEMORY_BYTES` raised to 256 MiB | `caps_refuse_scrypt_over_64_mib` FAILED (15 passed, 1 failed); reverted |
| `$2x$` refusal branch removed | `parse_refuses_bcrypt_2x` FAILED (15 passed, 1 failed); reverted |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] PBKDF2 cap counts output blocks**
- **Issue:** a cap on iterations alone lets a long stored hash (many PRF blocks) multiply the verify cost.
- **Fix:** iterations x ceil(hash_len / block_len) <= 5,000,000. Exactly 5,000,000 with a single-block hash is
  still accepted (boundary test).
- **Commit:** 6403b9e

**2. [Rule 2 - Missing critical] Hash-length floor and size caps**
- **Issue:** a 1-byte stored hash would match unrelated passwords with probability 1/256. Unbounded salts, hashes
  and strings would allow allocation abuse.
- **Fix:** `MIN_HASH_BYTES` = 16 (scrypt, Firebase, PBKDF2; SHA-2 must equal the digest length), a non-empty salt
  for scrypt/Firebase, and `MAX_SALT_BYTES`, `MAX_HASH_BYTES` and `MAX_ENCODED_LEN`.
- **Commit:** 6403b9e, 6f5b204

**3. [Rule 2] Push-trigger path for the fuzz workflow**
- Added `crates/anvil-core/src/policy/password_import.rs` to the `push` paths of fuzz.yml (as was done for
  home_realm.rs), so pushes to main that touch the parser run the smoke. This is in addition to the matrix entry.

No other deviations. No files outside files_modified were touched.

## Notes for downstream plans

- 07-09 (dispatcher): call `parse_stored`, then `check_stored_caps` (fail closed on any error), then route on the
  variant. For Firebase, validate the profile parameters with `check_scrypt_params(mem_cost, rounds, 1)`.
- 07-14 (import service): use `parse_import_value(record["password"])` to get the reason codes, then
  `convert_import`. `HashPolicyError::reason()` gives the report string.

## Self-Check

- FOUND: crates/anvil-core/src/policy/password_import.rs
- FOUND: fuzz/fuzz_targets/password_hash_parse.rs
- FOUND: commit c0e623e
- FOUND: commit 6403b9e
- FOUND: commit 8b459c4
- FOUND: commit 6f5b204

Self-Check: PASSED
