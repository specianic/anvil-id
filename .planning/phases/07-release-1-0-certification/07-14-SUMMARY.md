---
phase: 07-release-1-0-certification
plan: 14
subsystem: user-import
tags: [password-import, user-import, hash-profiles, firebase, rehash, cas, cli, ADM-08]
requires:
  - "07-02 parse_import_value / convert_import / FIREBASE_PROFILE_PREFIX / parse_stored"
  - "07-03 HashProfileMaterial, PROFILE_SIGNER_KEY_PURPOSE, profile_signer_key_aad, audit actions"
  - "07-04 module/CLI skeletons"
  - "07-08 UserRepo::replace_password_if, PasswordProfileRepo"
  - "07-09 PasswordDispatcher (verifies with Some(profile))"
provides:
  - "anvil_core::service::user_import::{UserImportService, ImportRequest, RawRecord, ImportRecord, ImportReport, ImportCounts, RecordOutcome, Outcome, RejectReason, IMPORT_BATCH_MAX, MAX_RECORD_BYTES, check_batch_size, check_source}"
  - "anvil_core::service::hash_profile::{HashProfileService, NewHashProfile, HashProfileSummary, seal_signer_key, open_signer_key, check_new_profile}"
  - "FlowService: Firebase profile resolution at VerifyPassword and CAS rehash"
  - "anvilid users import (real), docs/IMPORT-EXPORT.md (import part)"
affects: [07-17 (admin import route + profiles API use these services), 07-22 (docs site links IMPORT-EXPORT), 07-23 (gate ticks ADM-08)]
tech-stack:
  added: []
  patterns:
    - "One import service, two front ends (CLI batches, admin route caps at IMPORT_BATCH_MAX)"
    - "Content-hash idempotency computed in memory on both sides; nothing stored"
    - "Profile material resolved in core and passed to the hasher; web adapter never reads storage"
key-files:
  created:
    - crates/anvil-web/tests/import_login.rs
    - crates/anvilid/tests/users_import_cli.rs
    - docs/IMPORT-EXPORT.md
  modified:
    - crates/anvil-core/src/service/user_import.rs
    - crates/anvil-core/src/service/hash_profile.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvilid/src/users_import.rs
  deleted:
    - crates/anvilid/tests/users_import_skeleton.rs
decisions:
  - "Service input is RawRecord { line, text } (NDJSON lines), parsed in the service, so JSON errors get line numbers and invalid_record; RawRecord::from_ndjson helps the admin route"
  - "HashPolicyError::Malformed maps to reason invalid_record (the plan's reason list has no `malformed`)"
  - "Same email twice in one batch: the second is invalid_record; same id twice: id_conflict (dry run and real run agree)"
  - "Existing email with a different record id: id_conflict (ids are never changed, even with update)"
  - "A record without password leaves the credential out of the comparison and untouched; with update and a password, the password is reset to the imported hash (documented)"
  - "Dry runs still record one users_imported event with dry_run: true (the must-have asks for the flag); no user/credential/attribute rows are written"
  - "HashProfileService returns HashProfileSummary (no key, no sealed blob); 07-17 builds its DTO from it"
  - "Missing profile or an unopenable sealed key at sign-in: verify(…, None) -> dispatcher fails closed, ordinary login failure; storage errors still propagate"
  - "User + credential are created atomically (UserRepo::create); attributes are written right after, validated beforehand"
metrics:
  duration: ~95min
  completed: 2026-11-26
requirements: [ADM-08 (not ticked; the gate 07-23 ticks it)]
---

# Phase 7 Plan 14: User import with legacy hashes Summary

One core `UserImportService` imports NDJSON user records with legacy password hashes,
idempotently and audited; `HashProfileService` keeps Firebase signer keys sealed with the KEK;
sign-in verifies imported hashes (resolving Firebase profiles in core) and rehashes to Argon2id
with a compare-and-swap; `anvilid users import` streams files in batches of 1,000.

## Service APIs

```rust
// service::user_import
pub const IMPORT_BATCH_MAX: usize = 1000;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub struct RawRecord { pub line: usize, pub text: String }          // Debug: line + len only
impl RawRecord { pub fn from_ndjson(body: &str) -> Vec<RawRecord> } // skips blank lines
pub struct ImportRecord { email, email_verified, claims, attributes, id: Option<Value>, password: Option<Value> } // deny_unknown_fields; Debug redacts password
pub struct ImportRequest<'a> { records: Vec<RawRecord>, dry_run, update, source: Option<&'a str>, actor: AuditActor, ctx: &'a RequestContext }
pub struct UserImportService { storage, clock, check: Arc<dyn AttributeSchemaCheck> }
impl UserImportService { pub async fn import(&self, tenant: TenantId, req: ImportRequest<'_>) -> Result<ImportReport, CoreError> }
pub fn check_batch_size(n) / check_source(Option<&str>) -> Result<(), CoreError>   // Validation on "records" / "source"

// service::hash_profile
pub struct NewHashProfile { name, kind: ProfileKind, signer_key: SecretBox<[u8]>, salt_separator: Vec<u8>, rounds: u32, mem_cost: u8 }
pub struct HashProfileSummary { id, name, kind, salt_separator, rounds, mem_cost, created_at } // no key material
pub struct HashProfileService { storage, clock, kek: Arc<Kek> }
impl HashProfileService {
    create(tenant, NewHashProfile, actor, ctx) -> HashProfileSummary   // Conflict on duplicate name; audited
    list(tenant) / get(tenant, id) / exists(tenant, id)
    delete(tenant, id, actor, ctx)                                     // NotFound; Conflict while count_references > 0; audited
    material_for(tenant, id) -> Option<HashProfileMaterial>            // Internal if the sealed key does not open
}
pub fn seal_signer_key / open_signer_key / check_new_profile  // limits: name 1-64, key 1-256 B, separator <= 64 B, check_scrypt_params(mem_cost, rounds, 1)
```

## Report schema (serde, for 07-17)

```json
{"dry_run": false,
 "counts": {"created": 0, "unchanged": 0, "conflict": 0, "updated": 0, "rejected": 0, "weak": 0},
 "records": [{"line": 1, "outcome": "created|unchanged|conflict|updated|rejected",
              "reason": "invalid_email|invalid_record|unknown_scheme|weak_parameters|over_cap|refused_variant|unknown_profile|id_conflict",
              "user_id": "uuid", "weak": false}]}
```
`reason` and `user_id` are omitted when absent. Audit `users_imported` details: `created`,
`unchanged`, `conflict`, `updated`, `rejected`, `weak`, `dry_run`, `source`.

## flow.rs

`Effect::VerifyPassword` calls `hash_profile_for(tenant, phc)`: only for strings starting with
`FIREBASE_PROFILE_PREFIX` it parses the profile id and calls `material_for`; `None` on a missing
profile or a key that does not open. `rehash(tenant, user, old_phc, password)` uses
`replace_password_if`; a `false` result is ignored.

## CLI behaviour

`anvilid users import <FILE|-> [--tenant default] [--dry-run] [--update] [--source LABEL]`: opens
storage like tenant_config.rs (`open_for_cli`), resolves the tenant (error if unknown), reads lines
with a 64 KiB + 1 cap (longer lines are cut and rejected by the service; non-UTF-8 lines become
`invalid_record`), skips blank lines, batches 1,000 records per service call. Summary on stdout:
batches, counts, weak count, `line N: <reason>` for rejections, conflicting line numbers. Exit
non-zero iff a record was rejected (stderr: "N record(s) rejected ..."); conflicts alone exit 0.

## Tests

- anvil-core (`cargo test -p anvil-core --lib -- service::user_import service::hash_profile`, 11 passed):
  `import_batch_cap_enforced`, `rejection_reason_codes`, `valid_record_keeps_id_and_converts_password`,
  `firebase_record_names_its_profile`, `content_hash_ignores_key_order_and_sees_every_field`,
  `debug_and_report_never_carry_the_hash`, `ndjson_split_keeps_line_numbers`, `source_label_checked`,
  `profile_signer_key_aad_bound`, `new_profile_validation`, `new_profile_debug_redacts_the_signer_key`.
- anvil-web `tests/import_login.rs` (SQLite, 11 passed): `imported_users_log_in_with_old_password_and_are_rehashed`
  (bcrypt Openwall U*U, scrypt RFC 7914 N=1024, Firebase published vector with a created profile,
  PBKDF2-SHA1 c=4096 RFC 6070 test 5, Django pbkdf2_sha256 and salted SHA-256 computed with aws-lc-rs,
  Argon2i PHC README; UI login, then `$argon2id$`, then login again), `imported_wrong_password_fails`,
  `imported_rehash_cas_keeps_concurrent_change`, `imported_firebase_missing_profile_fails_closed`,
  `imported_over_cap_hash_refused_at_import`, `import_outcomes_idempotency_and_dry_run`,
  `import_preserves_ids_and_detects_id_conflicts`, `import_batch_cap_enforced`,
  `profile_signer_key_sealed_and_never_returned`, `profile_delete_refused_while_referenced`,
  `import_never_leaks_hash` (report JSON/Debug, every audit event, a refused-batch error, and all
  tracing output captured by a test subscriber, including logins).
- anvilid `tests/users_import_cli.rs` (5 passed): help flags, no-installation error,
  `mixed_file_rerun_and_dry_run`, `conflict_needs_update`, `large_file_runs_in_batches` (2,500 lines,
  `batches: 3`, three `users_imported` events); stdout/stderr scanned for hash material.
- anvilid unit: `users_import::tests::next_line_splits_and_caps_long_lines`.
- Regression: `cargo test -p anvil-core --lib -- service::flow` 21 passed; anvil-web `flow_login` 9,
  `security_enumeration` 9, `flow_login_factors` 3 passed.

- `cargo test -p anvil-core -p anvilid -p anvil-web --locked --no-fail-fast` (shared tree, incl. other
  wave-3 plans' in-progress work): 2821 passed, 0 failed.
- `cargo clippy -p anvil-core --all-targets`, `-p anvil-web --tests`, `-p anvilid --all-targets` with
  `-D warnings`: clean. `scripts/check-release-graph.sh`: OK. No `TRANSITIONAL(07-14)` left.

## Mutation check

| Mutation | Result |
|---|---|
| `rehash` uses `set_password` instead of `replace_password_if` | `imported_rehash_cas_keeps_concurrent_change` FAILED (the concurrent password was overwritten); reverted |

## Task Commits

1. `b908bf8` feat(07-14): UserImportService and HashProfileService (sealed signer key)
2. `b5399fa` feat(07-14): first-login verification of imported hashes with CAS rehash
3. `f33d020` feat(07-14): anvilid users import CLI and import documentation

## Deviations from Plan

1. **[Test design] CAS race hook lives in a hasher wrapper, not a storage wrapper.** The rehash calls
   `PasswordHasher::hash` between the successful verify and `replace_password_if`; the test's
   `HookedHasher` stores a different password at that moment. Same race window, without
   re-implementing the whole `Storage`/`UserRepo` surface in the test. The mutation check proves it
   detects an unconditional write.
2. **[Test placement] Storage-backed import/profile tests are in import_login.rs** (core services
   have no storage-backed test harness; allowed by the plan). `profile_signer_key_aad_bound` and
   `import_batch_cap_enforced` exist as pure unit tests in core, and `import_batch_cap_enforced`
   again storage-backed.
3. **[Tracing] Core has no logging dependency**, so the tracing capture for `import_never_leaks_hash`
   runs in anvil-web with a hand-written minimal `tracing::Subscriber` (anvil-web has no
   tracing-subscriber dev-dependency and its manifest is not this plan's).
4. **[Test harness] Distinct peer addresses per UI login** in import_login.rs, because the per-address
   auth rate limit returned 429 after a few logins in one test.
5. Task 1 was committed as a single feat commit (tests and implementation together) rather than
   separate RED/GREEN commits.
6. `--update`/`--source` help text in users_import.rs corrected to what the service does (matched by
   email; the label goes to the audit log).

No files outside files_modified were touched. The bcrypt, scrypt and Firebase paths stay separable
(07-01 approval still pending): they are individual `ImportPassword` variants and test cases; this
plan adds no scheme-specific code outside the Firebase profile service.

## Not run

- Postgres-backed runs (no Docker; left for CI). import_login.rs uses `Backend::from_env()`, so it
  runs on Postgres in CI once 07-11's Postgres `password_profiles`/`replace_password_if` land.

## Self-Check: PASSED

Commits b908bf8, b5399fa, f33d020 exist; import_login.rs, users_import_cli.rs, IMPORT-EXPORT.md exist;
users_import_skeleton.rs is deleted.
