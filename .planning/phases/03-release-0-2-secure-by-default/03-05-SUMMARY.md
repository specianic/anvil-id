---
phase: 03-release-0-2-secure-by-default
plan: 05
subsystem: storage-sqlite
tags: [sqlite, migrations, passkeys, totp, recovery-codes, consent, audit, job-lease, sqlx]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: Phase 3 ports, contract suite and TRANSITIONAL shims (03-02)
provides:
  - SQLite migrations 0003 (transactional) and 0004 (no-transaction token_family rebuild)
  - Every Phase 3 storage port method on SQLite with compile-checked sqlx queries
  - AuditRepo, MailSettingsRepo and JobRepo on SQLite, wired into Storage
  - Plaintext inspection covering TOTP seeds, recovery codes, SMTP passwords, CAPTCHA secrets
affects: [03-06, 03-10, 03-12, 03-13, 03-14, 03-15, 03-16, 03-17, 03-21, 03-23, 03-24]
tech-stack:
  added: []
  patterns:
    - "Table rebuilds that touch referenced tables run as `-- no-transaction` migrations with foreign keys off; FK violations abort before COMMIT through a CHECK (n = 0) temp table fed by pragma_foreign_key_check"
    - "Repository helpers live in per-concern modules (credentials.rs, consent.rs); trait impls in users.rs/grants.rs delegate"
    - "Sealed bytes kept in TEXT columns as unpadded base64url (local encoder in convert.rs; no new dependency)"
key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0003_release_0_2.sql
    - crates/anvil-storage-sqlite/migrations/0004_release_0_2_token_family.sql
    - crates/anvil-storage-sqlite/src/{credentials,consent,audit,mail_settings,jobs}.rs
  modified:
    - crates/anvil-storage-sqlite/src/{lib,convert,users,clients,sessions,grants,keys,flows}.rs
    - crates/anvil-storage-sqlite/.sqlx/
    - crates/anvil-storage-sqlite/tests/plaintext.rs
  deleted:
    - crates/anvil-storage-sqlite/src/pending.rs
key-decisions:
  - "0004 uses sqlx 0.9.1's native `-- no-transaction` support (verified in sqlx-sqlite migrate.rs: no_tx migrations are executed without a wrapping transaction). The script runs PRAGMA foreign_keys=OFF; BEGIN; rebuild; integrity check; COMMIT; PRAGMA foreign_keys=ON. Codes and refresh tokens survive; no fallback was needed"
  - "Last 0.1 SQLite migration version = 2; 0.2 adds versions 3 and 4"
  - "Migrated password credentials get randomblob(16) ids (not version-tagged UUIDs); new password rows get CredentialId::new_v7()"
  - "TOTP sealed seed stored as base64url in credential.secret; last step and passkey counter share credential.counter"
  - "credential has CHECK ((kind = 'webauthn') = (external_id IS NOT NULL)) on top of the partial unique indexes"
duration: 20min
completed: 2026-11-25
---

# Phase 3 Plan 05: SQLite storage for Release 0.2 Summary

**SQLite now implements the full 0.2 storage contract (228/228 contract tests on memory and file databases, 0 shims). Migrations 0003 and 0004 bring a populated 0.1 database to the 0.2 schema without losing a code, refresh token, family, flow or password.**

## Performance

- **Duration:** about 20 min
- **Tasks:** 3
- **Files:** 18 source/migration/test files plus regenerated `.sqlx/` metadata

## Accomplishments

### Migrations

- **0003_release_0_2.sql** (transactional):
  - `credential` rebuild: own `id`, kinds `password|webauthn|totp`, plus `external_id`, `counter`, `backup_eligible`, `label` and `last_used_at`. Partial unique indexes: one password per user, one TOTP per user, one `external_id` per tenant. Password rows are copied over.
  - `flow` rebuild adding kinds `settings` and `consent`, copying every row.
  - Both rebuilds are annotated `-- anvil:non-destructive-rebuild`. Neither table has inbound foreign keys, so dropping them inside the transaction cascades nothing.
  - New tables: `recovery_code`, `consent_grant`, `access_token`, `audit_event` (3 indexes), `email_template`, `smtp_settings`, `job_lease`.
  - New `client` columns: `token_format`, `consent_mode`, `id_token_signed_response_alg`, `can_introspect`. New `browser_session` columns: `ip`, `user_agent`.
- **0004_release_0_2_token_family.sql** (`-- no-transaction`): the SQLite 12-step rebuild of `token_family` with the new revoke reasons, in this order:
  1. `PRAGMA foreign_keys = OFF; BEGIN;`
  2. create `token_family_new`, then `INSERT ... SELECT` every row
  3. `DROP` the old table, `RENAME` the new one, recreate the indexes
  4. `CREATE TEMP TABLE anvil_fk_violations (n INTEGER NOT NULL CHECK (n = 0)); INSERT ... SELECT count(*) FROM pragma_foreign_key_check;`. Any dangling reference fails the CHECK and aborts before COMMIT. I confirmed with the sqlite3 CLI that the CHECK fires.
  5. `COMMIT; PRAGMA foreign_keys = ON;`

  The rebuild can be re-run safely if the process dies between COMMIT and sqlx's bookkeeping insert.

### Data preservation proof

- New unit test `migrations_0003_0004_preserve_a_populated_0_1_database` (lib.rs). It applies 0001+0002 only and asserts the last version is 2. It then seeds a tenant, a user, a password credential, a flow, two families (one revoked with `refresh_reuse`), one code and two refresh tokens, and runs the remaining migrations. It asserts:
  - every row survives, and the password keeps its secret and timestamps and gets a 16-byte id;
  - `consent_revoked` is now accepted;
  - `PRAGMA foreign_keys` = 1 on the migrating connection, and `pragma_foreign_key_check` is empty;
  - a dangling refresh-token insert is rejected;
  - deleting a family still cascades to its code and refresh token. This shows the references were re-bound to the rebuilt table.
- `sqlx migrate run` (sqlx-cli 0.9.1) also applied 3 and 4 to the dev database.

### Repositories

- **credentials.rs**:
  - `update_passkey` is one UPDATE `... AND (counter < ?new OR (?new = 0 AND counter = 0))`.
  - `advance_totp_step` is one UPDATE `... AND (counter IS NULL OR counter < ?step)`; the last step is stored in `counter`.
  - `consume_recovery_code` is one UPDATE `... AND used_at IS NULL`. The notice is enqueued in the same transaction only if that UPDATE changed one row.
  - `create_totp`, `delete_credential` (a TOTP takes its recovery codes with it; passwords are excluded by `kind IN ('webauthn','totp')`) and `replace_recovery_codes` each run as one writer transaction.
- **consent.rs**: `upsert_consent` reads the grant and merges the scopes as a sorted union (a revoked grant is reset to the new scopes) in Rust, then writes with `INSERT ... ON CONFLICT DO UPDATE`, all in one writer transaction. `revoke_consent` revokes the grant and the user's families for that client (`consent_revoked`) in one transaction.
- **grants.rs**: `create_family` (shares `insert_family` with `create_code`), `create_access_token`, `find_access_token` (in any state, with its family), `revoke_access_token`.
- **sessions.rs**: `get`, `list_for_user` (newest first), `list` (keyset on id), `revoke_with_families`, `revoke_all_for_user(except)` (UPDATE ... RETURNING, then revoke families per session, in one transaction). `ip` and `user_agent` are persisted.
- **keys.rs**: `list`; `promote` runs the retire UPDATE before the activate UPDATE, requires each to change exactly one row, rolls back otherwise, and maps a second active key to Conflict; `delete_expired`.
- **flows.rs**: `swap_state` as one conditional UPDATE.
- **audit.rs**: keyset pagination on `id DESC` with a fixed set of `(?n IS NULL OR col = ?n)` predicates, so the query stays compile-checked. `purge_before` is installation-wide.
- **mail_settings.rs**: template and SMTP upserts and deletes.
- **jobs.rs**: `try_lease` is one `INSERT ... ON CONFLICT(name) DO UPDATE ... WHERE leased_until <= now OR owner = excluded.owner`.
- `purge_expired` also deletes expired opaque access tokens. Recovery codes and audit rows are not purged there.
- `clients.rs`/`sessions.rs`: the 03-02 guards (`ensure_phase3_defaults`, `ensure_phase3_update_absent`, `ensure_no_request_context`) are removed and the new columns are read and written. `pending.rs` is deleted. `grep TRANSITIONAL|Unsupported(` in `src/` returns nothing.

### Plaintext inspection

- The test now also stores:
  - a TOTP credential sealed with `TOTP_SEED_PURPOSE` and `credential_aad(id)`;
  - 10 recovery codes hashed with `recovery_code_hash`;
  - an opaque access token;
  - SMTP settings with a sealed password;
  - a sealed CAPTCHA secret in tenant settings.
- It scans every column and also the raw bytes of the database file and its WAL (while the storage is open) for: the seed bytes, base32 and base64url; every recovery code, raw and normalised; the SMTP password; the CAPTCHA secret. Positive controls show the raw scan finds the SMTP host and the CAPTCHA site key.

## Task Commits

1. **Task 1: Migrations 0003 and 0004:** `0b42b91`
2. **Task 2: Repository implementations and Storage wiring:** `8d86b23`
3. **Task 3: Plaintext inspection for new secrets:** `969a1e6`

## Verification

- `cargo test -p anvil-storage-sqlite`: lib 8/8, contract 228/228 (memory + file, including all concurrency tests), plaintext 1/1.
- `scripts/sqlx.sh check crates/anvil-storage-sqlite`: metadata current.
- `cargo clippy -p anvil-storage-sqlite --all-targets -- -D warnings`: clean.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] No base64 dependency in the SQLite crate**
- **Found during:** Task 2
- **Issue:** The TOTP sealed seed goes into the TEXT `secret` column as base64url. The crate has no base64 dependency, `anvil-jose` is dev-only here, and `Cargo.toml` is not in this plan's files.
- **Fix:** Added a small unpadded base64url encoder/decoder in `convert.rs`. The decoder rejects non-canonical input as Corrupt. A unit test covers round trips, known vectors and garbage.
- **Commit:** 8d86b23

**2. [Rule 2 - Correctness] Integrity check in 0004 aborts the migration**
- **Issue:** A bare `PRAGMA foreign_key_check` in a script only returns rows. It would not stop a rebuild that left dangling references.
- **Fix:** The violation count goes into a temp table with `CHECK (n = 0)`, so any violation aborts before COMMIT.
- **Commit:** 0b42b91

## Issues Encountered

- Between Task 1 and Task 2, the Task 1 commit leaves the SQLite repositories on the old credential schema. Password inserts fail at runtime until `8d86b23`. Both commits landed minutes apart.
- If 0004 failed midway, the migrating connection would be left inside an open transaction with foreign keys off. Startup fails on any migration error, so the process exits. The re-run is idempotent.
- Parallel plans had in-progress edits in the Postgres, web and binary crates. All commits used `git commit -- <paths>`, and only files of this plan were committed.

## Next Phase Readiness

- 03-06 (Postgres) can mirror this schema. Postgres needs no rebuild for the CHECK changes (`ALTER TABLE ... DROP/ADD CONSTRAINT`).
- 03-16's `scripts/check-migrations.sh` can rely on `-- anvil:non-destructive-rebuild` in 0003 (twice) and 0004.

## Self-Check: PASSED
