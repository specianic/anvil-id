---
phase: 03-release-0-2-secure-by-default
plan: 32
subsystem: storage
tags: [postgres, sqlite, migration, tenant-isolation, base64url, gap-closure]
requires:
  - phase: 03-05
    provides: SQLite 0003 with composite (tenant_id, user_id) FKs and sealed TOTP text
  - phase: 03-06
    provides: Postgres 0003 and the runtime tenant-membership pre-checks
  - phase: 03-16
    provides: 0.1 -> 0.2 upgrade test and check-migrations lint
provides:
  - One base64url implementation (anvil-jose::encoding) used by the SQLite backend
  - Postgres schema-level tenant isolation for every user-owned table, the same as SQLite
affects: [phase-03-gate]
tech-stack:
  added: []
  patterns:
    - "Composite FK (tenant_id, user_id) -> \"user\"(tenant_id, id) on every user-owned table, both backends"
    - "NOT VALID FK when an upgraded database may hold harmless legacy orphans; new rows are still checked"
key-files:
  created: []
  modified:
    - crates/anvil-jose/src/encoding.rs
    - crates/anvil-storage-sqlite/Cargo.toml
    - crates/anvil-storage-sqlite/src/convert.rs
    - crates/anvil-storage-sqlite/src/credentials.rs
    - crates/anvil-storage-postgres/migrations/0003_release_0_2.sql
    - crates/anvil-storage-postgres/src/lib.rs
    - crates/anvil-storage-postgres/src/credentials.rs
    - crates/anvil-storage-postgres/src/consent.rs
key-decisions:
  - "SQLite keeps only a thin sealed_from_text wrapper around anvil_jose::encoding::b64url_decode (Corrupt mapping); encoding calls anvil_jose::encoding::b64url directly"
  - "anvil-jose becomes a normal dependency of anvil-storage-sqlite (it was already transitive through anvil-core; check-deps.sh passes)"
  - "Postgres 0003 (unreleased) amended: UNIQUE (tenant_id, id) on \"user\"; composite FKs on credential, self_service_token, browser_session (swapped from the 0.1 single-column FKs), recovery_code, consent_grant, and authorization_code (NOT VALID)"
  - "The 03-06 WHERE EXISTS pre-checks stay as defense in depth (clearer error, no query or .sqlx change)"
requirements-completed: []
duration: 35min
completed: 2026-11-25
---

# Phase 3 Plan 32: Storage follow-ups (shared base64url, Postgres composite tenant FKs) Summary

**The SQLite backend now uses the shared strict base64url from anvil-jose instead of its own copy. On Postgres, the schema itself now enforces tenant isolation for every user-owned table through composite (tenant_id, user_id) foreign keys, the same as SQLite.**

## Performance

- **Duration:** about 35 min
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Removed the hand-rolled `b64url_encode` and `b64url_decode` from `anvil-storage-sqlite/src/convert.rs`. The only replacement is `sealed_from_text`, which calls `anvil_jose::encoding::b64url_decode`. That decoder is strict: it rejects padding, the standard alphabet, whitespace and non-canonical trailing bits, and any non-canonical value still maps to `StorageError::Corrupt`. Extra strictness vectors were added to the anvil-jose test.
- Amended Postgres 0003, which is not released yet:
  - added a `user_tenant_id_key UNIQUE (tenant_id, id)` constraint as the target for the composite keys;
  - `credential`, `self_service_token` and `browser_session` now use composite FKs in place of their 0.1 `user_id` FKs;
  - `recovery_code` and `consent_grant` declare the composite FK in their `CREATE TABLE`;
  - `authorization_code` gets a composite FK, added `NOT VALID` (see deviations).
- New test `composite_tenant_foreign_keys_reject_cross_tenant_rows`. It runs raw SQL on a fully migrated database and checks three things for each of the six tables:
  - a row written under tenant A for a user of tenant B fails with SQLSTATE 23503;
  - the same row under the user's own tenant succeeds;
  - deleting the user still cascades to the row.
- The upgrade test now also seeds a 0.1 authorization code that points to a user who no longer exists, to show that 0003 still applies.

## Task Commits

1. **Task 1: Shared base64url in SQLite storage** - `75a6f12` (refactor)
2. **Task 2 RED: failing composite-FK test** - `b452beb` (test)
3. **Task 2 GREEN: Postgres composite tenant FKs** - `445c02f` (feat)

## Verification

- `cargo test -p anvil-jose -p anvil-storage-sqlite`: green. `cargo clippy` on both crates with `-D warnings`: clean. The grep confirms there is no `fn b64url_encode` or `fn b64url_decode` left in `convert.rs`.
- `cargo test -p anvil-storage-postgres`: lib 15/15, contract 114/114, plaintext 1/1, upgrade 116/116 (the 0.1 to 0.2 path plus the contract suite on upgraded databases).
- `scripts/check-migrations.sh`: OK. Released 0001 and 0002 are untouched.
- `scripts/check-deps.sh`: OK.
- `cargo clippy -p anvil-storage-postgres --all-targets -D warnings`: clean.
- `.sqlx` check: no queries changed. `cargo sqlx prepare --check` passes against a freshly migrated database (see deviations).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] anvil-jose moved from dev-dependency to normal dependency of anvil-storage-sqlite**
- **Found during:** Task 1
- **Issue:** anvil-jose was only a dev-dependency, so the library could not call `anvil_jose::encoding`.
- **Fix:** Moved it to `[dependencies]`. It was already a transitive dependency through anvil-core, and the ARCHITECTURE.md §4 rules and `check-deps.sh` both allow it.
- **Files modified:** crates/anvil-storage-sqlite/Cargo.toml
- **Commit:** 75a6f12

**2. [Rule 2 - Parity] Composite FKs also on self_service_token, browser_session and authorization_code**
- **Found during:** Task 2
- **Issue:** SQLite has composite FKs on these 0.1 tables too. On Postgres, `self_service_token` and `browser_session` only had a `user_id` FK, and `authorization_code` had no user FK at all.
- **Fix:** Added them in 0003. `authorization_code` uses `NOT VALID` for two reasons: 0.1 had no FK there, and deleting a user only revokes its token families. An upgraded database can therefore contain expired codes of deleted users. Those rows can no longer be used, and every new or updated row is still checked. Deleting a user now cascades to its codes, as on SQLite.
- **Files modified:** 0003_release_0_2.sql, src/lib.rs (tests)
- **Commit:** 445c02f

**3. [Rule 3 - Blocking] sqlx metadata check run against a separate dev database**
- **Found during:** Task 2 verification
- **Issue:** `scripts/sqlx.sh check` reuses the dev database `anvil_dev`. That database still has the old 0003 applied, so sqlx refuses with "migration 3 was previously applied but has been modified". Dropping and recreating `anvil_dev` was not permitted.
- **Fix:** Created a new database, `anvil_dev_0332`, on the same dev container. Ran the script's steps against it by hand (`sqlx migrate run` and `cargo sqlx prepare --check`). Both passed.
- **Follow-up:** Developers need to recreate their local `anvil_dev` once before `scripts/sqlx.sh` works again.

## Next Phase Readiness

Storage-level gaps found in 03-05 and 03-06 are closed for the Phase 3 gate.

## Self-Check: PASSED
