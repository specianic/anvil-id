---
phase: 02-release-0-1-first-login
plan: 06
subsystem: storage-postgres
tags: [postgres, sqlx, storage, contract-suite, concurrency, secrets-at-rest]
requires:
  - phase: 02-02
    provides: 0.1 storage ports, domain model, 67-test contract suite
  - phase: 02-01
    provides: anvil_jose::encoding::secret_hash, scripts/sqlx.sh crate filter
provides:
  - "PostgresStorage implementing every 0.1 port (9 repos + purge_expired)"
  - "migration 0002_release_0_1.sql (Postgres)"
  - "Postgres secrets-at-rest row-inspection test (tests/plaintext.rs)"
affects: [02-12, 02-20, anvilid]
tech-stack:
  added: []
  patterns:
    - "query_as! row structs + into_model() per aggregate; shared insert_* helpers generic over PgExecutor so intent methods reuse them inside one transaction"
    - "Races decided by one conditional statement (UPDATE ... WHERE consumed_at IS NULL RETURNING / INSERT ... ON CONFLICT DO UPDATE WHERE expired RETURNING) under READ COMMITTED"
    - "Outbox claim: UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING, sorted in Rust (RETURNING order is undefined)"
    - "purge_expired: batched DELETE ... WHERE ctid IN (SELECT ctid ... LIMIT 1000) per table"
key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0002_release_0_1.sql
    - crates/anvil-storage-postgres/src/{users,clients,keys,sessions,flows,setup,outbox}.rs
    - crates/anvil-storage-postgres/tests/plaintext.rs
  modified:
    - crates/anvil-storage-postgres/src/{lib,convert,tenants,grants}.rs
    - crates/anvil-storage-postgres/tests/support/mod.rs
    - crates/anvil-storage-postgres/.sqlx/
  deleted:
    - crates/anvil-storage-postgres/src/pending.rs
key-decisions:
  - "token_family, authorization_code and refresh_token reference only tenant (and code/refresh -> family); no FK to user/client/session, so deleting a user or client revokes families instead of deleting them"
  - "Lists are text[]; structured documents (settings, claims, params, payload, claims request) jsonb; JWKs and flow state text so they round-trip byte for byte"
  - "UserRepo::delete / ClientRepo::delete stamp revoked_at with date_trunc('milliseconds', now()) because the port passes no timestamp"
  - "complete_verification rolls back (token stays unconsumed) when the user's email changed; the token can never succeed anyway"
  - "install: no pre-check; any Conflict is re-classified as AlreadyInstalled iff the system tenant exists, else surfaced as Conflict"
requirements-completed: [OPS-02, OIDC-03, OIDC-05, QUAL-02]
duration: ~50min
completed: 2026-11-25
---

# Phase 2 Plan 06: Postgres backend for every 0.1 storage port Summary

**PostgresStorage now implements all nine 0.1 repositories and `purge_expired`. All 67 contract tests pass on Postgres 18 (testcontainers), including the 32-way consume, 16-way rotate, jti, recovery and setup concurrency tests. Repeated runs (4x) were stable. A row-inspection test proves that secrets are stored only as 32-byte hashes.**

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Migration 0002 and tenant, client, key, setup and outbox repositories | 504a213 |
| 2 | User, session, flow and grant repositories, purge, shim removed | 7f5c892 |
| 3 | Plaintext row-inspection test and final metadata | 1b07825 |

## What was built

- **Migration 0002** adds `tenant.host` with a partial unique index. It creates `user` (quoted, unique (tenant, email), partial unique (tenant, username)), `credential` (PK (user_id, kind)), `self_service_token`, `client`, `signing_key` (partial unique `(tenant_id, alg) WHERE state='active'`), `browser_session`, `authorization_request`, `flow`, `token_family`, `refresh_token`, `replay_guard` (PK (tenant, kind, value_hash)), `admin_setup_token` and `email_outbox`. All hash columns have `CHECK (octet_length = 32)` and all enum columns have CHECK lists. Every tenant-scoped table has `ON DELETE CASCADE`. `authorization_code` is changed in place with ALTERs: auth context columns are added, `code_challenge` becomes nullable, `token_family_id` becomes NOT NULL with a FK, and the tenant FK is recreated with CASCADE.
- **Atomic contracts:**
  - `rotate_refresh` is one transaction: a conditional UPDATE, then insert the child and return the family. With 0 rows it classifies the result: if the token was consumed it revokes the family (`refresh_reuse`) and returns ReuseDetected, otherwise NotFound.
  - `record_jti` is `INSERT ... ON CONFLICT DO UPDATE ... WHERE replay_guard.expires_at <= now RETURNING`.
  - `complete_setup` consumes the token with `UPDATE admin_setup_token ... WHERE used_at IS NULL AND expires_at > now RETURNING`. Every later failure rolls the consumption back.
  - `complete_recovery` consumes the token, upserts the password, verifies the email, revokes sessions and families, and enqueues the notice, all in one transaction.
- **Outbox** claims with `FOR UPDATE SKIP LOCKED`. One claim also increments `attempts` and sets `next_attempt_at = now + lease`.
- **`.sqlx/`** was regenerated with 75 queries. Stale Phase 1 files were removed, and `scripts/sqlx.sh check crates/anvil-storage-postgres` passes.

## Verification

- `cargo test -p anvil-storage-postgres`: 5 unit, 67 contract and 1 plaintext test pass.
- `cargo clippy -p anvil-storage-postgres --all-targets -- -D warnings`: clean (online and with `SQLX_OFFLINE=true`).
- `scripts/sqlx.sh check crates/anvil-storage-postgres`: passes.
- `src/pending.rs` is gone, and `grep Unsupported crates/anvil-storage-postgres/src` finds nothing.

## Duplication cost vs SQLite

The Postgres crate is about 2,700 lines (src + migration 0002). The SQLite crate is about 3,100 lines. Most of the duplication is SQL text and row-to-model mapping. The concurrency logic differs on purpose. Postgres uses row locks with READ COMMITTED re-evaluation and `SKIP LOCKED`. SQLite uses one writer connection. So only the mapping code is truly shared logic. A shared "row mapping" layer is not worth adding: the column types differ (uuid/timestamptz/jsonb/text[] vs BLOB/INTEGER ms/TEXT JSON), and the contract suite already holds the two backends to the same behaviour. The real cost is that every port change touches both crates, and both `.sqlx/` directories need a fresh prepare.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Built and tested in a private git worktree**
- **Found during:** Task 1
- **Issue:** Parallel wave-2 plans had uncommitted, non-compiling edits in `anvil-core` in the shared working tree, so `cargo build -p anvil-storage-postgres` failed outside this crate.
- **Fix:** Built, prepared `.sqlx/` and tested in a detached worktree at HEAD (`target/wt-02-06`, since removed), with this crate synced in. Only files in this crate were committed from the main tree.

**2. [Rule 3 - Blocking] tests/support/mod.rs passes the database URL**
- **Found during:** Task 3
- **Issue:** The row-inspection test needs a plain connection to the per-test database, but the factory exposed no URL. The file is in this crate but not in the plan's `files_modified`.
- **Fix:** `TestStorage._guard` now holds the URL `String`, and `plaintext.rs` downcasts it. The contract suite is unchanged.
- **Commit:** 1b07825

**3. [Rule 2 - Correctness] Positive controls in the plaintext test**
- The scan also has to find the clear-text user email and each stored hash. Without that, an empty scan could pass vacuously.

## Contract issues

None found. One note for the orchestrator: `UserRepo::delete` and `ClientRepo::delete` take no `now` parameter, so the family `revoked_at` comes from the database clock (truncated to ms) rather than from the caller. If that matters for audit consistency, a later port revision could add `now`.

## Self-Check: PASSED
