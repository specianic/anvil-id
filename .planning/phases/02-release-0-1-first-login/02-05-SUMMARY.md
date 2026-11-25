---
phase: 02-release-0-1-first-login
plan: 05
subsystem: storage-sqlite
tags: [sqlite, sqlx, storage, migrations, atomicity, secrets-at-rest]
requires:
  - phase: 02-02
    provides: 0.1 storage ports, domain model, 67-test contract suite
  - phase: 02-01
    provides: anvil-jose encoding::secret_hash (dev-dependency), sqlx.sh crate filter
provides:
  - SQLite implementation of every 0.1 storage port (no Pending, no Unsupported)
  - migration 0002_release_0_1.sql (STRICT tables for all 0.1 aggregates)
  - Storage::purge_expired on SQLite (rowid-batched)
  - secrets_never_stored_plaintext row-inspection test
affects: [02-07, 02-08, 02-09, 02-10, 02-12, anvilid]
tech-stack:
  added: []
  patterns:
    - "insert_* helpers take &mut SqliteConnection so the same insert serves single calls and intent transactions"
    - "single-statement partial updates (COALESCE / CASE WHEN set-flag) so a conflict changes nothing"
    - "composite FKs (tenant_id, user_id) -> user(tenant_id, id) for defence-in-depth tenant isolation"
key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0002_release_0_1.sql
    - crates/anvil-storage-sqlite/src/{users,clients,keys,sessions,flows,setup,outbox}.rs
    - crates/anvil-storage-sqlite/tests/plaintext.rs
  modified:
    - crates/anvil-storage-sqlite/src/{lib,convert,tenants,grants}.rs
    - crates/anvil-storage-sqlite/.sqlx/ (Phase 1 query files replaced)
  deleted:
    - crates/anvil-storage-sqlite/src/pending.rs
key-decisions:
  - "Phase 1 authorization codes are not carried over by 0002 (they lack the new NOT NULL auth context and live minutes); the table is replaced, and a unit test proves 0002 applies on a populated Phase 1 DB"
  - "Families have no FK to user/session/client (they outlive them, revoked); codes, credentials, sessions and self-service tokens cascade from user via composite (tenant_id, user_id) FKs"
  - "UserRepo::delete and ClientRepo::delete take no `now`, so the family revocation is stamped with the storage clock (truncate_to_ms(now_utc))"
  - "complete_verification on a changed email rolls back, so the token is not consumed"
  - "purge_expired also deletes idle-expired sessions, sent outbox mails, and families past absolute expiry that no live code references (their unusable refresh tokens cascade)"
  - "rotate_refresh rejects a child whose family_id differs from the consumed token's family with Conflict (rolled back)"
requirements-completed: [OPS-02, OIDC-03, OIDC-05, QUAL-02]
duration: 30min
completed: 2026-11-25
---

# Phase 2 Plan 05: SQLite storage for every 0.1 port Summary

**SQLite now implements all nine 0.1 storage repos plus purge. Every multi-row intent runs as one transaction on the single writer connection. All 134 contract tests pass on in-memory and file (WAL) databases, including the 32-way consume, 16-way rotation, jti, recovery and setup concurrency tests. A row-inspection test shows that only 32-byte digests of secrets ever reach disk.**

## Performance

- **Duration:** about 30 min
- **Completed:** 2026-11-25
- **Tasks:** 3/3
- **Files:** 16 source/test/migration files, plus refreshed `.sqlx/` (74 query files)

## Accomplishments

- **Migration 0002** (forward-only):
  - Tenant gains `host` (partial unique index) and `settings` JSON.
  - New STRICT tables: user, credential, client, signing_key (partial unique index on active per (tenant, alg)), browser_session, flow, authorization_request, token_family, refresh_token, replay_guard, self_service_token, admin_setup_token, email_outbox.
  - authorization_code is recreated with the authentication context and a mandatory `token_family_id` FK.
  - Every tenant-scoped table cascades from tenant. There are CHECK constraints on blob lengths, enum values and JSON validity, plus expiry indexes for purge.
- **Repos:** each aggregate has its own module. Rows decode through `TryFrom<Row>`, and bad data comes back as `StorageError::Corrupt`. Lists use keyset pagination (fetch `limit + 1`). Partial updates are single statements, so a unique conflict changes nothing.
- **Atomic intents on the writer:**
  - `create_code` inserts the family, then the code.
  - `consume_code` is a single `UPDATE ... RETURNING` followed by a read that classifies losers.
  - `rotate_refresh` runs the conditional consume in one transaction. Reuse revokes the family as `refresh_reuse`, keeping any earlier reason.
  - `record_jti` is an `INSERT ... ON CONFLICT DO UPDATE ... WHERE expired` (1 row means Recorded, 0 means Replayed).
  - `UserRepo::create`, `issue_self_service_token`, `complete_verification` and `complete_recovery` each run as one transaction. Recovery upserts the password, verifies the email, revokes sessions and families, and enqueues the notice.
  - `install` and `complete_setup` also run as one transaction each.
  - `claim_due` is one `UPDATE ... RETURNING`. Results are re-sorted oldest-first because SQLite does not guarantee RETURNING order.
- **purge_expired** deletes in batches of up to 1000 rows per statement (rowid subquery) and keeps consumed-but-unexpired codes and refresh tokens.
- `pending.rs` and every `StorageError::Unsupported` are gone from the crate, along with the transitional dead-code expects in `convert.rs`.

## Task Commits

1. **Task 1: Migration 0002 and the tenant, client, key, setup and outbox repos:** `a12d7d8` (feat)
2. **Task 2: User, session, flow and grant repos, purge, shim removed:** `fbca624` (feat)
3. **Task 3: Plaintext row-inspection test and current sqlx metadata:** `f9bfcb1` (test)

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 2 - Correctness] A test proves migration 0002 applies on a Phase 1 database**
- **Found during:** Task 2
- **Issue:** The plan requires 0002 to stay valid on a Phase 1 database, but nothing tested that.
- **Fix:** Added the unit test `migration_0002_applies_on_a_phase1_database`. It applies only 0001, seeds a Phase 1 tenant and code, runs the full migrator, and checks that the tenant survives with default settings.
- **Commit:** fbca624

**2. [Rule 2 - Test strength] The plaintext scan has positive controls**
- **Found during:** Task 3
- **Issue:** A scan that silently matched nothing would make "no plaintext found" pass even if secrets were stored.
- **Fix:** The test first checks that the scanner finds a known plaintext value (the client name, TEXT) and a stored digest (BLOB). It then checks that none of the 11 markers appears anywhere. Flow CSRF/cookie and the jti hash are covered too, beyond the plan's list.
- **Commit:** f9bfcb1

**3. [Process] Task 1's contract tests are not all green on their own**
- `complete_setup_*` reads back through `users()`, and `client_delete_revokes_families` reads families through `grants()`. Both were still `Pending` at the Task 1 commit, so these tests failed until Task 2. Every tenant, client, key, install/peek-setup and outbox test passed at Task 1. Everything passes after Task 2.

## Contract issues

None. The shared contract suite was not modified, and no backend-side workaround was needed.

## Notes for the orchestrator and downstream plans

- **Possible plaintext in outbox payloads (02-08 / mail):** `NewEmail.payload` is free-form template data. If verification, recovery or invitation emails put the token link into the payload, the plaintext token sits in `email_outbox.payload` until the mail is sent and purged. That is outside what this test seeds and the ports allow it. Consider building the link at send time from a non-secret reference, or accept and document it. `purge_expired` already deletes sent mails.
- `UserRepo::delete` and `ClientRepo::delete` take no `now`, so storage stamps the revocation itself. Adding a `now` parameter would make them testable like the other methods. That is a port change, so I left it alone.
- Table names follow the plan (`user`, `client`, ...). The outbox recipient column is `recipient`, because `to` is awkward as SQL.

## Verification

- `cargo test -p anvil-storage-sqlite`: 6 unit tests, 134 contract tests (67 × memory/file) and 1 plaintext test pass. The contract run was repeated 5× with no flakes.
- `scripts/sqlx.sh check crates/anvil-storage-sqlite`: exit 0. The Phase 1 query files were removed by prepare.
- `cargo clippy -p anvil-storage-sqlite --all-targets -- -D warnings`: clean.
- `src/pending.rs` is absent, and `grep -rn Unsupported crates/anvil-storage-sqlite/src` finds nothing.

## Self-Check: PASSED
