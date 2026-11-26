---
phase: 05-release-0-4-operate-it
plan: 07
subsystem: storage
tags: [postgres, sqlx, migrations, rbac, webhooks, skip-locked, dcr, cimd, attributes, upgrade]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 Phase 5 model, 05-02 storage ports, PostgresPending shims and the Phase 5 contract suite
provides:
  - Postgres migration 0006_release_0_4.sql (same logical schema as SQLite 0007)
  - PgRoles, PgAttributes, PgRegistration, PgWebhooks (FOR UPDATE OF d SKIP LOCKED claims)
  - ClientRepo registration columns, upsert_cimd, registration-token lookup and rotation on Postgres
  - Consent resources (sorted union, reset on re-grant after revocation)
  - Webhook enqueue inside AuditRepo::append (same transaction, Rust UUIDv7 ids)
  - Administrator role created by SetupRepo::install and assigned by complete_setup; 0006 backfill for upgraded installations
  - Retention: completed deliveries purged with the audit retention, IATs 7 days after expiry or revocation
  - 0.3 -> 0.4 upgrade test (fixtures/release_0_3.sql)
affects: [05-12, 05-14, 05-15, 05-19, 05-21, 05-23, OPS-03 HA path]

tech-stack:
  added: []
  patterns:
    - "Claim with joined endpoint: CTE `UPDATE … WHERE id IN (SELECT d.id … JOIN webhook_endpoint e … FOR UPDATE OF d SKIP LOCKED) RETURNING …`, then join the endpoint in the outer SELECT"
    - "Idempotent insert that reports 'held afterwards': `ON CONFLICT … DO UPDATE SET x = table.x RETURNING …` (DO NOTHING would return no row for an existing or concurrently inserted row)"
    - "Fan-out with Rust ids: select subscribed endpoint ids inside the transaction, generate one UUIDv7 per row, insert via `unnest($1::uuid[], $2::uuid[])`"
    - "Guarded upsert: `ON CONFLICT (tenant_id, client_id) DO UPDATE … WHERE client.registration_source = 'cimd'`; no returned row = Conflict"

key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0006_release_0_4.sql
    - crates/anvil-storage-postgres/src/roles.rs
    - crates/anvil-storage-postgres/src/attributes.rs
    - crates/anvil-storage-postgres/src/registration.rs
    - crates/anvil-storage-postgres/src/webhooks.rs
    - crates/anvil-storage-postgres/tests/fixtures/release_0_3.sql
  modified:
    - crates/anvil-storage-postgres/src/{lib,clients,consent,audit,setup,users}.rs
    - crates/anvil-storage-postgres/tests/upgrade.rs
    - crates/anvil-storage-postgres/.sqlx/
  deleted:
    - crates/anvil-storage-postgres/src/pending.rs

key-decisions:
  - "Webhook event types are not enumerated in a CHECK (length check only, validated on read), matching SQLite 0007, so a new WebhookEventType does not need a CHECK swap migration"
  - "Mirrored SQLite 0007's CHECKs: (previous_secret_enc IS NULL) = (previous_secret_expires_at IS NULL), (status = 'pending') = (completed_at IS NULL), last_http_status BETWEEN 100 AND 999"
  - "Backfilled administrator role id is gen_random_uuid() (v4): the only generator on every supported Postgres version; nothing depends on role id ordering. Description 'Full administrative access', same as SQLite"
  - "complete_setup fails with Conflict (rolling back the token consumption) if the admin tenant has no administrator role, the same rule as SQLite"
  - "AuditRepo::purge_before also deletes delivered/failed deliveries completed before the cutoff (return value counts audit events only); purge_expired drops IATs 7 days after expiry or revocation. Same rules as SQLite (05-06)"
  - "payload_json is text (byte-for-byte round trip), events text[], user.attributes / claim / consent resources jsonb, position and uses_remaining bigint (full u32 range)"

patterns-established:
  - "assign_role/assign_admin_role use DO UPDATE no-op conflicts so `true` always means the user holds the role afterwards, even under concurrent assignment"

requirements-completed: []  # Storage layer only; the requirements close with their service/web plans. Checkboxes are not ticked by wave plans (shared rules).

duration: ~70min
completed: 2026-11-26
---

# Phase 5 Plan 07: Postgres 0006 and every Phase 5 repository Summary

**Postgres now stores every Phase 5 entity. Migration 0006 adds roles, attributes, webhooks, initial access tokens, client registration columns and consent resources, and backfills administrators. Webhook claims use `FOR UPDATE OF d SKIP LOCKED`, so N nodes never claim the same row. All 190 contract tests, the upgrade suite (195, including the new 0.3 -> 0.4 test) and plaintext (2) pass on a local PG14 cluster. No TRANSITIONAL(05-07) is left.**

## Performance

- **Duration:** about 70 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 62 in the feature commit (19 source/migration files plus regenerated .sqlx), 2 in the test commit

## Schema (0006_release_0_4.sql)

Additive only, except the backfill. New columns use constant defaults (metadata-only).

- `role`: uuid id, tenant FK cascade, `org_id` nullable, `permissions text[]`, `UNIQUE (tenant_id, id)`. Also a partial unique index `role_tenant_name_key ON role (tenant_id, name) WHERE org_id IS NULL`.
- `role_assignment`: PK (tenant_id, role_id, user_id). It has composite FKs to `role (tenant_id, id)` and `"user" (tenant_id, id)`, both ON DELETE CASCADE, plus an index on (tenant_id, user_id).
- `attribute_definition`: PK (tenant_id, name). Columns: `schema jsonb`, `claim jsonb` (object or NULL), `position bigint`.
- `"user".attributes`: `jsonb NOT NULL DEFAULT '{}'`, with a CHECK that it is an object.
- `client`: `registration_source text DEFAULT 'static'` (CHECK static/dynamic/cimd), `metadata_expires_at timestamptz`, and `registration_access_token_hash bytea` (32 bytes). Index on (tenant_id, registration_source).
- `initial_access_token`: `token_hash bytea UNIQUE` (32 bytes) and `uses_remaining bigint` (NULL = unlimited). Index on (tenant_id, id).
- `consent_grant.resources`: `jsonb NOT NULL DEFAULT '[]'` (array).
- `webhook_endpoint`: `UNIQUE (tenant_id, name)`, `UNIQUE (tenant_id, id)`, `events text[]`, sealed `secret_enc` / `previous_secret_enc`.
- `webhook_delivery`: composite FK to the endpoint with ON DELETE CASCADE. `payload_json text`, status CHECK. Indexes: due (status, next_attempt_at), endpoint log (tenant_id, endpoint_id, id), and a partial index on completed_at.
- Backfill: if the `system` tenant exists, it gets the `administrator` role (`[admin:write]`), and every existing system-tenant user is assigned to it.

`scripts/check-migrations.sh`: OK. 0001-0005 are unchanged.

## Task Commits

1. **Tasks 1+2 code: migration 0006, all repositories, shim removal, .sqlx:** `155fc69` (feat)
2. **Task 2 upgrade test + 0.3 fixture:** `07725d0` (test)

## Verification

All Postgres runs below used a throwaway local **PostgreSQL 14** cluster:
- Binaries from `/usr/lib/postgresql/14/bin`, listening on 127.0.0.1 with trust auth, TCP only (`-k ''`).
- The data dir was in the session scratchpad. The cluster has been stopped and its data dir deleted.
- The tests reached it through an uncommitted `server_url()` patch in `tests/support/mod.rs` and `tests/upgrade.rs`. The patch was reverted before each commit; `git diff` on those files is clean apart from the committed upgrade test.

- `cargo test -p anvil-storage-postgres --test contract`: **190 passed**. This includes the 36 Phase 5 tests, the 8-way `webhook_claim_concurrent_each_row_once` and the 8-way `iat_single_use_concurrent_single_winner`.
- `--test upgrade`: **195 passed**. That is the 190 contract tests on upgraded databases, plus the 0.1/0.2/issuer upgrade tests, plus the new `upgrade_from_0_3_backfills_administrators_and_keeps_rows`.
- `--test plaintext`: **2 passed**.
- The final run was repeated with `SQLX_OFFLINE=true` after rustfmt and the clippy fix: same counts.
- The concurrency tests (`concurrent`, `single_winner`; 14 tests) were run 5 times, all green.
- **Mutation check:** with `FOR UPDATE OF d SKIP LOCKED` removed from `claim_due`, `webhook_claim_concurrent_each_row_once` failed 3 of 3 runs ("a row was claimed twice"). The lock is restored.
- Lib tests `composite_tenant_foreign_keys_reject_cross_tenant_rows` (now also covers `role_assignment`) and `migration_0003_upgrades_a_populated_0_1_database`: both passed. They were pointed at the local cluster through a temporary, reverted patch.
- `.sqlx` was regenerated with `cargo sqlx prepare` in the crate dir against a migrated `anvil_dev` database on the local cluster. `cargo sqlx prepare --check` is clean. No `.sqlx` file was hand-edited.
  - The first `--check` right after rustfmt reported missing queries, apparently a stale incremental build. Re-running prepare produced the same file set, and the next `--check` passed.
- `SQLX_OFFLINE=true cargo clippy -p anvil-storage-postgres --all-targets --locked -- -D warnings`: clean.
- `rustfmt --edition 2024 --check` on every touched .rs file: clean.
- `grep -rn "TRANSITIONAL(05-07)" crates/`: empty.

## Not run (left for CI)

- PG18 testcontainers runs (`just test-pg`), and `scripts/sqlx.sh check crates/anvil-storage-postgres` against the PG18 dev container. Docker is down here, and sqlx.sh hard-codes the Docker container on port 55432.
- The other Docker-only lib tests in `migrate.rs` (destructive-migration guard). They do not depend on this plan's code paths beyond 0006 being non-destructive. The `migrate_embedded_migrations_are_not_destructive` check is name-based, and 0006 has no `destructive` prefix.
- anvil-web / anvilid Postgres runs (`ANVILID_TEST_DB=postgres`).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] One feature commit for both tasks' code**
- **Issue:** `lib.rs` (module list, Storage accessors), `pending.rs` (the shim had to go as one unit) and `.sqlx` are shared by both tasks. A Task-1-only commit would either not compile or keep half the shims.
- **Fix:** all repository code went into `155fc69`. The upgrade test and fixture are a separate commit, `07725d0`.

**2. [Rule 3 - Blocking] `UserRow` fields made `pub(crate)`**
- **Issue:** `users_with_role` returns `Page<User>`, and `query_as!` into the existing `UserRow` from roles.rs needs visible fields. This avoids a second user row type.
- **Fix:** `users.rs` is in this plan's files. The change is visibility only.

**3. [Rule 2 - Security test] Cross-tenant FK test covers `role_assignment`**
- `composite_tenant_foreign_keys_reject_cross_tenant_rows` in `lib.rs` now also proves that an assignment naming another tenant's role/user is rejected (23503), and that it cascades with the user.

**4. [Alignment] Schema details mirrored from 05-06's in-progress SQLite 0007**
- These were read from the working tree while it was being written: no enumerated event-type CHECK, the pairing CHECKs, the HTTP status range, the role description, the purge rules and the `complete_setup` Conflict rule.
- Re-compared after 05-06 landed (eedfa24, 05-06-SUMMARY key decisions): every rule matches.
  - complete_setup returns Conflict and rolls back.
  - purge_before deletes delivered/failed deliveries with `completed_at < cutoff` and counts only audit events.
  - purge_expired deletes IATs 7 days after expiry or revocation.
  - The backfill assigns every system-tenant user regardless of status, while holders_of_permission counts only active users.
  - The `user.attributes` CHECK requires a JSON object.
  - The upsert_cimd guard is the same.
- Only difference: the backfill role id is gen_random_uuid() (v4) here and a random v7-shaped id on SQLite. Nothing depends on it.

### Deferred (out of scope, not fixed)
- `tests/plaintext.rs` (not in this plan's files) does not yet inspect the new secret-bearing columns: `webhook_endpoint.secret_enc` / `previous_secret_enc`, `initial_access_token.token_hash`, `client.registration_access_token_hash`. Only hashes and sealed bytes reach these columns through the ports, but the row-inspection test should be extended. Candidate: the plan that owns plaintext.rs, or a gap-closure plan.

## Self-Check: PASSED
- Created files exist (0006 migration, roles/attributes/registration/webhooks.rs, release_0_3.sql). pending.rs is deleted.
- Commits 155fc69 and 07725d0 are in `git log`.
