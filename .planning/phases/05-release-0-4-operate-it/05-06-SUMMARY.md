---
phase: 05-release-0-4-operate-it
plan: 06
subsystem: storage-sqlite
tags: [sqlite, migration, rbac, attributes, webhooks, dcr, cimd, consent, upgrade]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 domain model, 05-02 ports and the 36-test Phase 5 contract suite
provides:
  - SQLite migration 0007_release_0_4 (additive schema plus the administrator backfill)
  - RoleRepo, AttributeRepo, WebhookRepo, RegistrationRepo on SQLite
  - ClientRepo upsert_cimd / get_by_registration_token / set_registration_token and stored registration fields
  - Consent resources stored and merged
  - Webhook enqueue inside AuditRepo::append (same transaction)
  - Administrator role created by install and assigned by complete_setup
  - 0.3 -> 0.4 upgrade test, run through the full contract suite
affects: [05-07, 05-12, 05-14, 05-19, 05-21, 05-23]

tech-stack:
  added: []
  patterns:
    - "Webhook subscriptions stored as a JSON array of wire names; enqueue filters with json_each inside the audit transaction, delivery ids generated in Rust per endpoint"
    - "Claims (webhook) are one UPDATE ... WHERE id IN (SELECT ... LIMIT) RETURNING on the single writer, plus the endpoint read in the same transaction"
    - "CIMD upsert is one INSERT ... ON CONFLICT DO UPDATE ... WHERE registration_source = 'cimd' RETURNING; no row returned = Conflict"

key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0007_release_0_4.sql
    - crates/anvil-storage-sqlite/src/roles.rs
    - crates/anvil-storage-sqlite/src/attributes.rs
    - crates/anvil-storage-sqlite/src/webhooks.rs
    - crates/anvil-storage-sqlite/src/registration.rs
    - crates/anvil-storage-sqlite/tests/fixtures/release_0_3.sql
  modified:
    - crates/anvil-storage-sqlite/src/{lib,clients,consent,audit,setup}.rs
    - crates/anvil-storage-sqlite/tests/upgrade.rs
    - crates/anvil-storage-sqlite/.sqlx
  deleted:
    - crates/anvil-storage-sqlite/src/pending.rs

key-decisions:
  - "complete_setup returns Conflict (everything rolled back) if the admin tenant has no administrator role, so setup can never create an administrator without admin:write"
  - "Webhook delivery-log retention reuses audit retention: AuditRepo::purge_before also deletes delivered/failed deliveries with completed_at < cutoff (pending ones never); its return value still counts audit events only"
  - "purge_expired deletes initial access tokens 7 days after expiry or revocation"
  - "The backfill role id is a random UUID with v7/RFC 9562 variant bits, built in SQL with unhex(); its 48-bit prefix is random, not a timestamp"
  - "The backfill assigns administrator to every system-tenant user regardless of status; holders_of_permission still counts only active users"
  - "user.attributes CHECK requires a JSON object (json_type = 'object'), not just valid JSON"

requirements-completed: []

duration: ~45min
completed: 2026-11-26
---

# Phase 5 Plan 06: SQLite migration 0007 and every Phase 5 repository Summary

**SQLite stores every Phase 5 entity. Migration 0007 adds the role, attribute, webhook, DCR/CIMD and consent-resource schema and backfills the system tenant's `administrator` role for upgraded installations. All 36 new contract tests pass on memory and file databases and on the 0.1-, 0.2- and 0.3-upgraded databases. No TRANSITIONAL(05-06) shim remains.**

## Performance

- **Duration:** about 45 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 63 in the repository commit (most of them `.sqlx` metadata), 2 in the test commit

## Schema (0007_release_0_4.sql)

The file header says it is additive except for the backfill. It has no DROP, DELETE or RENAME, and `scripts/check-migrations.sh` passes with 0001-0006 unchanged.

- **role:** id, tenant_id (FK cascade), org_id (always NULL in 0.4), name, description, permissions (JSON), timestamps. Unique `(tenant_id, id)` is the FK target. Partial unique `(tenant_id, name) WHERE org_id IS NULL`.
- **role_assignment:** PK `(tenant_id, role_id, user_id)`. Composite FKs to role and user, both ON DELETE CASCADE, so an assignment can never cross tenants. Index on `(tenant_id, user_id)`.
- **attribute_definition:** PK `(tenant_id, name)`. Columns: schema (JSON), required, user_editable, claim (JSON or NULL), position, timestamps.
- **user.attributes:** `TEXT NOT NULL DEFAULT '{}'`. The CHECK requires valid JSON whose type is object.
- **webhook_endpoint:**
  - Unique `(tenant_id, name)` and `(tenant_id, id)`.
  - Columns: events (JSON array of wire names), enabled, secret_enc, previous_secret_enc, previous_secret_expires_at (a CHECK makes the two previous-secret columns NULL together), disabled_reason, timestamps.
- **webhook_delivery:**
  - Composite FK `(tenant_id, endpoint_id)` to the endpoint, cascade.
  - Status CHECK: pending/delivered/failed. A second CHECK: `(status = 'pending') = (completed_at IS NULL)`.
  - Indexes on `(status, next_attempt_at)` and `(tenant_id, endpoint_id, id)`, plus a partial index on completed_at.
- **initial_access_token:** token_hash UNIQUE (32 bytes), expires_at, uses_remaining (>= 0 or NULL), revoked_at.
- **client:**
  - `registration_source` (CHECK static/dynamic/cimd, default `'static'`).
  - `metadata_expires_at`.
  - `registration_access_token_hash` (32 bytes).
  - Index on `(tenant_id, registration_source)`.
- **consent_grant.resources:** JSON array, default `'[]'`.

## Backfill

For the tenant with slug `system`, if one exists:
- insert an `administrator` role with `["admin:write"]`. The id is UUID-shaped, built in SQL in the 16-byte BLOB encoding. The timestamps are the migration time in milliseconds.
- assign that role to every existing user of the system tenant.

A database without a system tenant gets no role (tested). New installations get the role from `SetupRepo::install` instead.

## Repositories

- **RoleRepo** (roles.rs): plain statements. `assign` is an insert-select over role JOIN user in the tenant with `ON CONFLICT DO NOTHING`, then an EXISTS check, in one writer transaction. `holders_of_permission` counts distinct active users through `json_each(permissions)`.
- **AttributeRepo** (attributes.rs):
  - `upsert` is `ON CONFLICT (tenant_id, name) DO UPDATE ... RETURNING`.
  - User values live in `user.attributes`. `set_user_values` replaces the whole object and bumps `updated_at` in one UPDATE.
- **WebhookRepo** (webhooks.rs):
  - CRUD. `update_endpoint` clears `disabled_reason` when re-enabling. `rotate_secret` is one UPDATE (the right-hand sides read the old row).
  - `claim_due` is one leasing UPDATE ... RETURNING plus the endpoint reads, in one transaction on the single writer. It skips disabled endpoints and does not count an attempt.
  - `complete` changes only pending rows and increments attempts on every variant. DisableEndpoint fails the delivery and disables the endpoint in the same transaction, both with `"gone"`.
  - `deliveries` lists newest first with an id cursor.
  - `redeliver` and `enqueue_test` are insert-select ... RETURNING (`None` for unknown or foreign rows).
- **enqueue_for_event:** called by `AuditRepo::append` in its transaction. The audit insert comes first, so a duplicate id rolls back and nothing is enqueued.
- **RegistrationRepo** (registration.rs): `consume_iat` is one conditional `UPDATE ... RETURNING`. `count_clients_by_source` is a count on the new column.
- **ClientRepo:**
  - The registration fields are stored on create and update.
  - `upsert_cimd` is one statement. It keeps the row id and created_at, and returns Conflict over a static or dynamic client.
  - `get_by_registration_token` matches dynamic clients only.
  - `set_registration_token` replaces or clears the hash.
- **Consent:** resources are merged as a sorted, de-duplicated union like scopes. A revoked grant is re-activated with exactly the new resources.
- **SetupRepo:** `install` creates the administrator role for the plan's system tenant in the install transaction. `complete_setup` assigns it in the setup transaction.
- **Purge:** `purge_expired` deletes IATs 7 days after expiry or revocation. `purge_before(cutoff)` also deletes completed deliveries older than the cutoff.

## Contract count

| Run | Tests |
|---|---|
| `--test contract` (memory + file) | 380 passed (190 per backend, including the 36 Phase 5 tests each) |
| `--test upgrade` | 578 passed: 3 contract runs (0.1-, 0.2-, 0.3-upgraded) x 190 + 8 upgrade tests |
| `--test plaintext` | 2 passed |
| `--lib` | 14 passed |

The 8-way `webhook_claim_concurrent_each_row_once` and `iat_single_use_concurrent_single_winner` pass on every SQLite variant.

## Task Commits

1. **Task 1 (and the Task 2 repository work): migration 0007, all repositories, shim removal, .sqlx:** `eedfa24` (feat)
2. **Task 2: 0.3 -> 0.4 upgrade test and fixture:** `9423733` (test)

## Verification run

- `cargo test -p anvil-storage-sqlite --test contract`: 380/380
- `cargo test -p anvil-storage-sqlite --test upgrade --test plaintext`: 578 + 2
- `cargo test -p anvil-storage-sqlite --lib`: 14
- `cargo clippy -p anvil-storage-sqlite --all-targets --locked -- -D warnings`: clean
- `scripts/sqlx.sh prepare crates/anvil-storage-sqlite`, then `scripts/sqlx.sh check crates/anvil-storage-sqlite`: OK
- `scripts/check-migrations.sh`: `migrations OK`
- `grep -rn "TRANSITIONAL(05-06)" crates`: empty
- Setup consumers still pass: `anvil-web --test security_setup` (7), `--test admin_api` (9), `--test security_admin` (10); `anvilid --test zero_config` (15), `--test cli` (1)
- `rustfmt --edition 2024` on every touched .rs file

## Not run

- The Postgres backend (05-07 owns it) and anything needing Docker.
- The full workspace test suite (per the shared rules, only targeted runs).
- `tests/plaintext.rs` has no new secret columns: initial access token hashes, registration access token hashes and webhook sealed secrets are not seeded there. The file is not in this plan's file list.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Tasks 1 and 2 share lib.rs and pending.rs, so the webhook repository landed in the Task 1 commit**
- Deleting pending.rs and wiring the accessors in lib.rs requires every repository at once. The webhook repo, the audit enqueue and the purge rules are therefore in `eedfa24`. The Task 2 commit holds the upgrade test and fixture.

**2. [Rule 2 - Missing critical] complete_setup refuses to create an administrator without the role**
- The port says setup assigns the role that install created. If the role is missing (the database was tampered with), a silent no-op would create an administrator with no permissions. The method now returns Conflict and rolls back everything. Every caller and contract test installs first.

**3. Purge placement**
- The plan names jobs.rs for the purge. jobs.rs only holds the JobRepo leases, and the purges live in lib.rs `purge_expired` and in `AuditRepo::purge_before`. Delivery-log retention uses the audit cutoff in `purge_before`, which is the only place that knows the retention. IAT cleanup is in `purge_expired`. jobs.rs, users.rs, grants.rs and convert.rs needed no change. **05-07 ("purge rules as SQLite") should mirror this.**

### Extra test coverage
- `upgrade_from_0_3_without_system_tenant_creates_no_role`, `upgrade_from_0_3_is_idempotent_on_restart` (the backfill runs once), and a fourth contract-suite run over the 0.3-upgraded database.

## Self-Check: PASSED
- Created files exist: 0007_release_0_4.sql, roles.rs, attributes.rs, webhooks.rs, registration.rs, fixtures/release_0_3.sql. pending.rs is deleted.
- Commits eedfa24 and 9423733 are present in `git log`.
