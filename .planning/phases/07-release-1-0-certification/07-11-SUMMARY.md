---
phase: 07-release-1-0-certification
plan: 11
subsystem: storage
tags: [postgres, migrations, par, password-profiles, upgrade, OIDC-18, ADM-08, ADM-09, QUAL-03]
requires:
  - "07-08: Phase 7 ports, SQLite 0010 reference schema, contract cases, beta.1 SQLite fixture"
provides:
  - "Postgres migration 0008_release_1_0_par_import.sql (additive, mirrors SQLite 0010)"
  - "Postgres implementation of every Phase 7 port method (PAR, families_for_user, replace_password_if, pending_self_service_tokens, PasswordProfileRepo)"
  - "Postgres upgrade tests 0.4 -> final and 1.0.0-beta.1 -> final, contract suite on the beta.1-upgraded database"
affects: [07-13 (PAR on Postgres), 07-14 (profiles, CAS rehash on Postgres), 07-15/07-17 (export reads on Postgres), 07-23 (pins 0008 in released-migrations.sha256)]
tech-stack:
  added: []
  patterns:
    - "PAR consume: one UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING (READ COMMITTED row-lock re-check)"
    - "Password CAS: UPDATE credential SET data = new WHERE ... AND data = expected, rows_affected == 1"
    - "Profile references: starts_with(data, prefix), exact and case-sensitive, never LIKE"
    - "Postgres upgrade snapshot: per table, ROW(beta.1 columns)::text sorted and aggregated, so columns added later do not affect the comparison"
key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0008_release_1_0_par_import.sql
    - crates/anvil-storage-postgres/src/password_profiles.rs
    - crates/anvil-storage-postgres/tests/fixtures/release_1_0_beta1.sql
  modified:
    - crates/anvil-storage-postgres/src/{lib,clients,grants,users}.rs
    - crates/anvil-storage-postgres/.sqlx
    - crates/anvil-storage-postgres/tests/upgrade.rs
key-decisions:
  - "password_hash_profile.rounds is bigint with CHECK 0..4294967295, so any u32 the model allows round-trips (Postgres integer is signed 32-bit). mem_cost is integer 0..255"
  - "pushed_authorization_request.params is jsonb with CHECK jsonb_typeof = 'object' (validated AuthorizationParams are always an object)"
  - "client_kind and password_hash_profile.kind have no CHECK (same as SQLite); unknown values read as StorageError::Corrupt"
  - "password_hash_profile gets a UNIQUE (tenant_id, id) composite FK target, following the Postgres conventions"
  - "PasswordProfileRepo::list orders by name COLLATE \"C\" to match SQLite's binary ordering"
  - "Docker was available, so verification used PG18 testcontainers and the scripts/sqlx.sh dev container instead of the local PG14 recipe"
metrics:
  duration: ~45min
  completed: 2026-11-26
---

# Phase 7 Plan 11: Postgres Phase 7 persistence Summary

Postgres now matches SQLite for every Phase 7 storage method. Migration 0008 is additive. PAR consume and the
password CAS are each decided by a single conditional UPDATE. No TRANSITIONAL(07-11) shim is left, and upgrades from
0.4 and from 1.0.0-beta.1 keep every row on Postgres.

## Migration 0008 (Postgres)

- `pushed_authorization_request(tenant_id uuid, uri_hash bytea(32), client_id text, params jsonb object, created_at,
  expires_at, consumed_at timestamptz NULL)`. PK `(tenant_id, uri_hash)`. Composite FK `(tenant_id, client_id) ->
  client(tenant_id, client_id) ON DELETE CASCADE` (target: the existing unique index `client_tenant_client_id_key`).
  Indexes on `expires_at` and `(tenant_id, client_id)`.
- `password_hash_profile(id uuid PK, tenant_id, name, kind, salt_separator bytea, rounds bigint, mem_cost integer
  0..255, signer_key_enc bytea NOT NULL, created_at)` with `UNIQUE (tenant_id, name)` and `UNIQUE (tenant_id, id)`.
- `client` ADD COLUMN `require_pushed_authorization_requests boolean NOT NULL DEFAULT false`, `client_kind text NOT
  NULL DEFAULT 'application'` (no CHECK) and `headless_native boolean NOT NULL DEFAULT false`. These are constant
  defaults, so the change is metadata-only and does not rewrite the table.
- 0007 is untouched and `scripts/check-migrations.sh` passes. 0008 is not added to `released-migrations.sha256`;
  07-23 pins it.

## Repositories

- `grants.rs`: `families_for_user` returns every state, ordered by created_at then id. `create_pushed_request`
  returns Conflict on a duplicate hash. `consume_pushed_request` is a single UPDATE ... RETURNING.
- `users.rs`: `replace_password_if` is a single conditional UPDATE on `credential.data`.
  `pending_self_service_tokens` returns the unconsumed, unexpired (kind, expires_at) pairs, oldest first. It never
  returns a hash or an address.
- `password_profiles.rs` (new) is registered in `lib.rs` as `PostgresStorage::password_profiles`.
- `clients.rs`: insert, update (COALESCE), CIMD upsert and every SELECT/RETURNING carry the three columns. The
  converter maps them, and an unknown `client_kind` reads as Corrupt. The refusal of non-default values is gone.
- `lib.rs`: `purge_expired` deletes expired pushed requests, consumed or not.

## Verification

Docker was available during this run. The Postgres suites therefore ran on **PG18 testcontainers**
(`postgres:18-alpine`), and the local PG14 recipe was not needed. No `server_url()` patch was made.

- `cargo test -p anvil-storage-postgres --test contract`: **253 passed**, the same count as one SQLite backend. This
  includes `par_consume_single_winner_under_concurrency` and `password_replace_if_concurrent_single_winner`.
- Concurrency subset (`contract concurren`, 18 tests) ran 3 times: 18/18 passed each time.
- `cargo test -p anvil-storage-postgres --test upgrade`: **515 passed**. That is 9 upgrade tests (7 earlier, 2 new
  beta.1 tests) plus the contract suite on the 0.1-upgraded and the beta.1-upgraded databases.
- `--test plaintext`: 3 passed. `--lib` (including the Docker lib tests): 15 passed.
- `.sqlx`: regenerated with `just sqlx-prepare crates/anvil-storage-postgres` against the migrated dev container
  (17 new query files, 6 obsolete ones removed by the tool), not edited by hand.
  `just sqlx-check crates/anvil-storage-postgres` is clean. The `anvil-dev-pg` container was removed afterwards.
- `cargo build` and `cargo clippy -p anvil-storage-postgres --all-targets --locked -- -D warnings`: clean.
  `rustfmt --edition 2024 --check` on the touched files: clean.
- `scripts/check-migrations.sh`: OK. `scripts/check-release-graph.sh`: OK.
- `grep -rn 'TRANSITIONAL(07-11)' crates/`: no match.

## Upgrade evidence (Postgres)

- 0.4 to final: `upgrade_from_0_4_keeps_every_row` now also asserts that the two new tables exist and are empty, and
  that client `rp` reads the defaults (false / application / false).
- 1.0.0-beta.1 to final (`fixtures/release_1_0_beta1.sql`, loaded at version 7): the same rows as the SQLite beta.1
  fixture, plus the browser_session the org-bound family refers to. The fixture populates 17 tables.
  `upgrade_from_1_0_beta1_keeps_every_row_and_defaults_new_columns` compares `count(*)` for every public table and a
  value snapshot of every beta.1 column, before and after. Both are equal, and no composite reference dangles. The
  client rows hold the new defaults in storage. The test then reads the org data back through the traits, checks
  that the beta.1 SAML replay guard still blocks, consumes the org-bound code, and runs `families_for_user`,
  `replace_password_if`, PAR create/consume and `password_profiles().list` on the upgraded rows.
  `upgrade_from_1_0_beta1_is_idempotent_on_restart` runs two more starts and finds the counts and snapshot unchanged,
  with every migration recorded once.
- The `upgraded_beta1_contract` module runs the full contract suite on the beta.1-upgraded database.

## What CI must confirm

- The same suites on CI's Docker (PG18): `just test-pg` and `scripts/sqlx.sh check crates/anvil-storage-postgres`.
  They are green locally on PG18 testcontainers, so CI is a re-confirmation.
- anvil-web / anvilid on Postgres (`ANVILID_TEST_DB=postgres`) was not run here.

## Deviations from Plan

1. **[Environment] Docker instead of the PG14 recipe.** `docker info` succeeded, so the plan's Docker branch applied:
   PG18 testcontainers and the `scripts/sqlx.sh` dev container. `ANVILID_PG_LOCAL` was not needed.
2. **[Rule 2] `rounds` is bigint.** A Postgres `integer` cannot hold the full u32 range of the model.
3. The beta.1 fixture adds a `browser_session` row that the SQLite fixture does not need. The family's `session_id`
   has no FK, but a real beta.1 database has the session, and the extra row widens the count coverage.

No file outside files_modified was changed.

## Problems seen in other plans' files

- The first clippy run failed in anvil-core with E0063: `ClientOptions` / `ClientOptionsPatch` were missing
  `client_kind`, `headless_native` and `require_pushed_authorization_requests` (config.rs, oauth/registration.rs).
  That was wave-3 work in progress in anvil-core/service/client.rs. It compiled cleanly a few minutes later, and I
  changed nothing there.

## Self-Check: PASSED

- FOUND: crates/anvil-storage-postgres/migrations/0008_release_1_0_par_import.sql
- FOUND: crates/anvil-storage-postgres/src/password_profiles.rs
- FOUND: crates/anvil-storage-postgres/tests/fixtures/release_1_0_beta1.sql
- FOUND commits: ba34e9f, 3a4747b
