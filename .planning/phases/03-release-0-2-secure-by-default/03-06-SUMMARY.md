---
phase: 03-release-0-2-secure-by-default
plan: 06
subsystem: storage-postgres
tags: [postgres, sqlx, migration, passkeys, totp, recovery-codes, consent, audit, job-lease]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "03-02 Phase 3 ports, contract suite and TRANSITIONAL shims"
provides:
  - Postgres migration 0003 (0.2 schema, additive)
  - Every Phase 3 port method on Postgres with compile-checked sqlx queries
  - Postgres plaintext inspection covering TOTP seeds, recovery codes, SMTP and captcha secrets
affects: [03-09, 03-10, 03-12, 03-13, 03-14, 03-15, 03-17, 03-21, 03-23, 03-24]
tech-stack:
  added: []
  patterns:
    - "Credential owner checks: INSERT ... SELECT ... WHERE EXISTS (user of this tenant), because Postgres FKs reference user(id) only"
    - "Trait impls delegate to per-concern modules (credentials.rs, consent.rs) because one trait impl cannot span files"
key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0003_release_0_2.sql
    - crates/anvil-storage-postgres/src/credentials.rs
    - crates/anvil-storage-postgres/src/consent.rs
    - crates/anvil-storage-postgres/src/audit.rs
    - crates/anvil-storage-postgres/src/mail_settings.rs
    - crates/anvil-storage-postgres/src/jobs.rs
  modified:
    - crates/anvil-storage-postgres/src/{lib,convert,users,clients,sessions,grants,keys,flows}.rs
    - crates/anvil-storage-postgres/.sqlx/
    - crates/anvil-storage-postgres/tests/plaintext.rs
  deleted:
    - crates/anvil-storage-postgres/src/pending.rs
key-decisions:
  - "Sealed TOTP seed stored hex-encoded in credential.data (text shared with PHC strings and passkey JSON); no new crate dependency"
  - "Consent scopes are a sorted, de-duplicated jsonb array in byte order (COLLATE \"C\"), merged by one INSERT ... ON CONFLICT DO UPDATE so concurrent first grants lose nothing"
  - "Credential/consent/recovery-code inserts for a user outside the tenant return StorageError::Backend (parity with the SQLite composite-FK violation)"
  - "JobRepo::release deletes the lease row; audit purge_before is batched by ctid like purge_expired"
duration: 45min
completed: 2026-11-25
---

# Phase 3 Plan 06: Postgres Release 0.2 storage Summary

**Postgres migration 0003 plus every Phase 3 repository method (passkeys, TOTP, recovery codes, consent, opaque access tokens, sessions, key promotion, audit, mail settings, job leases). The full 114-test contract suite, including the concurrency tests, now passes on testcontainers with one PgPool, and no TRANSITIONAL shim remains.**

## Performance

- **Duration:** about 45 min
- **Tasks:** 3
- **Files:** 6 created, 10 modified, 1 deleted, plus regenerated .sqlx metadata

## Accomplishments

- **Migration 0003 (additive):**
  - `credential` gets a uuid `id` (backfilled with `gen_random_uuid()`, then SET NOT NULL and a PK swap). It also gets `external_id`, `counter`, `backup_eligible`, `label` and `last_used_at`.
  - The `kind` CHECK is swapped to password/webauthn/totp. New partial unique indexes: one password per user, one TOTP per user, and `(tenant_id, external_id)`.
  - The `flow` kind CHECK and the `token_family` revoked_reason CHECK are swapped with DROP/ADD CONSTRAINT.
  - New tables: `recovery_code`, `consent_grant`, `access_token`, `audit_event` (indexes `(tenant_id, id DESC)`, `(tenant_id, action, id)`, `(at)`), `email_template`, `smtp_settings` and `job_lease`.
  - New `client` columns: `token_format`, `consent_mode`, `id_token_signed_response_alg`, `can_introspect`. New `browser_session` columns: `ip`, `user_agent`. All use constant defaults.
- **Upgrade test** (`migration_0003_upgrades_a_populated_0_1_database`): applies 0001+0002 through a filtered `Migrator`, seeds a tenant, user, password, client, session, revoked family and refresh token, then migrates. It checks that all rows are intact and the new columns hold their defaults. It also checks that the new reasons, flow kinds and credential kinds are accepted, that unknown values are still rejected, and that duplicate external ids and second passwords are rejected.
- **Repositories:**
  - Single-statement CAS: passkey counter (`counter < $new OR 0/0`), TOTP step (`counter IS NULL OR counter < $step`), recovery code (`used_at IS NULL`, with the notice enqueued in the same transaction only on success) and flow `swap_state`.
  - Transactions: `create_totp` (credential insert first, so a Conflict leaves the codes untouched), TOTP `delete_credential` (removes the codes too), `replace_recovery_codes` (`unnest($::bytea[])`), `revoke_consent`, `revoke_with_families`, `revoke_all_for_user` (`RETURNING id`, then families by `session_id = ANY`), and `promote` (retire, then activate, each checked for exactly one row; a second active key surfaces as Conflict).
  - `try_lease` is one `INSERT ... ON CONFLICT DO UPDATE ... WHERE leased_until <= now OR owner = EXCLUDED.owner RETURNING owner`.
  - Audit queries are keyset on `id DESC` with fixed optional predicates.
- `complete_recovery` takes the recipient from `UPDATE ... RETURNING user_id, email`, which replaces the 03-02 runtime query.
- The password upsert now uses `ON CONFLICT (tenant_id, user_id) WHERE kind = 'password'` with a generated v7 id.
- `purge_expired` now also deletes expired opaque access tokens.
- The plaintext test seeds a KEK-sealed TOTP seed, 10 peppered recovery-code hashes, a sealed SMTP password and a sealed captcha secret. It asserts that none of these appear in any text, bytea, jsonb or text[] column: the seed (raw bytes, hex, base32), each recovery code, the SMTP password and the captcha secret. Positive controls cover the new rows.

## Task Commits

1. **Task 1: Migration 0003:** `ba21539`
2. **Task 2: Repository implementations and Storage wiring:** `303a786`
3. **Task 3: Plaintext inspection for new secrets:** `2f66af7`

## Verification

- `cargo test -p anvil-storage-postgres` (offline metadata): lib 7/7, contract 114/114, plaintext 1/1.
- `cargo clippy -p anvil-storage-postgres --all-targets -- -D warnings`: clean.
- `scripts/sqlx.sh check crates/anvil-storage-postgres`: metadata current.
- `grep -rn "TRANSITIONAL\|Unsupported(" crates/anvil-storage-postgres/src`: no matches.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] Tenant check on user-owned inserts**
- **Found during:** Task 2
- **Issue:** The Postgres FKs reference `"user"(id)` only. That is unlike SQLite's composite `(tenant_id, user_id)` FK. A passkey, TOTP, recovery code or consent could therefore be written under tenant A for a user of tenant B.
- **Fix:** These inserts use `INSERT ... SELECT ... WHERE EXISTS (SELECT 1 FROM "user" WHERE tenant_id = $t AND id = $u)`. Zero rows returns `StorageError::Backend`.
- **Files modified:** credentials.rs, consent.rs
- **Commit:** 303a786

**2. [Rule 3 - Blocking] Existing password queries depended on the dropped `(user_id, kind)` PK**
- **Found during:** Task 2
- **Fix:** `insert_password` and `upsert_password` now supply a v7 id and target the partial unique index `ON CONFLICT (tenant_id, user_id) WHERE kind = 'password'`.
- **Commit:** 303a786

## Issues Encountered

- The local Docker host has about 270 leftover testcontainers Postgres containers from earlier runs. The shared contract container is never dropped by design (see `tests/support/mod.rs`). They are harmless but use resources. Running `docker ps -q --filter ancestor=postgres:18-alpine` and removing everything except `anvil-dev-pg` would clean them up. Logged here only; not fixed (out of scope).
- A 0.1 binary cannot write passwords against a 0.2 schema: its `ON CONFLICT (user_id, kind)` no longer matches a unique index, and it does not supply `credential.id`. A rolling 0.1 to 0.2 upgrade with mixed binaries is therefore not supported for password writes. Reads keep working.

## Next Phase Readiness

- Both backends now implement the full 0.2 contract (03-05 SQLite, 03-06 Postgres). Service plans can rely on every Phase 3 port.

## Self-Check: PASSED
