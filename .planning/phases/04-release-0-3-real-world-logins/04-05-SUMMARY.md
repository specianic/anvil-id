---
phase: 04-release-0-3-real-world-logins
plan: 05
subsystem: storage-postgres
tags: [postgres, sqlx, migrations, backchannel-logout, skip-locked, connections, branding, email-change]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: 04-01 Phase 4 ports, contract suite (32 tests) and TRANSITIONAL(04-05) shims
provides:
  - Postgres migration 0004_release_0_3.sql (additive; CHECK swaps; 7 new tables; client/resource columns)
  - PgConnections, PgBranding, PgLogout repositories
  - logout::enqueue_deliveries / record_rp_session (same-transaction enqueue-on-revoke)
  - SessionRepo::upgrade_auth, UserRepo::complete_email_change on Postgres
  - Regenerated .sqlx offline metadata; 0.2 -> 0.3 upgrade test; connection-secret plaintext/AAD test
affects: [04-07, 04-11, 04-13, 04-16, 04-21, 04-25]

tech-stack:
  added: []
  patterns:
    - "Revoking intents collect the ids from `UPDATE browser_session … RETURNING id` and pass exactly those to enqueue_deliveries on the same transaction"
    - "Delivery ids are generated in Rust (UUIDv7) and inserted with one INSERT … SELECT FROM UNNEST(arrays)"
    - "FK violations on identity links are reported as Conflict (port contract), unique violations as Conflict via map_err"

key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0004_release_0_3.sql
    - crates/anvil-storage-postgres/src/connections.rs
    - crates/anvil-storage-postgres/src/branding.rs
    - crates/anvil-storage-postgres/src/logout.rs
  modified:
    - crates/anvil-storage-postgres/src/{lib,clients,grants,sessions,users,flows}.rs
    - crates/anvil-storage-postgres/tests/{upgrade,plaintext}.rs
    - crates/anvil-storage-postgres/.sqlx/
  deleted:
    - crates/anvil-storage-postgres/src/pending.rs

key-decisions:
  - "Postgres keeps branding drafts in their own table branding_draft (PK tenant+scope, UNIQUE preview_hash) instead of draft columns on branding, so a scope can have a draft without live branding and live columns stay NOT NULL; semantics match the port and SQLite"
  - "Client list columns (post_logout_redirect_uris, allowed_resources) and resource are jsonb arrays with jsonb_typeof CHECKs, as the plan specifies (existing 0.1 lists stay text[])"
  - "rp_session and identity_link use composite FKs; added UNIQUE (tenant_id, id) on browser_session and connection as targets"
  - "connection.kind is derived from config on write and cross-checked on read (mismatch = Corrupt)"
  - "UserRepo::delete revokes the user's live sessions (DB clock, ms) and enqueues their deliveries before the cascade delete; unknown user rolls back"
  - "complete_email_change: consume token -> SELECT old email FOR UPDATE -> UPDATE user; a unique violation returns Conflict and the dropped transaction rolls the token consumption back"

patterns-established:
  - "Local Postgres verification without Docker: a throwaway PG cluster (initdb/pg_ctl from the distro package) plus a worktree copy whose test server_url points at it (never committed)"

requirements-completed: [SEC-03, OIDC-12, OIDC-16, AUTH-11, AUTH-13, UI-03]

duration: 75min
completed: 2026-11-25
---

# Phase 4 Plan 05: Postgres 0004 + all Phase 4 repositories Summary

**Postgres now implements the whole Phase 4 storage contract: migration 0004, connections and identity links, branding with logos and preview drafts, RP sessions, and a back-channel logout queue leased with `FOR UPDATE SKIP LOCKED`. Every revoking intent enqueues its deliveries in its own transaction. upgrade_auth and complete_email_change are implemented, the regenerated .sqlx metadata is committed, and the shims are deleted.**

`requirements-completed` lists the requirement IDs this backend work contributes to. No requirement checkbox was ticked.

## Performance

- **Duration:** about 75 min
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files modified:** 15 source/test/migration files plus the .sqlx directory (44 entries added, 13 stale entries removed)

## Accomplishments

### Migration 0004 (additive, one transaction)
- CHECK swaps with DROP/ADD CONSTRAINT: `flow_kind_check` (+logout), `self_service_token_kind_check` (+email_change), `email_template_kind_check` (+login_code, email_change, email_changed)
- `client`: `post_logout_redirect_uris jsonb '[]'`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `allowed_resources jsonb '[]'`, `mfa_policy` CHECK
- `resource jsonb NOT NULL DEFAULT '[]'` on authorization_code, token_family, access_token
- New tables: `connection` (UNIQUE tenant+slug), `identity_link` (composite FKs to user and connection, UNIQUE tenant+connection+subject), `rp_session` (composite FK to browser_session, cascade), `logout_delivery` (no user/session/client FK, partial due index), `branding_logo`, `branding`, `branding_draft`
- `scripts/check-migrations.sh` passes. Released 0001–0003 and the sha256 manifest are untouched.

### Repositories
- **ConnectionRepo:** slug order uses `COLLATE "C"` (byte order). An FK violation on a link is reported as `Conflict`. `create_user_with_link` runs in one transaction.
- **BrandingRepo:** `Keep`/`Clear`/`Set` logo handling inside an upsert. Logos are content-addressed (`ON CONFLICT DO NOTHING`). `put_draft` replaces the scope's draft. `draft_by_preview` checks tenant, hash and expiry.
- **LogoutRepo:** `claim_due_deliveries` leases rows with `UPDATE … WHERE id IN (SELECT … ORDER BY next_attempt_at, id LIMIT n FOR UPDATE SKIP LOCKED)`. `complete_delivery` handles all three `DeliveryResult` variants.
- **Enqueue-on-revoke:** `revoke`, `revoke_with_families`, `revoke_all_for_user`, `complete_recovery` and `delete` pass exactly the ids returned by their revoking UPDATE. `create_code` records the `rp_session` in its own transaction.

## Task Commits

1. **Task 1: Migration 0004 and upgrade test:** `4718222` (feat)
2. **Task 2: Repositories, enqueue-on-revoke, intents, shims removed:** `dd13d80` (feat)
3. **Task 3: sqlx metadata and plaintext test:** `c9a9629` (chore)
4. **Parity fix with SQLite 04-04:** `f579716` (fix)

## Verification

Docker is unavailable on this machine, so testcontainers cannot run. Instead:
- A throwaway **PostgreSQL 14** cluster (distro `initdb`/`pg_ctl`, 127.0.0.1:55499, trust auth, in the session scratchpad) ran all of the following, in a worktree (`target/wt-04-05`) whose test `server_url()` was patched to point at it. The patch was never committed.
  - `--test contract`: **146 passed, 0 failed.** This includes all 32 Phase 4 tests, the 8-way delivery claim and the N=8 email-change race.
  - `--test upgrade`: **149 passed.** That is the 0.1 and 0.2 upgrade tests, the idempotent restart test and the whole contract suite on upgraded databases.
  - `--test plaintext`: **2 passed.** These are the existing scan and the new connection-secret/AAD test.
- `cargo sqlx prepare` ran against the same PG14 database. All 106 unchanged query entries came out **byte-identical** to the committed PG18-generated ones, so PG14 metadata is equivalent. A local build with `SQLX_OFFLINE=true` passes, as do `cargo clippy -p anvil-storage-postgres --all-targets -D warnings`, `cargo fmt --check` and `cargo check --workspace --all-targets` (worktree).
- `grep -rn "TRANSITIONAL(04-05)" crates/` returns nothing.

**Still to run in CI:** the Postgres 18 testcontainers runs (`cargo test -p anvil-storage-postgres`, including the `--lib` migration tests in lib.rs/migrate.rs, which were not run locally) and `scripts/sqlx.sh check crates/anvil-storage-postgres` against PG18.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Local Postgres instead of Docker**
- **Found during:** Task 1
- **Issue:** Docker is not installed in this WSL distro, so testcontainers and `scripts/sqlx.sh db-up` cannot run.
- **Fix:** Ran a throwaway PG14 cluster from the installed distro binaries and a patched worktree, both local only. .sqlx was regenerated with `cargo sqlx prepare` against that cluster; existing entries are unchanged.
- **Files:** none committed

**2. [Design] branding_draft table**
- The plan lists `branding` and `branding_logo` only, and SQLite 04-04 plans draft columns on `branding`. Postgres uses a separate `branding_draft` table so that a scope can have a draft without live branding while the live columns stay NOT NULL. Port semantics are unchanged.

**3. [Rule 2] Composite FKs for rp_session and identity_link -> connection**
- Added `UNIQUE (tenant_id, id)` on `browser_session` and `connection` as FK targets, so these rows cannot cross tenants at the schema level (the 0003 convention).

**4. [Rule 1 - Parity] rp_session recording and purge aligned with SQLite 04-04**
- **Found during:** state update (04-04's decisions landed while this plan was running)
- **Issue:** Postgres `create_code` failed on a missing session (FK) where SQLite skips the RP session. Postgres also never purged deliveries or expired drafts.
- **Fix:** `record_rp_session` now uses `INSERT … SELECT FROM browser_session WHERE tenant_id AND id ON CONFLICT DO NOTHING`. `purge_expired` deletes `logout_delivery` rows past `give_up_at` and expired `branding_draft` rows. .sqlx regenerated (3 new entries, 1 stale removed).
- **Files:** src/logout.rs, src/lib.rs, .sqlx
- **Commit:** f579716

### Notes
- Between commits `dd13d80` and `c9a9629`, the offline build of the crate needed the new .sqlx entries. Both commits landed back to back.
- SQLite's `purge_expired` also deletes token families past their absolute lifetime. Postgres has never done this, and the gap predates Phase 4 (02-02). Out of scope here and left unchanged.
- The main tree's anvil-core build was temporarily broken by another wave-2 plan's in-progress edits (`service/flow.rs`), so every compile and test ran in the worktree.

## Issues Encountered
None blocking.

## Next Phase Readiness
- Postgres and SQLite (04-04) both satisfy the full Phase 4 contract. Service-layer plans can depend on `connections()`, `branding()`, `logout()`, `upgrade_auth` and `complete_email_change` on both backends.

## Self-Check: PASSED

- The migration, connections.rs, branding.rs and logout.rs all exist, and pending.rs is gone. Commits 4718222, dd13d80, c9a9629 and f579716 are in the history.
- A re-run at the final committed state (f579716) against local PG14 passed: contract 146/146, plaintext 2/2, upgrade 149/149. Offline clippy -D warnings and fmt are clean.
