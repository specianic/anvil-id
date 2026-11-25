---
phase: 04-release-0-3-real-world-logins
plan: 04
subsystem: storage-sqlite
tags: [sqlite, migration, check-rebuild, connections, branding, backchannel-logout, rp-session, sqlx]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01 Phase 4 ports, contract suite (32 tests) and TRANSITIONAL(04-04) shims"
provides:
  - SQLite migration 0005_release_0_3.sql (CHECK-widening rebuilds + 6 new tables + new columns)
  - SqliteConnections, SqliteBranding, SqliteLogout repositories
  - logout::enqueue_deliveries / record_rp_session used by every revoking intent and create_code
  - SessionRepo::upgrade_auth and UserRepo::complete_email_change on SQLite
  - 0.2 -> 0.3 upgrade test plus a contract-suite run over a 0.2-upgraded database
  - Connection-secret plaintext/AAD test (SEC-03)
affects: [04-05, 04-08, 04-11, 04-13, 04-18, 04-21, 04-24, 04-gate]

tech-stack:
  added: []
  patterns:
    - "Revoking intents use the session ids returned by their own UPDATE ... RETURNING, so a call that revokes nothing enqueues nothing"
    - "rp_session is recorded with INSERT OR IGNORE ... SELECT FROM browser_session (only an existing session of the tenant; no FK error for unknown sessions)"
    - "Draft-only branding rows keep the published columns NULL; get() filters tokens IS NOT NULL"

key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0005_release_0_3.sql
    - crates/anvil-storage-sqlite/src/connections.rs
    - crates/anvil-storage-sqlite/src/branding.rs
    - crates/anvil-storage-sqlite/src/logout.rs
  modified:
    - crates/anvil-storage-sqlite/src/{lib,clients,grants,sessions,users,flows}.rs
    - crates/anvil-storage-sqlite/tests/upgrade.rs
    - crates/anvil-storage-sqlite/tests/plaintext.rs
    - crates/anvil-storage-sqlite/.sqlx/
  deleted:
    - crates/anvil-storage-sqlite/src/pending.rs

key-decisions:
  - "0005 is one transactional migration: flow, self_service_token and email_template have no inbound foreign keys (checked with pragma_foreign_key_list on a 0.2 schema), so the 0003 create/copy/drop/rename pattern applies; the file carries the -- anvil:non-destructive-rebuild marker"
  - "identity_link references connection through a composite (tenant_id, connection_id) FK (new unique index connection(tenant_id, id)); FK violations in create_link map to Conflict"
  - "claim_due_deliveries is a single UPDATE ... WHERE id IN (SELECT ... LIMIT) RETURNING on the single writer (equivalent to select-then-update in one tx)"
  - "BrandingRepo::delete unpublishes (published columns NULL) and drops the row only when no draft remains; put_draft sets updated_at only on a new row"
  - "purge_expired also removes logout deliveries past give_up_at and draft-only branding rows past preview expiry"

patterns-established:
  - "0.2 -> 0.3 upgrade test snapshots every row of every application table with quote() over the pre-upgrade columns and compares after migrating"

requirements-completed: [SEC-03, OIDC-12, OIDC-16, AUTH-11, AUTH-13, UI-03]

duration: 20min
completed: 2026-11-25
---

# Phase 4 Plan 04: SQLite 0005 and Phase 4 Repositories Summary

**SQLite now implements the whole Phase 4 storage contract. Migration 0005 widens three CHECK constraints through in-transaction rebuilds and adds connections, identity links, RP sessions, the logout delivery queue and branding. Every revoking intent enqueues back-channel deliveries in its own transaction, and 0.2 databases upgrade with every row intact.**

`requirements-completed` lists the requirements this storage work contributes to. None of them is delivered end to end yet, and no checkbox was ticked.

## Performance

- **Duration:** about 20 min
- **Started:** 2026-11-25T15:13Z
- **Completed:** 2026-11-25T15:33Z
- **Tasks:** 3
- **Files modified:** 2 + 11 + about 60 (.sqlx) across the three commits

## Accomplishments

### Rebuild approach (Pitfall 11)
- `flow` (adds `logout`), `self_service_token` (adds `email_change`) and `email_template` (adds `login_code`, `email_change`, `email_changed`) are rebuilt by create-new, copy every row, drop, rename, and then recreating every index. All of this runs inside sqlx's normal migration transaction with foreign keys on.
- No table references these three tables (verified with `pragma_foreign_key_list`), so the drop cascades nothing. The 0004-style no-transaction procedure is not needed.
- The file-level `-- anvil:non-destructive-rebuild` marker satisfies `scripts/check-migrations.sh`. Released files and the sha256 manifest are untouched.

### New schema
- New tables:
  - `connection` with UNIQUE(tenant, slug) and UNIQUE(tenant, id)
  - `identity_link` with composite FKs to user and connection (cascade), UNIQUE(tenant, connection, subject) and an index on (tenant, user)
  - `rp_session` with PK (tenant, session, client) and an FK to browser_session (cascade)
  - `logout_delivery`, which has no FK to session, user or client
  - `branding`, holding the published and draft records per scope, with a UNIQUE preview_hash
  - `branding_logo`, keyed by (tenant, sha256)
- New columns:
  - `client`: `post_logout_redirect_uris`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `allowed_resources`, `mfa_policy`
  - `resource` on `authorization_code`, `token_family` and `access_token`

### Enqueue helper
`logout::enqueue_deliveries(conn, tenant, user, &session_ids, now)` joins `rp_session` to `client` where `backchannel_logout_uri IS NOT NULL`. It inserts one row per (session x RP) with `sub` = user id, `sid` = session id, `next_attempt_at = now`, `give_up_at = now + 24h` and `attempts = 0`.

It runs in the same transaction as each revoking intent:
- `SessionRepo::revoke` and `revoke_with_families`: the session comes from `UPDATE ... RETURNING user_id`.
- `revoke_all_for_user` and `UserRepo::complete_recovery`: the ids come from `UPDATE ... RETURNING id`, so only sessions that call actually revoked are included.
- `UserRepo::delete`: collects the unrevoked session ids and enqueues before the user row (and with it the rp_session rows) is deleted.

`GrantRepo::create_code` records the RP session in its transaction.

### Intents
- `upgrade_auth` is a single conditional UPDATE on active sessions.
- `complete_email_change` runs in one transaction:
  1. Consumes the token with a conditional UPDATE.
  2. Reads the old email.
  3. Updates the email. A unique violation returns Conflict, the transaction is dropped and the token stays unconsumed.
  4. Enqueues the notice to the old address.

### Test counts (all on SQLite, offline metadata)
| Suite | Result |
|-------|--------|
| `--lib` | 14 passed |
| `--test contract` (memory + file) | 292 passed, 0 failed (the 64 Phase 4 failures from 04-01 are gone) |
| `--test upgrade` | 296 passed: 4 upgrade tests (0.1 x2, 0.2 x2) + contract suite over a 0.1-upgraded DB (146) + over a 0.2-upgraded DB (146) |
| `--test plaintext` | 2 passed (existing + `connection_secret_sealed_at_rest`) |

`scripts/check-migrations.sh`, `scripts/sqlx.sh check crates/anvil-storage-sqlite`, `cargo clippy -p anvil-storage-sqlite --all-targets -D warnings` and `cargo fmt --check` all pass.

## Task Commits

1. **Task 1: Migration 0005 + 0.2 upgrade test**: `a6b826f` (feat)
2. **Task 2: Repositories, enqueue-on-revoke, intents**: `e04a6ed` (feat)
3. **Task 3: sqlx metadata + plaintext test**: `c0dc1e3` (chore)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] rp_session insert guarded by the session's existence**
- **Found during:** Task 2
- **Issue:** A plain `INSERT OR IGNORE INTO rp_session` with the FK to browser_session would fail `create_code` whenever a caller passes a session id that is not stored. `OR IGNORE` does not cover FK errors.
- **Fix:** `INSERT OR IGNORE ... SELECT tenant_id, id, ... FROM browser_session WHERE tenant_id = ? AND id = ?`. It records only an existing session of the same tenant.
- **Commit:** e04a6ed

**2. [Rule 2 - Correctness] Housekeeping for the new queues**
- `purge_expired` also deletes logout deliveries past `give_up_at` and draft-only branding rows past their preview expiry. Without this, both tables would grow without bound.
- **Commit:** e04a6ed

**3. Upgrade test also runs the full contract suite over a 0.2-upgraded database**
- This covers the must-have "upgrades … then passes the contract suite". It adds about 146 tests to `--test upgrade`.

### Notes
- `convert.rs` (listed in files_modified) needed no change.
- Task 1's commit alone fails the existing `upgraded_contract` Phase 4 tests with `Unsupported`, as at 04-01. Task 2 makes them pass.
- Logos replaced or cleared stay in `branding_logo`, because rows are content-addressed and may be shared between scopes. Garbage collection of unreferenced logos is not implemented.
- Not run: `SQLX_OFFLINE=true cargo build --workspace --all-targets` in the main tree fails only because of 04-05's uncommitted Postgres files (missing Postgres .sqlx entries). In a clean worktree at c0dc1e3 the same build passes. Postgres and Docker runs were not attempted, as instructed.

## Issues Encountered
None blocking.

## Next Phase Readiness
- SQLite is complete for Phase 4 storage. 04-05 does the same for Postgres against the same contract.
- Service plans (logout worker, federation, branding, email change) can rely on SQLite behaviour matching the documented port semantics.

## Self-Check: PASSED

- 0005_release_0_3.sql, connections.rs, branding.rs and logout.rs (278 lines) exist. pending.rs is deleted.
- Commits a6b826f, e04a6ed and c0dc1e3 are in the history.
- `! grep -rn "TRANSITIONAL(04-04)" crates/` passes. `enqueue_deliveries` is used in sessions.rs and users.rs, and `rp_session` is written in the create_code transaction.
- In a clean worktree at c0dc1e3 (own CARGO_TARGET_DIR, since removed), `SQLX_OFFLINE=true cargo build --workspace --all-targets` passes.
