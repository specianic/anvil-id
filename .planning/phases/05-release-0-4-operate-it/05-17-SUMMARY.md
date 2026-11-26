---
phase: 05-release-0-4-operate-it
plan: 17
subsystem: operations, cli
tags: [cli, backup, restore, sqlite, vacuum-into, postgres, admin-recovery, healthcheck, distroless, adm-07, ops-07]

requires:
  - phase: 05-05
    provides: /health/ready + drain on SIGTERM (healthcheck target), open_for_cli pattern
  - phase: 05-06
    provides: SQLite RoleRepo (assign, roles_for_user, holders_of_permission), administrator role assigned by complete_setup
  - phase: 05-07
    provides: Postgres parity of the same repositories (admin recover runs on either backend through the storage traits)
provides:
  - "anvil_storage_sqlite::backup: backup_into (VACUUM INTO), inspect (integrity_check + max _sqlx_migrations version), inspect_for_restore (TooNew guard), latest_migration_version"
  - "SqliteStorage::close() (reader pool first, writer last so it checkpoints)"
  - "anvilid backup create --output FILE / backup restore --input FILE [--yes]; Postgres refused with docs/OPERATIONS.md#postgres"
  - "AdminRecoveryService { storage, clock, public_url }: issue(email, reset_mfa) -> RecoveryIssued, issue_fresh_admin() -> setup URL"
  - "anvilid admin recover [--email E [--reset-mfa]]"
  - "anvilid healthcheck [--url]: loopback-only HTTP/1.1 readiness probe, exit 0/1/2"
  - "docs/OPERATIONS.md: what to back up, SQLite backup/restore, Postgres, key rotation (KEK rotation not in 0.4), admin access recovery, container health checks"
affects: [05-20, 05-26, 05-27, release-0.4 docs, Helm/Compose health checks]

tech-stack:
  added: []
  patterns:
    - "Online SQLite backup = VACUUM INTO on a dedicated non-creating connection, written to a hidden temp file beside the target, checked, chmod 0600, fsync, rename, directory fsync"
    - "Offline restore holds serve.lock for its whole run; old -wal/-shm removed before the rename so a stale WAL is never replayed onto the restored file"
    - "Restore verifies the configured KEK opens one signing key of the copy (through the storage traits) before replacing anything"
    - "CLI-only services: a test scans anvil-web/src and anvilid/src and fails if anything but anvilid/src/recover.rs refers to AdminRecoveryService"

key-files:
  created:
    - crates/anvil-storage-sqlite/src/backup.rs
    - crates/anvilid/src/backup.rs
    - crates/anvilid/src/recover.rs
    - crates/anvilid/src/healthcheck.rs
    - crates/anvilid/tests/backup.rs
    - crates/anvilid/tests/admin_recover.rs
    - crates/anvilid/tests/healthcheck.rs
    - docs/OPERATIONS.md
  modified:
    - crates/anvil-core/src/service/admin_recovery.rs (05-02 skeleton filled)
    - crates/anvil-storage-sqlite/src/lib.rs (pub mod backup, close())
    - crates/anvilid/src/main.rs (Backup, Admin Recover, Healthcheck subcommands)
    - crates/anvilid/tests/cli.rs

key-decisions:
  - "The recovery URL reuses the self-service Recovery token and the system tenant's existing /ui/recovery reset page, issued with no email (issue_self_service_token(.., None)); completing it goes through UserRepo::complete_recovery (password set, sessions and token families revoked)"
  - "Recovery is refused for non-active accounts; a blocked last admin is a lockout (holders_of_permission counts active users only), so the no-email path covers it"
  - "issue_fresh_admin reuses build_setup_token/setup_url (the admin setup-url token); setup completion assigns administrator (05-06/05-07)"
  - "--reset-mfa audits each removed factor as totp_removed / passkey_removed (system actor), the same events as the admin removal path, plus admin_recovery_issued with fields [password_reset_link, administrator_role?, mfa?]"
  - "Restore refuses when no KEK is found or the configured KEK cannot decrypt the backup's signing keys (added guard, see deviations); if the copy's schema cannot be read the check is skipped with a warning"
  - "Backups and restored databases are chmod 0600 (password hashes and sealed secrets)"
  - "healthcheck maps localhost to 127.0.0.1 without DNS; wildcard listen addresses are probed on the family's loopback; a specific non-loopback listen or TLS on the main listener needs --url (exit 2)"
  - "The TooNew rule lives in the storage crate (inspect_for_restore) so it can be tested with raw SQL; anvilid has no sqlx dependency"

patterns-established:
  - "Exit-code CLI commands (healthcheck) call std::process::exit from main with 0/1/2 instead of returning anyhow errors"

requirements-completed: [ADM-07, OPS-07]  # Delivered by this plan; REQUIREMENTS.md checkboxes left to the orchestrator (shared rules).

duration: ~45min
completed: 2026-11-26
---

# Phase 5 Plan 17: CLI backup, restore, admin recover and healthcheck Summary

**SQLite backups now run online with `VACUUM INTO`, and a backup is checked and renamed into place atomically. Restore refuses a running server, a corrupt file, a backup from a newer binary and the wrong KEK. Postgres is refused with a pointer to the pg_dump/PITR docs. `admin recover` is shell-only: it issues a one-time reset URL, ensures the administrator role, can reset MFA, and creates a fresh admin only after a lockout. A loopback-only `healthcheck` covers distroless containers.**

## Performance

- **Duration:** about 45 min (last task commit 2026-11-26 05:15 +0100)
- **Tasks:** 2/2, plus one follow-up fix commit
- **Files:** 8 created, 4 modified

## Commands

| Command | Behaviour |
| ------- | --------- |
| `anvilid backup create --output FILE` | SQLite: VACUUM INTO into `.FILE.partial-<uuid>`, integrity check + migration version, chmod 0600, fsync, rename, dir fsync. Prints the version and tenant count, and warns on stderr that the KEK is not included. Refuses an existing FILE, a missing database and in-memory URLs. Postgres: exits non-zero with the `docs/OPERATIONS.md#postgres` pointer |
| `anvilid backup restore --input FILE [--yes]` | `inspect_for_restore`: corrupt/foreign/TooNew are refused. Then takes `serve.lock`, requires a KEK, and requires `--yes` if the db exists. Copies to `.anvilid.db.restore-<uuid>`, KEK-opens a signing key, re-inspects, removes the temp sidecars, fsyncs, removes the old `-wal`/`-shm`, renames, dir fsync. Postgres: refused like create |
| `anvilid admin recover --email E [--reset-mfa]` | Prints one `Recovery URL: {system issuer}/ui/recovery?token=…` (1 h, one use) and reports any role assignment or MFA removals |
| `anvilid admin recover` | Prints `Setup URL: …/setup?token=…` only when `holders_of_permission(system, admin:write) == 0`. Otherwise it exits non-zero and asks for `--email` |
| `anvilid healthcheck [--url URL]` | `GET /health/ready` over HTTP/1.1, with 2 s connect/read/write timeouts. Exit 0 on a 200 status line, 1 when not ready or unreachable, 2 when the target is refused or there is a usage error |
| `anvilid keys rotate` | Unchanged. KEK rotation is documented as not supported in 0.4 |

## Guard tests (security map)

| Guard | Test |
| ----- | ---- |
| Backup is a point-in-time snapshot while writing | `anvil-storage-sqlite` `backup::tests::backup_while_writing_is_a_consistent_snapshot`; `anvilid/tests/backup.rs::backup_create_while_serving_and_writing_is_consistent_and_warns_about_the_kek` |
| Backup never overwrites / never creates a source | `backup::tests::backup_refuses_an_existing_destination`, `backup_never_creates_a_missing_source`, `cli.rs::backup_create_needs_an_installation` |
| Restore refuses while server runs (serve.lock) | `backup.rs::backup_restore_refuses_while_the_server_runs` |
| Restore refuses truncated/foreign/missing files | `backup.rs::backup_restore_refuses_corrupt_and_foreign_files`, `backup::tests::inspect_rejects_truncated_and_foreign_files` |
| Restore refuses newer migration version | `backup::tests::restore_inspection_refuses_a_backup_from_a_newer_binary` |
| Restore refuses wrong/missing KEK and an existing db without --yes | `backup.rs::backup_restore_refuses_a_wrong_kek_and_an_existing_database_without_yes` |
| Restore removes -wal/-shm, serve starts on restored data | `backup.rs::backup_restore_round_trip_replaces_the_database_and_serve_starts` |
| Postgres backup fails explicitly with docs pointer (no URL echo) | `cli.rs::backup_on_postgres_fails_and_points_to_the_docs` |
| Recovery URL single use; opens reset page; audited by system actor | `admin_recover.rs::admin_recover_issues_a_one_time_recovery_url_for_a_system_admin` |
| Recovery token expires after 1 h (fixed clock) | `admin_recover.rs::admin_recover_token_expires_after_one_hour`; core `service::admin_recovery::tests::recovery_token_is_a_one_hour_recovery_token_bound_to_the_user` |
| Unknown / other-tenant / invalid email refused, nothing created | `admin_recover.rs::admin_recover_refuses_unknown_and_other_tenant_emails` |
| Blocked account refused | `admin_recover.rs::admin_recover_refuses_blocked_accounts` |
| --reset-mfa removes TOTP + passkeys only when asked (audited) | `admin_recover.rs::admin_recover_reset_mfa_removes_totp_and_passkeys_only_when_asked` |
| Administrator role ensured | `admin_recover.rs::admin_recover_assigns_the_administrator_role` |
| Fresh admin only on lockout | `admin_recover.rs::admin_recover_creates_fresh_admin_when_locked_out`, `admin_recover_without_email_refused_when_admin_exists` |
| No HTTP route to recovery | `admin_recover.rs::admin_recovery_has_no_http_route` |
| Healthcheck refuses non-loopback/non-http/credentials without connecting | `healthcheck.rs::healthcheck_refuses_other_hosts_without_connecting`; bin `healthcheck::tests::other_hosts_schemes_and_credentials_are_refused` |
| Healthcheck 0 when ready, 1 on 503/unreachable/non-HTTP/draining | `healthcheck.rs::healthcheck_is_ready_against_a_running_server`, `healthcheck_fails_when_not_ready_or_unreachable`, `healthcheck_fails_while_the_server_drains` |

## Task Commits

1. **Task 1, backup create/restore and Postgres guidance:** `b3bc5d5` (feat)
2. **Task 2, admin recover and healthcheck:** `fba9587` (feat)
3. **Follow-up, per-factor audit events for --reset-mfa:** `166b98e` (fix)

## Verification

- `cargo test -p anvil-storage-sqlite --lib backup`: 6 passed.
- `cargo test -p anvil-core --lib service::admin_recovery`: 2 passed.
- `cargo test -p anvilid`: every binary green. That covers 49 bin unit tests, admin_recover 10, backup 5, cli 18, healthcheck 4, and all the existing suites (serve 10, keys_cli 2, jobs 3, …); limiter_redis has 2 ignored, as before.
- `grep -rn "recover" crates/anvil-web/src/lib.rs crates/anvil-web/src/admin` finds only a doc comment about "recovery codes" on the existing credential-removal endpoint. There is no recovery route, and `admin_recovery_has_no_http_route` enforces this.
- `anvilid --help` lists `backup` and `healthcheck`. `anvilid admin --help` lists `recover`. Both are asserted in `cli.rs::help_lists_backup_admin_recover_and_healthcheck`.
- `SQLX_OFFLINE=true cargo clippy -p anvil-storage-sqlite -p anvilid --all-targets -- -D warnings`: clean. The only output is the pre-existing `serde-saphyr` unused-dependency manifest warning, which belongs to 05-01's manifest.
- `rustfmt --edition 2024 --check` on every touched .rs file: clean.

## Not run

- `cargo clippy -p anvil-core -- -D warnings` fails on another wave-4 plan's uncommitted `service/role.rs` (unused `caller`, collapsible if, unfulfilled expectation). It reported nothing in `admin_recovery.rs`, but anvil-core clippy has to be re-run once role.rs lands.
- Postgres runs: `admin recover` on Postgres goes through the same storage traits, but no Postgres test was run here because Docker was not used.
- No e2e/browser run. The reset page is checked over raw HTTP (GET returns 200 with the token and password fields), and the reset POST is exercised through `UserRepo::complete_recovery`.

## Deviations from Plan

### Auto-fixed / added

**1. [Rule 2 - Missing critical check] Restore verifies the KEK.**
- **Found during:** Task 1
- **Issue:** a backup restored next to a missing or different KEK would make `serve` generate a new KEK, or fail to open signing keys. The installation would be silently broken.
- **Fix:** restore requires a KEK, then checks that it decrypts one signing key of the copy before anything is replaced. Test: `backup_restore_refuses_a_wrong_kek_and_an_existing_database_without_yes`.
- **Commit:** b3bc5d5

**2. [Rule 2] Backups and restored databases are chmod 0600.**
- **Why:** `VACUUM INTO` creates the file with the umask, and the file holds password hashes and sealed secrets. Asserted in the online-backup test. Commit b3bc5d5.

**3. [Rule 3] TooNew check moved into the storage crate (`inspect_for_restore`).**
- **Why:** fabricating a "future" backup needs raw SQL, and anvilid's manifest (owned by 05-01) has no sqlx. Commit b3bc5d5.

**4. [Rule 3] `SqliteStorage::close()` added to lib.rs (a file this plan owns).**
- **Why:** the KEK check opens the temporary copy briefly. The reader pool closes first, so the writer is the last connection and checkpoints, and no WAL content is lost when the sidecars are removed. Commit b3bc5d5.

**5. Storage-backed recovery tests live in `anvilid/tests/admin_recover.rs`, not in anvil-core.**
- **Why:** anvil-core has no storage fake that covers the users, roles, setup and audit repositories. The fixed-clock expiry test runs AdminRecoveryService against SqliteStorage with a test `Clock`. Core keeps pure unit tests (token TTL/hash, URL shape).

**6. "Console token has admin:write" is checked as "the new user holds a role whose permissions contain admin:write" (and `holders_of_permission == 1`).**
- **Why:** the role-to-admin-scope mapping is still in another wave-4 plan's uncommitted `service/role.rs`, and depending on uncommitted work was not an option.

**7. [Rule 2] Per-factor audit events for `--reset-mfa`.**
- **What:** each removal is audited as `totp_removed` / `passkey_removed` with the system actor, matching `AccountService::admin_remove`. That path is private and needs the WebAuthn port, so it could not be called from the CLI.
- **Commit:** 166b98e

## Issues Encountered

- During Task 1, another plan's in-progress `service/role.rs` briefly broke the anvil-core build. It compiled again a few minutes later.
- The first restore run left `-wal`/`-shm` beside the temporary copy: the read-only re-inspection recreates them. Fixed by removing the sidecars after the last check, before the rename.

## Self-Check: PASSED
