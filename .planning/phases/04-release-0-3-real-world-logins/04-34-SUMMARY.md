---
phase: 04-release-0-3-real-world-logins
plan: 34
subsystem: storage
tags: [storage, sqlite, postgres, sqlx, migrations, backchannel-logout, linked-identities, branding, purge, gap-closure]
requires:
  - phase: 04-04
    provides: SQLite 0005 schema (rp_session, logout_delivery, branding, branding_logo, identity_link)
  - phase: 04-05
    provides: Postgres 0004 schema, record_rp_session / enqueue_deliveries, local PG14 verification pattern
  - phase: 04-17
    provides: LogoutService::prepare_delivery, canonical_issuer
  - phase: 04-25
    provides: AccountService::unlink and the last-sign-in-method rule
provides:
  - NewAuthorizationCode.issuer, RpSession.issuer, LogoutDelivery.issuer
  - ConnectionRepo::delete_link(tenant, user, id, email_sign_in) -> DeleteLinkOutcome
  - ConnectionRepo::create_user_with_link(tenant, user, link, token, email)
  - service::logout::logout_token_issuer (delivery issuer, else canonical)
  - SQLite migration 0006_release_0_3_logout_issuer.sql, Postgres migration 0005_release_0_3_logout_issuer.sql
  - purge_expired removes unreferenced logos (both) and expired token families (Postgres parity)
  - ClientRepo::delete removes the client's branding and preview draft
affects: [04-32, 04-36, 04-37]
tech-stack:
  added: []
  patterns:
    - "Guarded delete: one DELETE … WHERE <id> AND (<remaining-method EXISTS…>), then a SELECT to tell LastSignInMethod from NotFound"
    - "Postgres per-user serialisation: SELECT … FROM \"user\" … FOR UPDATE before the guarded DELETE (READ COMMITTED re-snapshots per statement)"
    - "INSERT … SELECT … ON CONFLICT DO UPDATE SET issuer = excluded.issuer for the RP session (latest code wins)"
key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0006_release_0_3_logout_issuer.sql
    - crates/anvil-storage-postgres/migrations/0005_release_0_3_logout_issuer.sql
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/model/{logout,grant}.rs
    - crates/anvil-core/src/service/{authorize,logout,account,upstream}.rs
    - crates/anvil-storage/src/contract/{mod,fixtures,logout,connections,branding,grants}.rs
    - crates/anvil-storage-sqlite/src/{lib,grants,logout,connections,clients}.rs, tests/upgrade.rs, .sqlx/
    - crates/anvil-storage-postgres/src/{lib,grants,logout,connections,clients,users}.rs, tests/upgrade.rs, .sqlx/
    - crates/anvil-web/src/admin/auth.rs
    - crates/anvil-web/tests/{backchannel,account_linked,account_profile}.rs, tests/token_support/mod.rs
    - crates/anvilid/tests/backchannel_worker.rs
key-decisions:
  - "The issuer lives only on rp_session and logout_delivery (not on authorization_code): NewAuthorizationCode carries it into create_code, which upserts it on the RP session"
  - "prepare_delivery goes through a pure helper logout_token_issuer(public_url, tenant, delivery) so the fallback is unit-tested; None only for rows written before 0006/0005"
  - "Postgres logo purge stops the logo step for the run on SQLSTATE 23503 (a concurrent put re-referenced a logo) instead of logging it: the crate has no tracing dependency, and adding one meant touching Cargo.toml and the shared Cargo.lock during a parallel wave"
  - "The NULL-issuer upgrade assertion is a new test in each upgrade.rs that reuses the existing 0.2 fixture, migrates to the last pre-issuer version, inserts one rp_session and one logout_delivery, then lets the binary apply the new migration; the existing 0.2 -> latest test is unchanged, so its destructive-flag check still covers 0005/0004"
duration: about 50 min
completed: 2026-11-26
---

# Phase 4 Plan 34: Storage Gap Closure Summary

**Logout tokens now carry the issuer the RP got its ID tokens from (recorded per RP session by new migrations SQLite 0006 / Postgres 0005). Unlinking is one atomic guarded storage intent that never removes the last sign-in method, even under concurrency or with an unverified email. Replaced and orphaned logos, deleted clients' branding and, on Postgres, expired token families are purged. `create_user_with_link` can store a verification token and email atomically for 04-37.**

## Port signatures (for 04-32 and 04-37)

- `NewAuthorizationCode { …, issuer: String, … }`. `build_code(client, params, session, issuer: &str, now)`.
- `RpSession { …, issuer: Option<String>, … }` and `LogoutDelivery { …, issuer: Option<String>, … }`. `None` appears only for rows written before the new migrations.
- `ConnectionRepo::delete_link(&self, tenant, user: UserId, id: IdentityLinkId, email_sign_in: bool) -> Result<DeleteLinkOutcome, StorageError>`.
- `pub enum DeleteLinkOutcome { Deleted, NotFound, LastSignInMethod }` in `anvil_core::ports`.
- `ConnectionRepo::create_user_with_link(&self, tenant, user, link, token: Option<&NewSelfServiceToken>, email: Option<&NewEmail>)`. The upstream JitCreate call passes `None, None`. 04-37 wires the token.
- `anvil_core::service::logout::logout_token_issuer(public_url, tenant, delivery) -> String`.
- The doc comments on `Storage::purge_expired` and `ClientRepo::delete` describe the new deletions.
- `AccountService::unlink` maps the `DeleteLinkOutcome`. `SignInMethods` and its unit test are gone, so the rule now lives only in storage.
- `admin_issuer_of` delegates to `canonical_issuer`.

## Migrations (for 04-32's sha256 pins)

- `crates/anvil-storage-sqlite/migrations/0006_release_0_3_logout_issuer.sql`
- `crates/anvil-storage-postgres/migrations/0005_release_0_3_logout_issuer.sql`

Both files are ADD COLUMN only (`rp_session.issuer`, `logout_delivery.issuer`, nullable). `scripts/check-migrations.sh` and `--self-test` pass, and no existing migration changed.

## Contract tests (for 04-32's security map)

New tests, registered in `storage_contract_tests!`:
- `rp_session_records_issuer_and_deliveries_copy_it` (logout.rs)
- `delete_link_keeps_a_sign_in_method` (connections.rs). It covers an unverified email with email sign-in on, TOTP not counting, password, passkey, second link, verified email, another user's link, unknown id, other tenant and unknown user.
- `delete_link_concurrent_never_removes_the_last_method` (connections.rs, 10 rounds)
- `create_user_with_link_stores_verification_atomically` (connections.rs)
- `purge_expired_removes_unreferenced_logos` (branding.rs)
- `client_delete_removes_its_branding` (branding.rs)
- `purge_expired_removes_expired_token_families` (grants.rs)

Existing tests updated: `assert_fresh_delivery` now checks that every revoking intent copies the issuer. `identity_link_delete_only_own`, `connections_isolated_by_tenant` and `create_user_with_link_is_atomic` use the new outcomes and arguments.

Web tests:
- `backchannel.rs::logout_token_iss_is_the_issuer_the_rp_signed_in_with` covers a custom-host tenant through `/t/acme` (path issuer) and through `Host: login.acme.test` (host issuer).
- `account_linked.rs::unverified_email_is_not_a_remaining_sign_in_method` and `verified_email_with_email_sign_in_allows_unlink`.

## Task Commits

1. **Task 1: ports, model, core wiring, contract tests:** `ae3e6b4`
2. **Task 2: SQLite backend, migration 0006, web wiring and tests:** `b8ae320`
3. **Task 3: Postgres backend, migration 0005, .sqlx:** `ea30d39`

## Verification

SQLite, main tree:
- `cargo test -p anvil-storage-sqlite`: lib 14, contract 306, plaintext 2, upgrade 311. All passed.
- `scripts/sqlx.sh prepare crates/anvil-storage-sqlite`, then `check`: clean.
- `cargo test -p anvil-core --lib`: 583 passed.
- anvil-web `--test backchannel --test account_linked --test account_profile --test logout --test security_logout --test admin_api --test upstream_login`: all passed.

Postgres, on a throwaway local PostgreSQL 14 cluster. It ran from `/usr/lib/postgresql/14/bin` on 127.0.0.1:55534 with trust auth and its data dir in the session scratchpad. It has since been stopped and deleted.
- `.sqlx` was regenerated with `cargo sqlx prepare` against a migrated `anvil_dev` database. `cargo sqlx prepare --check` is clean. `SQLX_OFFLINE=true cargo check -p anvil-storage-postgres --all-targets` passes.
- `--test contract`: 153 passed. `--test upgrade`: 157 passed. `--test plaintext`: 2 passed.
  - These ran through an uncommitted local patch of `server_url()` in `tests/support/mod.rs` and `tests/upgrade.rs`. The helper honours no URL environment variable. The patch was reverted before committing.
- `delete_link` tests were run 5 times, all green.
- Mutation check: with `FOR UPDATE` removed from the user-row lock, `delete_link_concurrent_never_removes_the_last_method` failed 3 out of 3 runs (`[Deleted, Deleted]`). The lock is restored.
- Mutation check: with `prepare_delivery` reverted to `canonical_issuer`, the web test `logout_token_iss_is_the_issuer_the_rp_signed_in_with` fails on the path case. The code is restored.

Lint:
- clippy `-D warnings` is clean for anvil-core, anvil-storage, both storage crates and anvilid (`--all-targets`), and for anvil-web `--lib` plus the tests above.
- `cargo fmt --all --check` is clean.
- `grep -rn SignInMethods crates/anvil-core/src` finds nothing.

**Not run here (left for CI):**
- The Postgres `--lib` migration tests: they start `postgres_container` directly and need Docker.
- Postgres 18 testcontainers runs and `scripts/sqlx.sh check crates/anvil-storage-postgres` against PG18.
- `ANVILID_TEST_DB=postgres` runs of anvil-web `backchannel` / `account_linked`. The web test support uses Docker, and 04-36 owns `tests/support/mod.rs` in this wave.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra files the signature changes forced**
- `crates/anvil-web/tests/token_support/mod.rs`: `issue_code` passes the tenant's canonical issuer to `build_code`.
- `crates/anvilid/tests/backchannel_worker.rs`: `signed_in` takes the server's issuer.
- `crates/anvil-storage-postgres/src/users.rs`: `insert_self_service_token` is now `pub(crate)`, so `create_user_with_link` reuses it instead of adding a second insert.

**2. [Design] Postgres logo purge does not log on 23503**
- The plan says to log at debug. The crate has no `tracing` dependency, so the logo step stops for the run without logging. See key decisions.

**3. [Design] Upgrade assertion as its own test**
- The plan says to extend the existing 0.2 -> 0.3 test. The new test reuses that test's fixture but has its own migration path (stop at the last pre-issuer version, insert rows, then upgrade), so the existing test stays unchanged. See key decisions.

### Notes for other wave-8 plans
- 04-36's untracked `crates/anvil-web/tests/backchannel_wake.rs` builds a `NewAuthorizationCode` literal. It needs `issuer: …` now, or it can use `build_code(…, issuer, now)`. I did not edit that file because it is not in this plan's files.

## Issues Encountered
- PostgreSQL rejected the scratchpad as a Unix-socket directory (path over 107 bytes). The cluster ran TCP-only (`-k ''`).

## Self-Check: PASSED

- Both migration files exist. Commits `ae3e6b4`, `b8ae320` and `ea30d39` are in the history.
