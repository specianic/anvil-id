---
phase: 06-release-1-0-orgs-and-sso
plan: 08
subsystem: storage-postgres
tags: [postgres, migrations, organizations, org-roles, org-connections, saml, upgrade]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-02 model/ids, 06-04 OrgRepo/RoleRepo/ConnectionRepo ports and the Phase 6 contract suite
provides:
  - Postgres migration 0007_release_1_0.sql (in place, transactional)
  - PgOrgs (OrgRepo) and the org methods of RoleRepo/ConnectionRepo on Postgres
  - org_id on Postgres codes/families/connections/roles/assignments; saml kinds, org_invitation templates, org branding, client organization policy stored
  - 0.4 -> 1.0 upgrade test with per-table row counts (Postgres)
affects: [06-12, 06-14, 06-17, 06-18, 06-19, 06-20, 06-26]

tech-stack:
  added: []
  patterns:
    - "Org-scoped FK targets: UNIQUE (tenant_id, id) on organization, UNIQUE (tenant_id, org_id, id) on connection for the domain routing FK"
    - "Partial-unique-index ON CONFLICT targets: ON CONFLICT (tenant_id, role_id, user_id) WHERE org_id IS NULL"
    - "Foreign key violations reported as Conflict through organizations::fk_conflict (convert.rs untouched)"

key-files:
  created:
    - crates/anvil-storage-postgres/migrations/0007_release_1_0.sql
    - crates/anvil-storage-postgres/src/organizations.rs
    - crates/anvil-storage-postgres/tests/fixtures/release_0_4.sql
  modified:
    - crates/anvil-storage-postgres/src/{lib,roles,connections,grants,clients,branding,mail_settings}.rs
    - crates/anvil-storage-postgres/tests/upgrade.rs
    - crates/anvil-storage-postgres/.sqlx (62 added, 22 removed, regenerated)
  deleted:
    - crates/anvil-storage-postgres/src/pending.rs

key-decisions:
  - "org_domain.connection_id has a composite FK (tenant_id, org_id, connection_id) -> connection (tenant_id, org_id, id), so routing to a connection outside the org fails in the database. ConnectionRepo::delete clears the routing target of referencing domains first, in the same transaction. SQLite reaches the same behaviour with a trigger."
  - "org_invitation.role_ids is jsonb (a JSON array of id strings), as in SQLite. uuid[] would have tripped the plaintext column scanner in tests/plaintext.rs, a file this plan does not own."
  - "invited_by is stored as invited_by_kind/invited_by_id, the same shape audit_event uses (AuditActor is not serde)"
  - "OrgRepo::delete also deletes the org's branding row (parity with SQLite 06-07). Drafts are left to expire."
  - "accept_invitation locks the invitation row (SELECT ... FOR UPDATE) and then consumes it with the conditional UPDATE, so a concurrent accept sees the token closed and gets Invalid"

patterns-established:
  - "A local PG14 cluster plus an uncommitted server_url() patch is enough to run the Postgres contract/upgrade/plaintext suites without Docker"

requirements-completed: []

duration: ~55min
completed: 2026-11-26
---

# Phase 6 Plan 08: Postgres migrations and every Phase 6 repository Summary

**Postgres now stores every Phase 6 aggregate. Migration 0007 adds organizations, memberships, invitations and verified domains in place. It also adds org-owned roles and in-org assignments, org and SAML connections, and org-bound codes and families. Both concurrency races are decided by the database. Everything ran on a local PostgreSQL 14 cluster: all 235 contract tests, the upgrade suite (242, including the new 0.4 -> 1.0 row-count test) and plaintext (2) pass. No TRANSITIONAL(06-08) marker is left.**

Requirements ORG-02, ORG-03 and ORG-04 now have Postgres storage. Their boxes are not ticked here; only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 55 min (reading, then commits at 11:24 +01:00)
- **Tasks:** 2/2
- **Files:** 3 created, 8 modified, 1 deleted, `.sqlx` regenerated

## Task Commits

1. **Task 1, migration 0007, 0.4 fixture and upgrade tests:** `b9bfe81` (feat)
2. **Task 2, repositories, shim removal, `.sqlx`:** `e191365` (feat)

## Schema (0007_release_1_0.sql)

The migration runs in one transaction. It has no DROP TABLE, DROP COLUMN, RENAME or type change, and `scripts/check-migrations.sh` passes it. 0001-0006 are unchanged.

- **New tables:**
  - `organization`: slug CHECK (tenant slug rule); `UNIQUE (tenant_id, slug)`; `UNIQUE (tenant_id, id)` as the FK target.
  - `org_membership`: PK (tenant, org, user); composite FKs to the org and the user, both CASCADE.
  - `org_invitation`:
    - the token is stored only as a 32-byte hash, `UNIQUE (token_hash)`;
    - `role_ids` is a jsonb array; `invited_by_kind` / `invited_by_id` hold the inviter;
    - CHECKs: accepted_at and accepted_user_id are set together, and an invitation is never both accepted and revoked.
  - `org_domain`:
    - the domain must be lowercase and 1-253 characters; `allow_local_password` defaults to true; `failing_since` is stored;
    - `UNIQUE (tenant_id, org_id, domain)`, plus the partial unique index `org_domain_verified_key (tenant_id, domain) WHERE verified_at IS NOT NULL`;
    - the composite routing FK goes to `connection (tenant_id, org_id, id)`;
    - CHECKs: status is verified exactly when verified_at is set, and failing_since needs a verified claim.
- **connection:**
  - `connection_kind_check` is swapped (DROP/ADD CONSTRAINT) to add `saml`;
  - new `org_id` column, with FK `connection_org_id_fkey` (tenant_id, org_id) -> organization CASCADE;
  - new `UNIQUE (tenant_id, org_id, id)`.
- **role:** `role_org_id_fkey` (tenant_id, org_id) -> organization CASCADE, and `role_tenant_org_name_key` UNIQUE (tenant_id, org_id, name) WHERE org_id IS NOT NULL.
- **role_assignment:**
  - new `org_id` column; `role_assignment_pkey` is dropped;
  - partial unique indexes `role_assignment_tenant_key` (WHERE org_id IS NULL) and `role_assignment_org_key` (WHERE org_id IS NOT NULL);
  - `role_assignment_membership_fkey` (tenant_id, org_id, user_id) -> org_membership CASCADE (MATCH SIMPLE, so tenant-wide rows are not checked).
- **Other columns and CHECKs:**
  - `authorization_code.org_id` and `token_family.org_id` are added without an FK, plus an index for revocation;
  - `replay_guard_kind_check` gains `saml_assertion_id`, and `email_template_kind_check` gains `org_invitation`;
  - `client.organization` text NOT NULL DEFAULT 'off', with a CHECK on off/optional/required.

**Diamond cascades** (tenant or org -> connection and -> org_domain, where org_domain also references the connection) were checked on PG14 with raw DELETEs:
- org delete and tenant delete both succeed;
- a direct connection delete is refused by the FK, which is why `ConnectionRepo::delete` clears the routing target first.

## Repositories

- **organizations.rs (PgOrgs):** every OrgRepo method.
  - `add_member` is `INSERT … WHERE EXISTS … ON CONFLICT DO NOTHING`, followed by the in-org role assignments, in one transaction. Anything other than `Added` rolls back.
  - `remove_member` and `delete` revoke the org-bound families (reason admin) in the same transaction. `delete` also removes the `org:{id}` branding row.
  - `accept_invitation` / `accept_invitation_with_new_user` lock the invitation row, decide in the order Invalid, EmailMismatch, then AlreadyMember or Conflict, and then run the conditional UPDATE plus the membership and the still-existing roles.
  - `mark_verified` is one conditional UPDATE; the partial unique index turns a second org into `Conflict`. `update_domain` maps a routing-FK violation to `None`.
  - `routed_domain` and `tenant_has_routing` join an enabled connection of the same org. `due_for_recheck` orders `last_checked_at NULLS FIRST, id`.
- **roles.rs:**
  - `insert_role` stores `org_id`; an unknown org gives `Conflict`.
  - The 0.4 methods (`list`, `assign`, `unassign`, `roles_for_user`, `users_with_role`, `holders_of_permission`) only see tenant roles and tenant-wide assignments.
  - New `assign_role_in_org` (shared with OrgRepo), plus the six org methods.
- **connections.rs:**
  - `org_id` is stored and read; an unknown org gives `Conflict`. SAML configs are stored.
  - New `list_for_org` and `has_links`.
  - `create_user_with_link` inserts the membership and its roles in the same transaction. An unknown org or role gives `Conflict` with nothing written.
  - `delete` clears domain routing targets first.
- **grants.rs:** `org_id` is written on families and codes and read on `get_family` / `consume_code`; `saml_assertion_id` replay entries are accepted.
- **clients.rs:** `organization` is read and written by create, update and upsert_cimd. upsert_cimd replaces it like `mfa_policy`.
- **branding.rs, mail_settings.rs:** the `org:` scope and `org_invitation` refusals are gone.
- **pending.rs** is deleted, and lib.rs wires `PgOrgs`.

## Upgrade test (tests/upgrade.rs, fixtures/release_0_4.sql)

`upgrade_from_0_4_keeps_every_row`:
- **Fixture:** 2 tenants (system and acme), 3 users, 3 roles (including the system `administrator`), 4 role assignments, 3 connections (google, oidc, github), 4 identity links, 3 replay guards, 2 email templates, 1 client, 1 session, 1 family and 1 code.
- **Row counts:** 11 tables are counted before and after the upgrade and must be equal: tenant, user, connection, identity_link, role, role_assignment, replay_guard, email_template, client, token_family, authorization_code.
- **Data checks after the upgrade:**
  - every link and assignment still has its targets (join check);
  - every 0.4 row is tenant-level (org_id NULL, client policy off);
  - the swapped CHECKs still reject unknown kinds.
- **0.4 behaviour through the traits:** the administrator role and its holder; tenant roles; idempotent re-assign with no duplicate row; connections; links; `has_links`; family `org_id = None`; client policy Off; the 0.4 replay entry still blocks while `saml_assertion_id` is accepted; the 0.4 templates plus an `org_invitation` put; deleting a user still cascades.
- **Org features on the upgraded schema:** create an org, add a 0.4 user with a 0.4 role, run `roles_for_user_in_org`, delete an org connection that a domain routes to (the claim stays, with `connection_id = None`), re-route, and delete the tenant.

`upgrade_from_0_4_is_idempotent_on_restart`: two starts, the version is past 6, and the row counts are unchanged.

## Verification

Every Postgres run used a throwaway local **PostgreSQL 14.24** cluster:
- Binaries from `/usr/lib/postgresql/14/bin`, trust auth, listening on 127.0.0.1 only with no unix socket. The data dir was in the session scratchpad.
- The cluster has been stopped and its data dir deleted.
- The suites reached it through an uncommitted `server_url()` patch in `tests/support/mod.rs` and `tests/upgrade.rs`. The patch was reverted before both commits. `tests/support/mod.rs` is unchanged, and `upgrade.rs` contains only the committed tests.

Results:
- `cargo test -p anvil-storage-postgres --test contract`: **235 passed**. That is 190 earlier tests plus the 45 Phase 6 tests. The concurrency subset (16 tests, including `invitation_accept_concurrent_single_winner` and `domain_mark_verified_concurrent_single_winner`) was re-run 3 times, all green.
- `--test upgrade`: **242 passed**. That is the 235 contract tests on upgraded databases, the 5 earlier upgrade tests and the 2 new 0.4 -> 1.0 tests.
- `--test plaintext`: 2 passed.
- Lib unit tests that need no Docker (convert, migrate name-based destructive checks): 8 passed.
- `.sqlx`: regenerated with `cargo sqlx prepare` (the same invocation `scripts/sqlx.sh` uses) in the crate dir, against a migrated `anvil_dev` on the local cluster. `cargo sqlx prepare --check` is clean. No file was edited by hand.
- `cargo clippy -p anvil-storage-postgres --all-targets -- -D warnings` (offline): clean.
- `cargo check -p anvilid`: OK.
- `rustfmt --edition 2024 --check` on the touched files: clean.
- `scripts/check-migrations.sh`: OK. `scripts/check-release-graph.sh`: OK.
- `grep -rn "TRANSITIONAL(06-08)" crates/`: no match.

## Not run here

- PG18 testcontainers runs (`just test-pg`) and `scripts/sqlx.sh check crates/anvil-storage-postgres` against the Docker dev container, because Docker is down. CI covers them, and the gate (06-26) confirms them.
- The Docker-only lib tests in `lib.rs` and `migrate.rs`:
  - `composite_tenant_foreign_keys_reject_cross_tenant_rows` inserts a raw role_assignment; with org_id NULL the composite role/user FKs still reject a cross-tenant row.
  - `migration_0003_…`, and the migrate lock/destructive tests.
- anvil-web / anvilid on Postgres (`ANVILID_TEST_DB=postgres`).

## Deviations from Plan

1. **[Rule 3 - Blocking] `org_invitation.role_ids` is jsonb, not uuid[].** `tests/plaintext.rs` (not owned by this plan) panics on any array column whose type is not text. jsonb is also what RESEARCH and SQLite use. Commit `b9bfe81`.
2. **[Rule 2 - Correctness] `ConnectionRepo::delete` clears `org_domain.connection_id` first.** Without this, deleting a connection that a domain routes to would fail on the routing FK. This keeps the claim and its verification, and matches the SQLite trigger. Commit `e191365`.
3. **[Parity] `OrgRepo::delete` deletes the org's branding row,** and the extra CHECKs (domain lowercase/length, token non-empty, failing_since needs verified, email 1-254, accepted xor revoked) mirror SQLite 0008. These were added after reading 06-07's in-progress files.
4. **`.sqlx` was regenerated with `cargo sqlx prepare` against the local cluster,** not by calling `scripts/sqlx.sh`, which needs the Docker container on port 55432. The arguments are the same.

No file outside files_modified was changed.

## Self-Check: PASSED

- FOUND: crates/anvil-storage-postgres/migrations/0007_release_1_0.sql, crates/anvil-storage-postgres/src/organizations.rs, crates/anvil-storage-postgres/tests/fixtures/release_0_4.sql
- MISSING as intended: crates/anvil-storage-postgres/src/pending.rs (deleted)
- FOUND commits: b9bfe81, e191365
