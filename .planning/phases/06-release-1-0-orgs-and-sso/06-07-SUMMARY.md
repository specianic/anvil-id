---
phase: 06-release-1-0-orgs-and-sso
plan: 07
subsystem: database
tags: [sqlite, migrations, organizations, rbac, saml, upgrade]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-02 model types and storage refusals, 06-04 OrgRepo/RoleRepo/ConnectionRepo ports and the 45-test contract suite
provides:
  - SQLite migration 0008_release_1_0.sql (additive, transactional)
  - SQLite migration 0009_release_1_0_rebuild.sql (no-transaction rebuild of connection, role, role_assignment, replay_guard, email_template)
  - SqliteOrgs (OrgRepo) and the org-level RoleRepo/ConnectionRepo methods on SQLite
  - org_id on codes/families, saml connections, saml_assertion_id replay kind, org_invitation templates, org branding scopes, client organization policy on SQLite
  - 0.4 -> 1.0 upgrade fixture and tests that count rows before and after the rebuild
affects: [06-08, 06-12, 06-14, 06-17, 06-18, 06-19, 06-20]

tech-stack:
  added: []
  patterns:
    - "Rebuild of referenced SQLite tables: `-- no-transaction`, foreign keys off, one explicit transaction for all rebuilds, pragma_foreign_key_check counted into a CHECK(n = 0) temp table before COMMIT"
    - "Partial unique indexes instead of a primary key on role_assignment; upserts name the index predicate (ON CONFLICT (...) WHERE org_id IS NULL / IS NOT NULL)"
    - "Shared intent steps on &mut SqliteConnection (insert_membership_on, assign_in_org_on) reused by add_member, the invitation accepts and create_user_with_link"

key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0008_release_1_0.sql
    - crates/anvil-storage-sqlite/migrations/0009_release_1_0_rebuild.sql
    - crates/anvil-storage-sqlite/src/organizations.rs
    - crates/anvil-storage-sqlite/tests/fixtures/release_0_4.sql
  modified:
    - crates/anvil-storage-sqlite/src/{lib,roles,connections,grants,clients,branding,mail_settings}.rs
    - crates/anvil-storage-sqlite/tests/upgrade.rs
    - crates/anvil-storage-sqlite/.sqlx (62 added, 23 removed)
  deleted:
    - crates/anvil-storage-sqlite/src/pending.rs

key-decisions:
  - "org_domain.connection_id has no foreign key on SQLite (ON DELETE SET NULL on a composite key would null tenant_id/org_id too); the writing statements check same-org, and an AFTER DELETE trigger on connection clears it"
  - "org_invitation stores the inviter as invited_by_kind + invited_by_id columns (AuditActor has no serde), like audit_event"
  - "OrgRepo::delete also deletes the org:{id} branding scope in its transaction, so org branding never outlives the org"
  - "All 0.4 tenant-level role queries now filter role_assignment.org_id IS NULL (and role.org_id IS NULL for list/assign), so org assignments never leak into tenant-wide views or the last-admin guard"

patterns-established:
  - "map_fk_err(what): foreign-key violations on inserts become StorageError::Conflict (organizations.rs, used by roles and connections)"

requirements-completed: []

duration: ~35min
completed: 2026-11-26
---

# Phase 6 Plan 07: SQLite migrations and Phase 6 repositories Summary

**SQLite now stores every Phase 6 aggregate. Migration 0008 adds the org tables and columns. Migration 0009 rebuilds connection, role, role_assignment, replay_guard and email_template with foreign keys off, and checks the foreign keys before COMMIT. SqliteOrgs implements OrgRepo, and the role, connection, grant, client, branding and mail repositories handle every org value. A populated 0.4 database upgrades without losing an identity link or a role assignment, and the 470-test contract suite is green on memory and file.**

Requirements: ORG-02, ORG-03 and ORG-04 have their SQLite storage in place. Nothing is ticked: only the gate plan (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 35 min (reading from 11:02; commits at 11:11 and 11:33 +01:00)
- **Tasks:** 2/2
- **Files:** 4 created, 9 modified, 1 deleted, plus the `.sqlx` metadata

## Task Commits

1. **Task 1, migrations 0008/0009, 0.4 fixture, upgrade tests:** `105002d` (feat)
2. **Task 2, OrgRepo and the org-level repository methods, `.sqlx`:** `bc0e806` (feat)

## Schema

**0008_release_1_0.sql** (normal, transactional, no existing row changes)
- `organization`: slug CHECK (2-63 characters, `[a-z0-9-]`, not starting with `-`, matching `validate_org_slug`), mfa_policy CHECK, JSON settings and metadata. Indexes: UNIQUE (tenant_id, slug) and UNIQUE (tenant_id, id), which is the composite FK target.
- `org_membership`: PK (tenant_id, org_id, user_id), FK to organization and FK to user (both CASCADE), index on (tenant_id, user_id).
- `org_invitation`:
  - columns: token_hash is 32 bytes and UNIQUE; email is 1-254 characters; roles is a JSON array; the inviter is stored as invited_by_kind (CHECK) and invited_by_id
  - CHECKs: accepted_at and accepted_user_id are set together; an invitation cannot be both accepted and revoked
  - keys and indexes: FK to organization (CASCADE); index on (tenant_id, org_id, created_at)
- `org_domain`:
  - columns: domain is lowercase and 1-253 characters; status CHECK pending/verified; routing; `allow_local_password` DEFAULT 1; `failing_since`
  - CHECKs: status = verified exactly when verified_at is set; failing_since needs verified_at
  - FK to organization (CASCADE)
  - UNIQUE (tenant_id, org_id, domain), so one claim per org
  - **partial UNIQUE (tenant_id, domain) WHERE verified_at IS NOT NULL**
  - recheck index on (last_checked_at, id) over verified claims
- Added columns:
  - `authorization_code.org_id` and `token_family.org_id`: nullable, no FK. Partial index `token_family_org_idx` over the org-bound families.
  - `client.organization`: NOT NULL DEFAULT 'off', with a CHECK.

**0009_release_1_0_rebuild.sql** (`-- no-transaction`, `-- anvil:non-destructive-rebuild`)
- The 0004 procedure:
  - `PRAGMA foreign_keys = OFF`, then `BEGIN`
  - five rebuilds in the order connection, role, role_assignment, replay_guard, email_template; each creates `x_new`, copies every column explicitly, drops `x`, renames `x_new` and recreates every index
  - `anvil_fk_violations (n CHECK (n = 0))` filled from `pragma_foreign_key_check`
  - `COMMIT`, then `PRAGMA foreign_keys = ON`
- connection: kind gains `saml`; `org_id` with FK (tenant_id, org_id) -> organization CASCADE; partial index on org_id. Trigger `connection_clears_org_domain`.
- role: FK (tenant_id, org_id) -> organization CASCADE. `role_tenant_name_uq` is unchanged; `role_org_name_uq` covers (tenant_id, org_id, name) WHERE org_id IS NOT NULL.
- role_assignment:
  - `org_id` column
  - the PK becomes `role_assignment_tenant_uq` (tenant_id, role_id, user_id) WHERE org_id IS NULL, plus `role_assignment_org_uq` (tenant_id, role_id, user_id, org_id) WHERE org_id IS NOT NULL
  - FK (tenant_id, org_id, user_id) -> org_membership CASCADE; MATCH SIMPLE, so it is not checked for tenant-wide rows
  - member index
- replay_guard: kind gains `saml_assertion_id`. email_template: kind gains `org_invitation`.

## Rebuild procedure notes

- **The hazard is real.** I ran 0009 without the PRAGMA lines, with foreign keys on, on the seeded 0.4 database: identity_link went from 4 rows to 0 and role_assignment from 5 to 0. With the committed file, both counts are unchanged.
- **Re-running is safe.** If the process crashes between COMMIT and sqlx's bookkeeping insert, the next run copies every row again with org_id NULL; no 1.0 binary has written org data yet. DROP TABLE also drops the trigger and indexes that the script recreates.
- `scripts/check-migrations.sh`: OK. The annotation is recognised, released files 0001-0007 are untouched (`git diff` is empty), and `--self-test` passes.

## Upgrade test (tests/upgrade.rs, 0.4 -> 1.0)

The fixture `fixtures/release_0_4.sql` holds:
- 2 tenants (system and default) and 4 users
- 3 roles, including the system `administrator` role, and 5 role assignments
- 4 connections of 4 kinds (google, github, oidc, oauth2) across both tenants, with 4 identity links
- 3 replay guards and 3 email template overrides
- a client, a token family and an authorization code

| Table | Before | After |
|---|---|---|
| connection | 4 | 4 |
| identity_link | 4 | 4 |
| role | 3 | 3 |
| role_assignment | 5 | 5 |
| replay_guard | 3 | 3 |
| email_template | 3 | 3 |

- `upgrade_from_0_4_keeps_every_row` checks:
  - the per-table counts, and that they equal the fixture numbers
  - a full value snapshot of every 0.4 table, equal before and after
  - `pragma_foreign_key_check` is empty and the schema is at version 9
  - new columns take their defaults: connection.org_id is None, client.organization is Off, and family and code org_id are None
  - both administrators still hold `admin:write`
  - the unexpired replay guard still detects a replay
  - foreign keys are enforced again: a link to an unknown connection is a Conflict, and deleting a connection removes only its own link
- `upgrade_from_0_4_keeps_identity_links_after_connection_rebuild`: each seeded link still points at its connection and user, `has_links` is true, and each seeded assignment still points at its role and user. No assignment gained an org.
- `upgrade_from_0_4_is_idempotent_on_restart`: two more starts (the same process, then a fresh connection) apply nothing. Counts and the snapshot are unchanged, and 9 migrations are recorded.
- `upgraded_v0_4_contract`: the full contract suite runs on a database built through the 0.4 upgrade, like the existing 0.1, 0.2 and 0.3 paths.

## Repositories

- **OrgRepo (`organizations.rs`)**
  - `delete`: one writer transaction. The cascade covers memberships and through them every in-org assignment, org-owned roles, connections with their links, domains and invitations. In the same transaction it revokes the org's families (`admin`, storage clock `now`) and deletes the `org:{id}` branding scope.
  - `remove_member`: deletes the membership (its assignments cascade) and revokes that user's families in that org, in one transaction.
  - `add_member`: one transaction (`insert_membership_on`). An existing member gives AlreadyMember. An unknown org, user or role, or a role owned by another org, gives NotFound with a rollback.
  - `accept_invitation`: one transaction on the single writer. Order: Invalid (closed or unknown token, or unknown user), then EmailMismatch, then AlreadyMember, then one conditional `UPDATE … WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now` (0 rows gives Invalid), then the membership and the invitation's roles that still exist.
  - `accept_invitation_with_new_user`: the same, with user and password inserts. A taken email or username is a Conflict, and nothing is written.
  - `mark_verified`: a unique violation of the partial index maps to Conflict. An already verified claim is returned unchanged.
  - Routing (`routed_domain`, `tenant_has_routing`) requires a verified claim, `routing = 1`, and an enabled connection of the same org.
- **RoleRepo**
  - org-owned roles: `create` refuses an org outside the tenant (FK, mapped to Conflict).
  - `assign_in_org_on`: the role must be a tenant role or owned by that org, and the user must be a member.
  - the org listing, unassign and holder queries are implemented.
  - the tenant-level queries now filter `org_id IS NULL`.
- **ConnectionRepo:** org_id round-trips; saml configs are stored; `list_for_org`; `has_links`; `create_user_with_link` with a membership adds the member and its roles in the user's transaction, and a refused membership rolls everything back.
- **GrantRepo / ClientRepo / BrandingRepo / MailSettingsRepo:** org_id on codes and families, `saml_assertion_id`, `client.organization` (insert, update, CIMD upsert), `org:` scopes, `org_invitation`.
- Every `TRANSITIONAL(06-07)` marker and refusal helper is gone (`grep -rn "TRANSITIONAL(06-07)" crates/` finds nothing), and `pending.rs` is deleted.

**Contract count:** `cargo test -p anvil-storage-sqlite --test contract` gives 470 passed and 0 failed: 380 earlier tests plus the 45 new ones, each on memory and file. Both concurrency tests pass (8 concurrent accepts, 8 concurrent verifications).

## Verification

- With the regenerated `.sqlx` (offline), `cargo test -p anvil-storage-sqlite` passes: lib 21, contract 470, plaintext 2, upgrade 951 (which includes every upgrade-path contract suite).
- `cargo clippy -p anvil-storage-sqlite --all-targets -- -D warnings`: clean.
- `scripts/sqlx.sh prepare crates/anvil-storage-sqlite`, then `scripts/sqlx.sh check crates/anvil-storage-sqlite`: OK.
- `scripts/check-migrations.sh` and `--self-test`: OK.
- `scripts/check-release-graph.sh`: OK.
- `rustfmt --edition 2024` on the changed files only.

## Not run here / blocked by peers

- **`cargo test -p anvil-web --no-run`** fails in one file: the untracked peer file `crates/anvil-web/tests/admin_keys.rs` (wave-3 plan 06-11, still in progress) passes a `time::Duration` where the clock expects `SignedDuration`. The anvil-web lib and the other test targets compiled. Nothing in storage is involved.
- **`scripts/check-security-tests.sh`** stops at "cargo test --list failed" for the same reason: it compiles the whole workspace.
- Postgres belongs to 06-08. No e2e: this plan has no UI.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Tenant-level role queries would have counted org assignments**
- **Found during:** Task 2
- **Issue:** after 0009, `role_assignment` rows can carry an org. Without a filter, `roles_for_user`, `users_with_role`, `holders_of_permission` (the last-admin guard), `unassign` and `list` would mix in org rows or org-owned roles. The upserts' `ON CONFLICT (tenant_id, role_id, user_id)` also no longer matches any unique index, so it would fail at runtime.
- **Fix:** add `org_id IS NULL` filters, add `role.org_id IS NULL` on `assign`, and add `WHERE org_id IS NULL` to the conflict targets, including `assign_admin_role` used by setup.
- **Commit:** bc0e806

**2. [Rule 2 - Missing critical] A routing connection is cleared when it is deleted**
- **Issue:** SQLite cannot `ON DELETE SET NULL` a single column of a composite FK, so `org_domain.connection_id` has no FK.
- **Fix:** same-org checks in `create_domain` and `update_domain`, plus the AFTER DELETE trigger `connection_clears_org_domain`, created in 0009 after the rebuild. Postgres (06-08) can use `ON DELETE SET NULL (connection_id)` instead.
- **Commit:** 105002d

**3. [Rule 2 - Missing critical] `create_user_with_link` with a membership for another user**
- **Fix:** refused with Conflict, and nothing is written.
- **Commit:** bc0e806

### Interpretations

- `invited_by` is stored as two columns instead of JSON, because `AuditActor` has no serde.
- `OrgRepo::delete` deletes the org's branding scope, so `org:` scopes never outlive the org.
- `record_check(ok = false)` on a *pending* claim updates `last_checked_at` only, since `failing_since` needs a verified claim (CHECK).
- `update_domain` does not use `now`: `org_domain` has no `updated_at`, and the port defines none.
- The Task 1 commit's identity-link test calls `has_links`, so it passed only after the Task 2 commit. Both commits are on main.
- Extra test: the full contract suite also runs on the 0.4-upgraded database (`upgraded_v0_4_contract`).
- Comments in `crates/anvil-storage/src/contract/*.rs` still say "refused until 06-07 / 06-08". Those files are not in this plan's scope, so I left them.

## Self-Check: PASSED

- FOUND: crates/anvil-storage-sqlite/migrations/0008_release_1_0.sql, 0009_release_1_0_rebuild.sql, src/organizations.rs, tests/fixtures/release_0_4.sql
- MISSING (as intended): crates/anvil-storage-sqlite/src/pending.rs
- FOUND commits: 105002d, bc0e806
