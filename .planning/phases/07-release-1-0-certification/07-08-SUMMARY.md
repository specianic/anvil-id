---
phase: 07-release-1-0-certification
plan: 08
subsystem: storage
tags: [ports, storage, sqlite, postgres, contract, migrations, upgrade, OIDC-18, ADM-08, ADM-09, QUAL-03]
requires:
  - "07-03: model::par, model::password_profile, the three Client fields"
provides:
  - "GrantRepo::{families_for_user, create_pushed_request, consume_pushed_request}"
  - "UserRepo::{replace_password_if, pending_self_service_tokens}"
  - "PasswordProfileRepo {create, get, list, delete, count_references} via Storage::password_profiles()"
  - "Storage::purge_expired also deletes expired pushed_authorization_request rows (consumed or not)"
  - "SQLite migration 0010_release_1_0_par_import.sql and full SQLite implementation"
  - "Contract cases for every new method (23 new cases), run on SQLite memory, file and three upgraded paths"
  - "Postgres: StorageError::Unsupported(\"TRANSITIONAL(07-11): ...\") for every new method"
affects: [07-11 (Postgres implementation and migration 0008), 07-13 (PAR), 07-14 (hash profiles, CAS rehash), 07-15/07-17 (export reads), 07-23 (pins 0010 in released-migrations.sha256)]
tech-stack:
  added: []
  patterns:
    - "Single-statement CAS for password rehash: UPDATE credential ... WHERE secret = expected, rows_affected == 1"
    - "PAR consume mirrors consume_code: one UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING"
    - "Profile references counted by exact, case-sensitive prefix (substr = prefix), never LIKE"
key-files:
  created:
    - crates/anvil-storage-sqlite/migrations/0010_release_1_0_par_import.sql
    - crates/anvil-storage-sqlite/src/password_profiles.rs
    - crates/anvil-storage/src/contract/par.rs
    - crates/anvil-storage/src/contract/password_profiles.rs
    - crates/anvil-storage-sqlite/tests/fixtures/release_1_0_beta1.sql
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/service/{bootstrap,session,registration}.rs (cfg(test) fakes only)
    - crates/anvil-storage/src/contract/{mod,clients,grants,users}.rs
    - crates/anvil-storage-sqlite/src/{lib,clients,grants,users}.rs
    - crates/anvil-storage-sqlite/.sqlx
    - crates/anvil-storage-sqlite/tests/upgrade.rs
    - crates/anvil-storage-postgres/src/{lib,grants,users}.rs
key-decisions:
  - "Export inventory: one read was missing, pending self-service tokens (research Pattern 4, existence only). Added UserRepo::pending_self_service_tokens(tenant, user, now) -> Vec<(SelfServiceKind, expires_at)>, oldest first; no hash, no address. Token families per user are families_for_user. Everything else already existed (see below)"
  - "families_for_user returns every state (revoked, expired), ordered by created_at then id; service families (user_id NULL) are excluded by construction"
  - "create_pushed_request: Conflict on duplicate (tenant, request_uri_hash); the composite FK (tenant_id, client_id) -> client rejects a client of another tenant and deletes pushed requests with their client"
  - "PasswordProfileRepo::delete does not refuse a referenced profile; the reference lives inside the PHC string, so callers check count_references first (documented on the trait)"
  - "password_hash_profile.kind and client.client_kind have no CHECK (research pitfall: CHECK-constrained discriminators need a rebuild to extend); unknown values read as StorageError::Corrupt"
  - "Postgres families_for_user and pending_self_service_tokens are TRANSITIONAL(07-11) shims too: implementing them needs Postgres .sqlx regeneration, which 07-11 owns. Postgres purge_expired carries a TRANSITIONAL(07-11) comment (no table yet, nothing to purge)"
metrics:
  duration: ~80min
  completed: 2026-11-26
---

# Phase 7 Plan 08: Foundation B (Phase 7 storage ports, SQLite, contract, upgrade) Summary

Every Phase 7 storage port now exists once in ports.rs. SQLite implements all of them on top of the
new additive migration 0010. The shared contract suite covers each method, including the PAR and
password-CAS concurrency cases. Postgres refuses every new method explicitly until 07-11. SQLite
upgrades from 0.4 and from 1.0.0-beta.1 keep every row.

## Final port names

```rust
// Storage
fn password_profiles(&self) -> &dyn PasswordProfileRepo;
// GrantRepo
async fn families_for_user(&self, tenant: TenantId, user: UserId) -> Result<Vec<TokenFamily>, StorageError>;
async fn create_pushed_request(&self, tenant: TenantId, request: &NewPushedRequest) -> Result<(), StorageError>;
async fn consume_pushed_request(&self, tenant: TenantId, request_uri_hash: &RequestUriHash, now: OffsetDateTime) -> Result<Option<PushedRequest>, StorageError>;
// UserRepo
async fn replace_password_if(&self, tenant: TenantId, user: UserId, expected: &str, new_phc: &str, now: OffsetDateTime) -> Result<bool, StorageError>;
async fn pending_self_service_tokens(&self, tenant: TenantId, user: UserId, now: OffsetDateTime) -> Result<Vec<(SelfServiceKind, OffsetDateTime)>, StorageError>;
// PasswordProfileRepo
async fn create(&self, tenant: TenantId, profile: &NewPasswordHashProfile) -> Result<PasswordHashProfile, StorageError>; // Conflict on duplicate id or (tenant, name)
async fn get(&self, tenant: TenantId, id: Uuid) -> Result<Option<PasswordHashProfile>, StorageError>;
async fn list(&self, tenant: TenantId) -> Result<Vec<PasswordHashProfile>, StorageError>; // name order
async fn delete(&self, tenant: TenantId, id: Uuid) -> Result<bool, StorageError>;
async fn count_references(&self, tenant: TenantId, id: Uuid) -> Result<u64, StorageError>; // phc starts with "$anvil-firebase-scrypt$profile=<hyphenated id>$"
```

`consume_pushed_request` returns `consumed_at = Some(now)`. The caller checks that `client_id` matches.

## Export inventory (research Pattern 4)

| Item | Port |
| --- | --- |
| user row, claims | `UserRepo::get` |
| custom attributes | `AttributeRepo::user_values` |
| credential metadata | `UserRepo::list_credentials`, `UserRepo::recovery_codes_remaining` |
| sessions | `SessionRepo::list_for_user` |
| consents | `GrantRepo::list_consents` |
| token families | **`GrantRepo::families_for_user` (new)** |
| identity links | `ConnectionRepo::links_for_user` |
| org memberships | `OrgRepo::memberships_of_user` |
| roles (tenant / org) | `RoleRepo::roles_for_user`, `RoleRepo::roles_for_user_in_org` |
| audit about / by the user | `AuditRepo::query` (`target`, `actor_id` filters) |
| pending self-service tokens | **`UserRepo::pending_self_service_tokens` (new)** |

07-15/07-17 should not need to edit ports.rs.

## Migration 0010 (SQLite)

- `pushed_authorization_request(tenant_id, uri_hash BLOB(32), client_id, params TEXT json_valid, created_at, expires_at, consumed_at NULL)`.
  PK `(tenant_id, uri_hash)`, FK `(tenant_id, client_id) -> client(tenant_id, client_id) ON DELETE CASCADE`
  (the target is the existing unique index `client_client_id_uq`). Indexes on `expires_at` and `(tenant_id, client_id)`.
- `password_hash_profile(id, tenant_id, name, kind, salt_separator BLOB, rounds, mem_cost 0..255, signer_key_enc BLOB NOT NULL, created_at, UNIQUE(tenant_id, name))`.
- `client` ADD COLUMN `require_pushed_authorization_requests` (0/1, default 0), `client_kind` (TEXT, default
  `'application'`, no CHECK) and `headless_native` (0/1, default 0).
- Transactional and additive only. 0008/0009 are untouched and `scripts/check-migrations.sh` passes. 0010 is not
  in the manifest (07-23 pins it).
- backup.rs copies the whole database with `VACUUM INTO`, so the new tables are included without changes.

## Contract cases added (registered in `storage_contract_tests!`)

`client_new_fields_round_trip` (replaces `client_new_fields_non_default_refused_until_columns_exist`),
`par_create_and_consume_round_trip`, `par_create_duplicate_hash_conflict`, `par_consume_twice_is_none`,
`par_consume_expired_is_none` (including the `expires_at == now` boundary), `par_consume_single_winner_under_concurrency`
(8 tasks x 10 rounds, exactly one `Some`), `par_tenant_isolation`, `par_purged_after_expiry`, `par_deleted_with_client`,
`password_profile_create_get_list_delete`, `password_profile_name_unique_per_tenant`, `password_profile_tenant_isolation`,
`password_profile_count_references`, `password_replace_if_swaps_only_matching`,
`password_replace_if_wrong_expected_is_noop`, `password_replace_if_concurrent_single_winner` (8 tasks x 5 rounds),
`pending_self_service_tokens_existence_only`, `families_for_user_every_state_oldest_first`.

## Upgrade evidence (SQLite)

- 0.4 to final: the existing tests now expect version 10. `upgrade_from_0_4_keeps_every_row` also checks that the two
  new tables exist and are empty, and that `v04-web` reads the new client defaults.
- 1.0.0-beta.1 to final (`fixtures/release_1_0_beta1.sql`, loaded at schema version 9): 2 tenants, 3 users,
  1 credential, 1 client (`organization = optional`), 1 organization, 1 membership, 1 pending invitation (with an org
  role), 1 SAML connection owned by the org, 1 identity link, 1 verified routing domain, 2 roles (tenant + org-owned),
  2 role assignments (tenant-wide + in-org), an org-bound token family and code, a SAML replay guard, an org
  invitation template and 1 audit event.
  `upgrade_from_1_0_beta1_keeps_every_row_and_defaults_new_columns` compares `count(*)` per table for every beta.1
  table, plus a full value snapshot of every beta.1 column, before and after. They are equal, and the foreign key
  check finds 0 violations. It then reads the org data back through the traits, consumes the beta.1 code (org kept),
  and runs `families_for_user`, `replace_password_if` and a PAR create/consume on the upgraded rows.
  `upgrade_from_1_0_beta1_is_idempotent_on_restart` runs two more starts and finds counts and snapshot unchanged
  with 10 migrations recorded.
- The full contract suite runs on the beta.1-upgraded database (`upgraded_beta1_contract`), next to the existing
  0.1, 0.2, 0.3 and 0.4 runs.

## Deviations from Plan

1. **[Rule 2] Added `UserRepo::pending_self_service_tokens`.** This was the one export-inventory read that was missing
   (the plan says to add missing reads here). It is implemented on SQLite and covered by a contract case.
2. **[Rule 3] Plan command syntax.** `just sqlx-prepare crate=...` / `just sqlx-check crate=...` pass the literal
   `crate=...` to the script, which rejects it. I used the positional form `just sqlx-prepare crates/anvil-storage-sqlite`.
3. Extra contract cases beyond the named list: duplicate-hash conflict, client cascade, profile CRUD, reference
   counting, CAS success path, and the export reads.
4. The core fakes needed only `password_profiles()` (the fakes implement `Storage` but not `GrantRepo` or `UserRepo`).
   No other fake in the workspace implements these traits.

## Verification

- Preflight passed: 06-26-SUMMARY.md exists, and the newest migrations were SQLite 0009 and Postgres 0007 before this plan.
- `cargo test -p anvil-storage-sqlite --test contract`: 506 passed (memory and file).
- `cargo test -p anvil-storage-sqlite --test upgrade`: 1278 passed. That is 13 upgrade tests plus the contract suite on
  the 0.1, 0.2, 0.3, 0.4 and beta.1 upgrade paths.
- `cargo test -p anvil-storage-sqlite --lib --test plaintext`: 21 + 3 passed. `cargo test -p anvil-core --lib`: 1052 passed.
- `cargo build --workspace --all-targets --locked`: OK. An earlier run failed in anvil-web
  (`api_flows::problem`, 07-10 work in progress); it passed once that landed.
- `cargo clippy` on anvil-core, anvil-storage, anvil-storage-sqlite and anvil-storage-postgres (all targets): clean.
- `scripts/check-migrations.sh`: OK. `just sqlx-check crates/anvil-storage-sqlite`: OK. .sqlx was regenerated with
  `just sqlx-prepare crates/anvil-storage-sqlite`, not edited by hand.
- `grep -rn "TRANSITIONAL(07-08)" crates/` finds nothing. TRANSITIONAL(07-11) appears only in anvil-storage-postgres
  (lib.rs, grants.rs, users.rs, plus 07-03's clients.rs).
- Not run: Postgres contract and upgrade tests (no Docker; left for CI). On Postgres the new contract cases fail with
  `Unsupported("TRANSITIONAL(07-11): ...")` until 07-11 lands.
- `scripts/check-release-graph.sh` fails on `crates/anvil-web/src/adapters/argon2.rs:117` (`#[cfg(test)] fn
  available_permits`), committed by 07-09 in aaab694. That is outside this plan, so I reported it and did not fix it.

## Self-Check: PASSED

Commits f35c148, a843788 and f130991 exist. The migration, password_profiles.rs, contract/par.rs (287 lines),
contract/password_profiles.rs and the beta.1 fixture all exist.
