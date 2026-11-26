---
phase: 07-release-1-0-certification
plan: 03
subsystem: core-model
tags: [model, audit, admin-scope, password-hasher, storage, OIDC-18, UI-05, AGT-03, ADM-08, ADM-09]
requires: []
provides:
  - "Client/NewClient: require_pushed_authorization_requests: bool, client_kind: ClientKind (application|agent), headless_native: bool; ClientUpdate: the same as Option<_>"
  - "TenantSettings.par: ParSettings { require_pushed_authorization_requests } and TenantSettings.headless: HeadlessSettings { allowed_origins } (serde defaults; omitted from JSON when default)"
  - "HeadlessSettings::validate_origin(&str, dev: bool) -> Result<(), &'static str> and HeadlessSettings::validate(&self, dev)"
  - "model::par::{NewPushedRequest, PushedRequest (is_usable), RequestUriHash = SecretHash}"
  - "model::password_profile::{PasswordHashProfile, NewPasswordHashProfile, ProfileKind::FirebaseScrypt, HashProfileMaterial (signer_key: SecretBox<[u8]>, Debug redacts), PROFILE_SIGNER_KEY_PURPOSE, profile_signer_key_aad(tenant, profile_id)}"
  - "AuditAction::{UsersImported, UserExported, PasswordProfileCreated, PasswordProfileDeleted} (no webhooks)"
  - "admin_scope::{ADMIN_USERS_EXPORT, scope_covers, export_scope_satisfied}"
  - "PasswordHasher::verify(phc, password, profile: Option<&HashProfileMaterial>)"
affects: [07-08 (SQLite client columns, replaces the contract case), 07-09 (hasher dispatcher removes the Argon2Pool refusal), 07-11 (Postgres client columns), 07-12 (exposes fields in DTO/YAML/DCR), 07-13 (PAR), 07-14 (hash profiles, passes Some(profile)), 07-17 (export routes use export_scope_satisfied), 07-21 (UPGRADING: export scope via admin:write)]
tech-stack:
  added: []
  patterns:
    - "One scope coverage rule: admin_scope::scope_covers; scope_satisfies, export_scope_satisfied and role.rs all call it"
    - "TRANSITIONAL storage refusal: non-default new fields -> StorageError::Unsupported(\"TRANSITIONAL(07-08|07-11): ...\")"
key-files:
  created:
    - crates/anvil-core/src/model/par.rs
    - crates/anvil-core/src/model/password_profile.rs
  modified:
    - crates/anvil-core/src/model/{mod,client,tenant,audit}.rs
    - crates/anvil-core/src/policy/webhook_event.rs
    - crates/anvil-core/src/service/{admin_scope,role,flow,bootstrap,client,client_auth,registration,config}.rs
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/oauth/{authorize_request,cimd}.rs
    - crates/anvil-storage-sqlite/src/clients.rs
    - crates/anvil-storage-postgres/src/clients.rs
    - crates/anvil-storage/src/contract/{clients,fixtures,tenants,mod}.rs
    - crates/anvil-web/src/adapters/argon2.rs
    - crates/anvil-web/src/admin/{dto,mod}.rs
    - crates/anvil-web/tests/*.rs (construction sites and hasher fakes, see below)
    - crates/anvilid/tests/backchannel_worker.rs
    - fuzz/fuzz_targets/authorize_parse.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - admin-ui/src/routes/t/$tenant/audit/index.tsx
key-decisions:
  - "admin:users:export is covered only by itself and admin:write (scope_covers: admin:read covers :read only; admin:{r}:write covers admin:{r}:read only). Bootstrap clients keep `admin:read admin:write`, which already covers export, so no bootstrap scope list change"
  - "scope_satisfies now goes through scope_covers too (same behaviour, verified by the existing admin_scope tests), so there is exactly one coverage rule"
  - "The four new audit actions are not webhook events (bulk admin operations, like TenantConfigApplied)"
  - "TenantSettings.par/headless are skipped in serialization when default, so the config export and its JSON schema stay unchanged until 07-12 exposes them (the admin_config schema test caught the export change)"
  - "The admin settings PATCH merge keeps the stored par/headless values instead of resetting them"
  - "The TRANSITIONAL refusal also covers upsert_cimd and the setup transaction (both go through the same helpers)"
  - "RequestUriHash is a type alias of SecretHash, like CodeHash; PasswordHashProfile.id is a plain Uuid as specified"
  - "HashProfileMaterial uses secrecy::SecretBox<[u8]> (anvil-core has no zeroize), so it is not Clone/PartialEq"
metrics:
  duration: ~75min
  completed: 2026-11-26
---

# Phase 7 Plan 03: Foundation A (model, audit, scope, hasher port) Summary

Every Phase 7 model field and type now exists once: ClientKind and the client PAR/agent/headless flags, tenant PAR and headless settings, the PAR and Firebase hash profile models, four audit actions, the `admin:users:export` scope under one coverage rule, and the profile argument on `PasswordHasher::verify`. Both storage backends refuse non-default values explicitly until their columns exist.

## Final names

- `ClientKind::{Application (default), Agent}`, stored strings `application` / `agent`. Fields on `Client`, `NewClient`:
  `require_pushed_authorization_requests`, `client_kind`, `headless_native`. On `ClientUpdate` they are `Option<_>`.
- `ParSettings { require_pushed_authorization_requests }`, `HeadlessSettings { allowed_origins }`,
  `HeadlessSettings::validate_origin(origin, dev)` (exact `https://host[:port]`, lowercase; no path, query, fragment,
  userinfo or wildcard; with `dev`, `http://localhost` and `http://127.0.0.1` are accepted too) and `validate(&self, dev)`.
- `NewPushedRequest { request_uri_hash, client_id, params: Value, created_at, expires_at }`,
  `PushedRequest { client_id, params, expires_at, consumed_at }` + `is_usable(now)`, `RequestUriHash`.
- `PasswordHashProfile { id: Uuid, tenant_id, name, kind, salt_separator, rounds, mem_cost, signer_key_sealed, created_at }`,
  `NewPasswordHashProfile` (the same fields without tenant_id), `ProfileKind::FirebaseScrypt` (`firebase_scrypt`),
  `HashProfileMaterial { salt_separator, signer_key: SecretBox<[u8]>, rounds, mem_cost }` + `signer_key()`,
  `PROFILE_SIGNER_KEY_PURPOSE = "anvilid/password-profile-signer-key/v1"`, `profile_signer_key_aad(tenant, profile_id)`
  (tenant id bytes followed by profile id bytes).
- Audit strings: `users_imported`, `user_exported`, `password_profile_created`, `password_profile_deleted`. Added in
  `AuditAction` (ALL, as_str and parse through `str_enum!`), the webhook classifier (None), and the admin DTO wire enum.
  `ALL.len()` is 102.
- Scope: `ADMIN_USERS_EXPORT = "admin:users:export"`, `scope_covers(held, wanted)`, `export_scope_satisfied(&Scope)`.
  `role.rs::admin_scope_covers` is deleted. The `ALL_ADMIN_SCOPES` length assertion is now `2 + 2 * RESOURCES.len() + 1`.

## Tests added

`client_kind_round_trips_and_unknown_is_error`, `tenant_settings_beta1_json_parses_with_new_defaults`,
`headless_origin_validation_rejects_wildcard_path_and_http`, `export_scope_not_implied_by_admin_read`,
`export_scope_not_implied_by_users_read`, `export_scope_not_implied_by_users_write`, `export_scope_implied_by_admin_write`,
`role_escalation_users_write_cannot_grant_export`, `hash_profile_material_debug_redacts`, `profile_kind_round_trips`,
`signer_key_aad_binds_tenant_and_profile`, PAR model tests, the audit round trip of the new variants, and the webhook
"do not emit" list. Also `argon2_pool_refuses_profile_material`, and the contract case
`client_new_fields_non_default_refused_until_columns_exist`, which runs on SQLite memory and file, and on Postgres in CI.

## TRANSITIONAL markers left

- `TRANSITIONAL(07-08)`: crates/anvil-storage-sqlite/src/clients.rs (`NEW_FIELDS_UNSUPPORTED`, read defaults, refusals in
  insert_client, update and upsert_cimd).
- `TRANSITIONAL(07-11)`: crates/anvil-storage-postgres/src/clients.rs (same shape).
- `TRANSITIONAL(07-09)`: crates/anvil-web/src/adapters/argon2.rs. `Some(profile)` returns `CoreError::Internal`.
- The contract case in crates/anvil-storage/src/contract/clients.rs accepts either marker. 07-08 replaces it.
- service/flow.rs passes `None` as the profile, with a comment pointing to 07-14 (no marker).

## OpenAPI

Changed: the four audit actions in `AuditAction`, plus `admin:users:export` in the oauth2 scopes with its own
description (an explicit `scope_description` arm in admin/mod.rs). Without that arm the generic fallback would have
said "Read users". `admin-ui/src/api/schema.d.ts` was regenerated with `npm run gen:api`.

## Deviations from Plan

### Extra files the compiler (or the gates) named

None of these are owned by another wave-1 plan:
- `crates/anvil-web/tests/admin_api.rs`: two direct `Argon2Pool::verify` calls needed the profile argument.
- `crates/anvil-storage/src/contract/mod.rs`: registers the new contract case (one-line additive edit).
- `crates/anvil-web/src/admin/mod.rs`: the scope description arm. The commit staged only that hunk, because 07-04 had
  uncommitted edits in the file at the time.
- `fuzz/fuzz_targets/authorize_parse.rs`: a `Client` literal in the fuzz workspace, which `cargo build --workspace`
  does not cover. The orchestrator reported it; `just fuzz-check` now passes.

### Auto-fixed issues

1. **[Rule 1 - Bug] Settings PATCH would have reset par/headless.** `TenantSettingsPatch::merge` builds the full settings
   struct, so it now copies `current.par` / `current.headless`.
2. **[Rule 1 - Bug] Config export grew `par`/`headless` keys** that the JSON schema does not describe. The
   `admin_config::json_schema_matches_the_document_types` test failed on it. Both settings now use
   `skip_serializing_if = is_default`, so nothing changes in exports or stored JSON while the values are default.
3. **[Rule 2] upsert_cimd also refuses non-default new fields.** It is a separate write path that the plan did not name.
4. Plan-listed files that needed no change (their literals already use `..Default::default()` / `..settings`):
   service/tenant.rs, service/token.rs, upstream/linking.rs, the storage plaintext/upgrade tests, and several anvil-web
   tests (account_security, admin_audit, authorize_prompt, authorize_step_up, backchannel, console_client, discovery,
   flow_login, flow_mfa_policy, flow_registration, id_token_alg, jwks_rotation, org_switch, security_bruteforce,
   upstream_buttons).

## Verification

- `cargo build --workspace --all-targets --locked`: OK.
- `cargo test --workspace --locked --no-fail-fast`: 4571 passed. The only failures were all 243 tests of
  anvil-storage-postgres `tests/upgrade.rs` (connection refused, no Postgres or Docker on this host; left for CI), and
  the `admin_config` schema test, which was then fixed (see above; re-run 13/13).
- After the serialization fix, re-run: anvil-core lib 1052/1052, anvil-storage-sqlite all tests (contract 472, upgrade,
  plaintext), and anvil-web openapi_drift 3/3. The contract case passes on SQLite memory and file.
- `just test-pg` was not run (no Docker). Left for CI.
- `npm run check:api` (up to date) and `npm run typecheck` (clean). `npm ci` was skipped because the existing
  node_modules were in use by parallel plans.
- `just fuzz-check`: OK.
- `scripts/check-release-graph.sh`: OK.
- Every TRANSITIONAL marker found by grep is one of the converter refusals, their contract case, or the Argon2Pool
  refusal.

## Self-Check: PASSED

Commits 03d3bfe and 3f5bffe exist. model/par.rs and model/password_profile.rs exist.
