---
phase: 07-release-1-0-certification
plan: 12
subsystem: client-and-tenant-configuration
tags: [admin-api, yaml, dcr, cimd, openapi, OIDC-18, UI-05, AGT-03]
requires:
  - "07-03: Client.require_pushed_authorization_requests / client_kind / headless_native, TenantSettings.par / headless, HeadlessSettings::validate_origin"
  - "07-08: SQLite client columns (non-default values persist)"
provides:
  - "service::client::validate_client_policy(&ClientPolicyView, ClientSource) -> Result<(), CoreError> and ClientPolicyView::of(&ClientInput, &ClientOptions)"
  - "ClientOptions / ClientOptionsPatch: require_pushed_authorization_requests, client_kind, headless_native"
  - "service::tenant::{validate_headless_settings, headless_origin_issues, MAX_HEADLESS_ORIGINS = 50}"
  - "NewTenantInput.dev_mode, TenantPatch.dev_mode, ConfigService.dev_mode, config::Validators.dev_mode"
  - "Admin API: ClientView/CreateClient/UpdateClient fields, ClientKind wire enum, TenantSettings.par/headless (ParSettings, HeadlessSettings DTOs), NewTenantSettings and TenantSettingsPatch par/headless"
  - "YAML: ClientSection require_pushed_authorization_requests, client_kind, headless_native (omitted when default); tenant.settings.par and tenant.settings.headless"
  - "DCR: RFC 9126 §6 require_pushed_authorization_requests metadata, stored and echoed (registration response and RFC 7592 reads)"
affects: [07-13 (PAR reads the client and tenant flags), 07-16 (agent consent reads client_kind), 07-18 (native headless reads headless_native), 07-21 (UPGRADING/compatibility), 07-23 gate]
tech-stack:
  added: []
  patterns:
    - "One policy function for security-relevant field combinations, called by every client write path with the client's source"
    - "Development mode passed explicitly from the caller (AppConfig::dev_mode) into tenant and config services"
key-files:
  created:
    - crates/anvil-web/tests/admin_client_fields_v10.rs
  modified:
    - crates/anvil-core/src/service/{client,tenant,config,registration}.rs
    - crates/anvil-core/src/model/config_doc.rs
    - crates/anvil-core/src/oauth/{registration,cimd}.rs
    - crates/anvil-web/src/admin/{dto,tenants,config}.rs
    - crates/anvilid/src/tenant_config.rs
    - crates/anvil-web/tests/{security_registration,security_cimd,registration_dcr}.rs
    - crates/anvilid/tests/tenant_config.rs
    - docs/schemas/tenant-config-v1.json
    - docs/CONFIG-YAML.md
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
key-decisions:
  - "headless_native is refused for dynamic and CIMD clients whoever sets it (admin API included), not only when DCR/CIMD try to set it"
  - "client_kind may be set by an administrator on any client, dynamic ones included; an RFC 7592 update keeps the stored marker. No DCR/CIMD agent default in 1.0"
  - "DCR always echoes require_pushed_authorization_requests (false too); an RFC 7592 update replaces every value, so omitting it resets it to false"
  - "par/headless stay under tenant.settings in the YAML (TenantSection.settings is the full TenantSettings; 07-10's e2e already uses that path), still omitted from exports while default"
  - "headless.allowed_origins: at most 50 entries"
  - "CIMD documents never set any of the three fields (require_pushed_authorization_requests included); CIMD clients follow the tenant PAR policy"
metrics:
  duration: ~70min
  completed: 2026-11-26
---

# Phase 7 Plan 12: Client and tenant field exposure Summary

The 1.0 client fields (`require_pushed_authorization_requests`, `client_kind`, `headless_native`) and the tenant settings
`par` and `headless` are now readable and writable through the admin API, the tenant YAML (plan, apply, export) and,
for the PAR flag only, dynamic registration. One function, `validate_client_policy`, enforces the field-combination
rules on every client write path.

## Validation function

`anvil_core::service::client::validate_client_policy(c: &ClientPolicyView, source: ClientSource) -> Result<(), CoreError>`.
`ClientPolicyView { consent_mode, require_pkce (effective), client_kind, headless_native }` is built with
`ClientPolicyView::of(&ClientInput, &ClientOptions)`. Errors are `CoreError::Validation` on `consent_mode` or
`headless_native` (admin API 422 naming the field, YAML `clients[i].<field>`, DCR `invalid_client_metadata`).

Call sites:
- `ClientService::insert` (create, create_static, create_dynamic) with source `static` or `dynamic`;
- `ClientService::apply_update` (admin update and RFC 7592 update) with the stored `registration_source`;
- `config::validate_client_section` (YAML/config plan and apply) with source `static`;
- `oauth::registration::validate` (DCR) with source `dynamic`;
- `oauth::cimd::validate` (CIMD document) with source `cimd`.

| Rule | Refused when | Field |
| --- | --- | --- |
| Agents never skip consent (Q7) | `client_kind = agent` and `consent_mode = skip_first_party` | `consent_mode` |
| Native headless only for admin clients | `headless_native` and source is `dynamic` or `cimd` | `headless_native` |
| Native headless never for agents | `headless_native` and `client_kind = agent` | `headless_native` |
| Native headless only first-party | `headless_native` and `consent_mode != skip_first_party` | `headless_native` |
| Native headless needs PKCE | `headless_native` and `require_pkce = false` | `headless_native` |

The agent rule is checked first. `client_policy_truth_table` checks all 48 combinations (kind x consent x headless x
PKCE x source) against these rules, written out separately in the test.

DCR and CIMD never read `client_kind` or `headless_native`. Like any unknown metadata they are ignored (RFC 7591 §2)
and the result is always `application` / `false`. No new `is_registration_forbidden_*` helper was needed: the parsers
never map the keys, and the source rule above blocks the flag for those clients.

Headless origins use `service::tenant::validate_headless_settings` (field `headless.allowed_origins`, message
`entry {i}: ...`) in `TenantService::create` and `update` (on change). The config validator calls
`headless_origin_issues` and reports `tenant.settings.headless.allowed_origins[i]`. Both go through the 07-03
`HeadlessSettings::validate_origin(origin, dev)`. Dev mode comes from `AppConfig::dev_mode()` in the admin handlers,
the admin config service and the CLI.

## Field names

- Admin API client (`ClientView`, always present; `CreateClient` / `UpdateClient`, optional):
  `require_pushed_authorization_requests: bool`, `client_kind: "application" | "agent"`, `headless_native: bool`.
- Admin API tenant settings (`TenantSettings` view, always present): `par: {require_pushed_authorization_requests}` and
  `headless: {allowed_origins: [...]}`. They are accepted on create (`NewTenantSettings`). On `PATCH`
  (`TenantSettingsPatch`) each object is replaced whole.
- YAML `clients[]`: the same three keys, omitted from exports when default. YAML `tenant.settings.par` /
  `tenant.settings.headless` are omitted when default, as in 07-03.
- DCR: `require_pushed_authorization_requests` (boolean; anything else is `invalid_client_metadata`), echoed in the
  201 response, RFC 7592 GET and PUT.

## Tests

- Core unit tests: `client_policy_truth_table`, `agent_client_cannot_skip_consent`, `policy_view_takes_the_effective_pkce_value`
  (service::client); `dcr_require_par_is_stored_and_echoed`, `client_kind_agent_refused_via_dcr_metadata_injection`
  (oauth::registration); `headless_native_refused_via_cimd` (oauth::cimd); `headless_settings_are_validated`
  (service::tenant); `client_policy_and_headless_origins_are_validated_with_paths` (service::config);
  `client_v10_fields_default_and_are_omitted_when_default` (model::config_doc);
  `par_metadata_stored_and_admin_fields_never_taken_from_the_request` (service::registration).
- `admin_client_fields_v10` (8): `client_v10_fields_round_trip`, `agent_client_cannot_skip_consent`,
  `headless_native_requires_first_party`, `headless_native_requires_pkce`, `headless_native_refuses_agent`,
  `tenant_par_and_headless_settings_round_trip`, `headless_origins_reject_wildcard_and_path` (PATCH and POST tenant,
  production and development mode), `config_document_carries_v10_fields_and_matches_the_schema` (config apply/export
  over HTTP validated against the published schema, plus a 422 for agent + skip at `clients[0].consent_mode`).
- `security_registration`: `dcr_require_par_must_be_boolean`, `headless_native_refused_via_dcr` (registration and
  RFC 7592 update ignore it; an admin PATCH on the dynamic client is 422), `client_kind_agent_refused_via_dcr_metadata_injection`
  (ignored for any value; an admin-set agent marker survives an RFC 7592 update).
- `security_cimd`: `headless_native_refused_via_cimd` (a document with `headless_native`, `client_kind`, `consent_mode`
  materialises as application / false / required; a `ClientService::update` setting the flag on the CIMD client is refused).
- `registration_dcr`: `require_pushed_authorization_requests_is_stored_and_echoed`.
- `anvilid/tests/tenant_config`: `yaml_v10_fields_round_trip_and_refusals` (CLI plan shows the diffs, apply, export
  carries every value, re-apply is "No changes.", agent + skip and wildcard/path origins refused by path with nothing
  changed).

Mutation check: with the agent rule disabled (`if false && ...`), `admin_client_fields_v10::agent_client_cannot_skip_consent`
fails (expected 422, got 201). The rule was restored afterwards.

## Verification

- `cargo test -p anvil-core --lib`: 1083 passed.
- `cargo test -p anvil-web --test admin_client_fields_v10 --test security_registration --test security_cimd --test registration_dcr`: 8 + 21 + 13 + 7 passed.
- `cargo test -p anvil-web` on admin_api, admin_api_v02, admin_api_v03, admin_config, security_admin_config,
  admin_registration, admin_audit, cimd, console_client, headless_flows, security_headless, openapi_drift,
  security_admin_v10 and consent: 144 passed, 0 failed.
- `cargo test -p anvilid --test tenant_config`: 6 passed.
- `UPDATE_OPENAPI=1 cargo test -p anvil-web --test openapi_drift`, then the drift test: 3 passed. The admin-v1.json
  diff holds only this plan's additions.
- `npm run gen:api`, `npm run check:api` (up to date) and `npm run typecheck` (clean). `npm ci` from `just console-check`
  was skipped because node_modules is shared with parallel plans.
- `cargo clippy` (anvil-core all targets, anvil-web and anvilid lib/bins and the touched tests): clean.
  `scripts/check-release-graph.sh`: OK.
- Not run: Postgres (`just test-pg`, no Docker) and a full `cargo test --workspace` (07-13's in-progress
  security_par.rs did not compile for part of the run). Both are left for CI and the gate.

## Deviations from Plan

### Extra files the build required

- `crates/anvil-web/src/admin/config.rs` and `crates/anvilid/src/tenant_config.rs`: one line each, setting the new
  `ConfigService.dev_mode` from `AppConfig::dev_mode()`. Development mode must reach the YAML path, or 07-10's e2e spec
  (which sets `http://localhost:<port>` through config apply) would be refused. Neither file belongs to another
  wave-3 plan.

### Design choices that differ from the plan

1. **[Rule 3] par/headless placement in YAML.** The plan said "TenantSection gets `par` and `headless`".
   `TenantSection.settings` already is the full `TenantSettings`, so both live at `tenant.settings.par` /
   `tenant.settings.headless` and no second copy was added. 07-10 already uses that path. They stay omitted from
   exports while default, because the 07-03 `skip_serializing_if` lives in model/tenant.rs, which this plan does not own.
2. **[Rule 2] Stricter headless rule.** `headless_native` is refused for dynamic and CIMD clients even when an
   administrator sets it. This applies Pitfall 9 ("admin-only flag, never via DCR/CIMD") to the client and not only
   to the request.
3. **[Rule 2] Cap of 50 origins** on `headless.allowed_origins`, in the API, YAML and JSON schema.
4. **Commit split.** The Task 1 commit also carries the config.rs/config_doc.rs and admin DTO edits, so that each
   commit compiles (the new `ClientOptions` fields and `dev_mode` touch every construction site). Task 2 carries the
   new tests, the docs and the regenerated contracts.

## Problems seen in other plans' files

- `crates/anvil-web/tests/security_par.rs:432` (07-13, uncommitted at the time) called `ClientRepo::update` with three
  arguments, which broke `cargo build --workspace --all-targets` during the run. A later `cargo build -p anvil-web --tests`
  compiled again.

## Commits

- `3a032b7` feat(07-12): validate_client_policy on every client write path, DCR PAR metadata, headless origin checks
- `3f86ffd` feat(07-12): admin API and YAML exposure of PAR, agent and headless fields; contracts regenerated

## Self-Check: PASSED

- FOUND: crates/anvil-web/tests/admin_client_fields_v10.rs (contains `agent_client_cannot_skip_consent`)
- FOUND: docs/schemas/tenant-config-v1.json (contains `require_pushed_authorization_requests`)
- FOUND: crates/anvil-core/src/oauth/registration.rs (calls `validate_client_policy`; contains `headless_native`)
- FOUND: commits 3a032b7, 3f86ffd
