---
phase: 05-release-0-4-operate-it
plan: 01
subsystem: foundation
tags: [cargo, redis, metrics, opentelemetry, jsonschema, serde-saphyr, domain-model, errors, audit, openapi]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: 0.3 domain model, storage contract, admin API wire enums
provides:
  - Every Phase 5 runtime and dev dependency, declared once (no later plan edits a Cargo manifest or Cargo.lock)
  - Phase 5 domain types (role, attribute, webhook, registration, config_doc), new ids, client/consent/tenant fields
  - CoreError variants for DCR/CIMD/RBAC/refresh reuse, mapped through the single tables
  - 24 new AuditAction variants (80 total), typed AuditDetails constructors, NewAuditEvent.webhook
  - TRANSITIONAL(05-06)/(05-07) storage refusals plus a contract test that new fields are never dropped silently
  - Regenerated OpenAPI document and console types
affects: [05-02, 05-05, 05-06, 05-07, 05-12, 05-14, all Phase 5 plans]

tech-stack:
  added: [redis 1.8.3, metrics 0.24.6, metrics-exporter-prometheus 0.18.3, opentelemetry 0.33.1, opentelemetry_sdk 0.33.1, opentelemetry-otlp 0.33.1, tracing-opentelemetry 0.34.0, serde-saphyr 2.2.0, jsonschema 0.63.1]
  patterns:
    - "Storage refuses unsupported new fields with StorageError::Unsupported (TRANSITIONAL marker) instead of dropping them"
    - "SecretInput serializes only {configured: bool}; inline secret values are input-only"
    - "RefreshTokenReuse is a separate variant but wire-identical to invalid_grant (INVALID_GRANT_DESCRIPTION)"

key-files:
  created:
    - crates/anvil-core/src/model/role.rs
    - crates/anvil-core/src/model/attribute.rs
    - crates/anvil-core/src/model/webhook.rs
    - crates/anvil-core/src/model/registration.rs
    - crates/anvil-core/src/model/config_doc.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - crates/anvil-cache/Cargo.toml
    - crates/anvil-web/Cargo.toml
    - crates/anvilid/Cargo.toml
    - crates/anvil-core/src/error.rs
    - crates/anvil-core/src/model/{mod,ids,client,tenant,consent,audit}.rs
    - crates/anvil-storage-{sqlite,postgres}/src/{clients,consent,audit}.rs
    - crates/anvil-storage/src/contract/{clients,fixtures,tenants,mod}.rs
    - crates/anvil-web/src/errors.rs
    - crates/anvil-web/src/admin/dto.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "effective_dcr/effective_cimd live on TenantSettings (take the tenant slug) with Tenant convenience wrappers; the system tenant is always Disabled"
  - "WebhookResult error_class is &'static str (code-defined); the stored WebhookDelivery.last_error is Option<String>"
  - "SecretInput has hand-written serde: input accepts {configured} or {value}; output is always {configured}, so exports never carry clear secrets"
  - "TenantConfigDocument v1 uses a ConfigKind enum (only TenantConfig parses), deny_unknown_fields on every section, string kinds for EmailKind/SmtpTls (not serde types), and no logos"
  - "anvil-web gets opentelemetry_sdk[testing] as a dev-dep now (05-05 span test)"
  - "Redundant dev-dep entries for crates that are already normal deps of anvilid (serde_json, tower, tracing-subscriber) were added anyway so the plan's list is explicit; tokio dev-dep adds test-util"

patterns-established:
  - "Contract tests for transitional fields accept 'persisted faithfully' OR 'Unsupported with nothing stored', so they stay valid after the shims are removed"

requirements-completed: []

duration: ~45min
completed: 2026-11-26
---

# Phase 5 Plan 01: Foundation A (dependencies, model, errors, audit actions, OpenAPI) Summary

**Declared every Phase 5 dependency once (aws-lc-rs only, no ring, no new deny duplicates) and added all Phase 5 domain types, CoreError variants and audit actions. Existing construction sites compile. Storage refuses the new fields explicitly until 05-06/05-07.**

## Performance

- **Duration:** about 45 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files modified:** 46 (5 manifests/lock, 41 in the model commit)

## Accomplishments

### Task 1: dependencies (commit 66fd186)
- Workspace: redis 1.8.3 (`tokio-comp, connection-manager, script, tokio-rustls-comp`, no default features), metrics 0.24.6, metrics-exporter-prometheus 0.18.3 (no default features), opentelemetry and opentelemetry_sdk 0.33.1 `[trace]`, opentelemetry-otlp 0.33.1 `[http-proto, reqwest-blocking-client, trace]`, tracing-opentelemetry 0.34.0 (no default features), serde-saphyr 2.2.0, jsonschema 0.63.1 (no default features). reqwest gains `blocking`; testcontainers-modules gains `redis`.
- Normal edges: anvil-cache += redis, metrics. anvil-web += metrics, jsonschema. anvilid += metrics, metrics-exporter-prometheus, opentelemetry, opentelemetry_sdk, opentelemetry-otlp, tracing-opentelemetry, serde-saphyr.
- Dev edges:
  - anvilid: anvil-cache, anvil-storage[postgres-container], anvil-storage-sqlite, anvil-storage-postgres, http-body-util, opentelemetry_sdk[testing], reqwest, serde_json, tempfile, testcontainers-modules (postgres+redis), tokio[macros, rt-multi-thread, test-util], tower, tracing-subscriber, wiremock.
  - anvil-cache: testcontainers-modules, tokio[macros, rt-multi-thread, test-util].
  - anvil-web: opentelemetry_sdk[testing].
- `cargo tree -e normal -p anvilid | wc -l`: **1255 -> 1474**.
- Lockfile: only additions; no existing crate changed version.
- `cargo deny --locked check`: advisories, bans, licenses and sources all ok. The duplicate-warning list is identical before and after, so there are no new duplicates. ring, openssl and native-tls are absent (`cargo tree -i ring --target all` is empty).
- `scripts/check-deps.sh`: OK. **deny.toml and check-deps.sh needed no change** (no exceptions added; check-deps does not enumerate these crates).
- Mid-plan checkpoint: `cargo build --workspace --all-targets --locked` passed after Task 1.

### Task 2: model, errors, audit, compile fixes, OpenAPI (commit 4e6f4b5)
- New ids: RoleId, WebhookEndpointId, WebhookDeliveryId, InitialAccessTokenId.
- role.rs: Role/NewRole/RoleUpdate (`org_id` is always None in 0.4), validate_role_name, validate_permission, normalize_permissions, MAX_PERMISSIONS_PER_ROLE = 100, SYSTEM_ADMIN_ROLE = "administrator".
- attribute.rs: AttributeDefinition, ClaimRule, TokenTarget, MAX_SCHEMA_BYTES = 16 KiB, validate_attribute_name, check_schema_size.
- webhook.rs: WebhookEventType (dotted wire names, `test`), WebhookEvent, WebhookEndpoint/New/Update (Debug redacts sealed secrets), DeliveryStatus, WebhookDelivery, WebhookResult, WEBHOOK_SECRET_PURPOSE = "anvilid/webhook-secret/v1", webhook_aad, WEBHOOK_RETRY_SCHEDULE, WEBHOOK_TIMEOUT = 15 s, BATCH = CONCURRENCY = 8, WEBHOOK_LEASE = 45 s. A unit test asserts the lease is at least TIMEOUT x ceil(BATCH/CONCURRENCY) + 30 s.
- registration.rs: ClientSource, DcrPolicy, CimdPolicy, DcrSettings (max_clients 1000), CimdSettings (300 to 86400 s), InitialAccessToken/New, FetchedMetadata.
- config_doc.rs: TenantConfigDocument v1 plus the sections, SecretInput, ConfigPlan/ConfigChange/FieldDiff/ConfigObjectKind.
- client.rs: registration_source, metadata_expires_at, registration_access_token_hash (also in ClientUpdate as Option<Option<_>>).
- consent.rs: `resources` on ConsentGrant/NewConsent, plus normalize_resources.
- tenant.rs: dcr, cimd, claims (ClaimMappingSettings defaults as specified), effective_dcr/effective_cimd. Tests: 0.3 settings JSON parses with the defaults; the system tenant is forced to Disabled.
- audit.rs: 24 new actions (ALL = 80, asserted). New constructors: role, attribute, webhook_endpoint, webhook_event, webhook_delivery, client_source, config_plan. None of them accepts secrets. NewAuditEvent.webhook is None at every construction site.
- error.rs: InvalidClientMetadata (400), InvalidRedirectUri (400), InvalidSoftwareStatement (400), ClientMetadataUnavailable (503 temporarily_unavailable; description generic), LastAdministrator (409 conflict), RefreshTokenReuse (400 invalid_grant with INVALID_GRANT_DESCRIPTION; token.rs now uses the same const). Tests: core equality of code, status and description; anvil-web byte-identical oauth_json and problem_json responses (status, sorted headers, body).
- anvil-web errors.rs error_key: the three DCR errors map to `invalid_request`; ClientMetadataUnavailable maps to `server_error` at 503.
- Storage, both backends: read converters map the new fields to defaults. Write paths return `StorageError::Unsupported` for non-default values (client create/update, consent resources, audit `webhook: Some`). Markers: `TRANSITIONAL(05-06)` on SQLite, `TRANSITIONAL(05-07)` on Postgres.
- Contract test `client_phase5_fields_never_dropped`: each new field is either persisted faithfully or refused with nothing stored. `tenant_update_settings_round_trip` now uses non-default dcr/cimd/claims.
- AuditAction `wire_enum!` +24. Ran `just openapi-update` (via UPDATE_OPENAPI=1) and `npm run gen:api`.

## Task Commits

1. **Task 1: workspace dependencies:** `66fd186` (chore)
2. **Task 2: domain model, errors, audit actions, compile fixes, OpenAPI:** `4e6f4b5` (feat)

## Verification run

- `cargo build --workspace --all-targets --locked`: OK (after each task)
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: OK (exit 0; see the unused-dependency note below)
- `cargo test -p anvil-core --lib`: 606 passed
- `cargo test -p anvil-web --lib errors`: 11 passed
- `cargo test -p anvil-web --test openapi_drift`: OK. `cd admin-ui && npm run check:api`: up to date
- `cargo test -p anvil-storage-sqlite --test contract -- tenants outbox logout client`: 34 passed (memory and file), including the new phase5 test
- `cargo check --manifest-path fuzz/Cargo.toml --locked --bins`: OK
- `cargo deny --locked check`, `scripts/check-deps.sh`, no-ring check: OK
- `rustfmt --check --edition 2024` on every file touched: OK

## Not run

- Postgres contract suite and anything needing Docker (testcontainers). The Postgres refusals mirror SQLite but have not been exercised locally; CI covers them.
- `scripts/check-deps.sh --self-test` and the full workspace test suite (only targeted runs, per the shared rules).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TenantSettingsPatch would have reset DCR/CIMD/claims**
- **Found during:** Task 2 compile fixes
- **Issue:** filling the new TenantSettings fields with defaults in `TenantSettingsPatch::apply` would wipe the stored 0.4 sections on every admin settings PATCH.
- **Fix:** carry `current.dcr/cimd/claims` over unchanged.
- **Files:** crates/anvil-web/src/admin/dto.rs
- **Commit:** 4e6f4b5

**2. [Rule 2 - Missing test] Contract test for the transitional refusals**
- Added `client_phase5_fields_never_dropped` and registered it in `crates/anvil-storage/src/contract/mod.rs` (one-line additive edit to the shared registry; **forced extra file**).

**3. [Rule 3 - Blocking] Fuzz target construction site**
- `fuzz/fuzz_targets/authorize_parse.rs` builds a `Client` literal. The coordinator flagged it because 05-03 added `just fuzz-check` to CI. Added the three new fields with their defaults. **Forced extra file.**

### Notes
- Files listed in frontmatter that did not need edits (they compiled unchanged): several anvil-web tests (flow_*, consent, discovery, ...), service/authorize.rs, oauth/logout.rs, service/tenant.rs, the backend plaintext.rs/upgrade.rs tests, logout_support, ui_helpers, deny.toml, scripts/check-deps.sh.
- Cargo 1.100 prints `unused dependency` manifest warnings for crates that later plans will use (anvil-cache: metrics, redis; anvil-web: jsonschema; anvilid: metrics-exporter-prometheus, opentelemetry-otlp, serde-saphyr, tracing-opentelemetry). They do not fail `clippy -D warnings` (exit 0 verified) and go away as plans 05-02+ use the crates.

## Self-Check: PASSED
- All 5 created model files exist; commits 66fd186 and 4e6f4b5 are present in `git log`.
