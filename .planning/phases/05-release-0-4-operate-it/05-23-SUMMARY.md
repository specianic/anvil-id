---
phase: 05-release-0-4-operate-it
plan: 23
subsystem: admin-api
tags: [admin-api, attributes, webhooks, delivery-log, dcr, cimd, initial-access-token, openapi, tenant-issuer, security-tests]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-12 roles.rs route pattern and claim rule DTOs, 05-14 WebhookService (AppState::webhook_service), 05-15 CIMD resolver, 05-19 AttributeService (AppState::attribute_service), 05-20 validate_document, 05-21 RegistrationService IAT methods (AppState::registration_service)
provides:
  - Attribute admin API (definitions + user values) with per-pointer 422 problems
  - Webhook admin API (CRUD, secret once, rotation, test send, delivery log, redelivery)
  - Initial access token admin API (issue once, list, revoke)
  - Tenant settings dcr/cimd in the admin API (view = policy in force, PATCH merge, create)
  - TenantView.issuer and TenantView.discovery_url (server-computed)
  - ClientView.registration_source and ClientView.metadata_expires_at
  - service::tenant::registration_settings_issues / validate_registration_settings (shared with validate_document)
  - OpenAPI document with 81 operations and regenerated console types
affects: [05-24, 05-25, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "One settings validator returning (field, message) issues: TenantService turns the first into a 422, the declarative config reports all of them under tenant.settings.*"
    - "Tenant view shows effective DCR/CIMD policy (Tenant::effective_dcr/cimd), so the system tenant always reads disabled"

key-files:
  created:
    - crates/anvil-web/tests/admin_attributes.rs
    - crates/anvil-web/tests/admin_webhooks.rs
    - crates/anvil-web/tests/attribute_claims.rs
    - crates/anvil-web/tests/admin_registration.rs
    - crates/anvil-web/tests/security_admin_v04.rs
  modified:
    - crates/anvil-web/src/admin/attributes.rs
    - crates/anvil-web/src/admin/webhooks.rs
    - crates/anvil-web/src/admin/registration.rs
    - crates/anvil-web/src/admin/tenants.rs
    - crates/anvil-web/src/admin/clients.rs
    - crates/anvil-web/src/admin/dto.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - crates/anvil-core/src/service/tenant.rs (forced: DCR/CIMD validation, deferred item)
    - crates/anvil-core/src/service/config.rs (forced: validate_document calls it, deferred item)
    - crates/anvil-web/tests/openapi_drift.rs (forced: operation count 63 -> 81)

key-decisions:
  - "Validation failures stay 422 problems (the API's existing convention) where the plan wrote 400: invalid attribute schema/values, system-tenant DCR/CIMD policy"
  - "Attribute value refusals list every failing JSON pointer as a field error with a fixed message; values are never echoed"
  - "Webhook secret rotation is POST /webhooks/{id}/secret (same shape as client secret rotation), not /rotate"
  - "Redelivery is POST /tenants/{slug}/webhooks/deliveries/{delivery_id}/redeliver: the repository can only redeliver by delivery id, so nesting it under an endpoint id could not be checked before the new delivery is created"
  - "The API never accepts a caller-provided webhook secret (generated only; provided secrets stay a declarative-config feature)"
  - "Test send and redelivery answer 202 with the queued delivery; deliveries omit the payload; next_attempt_at only for pending deliveries"
  - "IAT create answers 201 without Location (there is no single-token GET); list items carry a computed `usable` flag"
  - "DCR/CIMD rules: hosts are names or IP literals without port (matching ignores ports), at most 100, no duplicates; CIMD allow_listed needs a host; no admin:* in dcr.allowed_scopes; RFC 8707 resources; max_clients <= 1000000; cache bounds 60..=604800 with min <= max. Validated on create and when dcr/cimd change (like the claim mapping)"
  - "Tenant issuer = AppState::admin_issuer_of (canonical issuer: custom host, public URL for default, else /t/{slug}); discovery_url = issuer + /.well-known/openid-configuration"

patterns-established:
  - "Table-driven scope test over every new route: no token / garbage token 401, unrelated scope 403, other resource's write scope 403, read cannot write, granting scope passes, admin:read never writes"

requirements-completed: [AUTH-14, ADM-05, OIDC-17, AGT-02, ORG-01]

duration: ~35min
completed: 2026-11-26
---

# Phase 5 Plan 23: 0.4 admin API bundle Summary

**Attributes, webhooks with their delivery log, initial access tokens and the DCR/CIMD tenant policies are now managed through the documented admin API (81 operations). The tenant view carries the server-computed issuer, the client view shows dynamic and CIMD clients, and one validator in TenantService (also used by the declarative config) enforces the registration settings, with the system tenant always disabled.**

## Performance

- **Duration:** about 35 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2, plus the core validation commit for the deferred items
- **Files:** 16 (5 created)

## Routes (all under `/api/admin/v1`)

| Method and path | Scope | Notes |
|---|---|---|
| `GET /tenants/{slug}/attributes` | admin:settings:read | position, then name |
| `GET /tenants/{slug}/attributes/{name}` | admin:settings:read | 404 for another tenant's |
| `PUT /tenants/{slug}/attributes/{name}` | admin:settings:write | create or replace; 422 naming `schema`, `name` or `claim` |
| `DELETE /tenants/{slug}/attributes/{name}` | admin:settings:write | values kept |
| `GET /tenants/{slug}/users/{user_id}/attributes` | admin:users:read | `{user_id, values}` |
| `PUT /tenants/{slug}/users/{user_id}/attributes` | admin:users:write | body `{values}`, replace mode; 422 lists each failing pointer |
| `GET /tenants/{slug}/webhooks` | admin:settings:read | name order, no secrets |
| `POST /tenants/{slug}/webhooks` | admin:settings:write | 201 `{endpoint, secret}` (secret once); 409 duplicate name; 422 URL refused by the outbound policy |
| `GET /tenants/{slug}/webhooks/{id}` | admin:settings:read | `secret_configured: true`, `previous_secret_expires_at` |
| `PATCH /tenants/{slug}/webhooks/{id}` | admin:settings:write | name, url, events, enabled |
| `DELETE /tenants/{slug}/webhooks/{id}` | admin:settings:write | with its delivery log |
| `POST /tenants/{slug}/webhooks/{id}/secret` | admin:settings:write | new secret once, previous signs for 24 h |
| `POST /tenants/{slug}/webhooks/{id}/test` | admin:settings:write | 202 queued delivery |
| `GET /tenants/{slug}/webhooks/{id}/deliveries` | admin:settings:read | newest first, cursor; status, attempts, last_http_status, error_class, next_attempt_at, completed_at; no payload |
| `POST /tenants/{slug}/webhooks/deliveries/{delivery_id}/redeliver` | admin:settings:write | 202 new delivery |
| `GET /tenants/{slug}/initial-access-tokens` | admin:clients:read | no values; `usable` |
| `POST /tenants/{slug}/initial-access-tokens` | admin:clients:write | 201 `{token, value}` (value once); `description`, `expires_in` (s), `uses`; 422 for the system tenant |
| `DELETE /tenants/{slug}/initial-access-tokens/{id}` | admin:clients:write | 404 if unknown or already revoked |

Tenant settings (on `GET/POST/PATCH /tenants[/{slug}]`, tenants scope): `dcr {policy, allowed_redirect_hosts, allowed_scopes, allowed_resources, allow_client_credentials, max_clients}` and `cimd {policy, allowed_hosts, min_cache_secs, max_cache_secs}`. The PATCH merges field by field. The view shows the policy in force. Tenant view: `issuer` and `discovery_url`. Client view: `registration_source` (`static|dynamic|cimd`) and `metadata_expires_at`.

## Security tests (security_admin_v04.rs)

`v04_admin_routes_require_scopes` (19 routes), `v04_admin_routes_isolate_tenants`, `webhook_secret_write_only_in_api` (responses, OpenAPI schema, sealed row, signature by both secrets), `initial_access_token_shown_once` (responses, OpenAPI schema, SHA-256 at rest), `system_tenant_registration_policies_forced_disabled` (API refusal, IAT refusal, and settings written behind the API's back still show disabled, are not advertised, and `/t/system/register` stays 404).

Mutation check: each mutation below made its named test fail:

| Mutation | Test that failed |
|---|---|
| system-tenant DCR rule removed from `registration_settings_issues` | system_tenant_registration_policies_forced_disabled |
| `TenantView::new` shows stored instead of effective DCR | system_tenant_registration_policies_forced_disabled |
| webhook PATCH authorized with read access | v04_admin_routes_require_scopes |

Core unit test: `service::tenant::registration_settings_are_validated`.

## Task Commits

1. **Deferred items: DCR/CIMD validation in TenantService, used by validate_document:** `e1f13dd` (feat)
2. **Task 1: attribute and webhook admin routes:** `02761ea` (feat)
3. **Task 2: IAT routes, DCR/CIMD settings, issuer, client fields, OpenAPI, security tests:** `3c0ce88` (feat)

## Verification run

- `cargo test -p anvil-web` with `--test` admin_attributes (4), admin_webhooks (4), attribute_claims (1), admin_registration (6), security_admin_v04 (5) and openapi_drift (3) all pass.
- Regression runs pass: admin_api (9), admin_api_v02 (9), admin_api_v03 (4), admin_config (7), security_admin_config (6), security_admin (10), security_admin_v02 (6), security_admin_v03 (5), registration_dcr (6), security_registration (18), cimd (14), security_cimd (12), discovery (12), admin_roles (6), security_rbac (12), webhooks (13), security_webhooks (6). `anvil-web --lib` (168), `anvil-core --lib` (801), `anvilid --test tenant_config` (4).
- `cargo clippy -p anvil-core -p anvil-web --lib --tests`: no warnings. `rustfmt --edition 2024` on every touched Rust file.
- `just openapi-update` (UPDATE_OPENAPI=1), then `npm run gen:api`. `npm run check:api` reports up to date, and `npm run typecheck` passes.

## Not run

- Postgres variants (`ANVILID_TEST_DB=postgres`) of the new test binaries: they need Docker and are left for CI.
- The e2e and conformance suites, and the full workspace run (targeted runs only, per the shared rules).

## Deviations from Plan

### Auto-fixed / forced

**1. [Rule 3 - Blocking, required by the prompt] DCR/CIMD validation in TenantService** (forced extra files `crates/anvil-core/src/service/tenant.rs`, `crates/anvil-core/src/service/config.rs`)
- No validation existed beyond config's system/min-max checks. Added `registration_settings_issues` and `validate_registration_settings`, called on tenant create and on update when dcr/cimd change. `validate_document` now reports the same issues. The config unit test `system_tenant_rules` gained an allowed host, because CIMD `allow_listed` without hosts is now an issue too.

**2. [Rule 3 - Blocking] openapi_drift operation count** (forced extra `crates/anvil-web/tests/openapi_drift.rs`): 63 -> 81.

**3. Status codes**
- The plan says 400 for invalid schemas/values and for the system-tenant PATCH. The API's convention for validation is 422 problem details (RFC 9457), so these are 422.

**4. Paths**
- Rotation is `/secret`, not `/rotate`, matching client secret rotation.
- Redelivery is flat under `/webhooks/deliveries/{delivery_id}`. The reason is in key-decisions.

**5. Tenant view issuer (deferred item from 05-04)**
- `TenantView::from` became `TenantView::new(tenant, issuer)` and `TenantList::new(page, issuer_of)`, because the issuer needs the public URL.

**6. TDD order**
- Tests and implementation were committed together per task, with no separate RED commits. The security tests were checked by mutation instead.

### Notes
- Plan's "client_credentials" DCR field is `allow_client_credentials` on the wire (same as the model and the declarative config).
- "A later request re-fetches it if policy allows" is proven over HTTP in `admin_registration::cimd_clients_are_listed_deleted_and_blocked_by_the_allow_list` (two fetches; then blocked by the allow-list with no fetch).

## Deferred items logged

- The 05-04 and 05-20 items are marked done. Console follow-up: use `tenant.issuer` in the tenants list.
- DCR/CIMD validation rules for the docs (05-25/05-27) and the JSON Schema owner.
- The security_admin_v04 test names for `scripts/check-security-tests.sh` (05-28).

## Self-Check: PASSED
