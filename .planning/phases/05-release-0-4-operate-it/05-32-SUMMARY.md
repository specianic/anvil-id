---
phase: 05-release-0-4-operate-it
plan: 32
subsystem: oauth, admin-api, config, discovery
tags: [gap-closure, admin-scopes, dcr, cimd, body-limit, json-schema, oidc-discovery, mcp]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-12 admin scope bounding; 05-20 declarative config plan/apply; 05-21 DCR; 05-23 DCR/CIMD tenant settings validation; 05-25 MCP docs and the path-insertion note"
provides:
  - "service::admin_scope::is_reserved_admin_token (admin, admin:*): the one admin-token rule for static clients, DCR, CIMD and dcr.allowed_scopes"
  - "service::client::check_admin_scopes(system_tenant, scopes): Validation on `scopes` outside the system tenant (create, scope updates, config plan/apply)"
  - "admin::branding::CONFIG_BODY_LIMIT (1 MiB) and is_config_document(method, path) in the body_limit layer"
  - "tenant-config-v1.json encodes the DCR/CIMD per-field bounds ($defs host_list, registration_list)"
  - "OIDC path-insertion discovery /.well-known/openid-configuration/t/{slug}"
affects: [05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Rules enforced in a service are also called from config::validate_document so plan/apply report them before any write"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/admin_scope.rs
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-core/src/service/config.rs
    - crates/anvil-core/src/oauth/registration.rs
    - crates/anvil-core/src/oauth/cimd.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-web/src/admin/branding.rs
    - crates/anvil-web/src/tenant.rs
    - crates/anvil-web/tests/security_admin_v04.rs
    - crates/anvil-web/tests/security_admin_config.rs
    - crates/anvil-web/tests/security_body_limit.rs
    - crates/anvil-web/tests/admin_config.rs
    - crates/anvil-web/tests/discovery.rs
    - docs/schemas/tenant-config-v1.json
    - docs/CONFIG-YAML.md
    - docs/MCP.md
    - docs/UPGRADING.md

key-decisions:
  - "The admin-scope refusal is a 422 field error on `scopes` (the admin API's Validation convention), not 400 as the plan wrote"
  - "apply_update checks admin scopes only when the patch sets `scopes`, so legacy clients stay editable until their scopes change"
  - "config::validate_client_section also calls check_admin_scopes (forced extra file): without it the refusal would only come from ClientService at write time, after other writes of a non-transactional apply"
  - "is_config_document matches POST and the exact path /api/admin/v1/tenants/{one segment}/config/(plan|apply) only; other methods and paths keep 64 KiB"
  - "The schema also caps dcr.allowed_scopes / allowed_resources at 100 entries (server-enforced); cross-field rules (min <= max cache, allow_listed needs a host) and case-insensitive host duplicates stay server-only, stated in the schema descriptions"
  - "OIDC path insertion shares the RFC 8414 classify loop (INSERTED_WELL_KNOWN), same slug validation and rewrite"

patterns-established:
  - "Negative tests were mutation-checked where the guard is easy to remove (config validation call)"

requirements-completed: [ORG-05, OIDC-17, AGT-01, AGT-02, ADM-06]

duration: ~45min
completed: 2026-11-26
---

# Phase 5 Plan 32: Protocol and admin gap fixes Summary

**One reserved admin-scope rule refusing `admin` / `admin:*` on non-system clients (API and config apply), a 1 MiB body limit for config plan/apply only, DCR/CIMD bounds in the published JSON Schema, and OIDC path-insertion discovery for path tenants**

## Performance

- **Duration:** ~45 min
- **Completed:** 2026-11-26
- **Tasks:** 2
- **Files modified:** 17 (16 planned + service/config.rs)

## Accomplishments

- `is_reserved_admin_token` replaces three copies (DCR `is_forbidden_scope` deleted, CIMD inline check, tenant `dcr.allowed_scopes`, which now also refuses bare `admin`)
- Static clients outside the system tenant cannot be created with, or patched to, admin scopes; system tenant unaffected; legacy clients stay editable and can drop the scope
- Config plan/apply report `clients[i].scopes` before any write
- `POST .../config/plan|apply` accept up to 1 MiB, 413 one byte above (announced and streamed); every other route stays at 64 KiB
- Schema: host lists `maxItems: 100` + `uniqueItems`, scope/resource lists `maxItems: 100`, `max_clients <= 1000000`, cache bounds 60..=604800
- `GET /.well-known/openid-configuration/t/{slug}` returns the same document as `/t/{slug}/.well-known/openid-configuration`; unknown/invalid slug 404

## Negative tests (for the 05-28 security map)

- `security_admin_v04.rs::static_client_admin_scope_refused_outside_system_tenant` (create with `admin:read`, `admin`, `admin:custom`; PATCH to `admin:clients:write`; nothing stored, no audit)
- `security_admin_v04.rs::legacy_admin_scope_client_stays_editable` (re-adding the scope refused)
- `security_admin_v04.rs::system_tenant_static_client_may_hold_admin_scopes` (positive control)
- `security_admin_config.rs::config_apply_refuses_admin_scope_on_non_system_client` (plan and apply, create and update; mutation-checked by removing the validate_document call)
- `service::admin_scope::tests::reserved_admin_tokens`; `service::tenant` registration settings test now includes `dcr.allowed_scopes: ["admin"]`
- `security_body_limit.rs::config_routes_accept_up_to_1_mib_and_no_more`; `admin_json_routes_answer_413_above_64_kib` extended (path containing "config", PUT on the config path)
- `admin::branding::tests::config_document_paths`
- `admin_config.rs::schema_encodes_registration_bounds` (schema and server both refuse each case)
- `tenant::tests::oidc_inserted_path`; `discovery.rs::oidc_path_insertion_serves_the_path_tenant`

## Task Commits

1. **Task 1: one admin-token rule; refuse admin scopes on non-system static clients** - `72f939b` (feat)
2. **Task 2: config body limit, schema bounds, OIDC path-insertion discovery** - `0c5b054` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Config validation calls the admin-scope rule**
- **Found during:** Task 1
- **Issue:** The plan relied on ClientService refusing during apply. Apply is not one transaction, so a refusal at write time could leave earlier writes (roles, connections, ...) in place, breaking "nothing changed".
- **Fix:** `check_admin_scopes` is `pub` with a `system_tenant: bool` parameter and is called from `config::validate_client_section`, so plan/apply report `clients[i].scopes` before any write.
- **Files modified:** crates/anvil-core/src/service/config.rs (not in files_modified; no wave-8 plan owns it)
- **Commit:** 72f939b

**2. [Convention] 422 instead of 400**
- The plan's behaviour said 400; admin API Validation errors are 422 problems (05-23 decision). Tests assert 422 on field `scopes`.

**3. [Rule 1 - Test] PUT on the config path checked with Content-Length only**
- PUT has no handler there, so a streamed oversized body gets 405 from the router before being read; the test checks the announced 413 only.

**4. Schema extra:** scope/resource lists also get `maxItems: 100` (a server-enforced bound the plan did not list).

**Note:** the UPGRADING.md entries for the body limit and the discovery URL were committed with Task 1 (same file).

## Verification

- SQLite: anvil-core lib (admin_scope, client, oauth::, tenant, config: 282 passed); anvil-web lib tenant:: and admin::branding; integration suites security_admin_v04, security_admin_config, security_registration, security_cimd, admin_api, admin_registration, security_body_limit, admin_config, admin_branding, discovery, resource_indicators, security_tenant, openapi_drift: all green
- clippy -D warnings on anvil-core and anvil-web (all targets): clean
- Plan grep checks on MCP.md, CONFIG-YAML.md and the schema pass; docs/openapi/admin-v1.json unchanged

## Not run

- `ANVILID_TEST_DB=postgres` for security_admin_v04 / security_admin_config (Docker not used; left for CI)

## Self-Check: PASSED
