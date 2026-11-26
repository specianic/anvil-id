---
phase: 06-release-1-0-orgs-and-sso
plan: 15
subsystem: oauth, client-service, declarative-config
tags: [organizations, org-admin, dcr, cimd, config, prune, security]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-20 config export/plan/apply; 05-32 is_reserved_admin_token and check_admin_scopes"
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-02 ORG_ADMIN_SCOPE, OrgClientPolicy, org_id on Role/Connection; 06-04 OrgRepo and org role/connection ports; 06-07/06-08 storage"
provides:
  - "oauth::registration::is_registration_forbidden_scope (reserved admin tokens + org:admin): the one self-registration rule for DCR, CIMD and dcr.allowed_scopes"
  - "check_admin_scopes refuses org:admin on system-tenant clients; check_org_policy(system, policy) refuses organization != off there"
  - "config: StoredConfig::tenant_connections / tenant_roles behind one filter is_document_managed (org_id.is_none)"
affects: [06-12, 06-17, 06-22, 06-26]

tech-stack:
  added: []
  patterns:
    - "Org-owned objects are runtime state of their org, like dynamic/CIMD clients: invisible to the tenant document on both plan sides"

key-files:
  created:
    - crates/anvil-web/tests/security_org_scopes.rs
  modified:
    - crates/anvil-core/src/oauth/registration.rs
    - crates/anvil-core/src/oauth/cimd.rs
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-core/src/service/config.rs
    - crates/anvil-web/tests/admin_config.rs
    - crates/anvilid/tests/tenant_config.rs

key-decisions:
  - "is_reserved_admin_token stays the one admin-token rule (admin_scope.rs untouched); the registration helper composes it with ORG_ADMIN_SCOPE, and the tenant dcr.allowed_scopes check uses the same helper"
  - "The system-tenant org:admin refusal lives in check_admin_scopes (same 422 on `scopes`), so client create/update and validate_document share it"
  - "check_org_policy runs on create and on every update against the merged policy (no legacy system client can hold a non-off policy: storage refused it until 06-07)"
  - "The org-owned filter sits on StoredConfig (tenant_connections / tenant_roles) rather than in load, so the pure document() path is filtered too and the full connection list stays available for the slug-collision check"
  - "A document connection whose slug belongs to an org connection is a validation error on connections[i].slug (slugs are unique per tenant across both kinds); without it the plan would show a create that fails with Conflict mid-apply"
  - "Org policy integration tests go through config apply (admin API) because the admin client DTO field is 06-12's; the ClientService rule itself is covered by unit tests"

patterns-established:
  - "Prune tests seed an org-owned role with the same name as the tenant role being pruned, proving name-based deletes stay tenant-scoped"

requirements-completed: []

duration: ~50min
completed: 2026-11-26
---

# Phase 6 Plan 15: org:admin reservation and org-owned objects outside tenant config Summary

**`org:admin` can never be self-registered (DCR, CIMD, `dcr.allowed_scopes`) or held by a system-tenant client, system-tenant clients keep organization policy off, and tenant YAML export/plan/`--prune` never see or delete org connections, org roles, their identity links, memberships or org role assignments.**

Requirements ORG-02 and ORG-03 are supported, not ticked (the gate 06-26 ticks REQUIREMENTS.md).

## Performance

- **Duration:** about 50 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 1 created, 7 modified

## Rules

- `is_registration_forbidden_scope(t) = is_reserved_admin_token(t) || t == "org:admin"`: DCR scope validation and default-scope filtering, CIMD scope validation, tenant `dcr.allowed_scopes` validation.
- `check_admin_scopes(system, scopes)`: system tenant refuses `org:admin`; other tenants refuse `admin`/`admin:*` (unchanged); static application-tenant clients may hold `org:admin`.
- `check_org_policy(system, policy)`: system tenant needs `off` (field `organization`); called from ClientService create/update and `config::validate_client_section`.
- DCR and CIMD clients are always stored with `organization: off` (already hard-coded by 06-02; now proven by tests).
- Config: `is_document_managed(org_id) = org_id.is_none()` behind `StoredConfig::tenant_connections()` / `tenant_roles()`, used by `document()` (export and the plan's current side, hence prune candidates), `check_against_stored`, `secret_matches`, `check_roles` and the prune/update connection lookup. Role deletes go by name through RoleService (`get_by_name` is tenant-level), so an org role with the same name is never touched.

## Negative tests

- `security_org_scopes.rs`: `dcr_cannot_register_org_admin_scope` (also PATCH tenant `dcr.allowed_scopes: [org:admin]` 422), `dcr_client_organization_policy_is_off`, `cimd_document_with_org_admin_scope_rejected` (with positive control, stored policy off), `system_tenant_client_cannot_allow_org_admin` (POST, PATCH, config plan/apply), `system_tenant_client_organization_policy_must_be_off` (optional/required, plan/apply; off accepted), `application_tenant_static_client_may_allow_org_admin` (201), `application_tenant_static_client_may_use_organization_required`
- `admin_config.rs`: `config_export_excludes_org_connections_and_org_roles`, `config_plan_never_lists_org_objects_as_deletes` (plus slug collision 422), `config_apply_prune_keeps_org_connections_and_org_roles` (tenant role/connection pruned as positive control; org role named like the pruned tenant role, org connection, identity link, membership and org assignment intact; then an empty document with prune), `config_client_organization_policy_round_trips` (export -> fresh tenant apply -> export equal, re-plan empty), `config_validate_refuses_org_admin_on_system_clients`
- `anvilid/tests/tenant_config.rs`: `tenant_config_prune_keeps_org_objects` (CLI export, `apply --prune`, re-apply no-op)
- Unit: `oauth::registration::tests::registration_forbidden_scopes`, `service::client::tests::{org_admin_scope_is_refused_in_the_system_tenant_only, org_policy_must_be_off_in_the_system_tenant}`, `service::tenant` registration settings case `org:admin`, `service::config::tests::{org_owned_objects_are_neither_exported_nor_pruned, a_document_connection_cannot_take_an_org_connection_slug, system_clients_refuse_org_admin_and_org_policy}`
- Mutation-checked: weakening `is_registration_forbidden_scope` fails the DCR and CIMD tests; making `is_document_managed` always true fails the export, plan and prune tests.

## Task Commits

1. **Task 1: org:admin reservation and client organization policy rules** - `b24ae94` (feat)
2. **Task 2: tenant YAML excludes org-owned objects; client policy round-trips** - `f3a8e31` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Org connection slug collision refused before any write**
- **Found during:** Task 2
- **Issue:** With org connections hidden from the plan, a document connection reusing an org connection's slug would plan as a create and fail with Conflict after earlier writes of the non-transactional apply.
- **Fix:** `check_against_stored` reports `connections[i].slug` ("is used by an organization connection").
- **Files modified:** crates/anvil-core/src/service/config.rs
- **Commit:** f3a8e31

**2. [Scope] Org policy integration tests through config apply, not the client DTO**
- The admin client DTO `organization` field belongs to 06-12 (parallel); the 201/422 policy cases use `POST .../config/apply` and the ClientService rule has unit tests. Once 06-12 lands, a DTO-level case can be added there.

**3. [Rule 1 - Test] DCR settings PATCH checked before seeding**
- Tenant updates validate DCR settings only when they change, so the PATCH refusal is tested before the misconfigured settings are written through storage.

No files outside files_modified were changed.

## Verification

- `cargo test -p anvil-core --lib -- oauth::registration oauth::cimd service::client service::config service::tenant`: 155 passed
- `cargo test -p anvil-web --test security_org_scopes --test security_registration --test security_cimd --test registration_dcr`: all passed (7/12/7/18)
- `cargo test -p anvil-web --test admin_registration --test security_admin_v04`: passed
- `cargo test -p anvil-web --test admin_config --test security_admin_config`: 13 + 7 passed
- `cargo test -p anvilid --test tenant_config`: 5 passed
- clippy on anvil-core (all targets) and the touched test targets: no warnings in these files
- `scripts/check-release-graph.sh`: OK

## Not run

- Postgres backend (`ANVILID_TEST_DB=postgres`) for these suites: Docker not used; left for CI. All runs above are SQLite.
- Full-workspace test run (avoided per the wave rules).

## Self-Check: PASSED
