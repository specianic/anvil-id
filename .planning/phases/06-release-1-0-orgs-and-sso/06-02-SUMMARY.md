---
phase: 06-release-1-0-orgs-and-sso
plan: 02
subsystem: core-model
tags: [organizations, saml, model, audit, webhooks, storage, openapi, console]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 0.4 model (role.org_id reserved), audit/webhook classification, claims mapping, admin wire enums
provides:
  - model/organization.rs and model/saml.rs (every Phase 6 domain type)
  - OrgId/OrgInvitationId/OrgDomainId; org_id on Role, Connection, code and token family
  - ConnectionConfig::Saml / ConnectionKind::Saml; client_id() -> Option<&str>
  - AuthorizationParams.organization, ReplayKind::SamlAssertionId, EmailKind::OrgInvitation, BrandingScope::Org
  - client organization policy (OrgClientPolicy, off by default) through ClientOptions/Patch and tenant YAML
  - ClaimMappingSettings.org_roles / org_permissions (defaults)
  - CoreError::FeatureDisabled (403 feature_disabled)
  - 18 AuditActions, 6 organization.* WebhookEventTypes and their classification
  - Resource::Organizations (admin:organizations:{read,write}) and ORG_ADMIN_SCOPE (org:admin)
  - reserved claims org_id, org_slug, org_roles, org_permissions
  - TRANSITIONAL storage refusals (06-07 SQLite, 06-08 Postgres), anvil-mail (06-20), admin SAML view (06-17), connection service (06-17)
  - regenerated OpenAPI and console types
affects: [06-04, 06-07, 06-08, 06-09, 06-13, 06-15, 06-16, 06-17, 06-18, 06-20, 06-26]

tech-stack:
  added: []
  patterns:
    - "Phase 6 values not yet migrated return StorageError::Unsupported behind one helper per repo file (refuse_unmigrated, refuse_org_grant, refuse_org_policy, refuse_org_scope)"
    - "Org webhook payload conventions: organization.created|deleted target = org id; member events target = user id + AuditDetails::org; domain events target = domain id + AuditDetails::org"

key-files:
  created:
    - crates/anvil-core/src/model/organization.rs
    - crates/anvil-core/src/model/saml.rs
    - .planning/phases/06-release-1-0-orgs-and-sso/deferred-items.md
  modified:
    - crates/anvil-core/src/model/{mod,ids,role,connection,grant,client,tenant,branding,mail_settings,config_doc,audit,webhook}.rs
    - crates/anvil-core/src/error.rs
    - crates/anvil-core/src/policy/{webhook_event,claims_mapping}.rs
    - crates/anvil-core/src/service/{admin_scope,client,config,connection,upstream,branding,...}.rs
    - crates/anvil-mail/src/{check,render}.rs
    - crates/anvil-storage-{sqlite,postgres}/src/{roles,connections,grants,clients,branding,mail_settings}.rs
    - crates/anvil-web/src/errors.rs, crates/anvil-web/src/admin/{dto,tenants,branding,email,webhooks,connections}.rs
    - docs/openapi/admin-v1.json, docs/schemas/tenant-config-v1.json
    - admin-ui/src/api/schema.d.ts, admin-ui/src/routes/t/$tenant/audit/index.tsx, admin-ui/src/components/{WebhookForm,ConnectionForm}.tsx, admin-ui/src/lib/email.ts

key-decisions:
  - "validate_org_slug uses the tenant slug rule as implemented (2-63 chars), not the 1-63 regex written in the plan"
  - "The org claim mapping rules may keep their own reserved names (org_roles / org_permissions); every other rule, and attributes, may use no reserved name"
  - "Client organization policy is wired through ClientOptions/ClientOptionsPatch and the tenant YAML client section (omitted when off); no admin DTO field yet"
  - "org_invitation is hidden from the email template admin API (404, not listed) until 06-20 adds its contract"
  - "A stored SAML config has no admin connection view: ConnectionView::new is fallible and returns CoreError::Internal (TRANSITIONAL(06-17))"
  - "Org branding drafts preview like client drafts (draft on top of the live tenant branding); admin view labels the scope 'org'"

patterns-established:
  - "TRANSITIONAL(plan) refusals for every non-default Phase 6 value at the storage write boundary"

requirements-completed: []

duration: ~60min
completed: 2026-11-26
---

# Phase 6 Plan 02: Foundation A (model, errors, audit actions, compile fixes, OpenAPI) Summary

**Every Phase 6 domain type, id, error, audit action, webhook event, admin scope and reserved claim now lives in anvil-core with serde defaults. Storage refuses each new value with an explicit TRANSITIONAL error until 06-07/06-08. The OpenAPI document and console types are regenerated.**

## Performance

- **Duration:** about 60 min (first task commit 09:13Z, last 09:31Z, plus reading and verification before and after)
- **Completed:** 2026-11-26
- **Tasks:** 4/4
- **Files modified:** 78 (+2 created)

## Accomplishments

- `model/organization.rs`: Organization, NewOrganization, OrganizationUpdate, OrgSettings, OrgMembership, NewMembership, OrgInvitation and NewOrgInvitation (Debug redacts `token_hash`), InvitationAccept, OrgDomain (`allow_local_password`, documented as defaulting to true per Q6/Q7), NewOrgDomain, OrgDomainUpdate, OrgDomainStatus, OrgClientPolicy (off/optional/required, default off), OrgClaims, ORG_INVITATION_TTL, DOMAIN_RECHECK_GRACE, MAX_ORG_DISPLAY_NAME and validate_org_slug.
- `model/saml.rs`: NameIdFormat (with URN mapping), SamlAttributeMapping, SamlConfig with `validate()` (entity id 1-1024, https sso_url, 1-3 single-CERTIFICATE PEMs of at most 16 KiB each, no transient NameID, https metadata_url), IdpMetadata, SamlSubjectConfirmation, SamlAssertionData and SamlIdentity. Each rejection has a unit test.
- Changed models:
  - `org_id: Option<OrgId>` on Role/NewRole, Connection/NewConnection, NewAuthorizationCode/AuthorizationCode and TokenFamily/NewTokenFamily.
  - New `RoleAssignment { role_id, user_id, org_id }` type.
  - `AuthorizationParams.organization`; a unit test shows 0.4 params still parse.
  - `ReplayKind::SamlAssertionId`, `EmailKind::OrgInvitation`, `BrandingScope::Org` (key `org:{uuid}`, canonical hyphenated form only).
  - `ClaimMappingSettings.org_roles` / `org_permissions` with defaults; a unit test shows a 0.4 settings blob still parses.
  - Client `organization` field in the model and the config doc.
- `CoreError::FeatureDisabled(&'static str)`: 403, error `feature_disabled`. It goes through the one core mapping, and a test in anvil-web proves the problem+json and OAuth outputs.
- 18 AuditActions plus typed `AuditDetails::org`, `::domain` and `::connection_id` constructors. 6 `organization.*` webhook event types are classified with ids-only payloads (`org_id`, `domain_id`), with a unit test per new action. Ids that are not id-shaped are dropped.
- `Resource::Organizations` is in ALL_ADMIN_SCOPES. `ORG_ADMIN_SCOPE = "org:admin"` is not an `admin:*` token, and tests show it satisfies no admin route.
- Reserved claims `org_id`, `org_slug`, `org_roles`, `org_permissions`. Tests show an attribute or role rule named `org_slug` (in any case) is refused at validation, and is never emitted at runtime.
- SAML on the OIDC/OAuth path: `providers::resolve` refuses it permanently (`InvalidRequest("saml connections use the SAML service")`), and `service/upstream.rs` handles `client_id() == None` as "configuration". `validate_config` returns `FeatureDisabled("saml")` (TRANSITIONAL(06-17)), which covers create, update and the tenant YAML plan.

## Per-crate compile checklist

- [x] anvil-core (Tasks 1+2): build all targets, 825 lib tests, clippy -D warnings. Commits 04b6c57, 4da9094
- [x] anvil-mail: tests green, clippy. Commit a2550d6
- [x] anvil-storage contract (fixtures, tenants). Commit 883b8ec
- [x] anvil-storage-sqlite: lib (24), contract (380), plaintext, upgrade all green. Commit c3e217d
- [x] anvil-storage-postgres: builds all targets, lib unit tests green (the Docker suites were not run). Commit c7ccdf5
- [x] anvil-web src: lib tests (171), clippy. Commit a336f7a
- [x] anvil-web tests: full `cargo test -p anvil-web` green (the openapi_drift failure before Task 4 was expected). Commit ed15346
- [x] anvilid tests: full `cargo test -p anvilid` green. Commit 187d761
- [x] Task 4 OpenAPI + console: openapi_drift green, `npm run check:api` and `npm run typecheck` green. Commit aa0635d

## TRANSITIONAL markers (owner plans)

| Marker | Where | What is refused |
|---|---|---|
| TRANSITIONAL(06-07) | anvil-storage-sqlite roles/connections/grants/clients/branding/mail_settings | org-owned roles, org connections, saml configs (create and update), org-bound codes and families, `saml_assertion_id` replay entries, org policy other than off, `org:` branding scopes, `org_invitation` templates |
| TRANSITIONAL(06-08) | anvil-storage-postgres (the same six files) | the same refusals |
| TRANSITIONAL(06-17) | anvil-core service/connection.rs `validate_config` | SAML connection create/update -> FeatureDisabled("saml") |
| TRANSITIONAL(06-17) | anvil-web admin/dto.rs `TryFrom<CoreConnectionConfig>` | SAML connection view -> CoreError::Internal |
| TRANSITIONAL(06-20) | anvil-mail check.rs/render.rs; anvil-web admin/email.rs | `org_invitation`: no contract, so checking or rendering it is an error; the admin API returns 404 and does not list it |

Each storage refusal helper has a unit test in both backends. The contract tests for these values belong to 06-04.

## Task Commits

1. Task 1, model/ids/errors/core compile fixes: `04b6c57`. This commit also carries the claims_mapping literal fixes and reserved names, because tenant.rs needed them to compile.
2. Task 2, audit actions/webhooks/scopes: `4da9094`
3. Task 3, other crates: `a2550d6`, `883b8ec`, `c3e217d`, `c7ccdf5`, `a336f7a`, `ed15346`, `187d761`
4. Task 4, OpenAPI + console: `aa0635d`

## Files Created/Modified (extra compile-fix files beyond files_modified)

- crates/anvil-core/src/oauth/{cimd,registration}.rs, crates/anvil-core/src/service/{bootstrap,registration}.rs: struct literals.
- crates/anvil-mail/tests/templates.rs: the "every kind" test skips contract-less kinds; new `kinds_without_a_contract_are_refused` test.
- crates/anvil-web/src/admin/webhooks.rs: holds the WebhookEventType wire mirror (the plan placed it in dto.rs).
- crates/anvil-web/src/admin/connections.rs: `view()` is now fallible.
- crates/anvil-web/tests/{admin_config,security_admin_v04}.rs and tests/{admin_support,authz}/mod.rs: struct literals.
- docs/schemas/tenant-config-v1.json: `claims.org_roles/org_permissions` and `client.organization` (admin_config's schema test requires them).
- admin-ui/src/components/ConnectionForm.tsx, admin-ui/src/lib/email.ts: the Record types needed the `saml` and `org_invitation` keys for typecheck. SAML is excluded from the creatable KINDS.
- Not touched although listed in files_modified (they compiled unchanged): anvil-core flow/registration.rs, service/{flow,account,mail_settings,role}.rs, oauth (only the listed sites changed); anvil-mail worker.rs (rendering goes through `render_with`, which refuses); storage contract grants/logout/access_tokens/connections/mail_settings/branding/clients; storage plaintext tests; anvil-web tests rbac_claims, security_admin_config, security_rbac, theme; anvilid tests/tenant_config.rs.

## Decisions Made

See key-decisions above. The notable points:

- **Org rules and reserved names:** the default org mapping rules emit `org_roles`/`org_permissions`, which are also reserved. `validate_mapping` lets each org rule keep its own reserved name and nothing else. `mapped_claims` does not emit the org rules yet (06-09).
- **Tenant claim mapping DTO:** `TokenClaimMapping -> ClaimMappingSettings` fills in the default org rules, and `TokenClaimMappingPatch::merge` keeps the stored org rules. The first auto-fix had nulled them, which would have changed behaviour; I caught and fixed it before committing.
- **Client organization policy:** wired end to end in core (options, patch, merge, changed-fields audit, tenant YAML export/plan/apply). Storage refuses any value other than off until 06-07/06-08.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Org claim rules would have been wiped on every tenant claims PATCH**
- **Found during:** Task 3 (auto-filled struct literal in admin/tenants.rs)
- **Fix:** merge keeps the current `org_roles`/`org_permissions`; a full mapping gets the defaults
- **Commit:** a336f7a

**2. [Rule 3 - Blocking] Schema test needed the new settings and client keys**
- **Found during:** Task 3 (anvil-web admin_config `json_schema_matches_the_document_types`)
- **Fix:** described them in docs/schemas/tenant-config-v1.json
- **Commit:** ed15346

**3. [Rule 3 - Blocking] Console Record types for ConnectionKind/EmailKind broke typecheck**
- **Found during:** Task 4
- **Fix:** labels added; SAML filtered out of the creatable kinds; configFromValues refuses `saml`
- **Commit:** aa0635d

**4. [Rule 2 - Missing critical] Email template admin API for a contract-less kind**
- **Issue:** without a fix, listing templates would have tried to load a default `org_invitation` file and failed with a 500
- **Fix:** the kind is filtered from the list and returns 404 on direct access (TRANSITIONAL(06-20))
- **Commit:** a336f7a

**5. [Plan text conflict] validate_org_slug length:** the plan says "same rule as tenant slugs" but writes `{0,62}` (1-63 characters). I implemented the actual tenant rule, 2-63 characters.

---

**Total deviations:** 4 auto-fixed, 1 plan-text interpretation. No scope creep.

## Issues Encountered

- `model::credential` and `model::webhook` Debug tests failed once and then passed. This is a pre-existing flake: UUIDv7 ids contained `171` during a short time window. Logged in deferred-items.md. My new test uses a robust assertion instead.

## Not run here

- The Postgres testcontainers suites (contract, upgrade, plaintext on Postgres) need Docker and are left for CI. The Postgres crate builds all targets, and its lib unit tests pass.
- Playwright e2e: none added or changed. The console change is limited to types, labels and lists.

## Verification

- `cargo build --workspace --all-targets --locked`: OK
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: OK
- `cargo test -p anvil-core --lib` (825), `cargo test -p anvil-mail`, `cargo test -p anvil-storage-sqlite` (contract 380, upgrade 578, plaintext), `cargo test -p anvil-web` (full), `cargo test -p anvilid` (full): green
- `cargo test -p anvil-web --test openapi_drift`, `npm run check:api`, `npm run typecheck`: green
- `scripts/check-release-graph.sh` OK; `scripts/check-security-tests.sh` OK (632 pairs)
- The TRANSITIONAL(06-07)/(06-08) greps match

## Next Phase Readiness

- 06-04 can add ports and contract tests against these types. Its contract tests for the new values should expect `StorageError::Unsupported` until 06-07/06-08.
- The `psl`, `bergshamra-dsig` and `flate2` unused-dependency warnings come from 06-01's manifests and will clear once later plans use those crates.

## Self-Check: PASSED

- FOUND: crates/anvil-core/src/model/organization.rs, crates/anvil-core/src/model/saml.rs
- FOUND commits: 04b6c57, 4da9094, a2550d6, 883b8ec, c3e217d, c7ccdf5, a336f7a, ed15346, 187d761, aa0635d
