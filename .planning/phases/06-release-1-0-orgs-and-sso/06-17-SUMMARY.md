---
phase: 06-release-1-0-orgs-and-sso
plan: 17
subsystem: admin-api
tags: [organizations, enterprise-sso, saml, oidc, domains, routing, branding, openapi, org-03, org-04, adm-02]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-04 ports (OrgRepo domains, ConnectionRepo list_for_org/has_links, SamlXml, DomainTxtLookup), 06-05 home_realm/domain_verification rules, 06-07/06-08 storage, 06-09 SAML adapter (parse_metadata, X.509 loader), 06-10 check_domain, 06-12 OrgAdminAuth/org_for/org_actor, 06-14 org connections in the upstream flow"
provides:
  - "ConnectionService owners (ConnectionOwner::{Tenant, Org}) with *_as methods, SAML rules and the saml_experimental flag enforcement; parse_idp_metadata"
  - "OrgDomainService { storage, clock, lookup }: add, list, get, verify, update (routing guards), delete; pure check_routing"
  - "BrandingService::effective(tenant, client, org) with client > org > tenant"
  - "20 operations under /api/admin/v1/tenants/{slug}/organizations/{org}/(connections|domains|branding)"
  - "ConnectionView.organization / .sp, SAML config DTO, SamlMetadataImport/View, DomainView, BrandingView.org_id, TenantView.features.saml, tenant claims org_roles/org_permissions"
affects: [06-22, 06-23, 06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "One service method per mutation with an owner parameter; the tenant-level API keeps its old signatures as thin wrappers"
    - "Org branding reuses the tenant/client handler code; only authorization differs by scope"

key-files:
  created:
    - crates/anvil-web/tests/admin_org_sso.rs
    - crates/anvil-web/tests/security_domains.rs
  modified:
    - crates/anvil-core/src/service/connection.rs
    - crates/anvil-core/src/service/org_domain.rs
    - crates/anvil-core/src/service/branding.rs
    - crates/anvil-web/src/admin/organizations.rs
    - crates/anvil-web/src/admin/connections.rs
    - crates/anvil-web/src/admin/branding.rs
    - crates/anvil-web/src/admin/tenants.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/src/theme.rs
    - crates/anvil-web/tests/admin_connections.rs
    - crates/anvil-web/tests/admin_branding.rs
    - crates/anvil-web/tests/security_admin_v10.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - admin-ui/src/components/ConnectionForm.tsx

key-decisions:
  - "Org connections are OIDC or SAML only (422 for social/OAuth2 kinds); they share the tenant's slug namespace and are changed only under the org (tenant-level PATCH/DELETE/PUT secret answer 409)"
  - "SAML flag: create, every change except a pure disable, and the metadata import need saml_experimental (403 feature_disabled); disable and delete always work"
  - "Tenant-level validate_config refuses SAML with 422 (field config) instead of FeatureDisabled, so tenant YAML gets a validation error too"
  - "X.509 parsing of SAML certificates uses bergshamra_keys::loader::load_x509_cert_pem (the loader the adapter verifies with) in the web layer; core keeps SamlConfig::validate (structure only)"
  - "Metadata URL fetch: every failure (blocked destination, network, status, >1 MiB) gives one 422 on field url that never echoes the URL"
  - "Org sub-routes (connections, domains, branding) use the organizations scopes for system admins, like the rest of the org API, not admin:settings"
  - "Routing guards answer 409 (pending domain, no or disabled target, lockout guard); a target that is not a connection of this org answers 422 on connection_id"
  - "The lockout guard runs on every update whose resulting allow_local_password is false (also routing=false or a target change), for every actor; routing=false + allow_local_password=true always passes (recovery)"
  - "A failed verification of a pending claim records only an audit event (no record_check: failing_since is for verified claims)"

requirements-completed: []

duration: ~80min
completed: 2026-11-26
---

# Phase 6 Plan 17: Org SSO administration (connections, domains, routing, branding) Summary

**An org now configures everything it needs for SSO through the management API. It can add OIDC connections and SAML connections (experimental, behind the operator flag), set up SAML from explicit fields, pasted metadata or an SSRF-guarded metadata URL, and copy the SP values from the response. It verifies domains by DNS TXT, where every failed check gives the same answer and only one org per tenant can verify a domain. It sets routing per domain, with a lockout guard on turning passwords off, and it can brand its sign-in pages. Org admins have access to their own org only.**

No requirement checkbox was ticked (wave rule). ORG-03, ORG-04 and ADM-02 (the API part) are prepared for the gate.

## Task Commits

1. **Task 1, org OIDC/SAML connections, flag, metadata import, tenant view, claim DTO:** `245f747` (feat)
2. **Task 2, domains, verification, routing guards:** `1fbbc79` (feat)
3. **Task 3, org branding, theme precedence, OpenAPI and console types:** `9b329a6` (feat)
4. **Call sites name `domain_check::check_domain` and `SamlXml::parse_metadata` (key links):** `a120aa2` (refactor)

## Routes (`/api/admin/v1/tenants/{slug}/organizations/{org}`, tag `organizations`, branding tag `branding`)

All of these take `OrgAdminAuth`. A system admin needs `admin:organizations:read` or `admin:organizations:write` (or `admin:read` / `admin:write`). The org's own admin is accepted for its own org only.

| Route | Notes |
|---|---|
| `GET\|POST /connections` | list (slug order) / create (OIDC or SAML) |
| `POST /connections/saml-metadata` | `{xml}` or `{url}` (exactly one); returns `SamlMetadataView {idp_entity_id, sso_url, signing_certs, metadata_url}`; stores nothing; needs the flag |
| `GET\|PATCH\|DELETE /connections/{id}` | another org's connection answers 404 |
| `PUT /connections/{id}/secret` | OIDC; SAML answers 422 (`secret`) |
| `GET\|POST /domains` | claim: 201 with `record_name` / `record_value`; 409 when the org already claimed the domain; 422 with the reason |
| `GET\|PATCH\|DELETE /domains/{id}` | PATCH `{connection_id?, routing?, allow_local_password?}` |
| `POST /domains/{id}/verify` | 200 with `status` verified or pending (pending looks the same for every cause); 409 when another org already verified the domain |
| `GET\|PUT\|DELETE /branding`, `PUT\|DELETE /branding/logo`, `POST /branding/preview`, `POST /branding/publish` | same bodies and limits as tenant/client branding |

Tenant level:
- `…/connections` lists org connections with `organization` set.
- PATCH, DELETE and PUT secret on an org connection answer 409.
- Creating a SAML connection there answers 422 (`config`).

The OpenAPI document grew from 102 to 122 operations.

## DTOs

- `ConnectionConfig` gains `saml` (`SamlConnectionConfig`):
  - `idp_entity_id`, `sso_url`;
  - `signing_certs` (PEM, public);
  - `name_id_format` (`NameIdFormat`), `attributes` (`SamlAttributeMapping`);
  - `metadata_url`.
- `ConnectionView` gains:
  - `organization: uuid|null`;
  - `sp: {entity_id = {issuer}/saml/{slug}, acs_url = {issuer}/ui/login/saml/{slug}/acs, metadata_url = {issuer}/saml/{slug}/metadata}` (SAML only).
  - For SAML, `redirect_uri` is the ACS URL.
  - `ConnectionView::new` is now infallible.
- `TenantView.features = {saml}`: true when `saml_experimental` is on, never for `system`.
- `DomainView`:
  - id, domain, status (pending|verified), record_name, record_value;
  - connection_id, routing, allow_local_password;
  - verified_at, last_checked_at, failing_since, created_at.
- `BrandingView` gains `org_id`, and `scope` can be `org`.
- **Deferred item resolved:** `TokenClaimMapping` / `TokenClaimMappingPatch` (tenants.rs) now carry `org_roles` and `org_permissions`.
  - On input, an absent field means the default rule and `null` disables it.
  - Names are validated by the existing `validate_mapping`.
  - The wrong "(06-09)" comments are gone.

## Core behaviour

- **Connections:**
  - `validate_config_for(config, in_org)`, `validate_saml`, `plan_create_for(.., org, ..)`.
  - `ConnectionService::{list_for_org, get_owned, create_as, update_as, set_secret_as, delete_as, parse_idp_metadata}`.
  - Audit details add `org_id` / `org_slug` for org connections.
  - The TRANSITIONAL(06-17) refusal and the view mapping are gone (`grep` finds nothing).
- **Domains (`OrgDomainService`):**
  - `add`: `normalize_domain` plus `new_token(random_bytes::<16>())`.
  - `verify`: calls `domain_check::check_domain`; a `mark_verified` Conflict becomes 409.
  - `update`: runs pure `check_routing(RoutingState)` on the resulting state, using `has_links` for the target.
  - `delete`.
  - Audit actions: `org_domain_created|verified|verification_failed|updated|deleted`, with target the claim id and details org plus domain. `org_domain_verified` is classified as the `organization.domain_verified` webhook (domain_id + org_id).
- **Branding:**
  - `effective` folds the tenant, org and client layers through `merge_tokens` (lowest first). Custom CSS order is tenant, org, client; the logo comes from the highest layer that has one.
  - `check_scope` refuses unknown orgs.
  - `theme.rs` reads `organization` from the flow's authorization request. It matches the canonical UUID first, then the slug; an unknown org falls back silently.

## Negative / security tests

- **admin_org_sso.rs (12):**
  - `saml_connection_refused_when_flag_off`: create, metadata import, enabling a stored disabled one, and renaming it all answer 403; disable and delete still work.
  - `saml_connection_refused_at_tenant_level`
  - `saml_connection_invalid_input_is_422`: not X.509, 0 or 4 certs, http SSO URL, transient NameID, http metadata_url, and a PATCH with a bad cert.
  - `metadata_url_to_private_address_is_blocked`: 127.0.0.1, 10/8, 169.254.169.254, ::1, http, file. All give one identical body, with no host echoed.
  - `org_admin_manages_own_connections_only`
  - `org_connections_are_oidc_or_saml_and_share_the_slug_namespace`
  - Positive tests: `org_oidc_connection_crud_with_write_only_secret`, `saml_connection_create_from_fields_returns_sp_values`, `saml_connection_from_pasted_metadata`, `saml_connection_from_metadata_url` (wiremock, including the >1 MiB refusal), `tenant_view_reports_saml_availability`, `tenant_settings_expose_org_claim_mapping` (including the reserved-name refusal).
- **admin_connections.rs (+1):** `tenant_connection_list_shows_org_connections_read_only` (409 on PATCH, DELETE and secret).
- **security_domains.rs (17):**
  - `domain_add_refuses_public_suffix`, `_ip_literal`, `_reserved_name`, `_wildcard`, `_scheme_or_path`.
  - `domain_verification_failures_are_indistinguishable`: no record, wrong value, and lookup failure (through a second router on the same storage with a failing lookup) give byte-identical status and body.
  - `second_org_cannot_verify_verified_domain`, `routing_requires_verified_domain`, `routing_target_must_be_same_org_connection`.
  - `disabling_local_password_requires_proven_connection`, which also covers routing=false while passwords are off, and the recovery path.
  - `disabled_target_connection_stops_routing`, `domain_delete_stops_routing`, `org_admin_cannot_touch_other_org_domains`.
  - Positive tests: `domain_add_normalises_and_returns_record`, `domain_verify_succeeds_with_matching_txt` (audit plus webhook classification), `allow_local_password_defaults_true`, `routing_to_new_connection_without_sign_ins_is_allowed`.
- **admin_branding.rs (+3):** `org_branding_put_get_delete`, `sign_in_page_uses_org_branding_when_request_names_org` (by slug and id; no or unknown org falls back to the tenant; the client still wins), `org_admin_can_brand_own_org_only`.
- **security_admin_v10.rs:**
  - new `v10_org_sso_routes_require_scopes`, covering all 20 new operations: 401 without a token, 403 with another scope, 403 with the read scope on writes, and passes with its own scope;
  - `org_admin_token_refused_for_other_org` now also covers connections, metadata import, domains and branding.
- **Core unit tests:**
  - `service::connection`: `saml_is_refused_at_tenant_level`, `org_connections_are_oidc_or_saml`, `saml_rules_name_config_fields_and_refuse_a_secret`, `only_disabling_counts_as_disabling`.
  - `service::org_domain`: 3 `check_routing` tables.
  - `service::branding`: `three_layers_keep_their_precedence_per_field`.

All of these negative-test names need to go into `scripts/check-security-tests.sh` at the gate (06-26).

### Mutation checks (guard removed, then restored from a backup)

| Guard disabled | Test that failed |
|---|---|
| lockout guard (`has_links` ignored) | `disabling_local_password_requires_proven_connection` |
| org filter in `OrgDomainService::get` | `org_admin_cannot_touch_other_org_domains` |
| `require_saml` always passes | `saml_connection_refused_when_flag_off` |
| tenant-level read-only guard (`get_mutable`) | `tenant_connection_list_shows_org_connections_read_only` |

The same-org filter on the routing target in `update` is defence in depth. Storage's `update_domain` refuses another org's connection too, so `routing_target_must_be_same_org_connection` still passed with only that service filter removed.

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test admin_org_sso --test admin_connections --test security_domains --test admin_branding --test security_admin_v10 --test theme --test openapi_drift`: 12 + 5 + 17 + 9 + 22 + 6 + 3 passed
- Regression: `admin_api`, `admin_orgs`, `admin_api_v02`, `admin_roles`, `enterprise_oidc`, `admin_config`, `upstream_login`: green; `cargo test -p anvilid --test tenant_config`: 5 passed
- `cargo test -p anvil-core --lib`: 987 passed
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings`: clean
- `cd admin-ui && npm run gen:api && npm run check:api && npm run typecheck`: up to date, no errors
- `grep -rn "TRANSITIONAL(06-17)" crates/`: no match
- `scripts/check-release-graph.sh`: OK
- `rustfmt --edition 2024` was run on every touched Rust file

## Not run

- The Postgres variant (`ANVILID_TEST_DB=postgres`): needs Docker, left for CI. No SQL was added; every storage call is an existing port method covered by the 06-04 contract suite.
- `scripts/check-security-tests.sh`: the new names are mapped at the gate.
- e2e: this plan has no UI (the console pages are 06-23).

## Deviations from Plan

### Auto-fixed / forced extras

1. **[Rule 3 - Blocking] `crates/anvil-web/tests/openapi_drift.rs`:** the operation count went from 102 to 122. This file is outside files_modified, but the plan's verify step runs `openapi_drift` (06-12 had the same deviation).
2. **[Rule 3 - Blocking] `admin-ui/src/components/ConnectionForm.tsx`:** one guard line (`if (config.type === "saml") return v;`). The new `saml` variant of `ConnectionConfig` broke `npm run typecheck`, which the plan's verify step runs. The tenant connection form never edits SAML connections.
3. **[Rule 2] Org connections are limited to OIDC and SAML.** The plan names only these two as enterprise connections. A social or OAuth2 org connection would otherwise be accepted and would be hidden from the sign-in page with no HRD route.
4. **[Rule 2] Tenant-level changes to org connections are refused with 409** (the plan says "read-only"). Without this, a tenant settings token could change an org's IdP outside the org's audit trail.

### Interpretations

- `?request=` in the plan's theme note is `?flow=` in the code (the theme link carries the flow id). The org comes from that flow's authorization request.
- Org sub-routes use the organizations scopes for system admins, not `admin:settings` (one principal rule for every `{org}` route, as 06-12 set up).
- Verification of an already verified claim returns it unchanged and records no event.
- The deferred item "org claim mapping not on the admin DTO" was in this plan's files (tenants.rs), so it is fixed here. That deferred-items.md entry can be closed.
- TDD: each task went into one commit (tests written alongside and run before committing). Peers build the same tree, so no RED commit was made, as in 06-05 and 06-12.

## Open items for later plans

- 06-22 (HRD): routing data comes from `OrgRepo::routed_domain`. `allow_local_password=false` is enforced at sign-in there (the password sign-in consequence is tested in hrd_login).
- 06-23 (console): use `TenantView.features.saml` for the Experimental badge, `ConnectionView.sp` for the copy fields, `POST …/connections/saml-metadata` to prefill, and `DomainView.record_name` / `record_value` for the DNS instructions.
- 06-25 (docs): document the recovery path (`routing: false, allow_local_password: true`, possible for an org admin or a tenant admin), the trade-off behind the conservative Q6/Q7 default, and that SAML changes need the flag.
- 06-26: add the negative-test names above to the security map.

## Self-Check: PASSED

- FOUND: crates/anvil-web/tests/admin_org_sso.rs (`saml_connection_refused_when_flag_off`), crates/anvil-web/tests/security_domains.rs (`domain_verification_failures_are_indistinguishable`), crates/anvil-core/src/service/org_domain.rs (`check_domain`), crates/anvil-web/src/admin/organizations.rs (`parse_idp_metadata` via ConnectionService, `domain_check` via OrgDomainService)
- FOUND commits: 245f747, 1fbbc79, 9b329a6, a120aa2
