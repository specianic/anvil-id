---
phase: 06-release-1-0-orgs-and-sso
plan: 04
subsystem: core-ports
tags: [organizations, ports, storage-contract, saml, dns, config, skeletons]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-01 dependencies (hickory, bergshamra, uppsala), 06-02 model/ids/errors and storage refusals
provides:
  - OrgRepo (orgs, members, invitations, domains) and Storage::organizations()
  - RoleRepo org methods, ConnectionRepo list_for_org/has_links, membership on create_user_with_link
  - DomainTxtLookup / TxtLookupError and SamlXml / SamlXmlReject ports
  - AddMemberOutcome enum
  - TRANSITIONAL(06-07)/(06-08) OrgRepo shims (pending.rs) and role/connection refusals
  - AppDeps.domain_txt, AppState::domain_txt()/domain_txt_arc()/saml_xml()
  - AppConfig.saml_experimental / domain_verification_resolvers and the matching anvilid keys
  - HickoryTxtLookup (TRANSITIONAL(06-10)) and SamlXmlAdapter (TRANSITIONAL(06-09))
  - pre-declared core/web modules and empty routers for every later Phase 6 plan
  - FakeTxt test double (TestApp::txt())
  - 45 contract tests for the new port methods
affects: [06-07, 06-08, 06-09, 06-10, 06-11, 06-12, 06-14, 06-17, 06-18, 06-19, 06-20, 06-22]

tech-stack:
  added: []
  patterns:
    - "Storage-level 'not found' stays bool/Option (no StorageError::NotFound); add_member uses AddMemberOutcome"
    - "Skeleton modules carry a doc naming the owner plan; empty routers answer 404"

key-files:
  created:
    - crates/anvil-storage-sqlite/src/pending.rs
    - crates/anvil-storage-postgres/src/pending.rs
    - crates/anvil-core/src/service/{organization,org_invitation,org_domain,domain_check,domain_recheck,saml}.rs
    - crates/anvil-web/src/adapters/{dns_txt,saml_xml}.rs
    - crates/anvil-web/src/admin/{organizations,keys}.rs
    - crates/anvil-web/src/ui/{select_organization,invitation,saml}.rs
    - crates/anvil-storage/src/contract/{orgs,org_invitations,org_domains}.rs
    - crates/anvilid/tests/config_phase6.rs
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/service/{mod,connection,upstream,session,registration,bootstrap}.rs
    - crates/anvil-storage-{sqlite,postgres}/src/{lib,roles,connections}.rs
    - crates/anvil-storage/src/contract/{mod,fixtures,roles,connections,grants,mail_settings,branding,clients}.rs
    - crates/anvil-web/src/{state,config}.rs, adapters/mod.rs, admin/{mod,connections,config}.rs, ui/mod.rs
    - crates/anvil-web/tests/{support/mod,ui_helpers/mod,health_metrics,security_ratelimit,admin_connections}.rs
    - crates/anvilid/src/{config,startup,tenant_config}.rs, crates/anvilid/tests/tenant_config.rs
    - docs/openapi/admin-v1.json

key-decisions:
  - "OrgRepo::add_member returns AddMemberOutcome {Added, AlreadyMember, NotFound} instead of bool, so callers can audit only real additions and see refused memberships"
  - "Plan 'NotFound' at storage level maps to the existing conventions (false / None / Conflict for FK refusals); StorageError gets no new variant (error.rs mapping untouched)"
  - "Pagination of OrgRepo::list / list_members uses PageRequest (keyset on org id / user id), like UserRepo::list"
  - "RoleRepo::assign refuses org-owned roles (false); 0.4 methods keep tenant-level semantics, documented on the trait"
  - "domain_verification_resolvers entries are ip or ip:port (default 53, port 0 refused); empty means system config; config show prints <system>"
  - "The SAML experimental warning goes through Config.warnings (logged at serve start and printed by config validate)"

patterns-established:
  - "Phase 6 contract tests call the real methods and expect success; until 06-07/06-08 they fail only with StorageError::Unsupported"

requirements-completed: []

duration: ~60min
completed: 2026-11-26
---

# Phase 6 Plan 04: Foundation B (ports, shims, AppDeps/AppConfig, operator keys, skeletons, contract suite) Summary

**Phase 6 now has one fixed storage, module and configuration contract. ports.rs has OrgRepo, the org-level RoleRepo and ConnectionRepo methods, DomainTxtLookup and SamlXml, each with its atomicity documented. Both backends refuse every new method with an explicit TRANSITIONAL error. The binary has the `saml_experimental` and `domain_verification_resolvers` keys. Every later module and router exists empty, and 45 contract tests pin the behaviour that 06-07 and 06-08 must implement.**

Requirements: ORG-02 is prepared, not ticked. Only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 60 min (reading plus three tasks; commits 10:43, 10:50 and 10:59 +01:00)
- **Tasks:** 3/3
- **Files:** 26 created, 39 modified

## Task Commits

1. **Task 1, ports, shims, core skeletons, ConnectionService fields:** `840ea00` (feat)
2. **Task 2, AppDeps/AppState/AppConfig, operator keys, web skeletons, OpenAPI:** `a87fe1b` (feat)
3. **Task 3, contract suite:** `48d3eb5` (test). This commit also adds an outcome-order note to two ports.rs doc comments.

## Port methods (crates/anvil-core/src/ports.rs)

- `Storage::organizations() -> &dyn OrgRepo`
- `OrgRepo`:
  - orgs: `create`, `get`, `get_by_slug`, `list(t, PageRequest)`, `update`, `delete(t, id, now)`. `delete` is one intent: it cascades memberships, org-owned roles and their assignments, in-org assignments, org connections with their links, domains and invitations, and revokes the org's families with reason Admin.
  - members: `add_member -> AddMemberOutcome`, `remove_member(t, org, user, now)` (also revokes that user's families in this org), `is_member`, `list_members(t, org, PageRequest)`, `memberships_of_user` (in slug order).
  - invitations: `create_invitation`, `list_invitations(t, org, include_closed)` (newest first), `revoke_invitation`, `invitation_by_hash`, `accept_invitation(t, &hash, user, verified_email, now) -> InvitationAccept`, `accept_invitation_with_new_user(t, &hash, &NewUser, &NewPasswordCredential, now)`. The outcome order is Invalid, then EmailMismatch, then AlreadyMember or Conflict.
  - domains: `create_domain`, `list_domains`, `get_domain`, `update_domain`, `delete_domain`, `mark_verified` (the partial unique index decides; a losing org gets Conflict), `record_check(t, id, ok, now)`, `unverify`, `routed_domain -> Option<(OrgDomain, Connection)>`, `tenant_has_routing`, `verified_domains_of_org`, `due_for_recheck(checked_before, limit)` (installation-wide).
- `RoleRepo` additions: `list_org_roles`, `assign_in_org(t, role, user, org, now)`, `unassign_in_org`, `roles_for_user_in_org`, `org_assignments(t, org, user) -> Vec<RoleAssignment>`, `org_holders_of_permission`. The trait doc now defines the tenant-level and org-level semantics.
- `ConnectionRepo` additions: `list_for_org` and `has_links`. `create_user_with_link` takes a sixth argument, `membership: Option<&NewMembership>`. `list` is documented to return tenant and org connections.
- Non-storage ports:
  - `DomainTxtLookup::txt(fqdn) -> Result<Vec<Vec<u8>>, TxtLookupError {NotFound, Failed}>`
  - `SamlXml { verify_response, parse_metadata, encode_redirect }` with `SamlXmlReject` (11 reason codes)
  - All Display texts are fixed (unit tested). All of these are in the dyn-compatibility test.

## TRANSITIONAL markers added

| Marker | Where | Behaviour |
|---|---|---|
| TRANSITIONAL(06-07) | anvil-storage-sqlite pending.rs (OrgRepo), roles.rs (6 org methods), connections.rs (list_for_org, has_links, create_user_with_link with Some(membership)) | `StorageError::Unsupported("… (06-07)")` |
| TRANSITIONAL(06-08) | anvil-storage-postgres, the same three files | `StorageError::Unsupported("… (06-08)")` |
| TRANSITIONAL(06-10) | anvil-web adapters/dns_txt.rs `HickoryTxtLookup::txt` | `Err(TxtLookupError::Failed)`, so no domain can verify |
| TRANSITIONAL(06-09) | anvil-web adapters/saml_xml.rs `SamlXmlAdapter` (3 methods) | `Err(SamlXmlReject::Unavailable)` |

`HickoryTxtLookup::new(&[SocketAddr]) -> Result<Self, DnsTxtSetupError>` only stores the resolvers for now. 06-10 builds the resolver there.

## Skeleton owners

| Module | Owner |
|---|---|
| core service::organization | 06-12 |
| core service::org_invitation | 06-12 (accept: 06-20) |
| core service::org_domain | 06-17 |
| core service::domain_check | 06-10 |
| core service::domain_recheck | 06-20 |
| core service::saml | 06-18 |
| web adapters::dns_txt | 06-10 |
| web adapters::saml_xml | 06-09 |
| web admin::organizations (tag `organizations`) | 06-12 (domains/connections 06-17) |
| web admin::keys (tag `keys`) | 06-11 |
| web ui::select_organization | 06-19 |
| web ui::invitation | 06-20 |
| web ui::saml: `routes()` inside the CSRF layer, `callback_routes()` merged after `fetch_metadata_layer()` | 06-18 |

The empty routers are merged in `admin/mod.rs::api_router()` and `ui/mod.rs::routes()`, so later plans never edit these route tables.

## ConnectionService pre-added fields

`saml_enabled: bool` and `saml_xml: Option<Arc<dyn SamlXml>>`, set at every construction site:
- web `admin/connections.rs` and `admin/config.rs`: `state.config().saml_experimental` / `Some(state.saml_xml())`
- `tests/admin_connections.rs`: the config value / `Some(SamlXmlAdapter)`
- CLI `anvilid/src/tenant_config.rs`, `anvilid/tests/tenant_config.rs` and core `UpstreamService::connections()` (which only opens secrets): `false` / `None`

## Operator keys

| Key | Env | CLI | Default | `config show` |
|---|---|---|---|---|
| `saml_experimental` | `ANVILID_SAML_EXPERIMENTAL` | `--saml-experimental` | false | `true`/`false`; when on, a warning that SAML 2.0 is experimental is logged at serve start and printed by `config validate` |
| `domain_verification_resolvers` | `ANVILID_DOMAIN_VERIFICATION_RESOLVERS` | `--domain-verification-resolvers` | empty (system config) | entries, or `<system>` |

Resolver entries are `ip`, `ip:port` or `[v6]:port`, with port 53 as the default. Port 0, host names, CIDRs and URLs fail with `invalid configuration: domain_verification_resolvers: entry N is not an IP address or IP:port`, which never echoes the value. Startup passes both keys into `AppConfig` and builds `HickoryTxtLookup::new(&resolvers)` into `AppDeps`.

`tests/config_phase6.rs` has 7 tests: defaults, env, file, CLI over env, empty list, invalid resolvers (a secret in `smtp_url` is never echoed), and a non-boolean flag.

## Contract tests (45 new, registered in storage_contract_tests!)

- **orgs.rs:** org_create_get_update_delete, org_slug_conflict_per_tenant, org_list_pagination, orgs_isolated_by_tenant, org_add_member_idempotent_with_roles, org_add_member_refuses_unknown_or_foreign, org_remove_member_revokes_only_that_orgs_families, org_delete_cascades_and_revokes_families, org_memberships_of_user, org_list_members_paginates
- **org_invitations.rs:** invitation_create_list_revoke, invitation_by_hash_and_unique_hash, invitation_accept_adds_membership_and_roles, invitation_accept_wrong_email_writes_nothing, **invitation_accept_concurrent_single_winner** (8 accepts), invitation_closed_tokens_are_invalid, invitation_existing_member_keeps_token, invitation_accept_with_new_user_is_atomic, invitations_isolated_by_tenant
- **org_domains.rs:** domain_create_list_get_delete, domain_create_refuses_foreign_routing_connection, domain_mark_verified_one_org_per_domain, **domain_mark_verified_concurrent_single_winner** (8 orgs), domain_update_routing_connection_same_org_only, domain_routed_domain_requires_verified_routing_enabled_connection, domain_record_check_failure_streak, domain_unverify_stops_routing, domain_due_for_recheck_across_tenants, domain_verified_domains_of_org, domains_isolated_by_tenant
- **roles.rs:** role_org_owned_name_unique_per_org, role_list_excludes_org_roles, role_assign_in_org_requires_membership, role_org_owned_role_only_in_its_org, role_tenant_role_in_org_scoped_to_that_org, role_holders_of_permission_ignores_org_assignments, role_org_holders_of_permission_counts_in_org_members
- **connections.rs:** connection_org_and_saml_round_trip, connection_has_links, create_user_with_link_with_membership
- **grants / mail_settings / branding / clients:** code_and_family_org_round_trip, record_jti_saml_assertion_id_replay, mail_template_org_invitation_round_trip, branding_org_scope_independent, client_organization_policy_round_trip

Fixtures added: new_org, expected_org, seed_org, new_membership, seed_member, new_org_role, seed_org_role, new_invitation, expected_invitation, unique_domain, new_org_domain, expected_domain, new_org_connection, seed_org_connection, new_saml_connection, new_org_family, seed_family_for, family_revocation. `expected_code`, `expected_family`, `expected_connection` and `expected_client` now copy `org_id` / `organization` from the input instead of hardcoding the 0.4 defaults.

**SQLite run:** 380 passed and 90 failed. The 90 failures are the 45 new tests × (memory, file). A diff showed the set of failing tests is exactly the set of new tests, and every failure is `StorageError::Unsupported`: 84 × "organizations (06-07)", plus 2 each for client organization policy, org_invitation templates and saml assertion replay guard. The full `cargo test --workspace` goes green again once 06-07 and 06-08 land, as the plan expects.

## Verification

- `cargo build --workspace --all-targets --locked`: OK
- `cargo clippy -p anvil-storage -p anvil-storage-sqlite -p anvil-storage-postgres -p anvil-web -p anvilid --all-targets -- -D warnings`: OK
- `cargo test -p anvil-core --lib`: 925 passed (this includes the ports dyn test and the Display tests)
- Backend lib tests `pending` (SQLite and Postgres): the explicit-refusal tests pass
- `cargo test -p anvil-web --test shell --test openapi_drift --test admin_connections --test health_metrics --test security_ratelimit`, plus the anvil-web lib tests for adapters and ui: green
- `cargo test -p anvilid --test config_phase6 --test tenant_config --test config_phase3/4/5 --test cli` plus the bin unit tests: green
- `just openapi-update` added the two tags. `npm run gen:api` left `schema.d.ts` unchanged, since tags produce no types, and `npm run check:api` is up to date.
- `scripts/check-release-graph.sh`: OK. `scripts/check-security-tests.sh`: OK (632 pairs).

## Deviations from Plan

1. **[Interface] `add_member` returns `AddMemberOutcome` instead of `bool`.** A bool cannot tell "added" from "already a member" from "refused" unless a StorageError::NotFound exists, and error.rs belongs to another plan. The ports.rs doc and the contract tests pin the enum. 06-12 and 06-14 should match on it.
2. **[Interface] Storage-level "NotFound" from the plan text** maps to `false` / `None`. Examples: `assign_in_org` on a non-member or another org's role, and `update_domain` with another org's connection. Inserts that the database would refuse through a foreign key (an unknown org on create_domain, create_invitation or an org-owned role) are `Conflict`, as `create_link` already does.
3. **[Interface] `assign_in_org` takes `now`,** like `assign`. `list` / `list_members` take `PageRequest` instead of `(after, limit)`. `record_check` and `mark_verified` return `Option<OrgDomain>` (None for an unknown id).
4. **[Interpretation] SAML warning.** It goes through `Config.warnings`, which `serve` already logs and `config validate` prints. No extra log call was added to startup.rs.
5. **Files in files_modified that were not touched:** `admin-ui/src/api/schema.d.ts` (it regenerated identically).

## Not run here

- Postgres contract suite (testcontainers/Docker): the crate builds all targets and its lib `pending` tests pass. The 45 new tests will fail with Unsupported there too until 06-08.
- No e2e: this plan has no UI.

## Self-Check: PASSED

- FOUND: crates/anvil-storage-sqlite/src/pending.rs, crates/anvil-storage-postgres/src/pending.rs, crates/anvil-storage/src/contract/{orgs,org_invitations,org_domains}.rs, crates/anvilid/tests/config_phase6.rs, crates/anvil-web/src/adapters/{dns_txt,saml_xml}.rs, crates/anvil-web/src/ui/saml.rs
- FOUND commits: 840ea00, a87fe1b, 48d3eb5
