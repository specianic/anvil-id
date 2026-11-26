---
phase: 06-release-1-0-orgs-and-sso
plan: 12
subsystem: admin-api
tags: [organizations, admin-api, org-admin, invitations, rbac, openapi, security]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-04 OrgRepo/RoleRepo org ports and AddMemberOutcome; 06-05 ORG_ADMIN_SCOPE and org policy; 06-07/06-08 SQLite/Postgres org storage (tenant-level role queries filter org_id IS NULL)"
provides:
  - "OrgService (orgs, members, org roles, in-org assignments, check_assignable, lockout guard, org_admin_principal)"
  - "OrgInvitationService::{create, list, revoke} (accept: 06-20)"
  - "Principal enum (SystemAdmin, OrgAdmin) on AdminAuth; OrgAdminAuth extractor for org sub-routes"
  - "AppState::{admin_orgs, admin_org_invitations, admin_api_resource}"
  - "19 operations under /api/admin/v1/tenants/{slug}/organizations (tag organizations)"
  - "client DTO field organization (off/optional/required)"
  - "test helpers create_org, add_member, create_role, org_admin_token(_with), admin_resource"
affects: [06-13, 06-15, 06-17, 06-20, 06-21, 06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "One verification path, two thin extractors: AdminAuth (system-only) and OrgAdminAuth (system or path-tenant org admin); AdminAuth::require refuses an org admin"
    - "Principal-dependent writes pass OrgActor into the service, so the lockout guard applies to org admins only"
    - "One role-eligibility function (check_assignable) for assignments, default roles and invitations"

key-files:
  created:
    - crates/anvil-web/tests/admin_orgs.rs
    - crates/anvil-web/tests/security_admin_v10.rs
  modified:
    - crates/anvil-core/src/service/organization.rs
    - crates/anvil-core/src/service/org_invitation.rs
    - crates/anvil-web/src/admin/organizations.rs
    - crates/anvil-web/src/admin/auth.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/tests/admin_support/mod.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "Org-admin failures: token not for this API (opaque, wrong tenant/issuer, aud without the admin resource, client gone or no longer allowed the resource, family revoked or bound to another org/user) -> 401 invalid_token; valid token but not an org admin of this org (no org:admin scope, org_id claim != path org, unknown org, not a member, org:admin no longer held) -> 403 insufficient_scope"
  - "Org-admin tokens must come from the tenant's canonical issuer (custom host, public URL for default, else /t/{slug})"
  - "The org_id claim is checked AND the family's server-side org_id must equal the path org"
  - "POST /{org}/members answers {user_id, added} (201 added, 200 already a member) instead of a member view"
  - "Invitations and default roles name roles by id; assignments by name with ?scope=org|tenant (absent: org-owned role first, tenant role fallback)"
  - "Org-owned role create/update/delete audit as role_created/updated/deleted with the org in the details (no org-role audit actions exist)"
  - "The invitation email is enqueued right after create_invitation commits (the port takes no email); an enqueue failure revokes the invitation again and returns the error"

requirements-completed: []

duration: ~75min
completed: 2026-11-26
---

# Phase 6 Plan 12: Organization admin API and the Q1 org-admin principal Summary

**Tenant admins can now create organizations, add members, define org roles, assign tenant and org roles within an org, and send invitations on the management API. An org admin can manage only their own org, using a JWT from their own tenant that carries `org:admin`, a matching `org_id` and the admin-API audience. The extractor re-checks membership and the `org:admin` permission on every request. A last-org-admin lockout guard stops an org admin from locking the org out; a tenant admin can still make that change, which is the recovery path.**

Requirements: ORG-02 and ORG-03 (the organization-admin part) are implemented. Nothing is ticked: only the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 75 min (reading, then commits at 12:00, 12:24 and 12:25 +01:00)
- **Tasks:** 3/3
- **Files:** 2 created, 9 modified

## Task Commits

1. **Task 1, OrgService and OrgInvitationService (core):** `ddcddfe` (feat)
2. **Task 2, admin routes, principal, client organization DTO, OpenAPI and console types:** `7ad6464` (feat)
3. **Task 3, integration and security tests plus admin_support helpers:** `4ad3b9a` (test)

## Routes (`/api/admin/v1/tenants/{slug}/organizations`, tag `organizations`)

| Route | System admin scope | Org admin of `{org}` |
|---|---|---|
| `GET /`, `POST /` | organizations read / write (create returns 422 in `system`) | refused (401: these routes use the system-only extractor) |
| `GET /{org}` (`{org}` is an id or a slug) | read | yes |
| `PATCH /{org}`, `DELETE /{org}` | write | 403 |
| `GET /{org}/members` | read | yes |
| `POST /{org}/members` `{user_id, role_ids}` | write | **403** (org admins invite instead) |
| `DELETE /{org}/members/{user_id}` | write | yes, with the lockout guard |
| `GET /{org}/members/{user_id}/roles` | read | yes |
| `PUT\|DELETE /{org}/members/{user_id}/roles/{role}?scope=org\|tenant` | write | yes; DELETE has the lockout guard |
| `GET\|POST /{org}/roles`, `GET\|PATCH\|DELETE /{org}/roles/{name}` | read / write | yes; PATCH that drops `org:admin` and DELETE have the lockout guard |
| `GET /{org}/invitations?include_closed=`, `POST /{org}/invitations`, `DELETE /{org}/invitations/{id}` | read / write | yes |

"Read" means `admin:organizations:read`, `admin:organizations:write`, `admin:read` or `admin:write`. "Write" means `admin:organizations:write` or `admin:write`.

DTOs: `OrganizationView` (id, slug, display_name, mfa_policy, default_role_ids, metadata, timestamps), `MemberView` (user_id, email, created_at), `MemberAdded`, `OrgRoleView` (it adds `scope` org/tenant), `OrgAssignmentView`, and `InvitationView` (id, email, role_ids, status open/accepted/revoked/expired, timestamps). No view has a token or hash field. The client create/update/view DTOs gain `organization` (`off`/`optional`/`required`). The service rule (for example, `off` only in `system`) is the existing ClientService check, which 06-15 owns.

The OpenAPI document went from 83 to 102 operations. `schema.d.ts` was regenerated, and `npm run check:api` and `npm run typecheck` pass.

## Principal rules (crates/anvil-web/src/admin/auth.rs)

- `Principal { SystemAdmin, OrgAdmin { tenant, org, user } }` lives on `AdminAuth`.
  - The `AdminAuth` extractor accepts only system-tenant tokens, as before. Every tenant-level and installation route uses it, so an org-admin token gets 401 on all of them.
  - `AdminAuth::require` and `require_full_admin` also refuse an `OrgAdmin` principal, as defence in depth.
- `OrgAdminAuth` covers every `{org}` sub-route.
  - It first tries the system-token path. On `invalid_token` it then tries the path tenant:
    - opaque tokens are refused (401), and so is the `system` slug;
    - the token is verified with the same `AccessTokenVerifier` against `admin_issuer_of(tenant)`;
    - `aud` must contain `{public_url}/api/admin/v1`;
    - the client must still exist and still list that resource in `allowed_resources`.
  - It then calls `OrgService::org_admin_principal`, which checks:
    - the `org:admin` scope;
    - the org is resolved by id or slug, and the `org_id` claim equals it (an unknown org also gets 403, so other orgs are not revealed);
    - a live family whose `client_id`, `user_id` (= `sub`) and `org_id` match;
    - the user is active, still a member, and `roles_for_user_in_org` still grants `org:admin`.
- `org_actor()` returns `OrgActor::TenantAdmin(AuditActor::admin(sub))` or `OrgActor::OrgAdmin(user)`. Org-admin changes are audited as `AuditActor::user(user)`.
- Org admins need a JWT access-token client that is allowed the admin API resource. Opaque tokens are refused and documented. Real issuance (`resource` + `org:admin` bounding) is 06-13's work.

## Core (crates/anvil-core/src/service/)

- **`OrgService { storage, clock }`**
  - Org CRUD: `create`, `get` (canonical UUID first, then slug), `list`, `update`, `delete`.
  - Members: `add_member` (handles `AddMemberOutcome`), `remove_member`, `list_members` (with email), `member_roles`.
  - Org roles: `list_roles`, `get_role`, `resolve_role`, `create_role`, `update_role`, `delete_role`.
  - Assignments: `assign`, `unassign`, plus `assignable_role_by_id`.
  - Principal: `org_admin_principal`.
  - Pure helpers: `refuse_system_tenant`, `validate_display_name`, `validate_metadata`, `refuse_admin_permissions`, `check_assignable(org, role)` (another org's role → NotFound, an `admin:*` permission → Validation `role`), `grants_org_admin`, `holds_org_admin_after`.
- **Lockout guard (`guard_lockout`):**
  - Org-admin actors only.
  - Fast path: a change to a single user passes when `org_holders_of_permission >= 2`.
  - Otherwise it walks the members until it finds an active member who still holds `org:admin` after the change. If there is none, it returns `Conflict("the organization would have no org admin")`.
  - It reads and then writes, the same race as the tenant last-admin guard. The recovery path is a tenant admin.
- **`OrgInvitationService { storage, clock, kek }`**
  - `create`:
    - normalises the email and dedupes the roles (at most 20), each passing `check_assignable`;
    - generates a `random_token()` (32 bytes) and stores only `SecretHash(sha256)`;
    - sets `expires_at = now + ORG_INVITATION_TTL` (7 days);
    - seals an `org_invitation` email whose payload holds `tenant_name`, `org_name`, `email`, `inviter`, `link = {issuer}/ui/invitation?token=…` and `expires_in`;
    - never looks up an account.
  - `list` and `revoke`. `accept` is left to 06-20.

## Negative / security tests (crates/anvil-web/tests/security_admin_v10.rs, 21 tests)

`v10_admin_routes_require_scopes` (19 operations: no token → 401 with `WWW-Authenticate`, another resource's scope → 403, read scope on writes → 403), `org_create_refused_in_system_tenant`, `org_role_with_admin_permission_refused`, `org_admin_token_manages_own_org`, `org_admin_token_refused_for_other_org`, `org_admin_token_refused_for_other_tenant`, `org_admin_token_refused_on_tenant_routes`, `org_admin_token_refused_on_installation_routes`, `org_admin_token_without_org_admin_scope_refused`, `org_admin_token_with_mismatched_org_id_refused`, `org_admin_token_refused_after_membership_removed`, `org_admin_opaque_token_refused`, `org_admin_cannot_add_member_directly`, `org_admin_invitation_with_foreign_or_admin_role_refused`, `org_admin_token_refused_after_org_admin_permission_removed`, `org_admin_token_without_admin_api_audience_refused`, `org_admin_cannot_remove_last_org_admin`, `org_admin_cannot_demote_last_org_admin` (unassign, role edit and role delete each return 409), `tenant_admin_can_remove_last_org_admin`, `invitation_response_identical_for_known_and_unknown_email`, `invitation_list_never_exposes_token_or_hash`.

`admin_orgs.rs` (7 tests): `org_crud_round_trip`, `members_add_list_remove`, `org_roles_crud`, `assignments_of_tenant_and_org_roles_within_the_org`, `removing_a_member_revokes_only_their_org_bound_tokens` (the org-bound refresh gets `invalid_grant` while the org-less refresh still gets 200), `invitations_create_list_revoke` (hash only, 7 days, sealed `org_invitation` email in the outbox), `org_changes_are_audited_and_webhook_classified`.

These names need to go into `scripts/check-security-tests.sh` at the gate (06-26).

### Mutation checks (guard removed, then restored)

Six guards were disabled together in one build, and `security_admin_v10` was run against it. Each targeted test failed: 8 failed and 13 passed. Each guard is independent and only loosens access, so every failure traces back to its own guard:

| Guard disabled | Test that failed |
|---|---|
| `aud` contains the admin resource (auth.rs) | `org_admin_token_without_admin_api_audience_refused` |
| `org_id` claim == path org (organization.rs) | `org_admin_token_with_mismatched_org_id_refused` (and `..._refused_for_other_org`: 401 instead of 403) |
| lockout guard on `remove_member` | `org_admin_cannot_remove_last_org_admin` |
| `require_system_admin` on `POST /members` | `org_admin_cannot_add_member_directly` |
| `roles_for_user_in_org` still grants `org:admin` | `org_admin_token_refused_after_org_admin_permission_removed` |
| `admin:*` check in `check_assignable` | `org_admin_invitation_with_foreign_or_admin_role_refused`, `org_role_with_admin_permission_refused` |

After the files were restored from backup, all 21 tests passed again.

## Deferred: tenant-restricted system admins (Q1, second half)

These are **not delivered here and are deferred to Phase 7.** System roles with a tenant list (an `admin_tenants` claim) need a second principal shape. It would have to be checked on every existing tenant-level and installation route (users, clients, connections, roles, keys, audit, config, webhooks, ...), and 06-CONTEXT Q1 says to include it only if it fits without a second authorization path. The Principal enum added here is where that variant would go.

## Deviations from Plan

1. **[Rule 3 - Blocking] `crates/anvil-web/tests/openapi_drift.rs`: the operation count went from 83 to 102.** This file is outside files_modified. The plan's own verify step runs `openapi_drift`, which counts operations.
2. **[Interpretation] `OrgService` has no `kek` field.** Nothing in it seals. Only `OrgInvitationService` holds the KEK.
3. **[Interpretation] Email enqueue after commit.** `OrgRepo::create_invitation` takes no `NewEmail`, so the email is enqueued right after the invitation is stored, as the plan allows. If enqueueing fails, the invitation is revoked again.
4. **[Interface] `POST /{org}/members` returns `MemberAdded {user_id, added}`.** No storage method reads back a single membership.
5. **[Addition] `default_role_ids` on PATCH org** (validated by `check_assignable`), because 06-14's JIT reads `OrgSettings.default_role_ids`. Org create takes no default roles: org-owned roles cannot exist before the org does.
6. **[Addition] Defence-in-depth checks in the extractor:** the org-admin client must still list the admin resource in `allowed_resources`, and the family's server-side `org_id` must match as well as the claim.
7. **Not touched:** `crates/anvil-web/src/admin/clients.rs`. The `organization` field flows through `dto.rs::into_parts`, so no change was needed.
8. **[Interpretation] Key link `ORG_ADMIN_SCOPE`:** the scope check lives in `OrgService::org_admin_principal`, which auth.rs calls, not in auth.rs itself. That keeps every storage-backed check in core.
9. **[Process] TDD:** each task was committed as one commit (no separate RED commit), as in 06-05, because peers build the same tree.

## Open items for later plans

- The org claim mapping rules (`org_roles` / `org_permissions`) are still not on the tenant-settings DTO, which lives in `admin/tenants.rs` (not owned here; see deferred-items).
- 06-13: real org-admin token issuance must put `{public_url}/api/admin/v1` in `aud` when the client requests it as `resource`, and must use the canonical issuer.
- 06-17: the connections, domains and branding sub-routes should take `OrgAdminAuth` and call `org_for(…)` (same module), and use `auth.org_actor()` for audit.
- 06-25: document the recovery path (a tenant admin re-adds or re-assigns an org admin) and the 401/403 split above.

## Verification

- `cargo build -p anvil-core --all-targets`; `cargo test -p anvil-core --lib`: 964 passed, including 11 new unit tests; `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean
- `cargo build -p anvil-web --all-targets`; `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean
- `cargo test -p anvil-web --test admin_orgs --test security_admin_v10`: 7 + 21 passed (SQLite)
- Regression: `security_admin`, `admin_api`, `admin_api_v02`, `admin_roles`, `security_admin_v04`, `console`, `openapi_drift`: all green
- `cd admin-ui && npm run gen:api && npm run check:api && npm run typecheck`: up to date, no errors
- `scripts/check-release-graph.sh`: OK

## Not run here

- Postgres variant of the tests (needs Docker/testcontainers): left for CI.
- `scripts/check-security-tests.sh`: not run, because the new names are mapped at the gate.
- No e2e: this plan has no UI.

## Self-Check: PASSED

- FOUND: crates/anvil-web/tests/admin_orgs.rs, crates/anvil-web/tests/security_admin_v10.rs, crates/anvil-core/src/service/organization.rs (`pub struct OrgService`), crates/anvil-web/src/admin/auth.rs (`OrgAdmin`), security_admin_v10.rs (`org_admin_token_refused_for_other_org`)
- FOUND commits: ddcddfe, 7ad6464, 4ad3b9a
