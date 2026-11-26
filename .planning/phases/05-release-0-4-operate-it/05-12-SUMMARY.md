---
phase: 05-release-0-4-operate-it
plan: 12
subsystem: rbac
tags: [rbac, roles, permissions, claims, admin-scopes, last-administrator, escalation, openapi, metrics]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 model/errors/audit actions, 05-02 RoleRepo/AttributeRepo ports and attribute_check fields, 05-06/05-07 role and attribute storage, 05-10 claims_mapping and JsonSchemaCheck, 05-05 metric names
provides:
  - RoleService (CRUD, assign/unassign, escalation and last-administrator guards, effective_admin_scopes)
  - UserClaimSource: roles/permissions/attributes into access tokens, ID tokens and UserInfo at code exchange and every refresh
  - System-tenant admin scopes bounded by the user's roles (decision Q3)
  - Last-administrator guard on unassign, role delete, role permission edit, user delete and user block
  - Role admin API (9 operations) and the tenant settings `claims` mapping
  - CoreError::RefreshTokenReuse on refresh reuse; anvil_tokens_issued_total{grant} and anvil_refresh_reuse_total
  - claims.rs uses the single policy::claims_mapping::RESERVED_CLAIMS list
affects: [05-17, 05-20, 05-23, 05-24, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Per-issuance claim source: UserClaimSource::load once, then claims(tenant, scope, target, check) per token"
    - "Refresh token keeps the full grant; the issued access-token scope is recomputed from roles at every exchange"
    - "Guards in the service, route rules in the handler: system role definitions need admin:write at the route, escalation and lockout checks live in RoleService/UserService"

key-files:
  created:
    - crates/anvil-web/tests/rbac_claims.rs
    - crates/anvil-web/tests/admin_roles.rs
    - crates/anvil-web/tests/security_rbac.rs
  modified:
    - crates/anvil-core/src/service/role.rs
    - crates/anvil-core/src/service/claims.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/src/service/userinfo.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-core/src/service/user.rs
    - crates/anvil-web/src/protocol/token.rs
    - crates/anvil-web/src/admin/roles.rs
    - crates/anvil-web/src/admin/tenants.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/src/admin/users.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "Admin scope bounding: admin scopes of a system-tenant user token = (what the requested scopes cover) ∩ (what the user's role permissions cover), written minimally. A user requesting admin:write whose role grants admin:read gets admin:read; no roles gives no admin scope. Non-admin scopes are unchanged."
  - "Only the issued access token and the response scope are bounded. The refresh token keeps the full grant, so restoring a role brings the admin scope back at the next refresh."
  - "System-tenant role definition writes need admin:write at the route (same rule as system clients and connections). Assignments use admin:users:write plus the service escalation check, which also applies to unassign: a caller cannot take away a role carrying admin scopes it does not hold."
  - "The last-administrator check counts active users holding admin:write through any role, after the change. It walks the holders of each admin:write role and stops at the first match. It reads and then writes without a transaction; `anvilid admin recover` (05-17) is the escape hatch."
  - "UserService::update runs the guard only when the patch sets a non-active status. The guard looks the tenant up by id because UserService takes a TenantId; no new fields were added."
  - "ID token extras drop every reserved claim (RESERVED_CLAIMS) that is not a standard user claim. Requested standard claims (`claims.id_token`) still pass. Access-token extras drop every reserved claim."
  - "Role path parameter is the role name; the user path parameter is `{user_id}`, matching users.rs and sessions.rs. Different names at the same segment would conflict in the router."
  - "The tenant settings patch merges `claims` field by field: an absent rule keeps the current one, and null disables it."

patterns-established:
  - "Lockout and escalation tests are checked by removing each guard (mutation) and seeing the named test fail"

requirements-completed: [ORG-05]

duration: ~35min
completed: 2026-11-26
---

# Phase 5 Plan 12: RBAC, role claims, admin scopes from roles, role admin API Summary

**Roles and permissions are managed through the admin API and reach tokens through the tenant's claim mapping. Custom attributes are included only when their stored value passes the current schema. Mapped claims are computed at code exchange, at every refresh and in UserInfo. In the system tenant, a user's roles decide which admin scopes the console token gets (Q3). The last `admin:write` holder cannot be removed by any path, and roles carrying admin scopes cannot be created, edited, assigned or unassigned beyond the caller's own scopes.**

## Performance

- **Duration:** about 35 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 8 in the Task 1 commit, 11 in the Task 2 commit

## Routes (all under `/api/admin/v1`, tag `roles`)

| Method and path | Scope | Notes |
|---|---|---|
| `GET /tenants/{slug}/roles` | admin:settings:read | name order |
| `POST /tenants/{slug}/roles` | admin:settings:write (system tenant: admin:write) | 201 with Location; 409 on a duplicate name; 422 on validation |
| `GET /tenants/{slug}/roles/{name}` | admin:settings:read | 404 for another tenant's role |
| `PATCH /tenants/{slug}/roles/{name}` | admin:settings:write (system tenant: admin:write) | rename, description, permissions; 409 on a duplicate name or LastAdministrator |
| `DELETE /tenants/{slug}/roles/{name}` | admin:settings:write (system tenant: admin:write) | cascades assignments; 409 on LastAdministrator |
| `GET /tenants/{slug}/roles/{name}/users` | admin:users:read | cursor pagination (`UserList`) |
| `GET /tenants/{slug}/users/{user_id}/roles` | admin:users:read | 404 for an unknown user |
| `PUT /tenants/{slug}/users/{user_id}/roles/{name}` | admin:users:write | idempotent; returns `AssignmentDto`; system tenant: 403 beyond the caller's admin scopes |
| `DELETE /tenants/{slug}/users/{user_id}/roles/{name}` | admin:users:write | 404 if not held; 403 beyond the caller's scopes; 409 on LastAdministrator |

DTOs are defined in roles.rs: RoleDto, RoleList, NewRoleDto, RolePatchDto, AssignmentDto. Tenant settings gain `claims` (`TokenClaimMapping` with `roles` and `permissions` rules, each `TokenClaimRule {claim, tokens, scope}`), and the patch type is `TokenClaimMappingPatch`. Both are in tenants.rs. User delete and update now document the 409.

## Claim rules (default mapping, from 05-01)

- `roles`: access token, ID token and UserInfo, gated by the `roles` scope.
- `permissions`: access token only, not gated.
- Attribute claims follow each definition's `claim` rule. A value is included only if `attribute_check` validates it against the current schema, so a value stored under an older schema is omitted. Without a check, attribute claims are omitted entirely.
- Mapped claims never override protocol or standard claims. `merge_access_token_extras` drops every reserved claim from access-token extras. ID-token extras drop reserved claims except standard user claims. UserInfo uses `entry().or_insert`.
- Client credentials tokens carry no role, permission or attribute claims.
- Claim mapping is validated with `validate_mapping` on tenant create and whenever it changes. A collision (for example `sub`, `email`, `Sub`, `iss`, `scope`, or roles and permissions sharing a claim) is a 422 on field `claim`.

## Q3 behaviour

- `effective_admin_scopes(tenant, roles)`: non-system tenants always get the empty set. In the system tenant, each role permission is expanded: admin:write covers every admin scope, admin:read covers every read scope, and admin:{r}:write also covers admin:{r}:read.
- `issued_scope` (token.rs) applies `bound_admin_scope` for system-tenant code and refresh exchanges. Client credentials grants are not affected (no user).
- Covered by tests: administrator role → `admin:write openid`; role [admin:read] requesting admin:write → `admin:read openid`; role [admin:users:read] → `admin:users:read openid`, which can read users but gets 403 on writes and on other resources; no roles → `openid`, and the admin API returns 403; removing the role and refreshing drops the scope, and restoring it brings the scope back.

## Security tests (security_rbac.rs)

`assigning_another_tenants_role_is_refused`, `assigning_to_another_tenants_user_is_refused`, `admin_scope_requires_role_permission`, `user_without_roles_gets_no_admin_scope`, `last_administrator_cannot_be_unassigned` (a blocked holder does not count), `last_administrator_role_cannot_be_deleted` (also covers the PATCH that drops admin:write), `role_routes_require_scopes`, `claim_mapping_collision_rejected` (PATCH and tenant create), `last_administrator_cannot_be_deleted`, `last_administrator_cannot_be_disabled`, `role_assignment_beyond_caller_scopes_is_refused` (assign, unassign, create, edit), `non_system_tenant_role_never_grants_admin_scopes`.

Unit tests in role.rs: `admin_write_covers_everything_and_read_covers_reads`, `non_system_roles_never_grant_admin_scopes`, `bound_admin_scope_intersects_with_roles`, `escalation_is_refused_beyond_the_callers_scopes`. In claims.rs: `id_token_extras_never_set_reserved_protocol_claims`, `access_token_extras_never_override_or_add_reserved_claims`.

### Mutation check (each guard removed, its test must fail)

Every one of the 12 mutations made its named test fail:

| Guard removed | Test that failed |
|---|---|
| assign escalation check | role_assignment_beyond_caller_scopes_is_refused |
| unassign escalation check | role_assignment_beyond_caller_scopes_is_refused |
| unassign last-admin check | last_administrator_cannot_be_unassigned |
| active-only holder filter | last_administrator_cannot_be_unassigned |
| role delete last-admin check | last_administrator_role_cannot_be_deleted |
| role permission-edit last-admin check | last_administrator_role_cannot_be_deleted |
| UserService::delete guard | last_administrator_cannot_be_deleted |
| UserService::update block guard | last_administrator_cannot_be_disabled |
| admin scope bounding in token.rs | admin_scope_requires_role_permission |
| validate_mapping in TenantService::update | claim_mapping_collision_rejected |
| system role definitions need admin:write (route) | role_routes_require_scopes |
| assign result check (cross-tenant user) | assigning_to_another_tenants_user_is_refused |

## Task Commits

1. **Task 1: RoleService, claims provider, admin-scope bounding, last-admin guard, metrics:** `c1382bf` (feat)
2. **Task 2: role admin API, tenant claim settings, OpenAPI, security tests:** `c0038d6` (feat)

## Verification run

- `cargo test -p anvil-core --lib`: 763 passed.
- `cargo test -p anvil-web --test rbac_claims` (9), `admin_roles` (6), `security_rbac` (12), `openapi_drift` (3) all passed. Also passed: `token`, `token_client_credentials`, `userinfo`, `console_client`, `security_refresh`, `security_userinfo`, `admin_api`, `admin_api_v02`, `admin_api_v03`, `security_admin`, `security_admin_v02`, `security_admin_v03`, `access_token_format`, `id_token_alg`, `resource_indicators`, `security_setup`, and `anvil-web --lib` (167).
- Metrics: `issuance_and_refresh_reuse_increment_the_token_counters` drives a real code exchange, a refresh and a reuse through `/token` under `metrics::set_default_local_recorder`.
- `cargo check --workspace --all-targets --locked`: OK. The only warning is the pre-existing unused `serde-saphyr` dependency in anvilid.
- `cargo clippy -p anvil-core -p anvil-web --lib --tests --locked`: no warnings in this plan's files.
- `rustfmt --edition 2024` on every touched Rust file.
- `just openapi-update` (UPDATE_OPENAPI=1) and `npm run gen:api` were run; `npm run check:api` reports the types are up to date.
- `grep -rn "fn mapped_claims" crates` finds only policy/claims_mapping.rs. `ID_TOKEN_PROTOCOL_CLAIMS` is gone, and `RESERVED_CLAIMS` is defined once.

## Not run / not green

- **`npm run typecheck` fails** in `admin-ui/src/routes/t/$tenant/audit/index.tsx`. The page's record of every audit action lacks the 24 actions added by 05-01 and `admin_recovery_issued`. This is pre-existing (05-12's regeneration adds no audit action) and is logged in deferred-items.md.
- The Postgres variant (`ANVILID_TEST_DB=postgres`) needs Docker and is left for CI.
- The full workspace test suite was not run (targeted runs only, per the shared rules).
- **One unexplained failure:** in one combined run of six test binaries, `last_administrator_cannot_be_unassigned` failed once on its first status assertion. It passed in more than 20 reruns afterwards: the test alone, the full binary 12 times, and the same six-binary combination 3 times. The guard is deterministic (an active-holder walk on a per-test database). Other plans were editing the shared tree at the same time. CI should watch for it.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The tenant settings DTOs live in dto.rs**
- The plan places the `claims` field in admin/tenants.rs, but `TenantSettings`, `NewTenantSettings` and `TenantSettingsPatch` are defined in dto.rs.
- The claim DTO types (`TokenTarget`, `TokenClaimRule`, `TokenClaimMapping`, `TokenClaimMappingPatch`) are defined in tenants.rs. dto.rs only gains the fields, the merge, and `pub(super)` on `double_option` and `ts`.
- **Forced extra file:** `crates/anvil-web/src/admin/dto.rs`. No wave-4 plan owns it.

**2. [Rule 3 - Blocking] openapi_drift.rs hardcodes the operation count**
- Changed 51 to 60 for the 9 new role operations. **Forced extra file:** `crates/anvil-web/tests/openapi_drift.rs`.

**3. [Rule 2 - Correctness] Document the 409 on user delete and update**
- The new guard makes these routes return 409 LastAdministrator. Their OpenAPI responses now say so (doc attributes only). **Forced extra file:** `crates/anvil-web/src/admin/users.rs`.

**4. [Rule 2 - Security] Unassign also runs the escalation check**
- The plan names create, edit and assign. Without the check on unassign, an `admin:users:write` caller could strip administrators down to the last one. The check now covers unassign, and the escalation test exercises it.

**5. [Rule 1 - Bug avoided] `{user_id}` path parameter**
- The plan lists `/users/{id}/roles`. users.rs and sessions.rs use `{user_id}` at that segment, and mixing names at the same segment is a router conflict, so the routes use `{user_id}`.

**6. Metrics test placement**
- The plan suggests `metrics::with_local_recorder`. The test uses `set_default_local_recorder` in the rbac_claims integration test, so a real issuance and a real reuse go through `/token`. The single-threaded tokio test runtime keeps the handler on the recorder's thread. No `metrics-util` dependency was added.

**7. TDD order**
- Task 1 is marked tdd. The implementation and the tests landed in one commit rather than a separate RED commit. The security tests were instead checked by mutation (above), which is the stronger evidence that each guard rejects bad input.

### Notes
- `protocol/userinfo.rs` needed no change: its constructor already passes `attribute_check`.
- `UserInfoService`, `TokenService`, `UserService` and `TenantService` gained no fields.

## Self-Check: PASSED
- Files exist: role.rs, roles.rs, rbac_claims.rs, admin_roles.rs, security_rbac.rs, admin-v1.json, schema.d.ts.
- Commits c1382bf and c0038d6 are present in `git log`.
