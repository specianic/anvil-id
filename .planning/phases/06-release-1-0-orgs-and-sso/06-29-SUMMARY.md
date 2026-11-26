---
phase: 06-release-1-0-orgs-and-sso
plan: 29
subsystem: admin-api, admin-console
tags: [organizations, users, openapi, console, gap-closure]
requires: ["06-12", "06-17", "06-21", "06-23", "06-24", "06-25"]
provides:
  - "GET /tenants/{slug}/users/{user_id}/organizations (listUserOrganizations)"
  - "GET /tenants/{slug}/users?email= (listUsers email lookup)"
  - "console user page and add-member-by-email on one request each"
  - "tenant connection page on the shared SecretRotation"
affects: ["06-26 (security test map)", "06-31 (docs for these endpoints)"]
tech-stack:
  added: []
  patterns:
    - "A route readable by either of two resources: try the users scope, then the organizations scope, return the first error"
    - "A per-endpoint query DTO (UserListQuery) instead of widening the shared ListQuery"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/organization.rs
    - crates/anvil-core/src/service/user.rs
    - crates/anvil-web/src/admin/organizations.rs
    - crates/anvil-web/src/admin/users.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/src/admin/mod.rs
    - crates/anvil-web/tests/admin_orgs.rs
    - crates/anvil-web/tests/admin_api.rs
    - crates/anvil-web/tests/security_admin_v10.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - admin-ui/src/routes/t/$tenant/users/$userId.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/members.tsx
    - admin-ui/src/routes/t/$tenant/connections/$connectionId.tsx
    - tests/e2e/specs/console-orgs.spec.ts
    - tests/e2e/specs/console-connections.spec.ts
decisions:
  - "listUserOrganizations accepts the users or the organizations read scope (admin:users:read|write, admin:organizations:read|write, admin:read|write)"
  - "An org admin token on these tenant routes gets 401 (the tenant extractor accepts only system tokens), the same answer as every other tenant route, not 403"
  - "Add member by email keeps accepting a pasted user id directly; that path is a separate feature, not the old cap fallback"
metrics:
  duration: "about 50 min"
  completed: 2026-11-26
---

# Phase 6 Plan 29: Per-user organizations, listUsers ?email=, console on them, one SecretRotation Summary

**The admin API now has two lookups. `GET /tenants/{slug}/users/{user_id}/organizations` returns a user's memberships, each with the user's roles in that org. `GET /tenants/{slug}/users?email=` finds one user by normalised address. The console's user page and its "add member by email" now each make one request; before, they fanned out over every organization or paged through up to 10 000 users. The tenant connection page uses the shared `SecretRotation`, so the console has one implementation of secret rotation.**

No requirement checkbox was ticked (shared rule). ADM-02 and ORG-02 are served by this plan's endpoints and console changes.

## New endpoints (for 06-31's docs)

| Path | Operation id | Tag | Scopes (any one) | Answers |
|---|---|---|---|---|
| `GET /api/admin/v1/tenants/{slug}/users/{user_id}/organizations` | `listUserOrganizations` | organizations | `admin:users:read`, `admin:users:write`, `admin:organizations:read`, `admin:organizations:write`, `admin:read`, `admin:write` | 200 `UserOrganizationList { items: [UserOrganizationView { organization: OrganizationView, roles: [OrgRoleView] }] }`, sorted by org slug, not paged. 404 for an unknown tenant, an unknown user, a non-UUID id or a user of another tenant. The system tenant has no orgs, so a system user gets `items: []`. 401 without a token, and also for an org admin token. 403 with no matching scope. |
| `GET /api/admin/v1/tenants/{slug}/users?email=` | `listUsers` (new query param) | users | as listUsers: `admin:users:read\|write`, `admin:read\|write` | 200 `UserList` with 0 or 1 items and `next_cursor: null`. The address is trimmed and lowercased (`normalize_email`) before comparing. A malformed address gets 422 on field `email`. `email` together with `after` gets 422 on field `after`. `limit` is still validated (1-200). |

How it works:
- **Core:** `OrgService::memberships_of_user(tenant, user)` checks that the user exists (otherwise `NotFound`). It then calls `OrgRepo::memberships_of_user` once, and for each org it uses the private `roles_in_org`. That is the same `roles_for_user_in_org` lookup `member_roles` now calls, so there is one role-resolution path. `UserService::find_by_email(tenant, raw)` runs `normalize_email` and then `UserRepo::get_by_email`.
- **Web:** `UserListQuery { after, limit, email }` belongs to `list_users` alone; the shared `ListQuery` is unchanged. The new handler sits in `admin/organizations.rs` and is registered in `admin/mod.rs` next to the user routes. The OpenAPI document went from 122 to 123 operations.

## Negative / security tests (for the 06-26 map)

`crates/anvil-web/tests/security_admin_v10.rs`:
- `org_admin_token_refused_for_user_organizations`: an org admin's token gets 401 for its own memberships and for a peer member's.
- `org_admin_token_refused_for_user_email_lookup`: 401, and the body does not contain the user id.
- `user_organizations_requires_users_or_admin_read_scope`:
  - no token gets 401 with `WWW-Authenticate`;
  - `admin:clients:read`, and clients/settings/sessions write, each get 403, and the body leaks no org;
  - each of the six granted scopes gets 200.
- `user_email_lookup_requires_users_read_scope`: `admin:clients:read` and `admin:organizations:write` each get 403 with no email leaked; `admin:users:read` gets 200.

`crates/anvil-web/tests/admin_orgs.rs`:
- `user_organizations_lists_memberships_with_roles`:
  - the orgs come back in slug order and the non-member org is absent;
  - the roles are an org role plus a tenant role assigned in the org, with their scopes, and a member with no roles gets `[]`;
  - the organizations read scope also works.
- `user_organizations_empty_for_user_without_memberships`
- `user_organizations_unknown_or_foreign_user_is_404`: a random id, a non-UUID, another tenant's user and an unknown tenant each get 404. The same user is found through their own tenant.

`crates/anvil-web/tests/admin_api.rs`:
- `list_users_email_filter_returns_the_user`: ` Alice@Example.COM` (padded, mixed case) finds alice@example.com, and `next_cursor` is null.
- `list_users_email_filter_unknown_returns_empty_page`
- `list_users_email_filter_rejects_malformed_and_after`: four malformed addresses get 422 on `email`; `email` + `after` gets 422 on `after`.

## Console changes

- **`users/$userId.tsx`:** `fetchMemberships` is one call to `GET …/users/{user_id}/organizations`. `MAX_ORG_PAGES`, the per-org `members/{id}/roles` scan and the truncation note are gone. The card markup, the test id `user-organizations`, the links and the "No roles" / "Roles: …" text are unchanged.
- **`organizations/$orgId/members.tsx`:** "Add member by email" makes one `listUsers` request with `query.email`.
  - An empty result keeps the existing "No user of this tenant has this email." next to the field.
  - The API's 422 `email` error is shown next to the field.
  - `USER_PAGE`, `MAX_USER_PAGES`, the paging loop and the "Not found among the first 10000 users, enter the id" fallback are removed.
  - The user-id path stays. A pasted UUID was always accepted directly and the field hint offers it ("The email (or id)"), so it is a separate feature, not the cap fallback.
- **`connections/$connectionId.tsx`:** `SecretCard` and its state, mutation, file input and confirm dialog are deleted. A thin `ConnectionSecret` card renders `SecretRotation` with these props:
  - `kind` is `connection.kind` and `configured` is `connection.secret_configured`;
  - `put` is the same tenant `PUT …/connections/{id}/secret` call;
  - `onSaved` makes the same `setQueryData` and `["connections"]` invalidation.
  
  The test ids and texts are the same as the shared component's (`connection-secret-status`, `connection-secret-input`, `rotate-connection-secret`, "Remove secret"), so no ids changed.
- **e2e `console-orgs.spec.ts`:** it records the admin API GETs the page sends.
  - "Add member" sends exactly one `?email=` request per attempt (unknown, malformed, then the member in upper case) and never a request with `after`. The malformed address shows the API's message.
  - The user page card makes exactly one `/users/{id}/organizations` request, with no `/members/{id}/roles` and no organizations-list request.
- **e2e `console-connections.spec.ts`:**
  - It now runs in a fresh tenant from `setUpConsoleTenant` (signed in with `createConsoleAdmin`), deleted in `afterAll`. The redirect URI is expected under `tenantIssuer(slug)`.
  - A new step removes the secret after confirming: the status becomes "Not set", the Remove button disappears, the API reports `secret_configured: false`, and the secret is then set again.

## Task Commits

1. Task 1, API: listUserOrganizations, listUsers `?email=`, tests, OpenAPI and schema.d.ts: `c22852f` (feat)
2. Task 2, console pages and e2e specs: `5445400` (feat)

## Verification

- `cargo test -p anvil-web --test admin_orgs --test admin_api --test security_admin_v10 --test openapi_drift`: 10 + 12 + 26 + 3 passed.
- `cargo test -p anvil-core --lib service::organization`: 8 passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. `rustfmt --edition 2024 --check` on my files: clean.
- `UPDATE_OPENAPI=1 … openapi_drift` and then the plain drift test: green. `cd admin-ui && npm run gen:api && npm run check:api && npm run typecheck && npm run build`: green. `routeTree.gen.ts` is unchanged (no new routes) and the tree stays clean after the build.
- `! grep MAX_ORG_PAGES|function SecretCard` in the two pages, and `SecretRotation` is present in the connection page.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK.
- **Local browser e2e without Docker (SQLite):** I built `cargo build -p anvilid` (debug, main tree) and ran it from a scratch copy with a fresh data dir and the run.sh flags (port 18229). `console-connections.spec.ts` and `console-orgs.spec.ts` **passed** (2/2). The instance was stopped and the scratch dir deleted.

## Not run

- `tests/e2e/run.sh sqlite|postgres` as written (it needs Docker for Mailpit and Postgres). Both specs are left for CI on both backends.
- `console-org-sso.spec.ts` (the other user of `SecretRotation`) was not re-run locally because it needs the mock DNS. Its component is unchanged.
- Postgres contract and integration tests (Docker).

## Deviations from Plan

### Auto-fixed / forced extras

1. **[Rule 3 - Blocking] `crates/anvil-web/tests/openapi_drift.rs`** (outside files_modified). It asserts the operation count, so I changed it from 122 to 123 for the new operation.
2. **[Plan assumption corrected] Org admin refusal is 401, not 403.** The plan's truth and behaviour list say an org-admin token on these routes is refused with 403. These are tenant-level routes under `AdminAuth`, which accepts only system-tenant tokens, so an org admin's token gets 401 before any scope check. That is the same answer `org_admin_token_refused_on_tenant_routes` (06-12) already asserts for `/users`. The tests assert 401. A missing scope still gets 403 (`user_organizations_requires_users_or_admin_read_scope`, `user_email_lookup_requires_users_read_scope`).
3. **DTO placement.** `UserOrganizationView` / `UserOrganizationList` live in `admin/organizations.rs` next to `OrganizationView` and `OrgRoleView`, which they compose. `UserListQuery` is in `dto.rs` as planned.
4. **Extra negative test** `user_email_lookup_requires_users_read_scope` (the plan named three security tests). The email lookup is a data-revealing query, so its scope refusal has a test of its own.
5. **console-connections.spec.ts moved to a fresh tenant** (it used `default`), following the console e2e rule, and gained the remove-secret step that the plan's "same visible behaviour" list names.

### Out of scope, noted

- `admin-ui/src/routes/t/$tenant/connections/index.tsx` still has its own `MAX_ORG_PAGES` loop. It pages the tenant's organizations to show the owning org's name on org connections. That is a different lookup that this plan's endpoints do not replace, and the file is not in this plan's files. It could use a `connection → organization` field on the connection list in a later release.

## Self-Check: PASSED
