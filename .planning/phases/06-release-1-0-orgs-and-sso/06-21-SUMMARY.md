---
phase: 06-release-1-0-orgs-and-sso
plan: 21
subsystem: admin-console
tags: [console, organizations, members, invitations, org-roles, react, tanstack-router, e2e, axe, ADM-02, ORG-02]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-12 org admin API (19 operations, OrganizationView/MemberView/OrgRoleView/InvitationView, client `organization` DTO field) and regenerated schema.d.ts; 06-16 console-v10.ts helpers"
provides:
  - "Console Organizations section: /t/$tenant/organizations (list), /new, /$orgId layout with Overview, Members, Invitations, Roles"
  - "Organizations entry in TENANT_PAGES (after Users)"
  - "OrgForm (org + org role forms, useOrganization/orgQueryKey) and OrgRoleAssignments (useAssignableRoles, useOrgRoles, RolePicker, ScopeBadge, per-member assignment panel)"
  - "User page Overview: Organizations card with links to each org"
  - "Client form: organization policy select (off/optional/required) with per-value help; client details show it"
  - "tests/e2e/specs/console-orgs.spec.ts and org helpers in tests/e2e/lib/console-v10.ts"
affects: [06-23, 06-24, 06-26]

tech-stack:
  added: []
  patterns:
    - "Nested detail layout: organizations/$orgId.tsx renders heading + a section <nav> of Links (aria-current) + Outlet; later sections add sibling files and an ORG_SECTIONS entry"
    - "Roles inside an org are addressed as `{scope}:{name}` (select option values, data-role on checkboxes), matching the API's `?scope=` addressing"
    - "Roles carrying admin permissions are filtered from org pickers (the API refuses them anyway); the org role form refuses them client-side"

key-files:
  created:
    - admin-ui/src/routes/t/$tenant/organizations/index.tsx
    - admin-ui/src/routes/t/$tenant/organizations/new.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/index.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/members.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/invitations.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/roles.tsx
    - admin-ui/src/components/OrgForm.tsx
    - admin-ui/src/components/OrgRoleAssignments.tsx
    - tests/e2e/specs/console-orgs.spec.ts
  modified:
    - admin-ui/src/lib/tenant.ts
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/routes/t/$tenant/clients/$clientId.tsx
    - admin-ui/src/routes/t/$tenant/users/$userId.tsx
    - tests/e2e/lib/console-v10.ts

key-decisions:
  - "Section navigation in the org layout is route links with aria-current, not ARIA tabs: each section is its own URL (deep-linkable, 06-23 adds siblings)"
  - "Member roles are managed in a side dialog per member (Roles of {email}); tenant and org roles are both offered, each with a scope badge"
  - "Add member accepts an email (looked up through the paged users list) or a user id; unknown emails are a field error, not a request"
  - "User memberships are computed client-side (orgs list + member-roles per org, 404 = not a member) because the API has no per-user membership list; logged as a deferred API gap"
  - "Invitations list shows open and expired by default with an 'accepted and revoked' toggle (the API's include_closed); 'open' is labelled Pending; no token or link is ever rendered"
  - "Default roles for JIT members are edited on the Overview only after the org exists (org roles cannot predate the org; create takes none)"
  - "The system tenant shows an explanatory notice instead of the list (the API refuses orgs there); the client form hides the organization select in the system tenant (policy must stay off)"

requirements-completed: [ADM-02, ORG-02]

duration: ~45min
completed: 2026-11-26
---

# Phase 6 Plan 21: Console organizations Summary

**Tenant admins can now manage organizations from the console. They list, create, edit and delete organizations (slug, display name, MFA policy, default roles). They add and remove members by email, define org roles, and give members tenant or org roles within the org. They send, list and revoke invitations, and no token is ever shown. A user's page lists their memberships, and a client's page sets its organization policy. Every call goes through the 06-12 API using the openapi-typed client.**

No requirement checkbox was ticked (shared rule). ADM-02 and ORG-02 above are the console halves.

## Pages and test ids

| Route | What | Test ids |
|---|---|---|
| `/t/$tenant/organizations` | list (cursor paged); system tenant notice | `new-org`, `open-org-{slug}`, `orgs-system-tenant` |
| `/t/$tenant/organizations/new` | create | `org-form`, `org-display-name`, `org-slug`, `org-mfa-policy`, `org-submit` |
| `/organizations/$orgId` (layout) | heading, slug, nav "Organization sections" (Overview, Members, Invitations, Roles) | `org-not-found` |
| `/organizations/$orgId` (index) | settings incl. default roles; delete with confirm | `org-default-roles`, `delete-org` |
| `/organizations/$orgId/members` | members table, add by email with roles, "Roles of {email}" side dialog, "Remove {email}" confirm | `add-member-form`, `add-member-email`, `add-member-roles`, `add-member`, `member-{email}`, `org-role-assignments`, `org-assign-role-select` (values `org:{name}`/`tenant:{name}`), `org-assign-role`, `member-role-{name}`, `role-scope` |
| `/organizations/$orgId/invitations` | invite (email + roles), list status/roles/sent/expiry, revoke confirm, closed toggle | `invite-form`, `invite-email`, `invite-roles` (checkbox `data-role`), `send-invitation`, `invitations-include-closed`, `invitation-row` (`data-email`, `data-status`), `invitation-status` |
| `/organizations/$orgId/roles` | org roles; create/edit dialog; delete confirm | `new-org-role`, `org-role-form`, `org-role-name`, `org-role-permissions`, `org-role-submit`, `org-role-{name}` |
| `/t/$tenant/users/$userId` (Overview) | Organizations card | `user-organizations` |
| `/t/$tenant/clients/$clientId` | organization policy select / detail | `client-organization-policy`, `client-organization` |

The pages use no inline styles, only Tailwind classes and the existing components (console CSP). Every list and mutation error is shown through ProblemAlert, and 422 field errors appear next to their fields.

## Task Commits

1. Task 1, organizations section, user memberships and client policy: `1f22b3e` (feat)
2. Task 2, console organizations e2e with axe: `518899a` (test)

## Verification

- `cd admin-ui && npm run typecheck && npm run build && npm run check:api`: green. `schema.d.ts` is unchanged and up to date (not regenerated here; 06-17 owns it this wave). `routeTree.gen.ts` is committed, and a second build leaves the tree clean.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK.
- **Local browser e2e without Docker (SQLite):**
  - Setup: `cargo build -p anvilid` (debug, main tree) built cleanly against the current tree. The binary was hardlinked into a scratch dir and run with a fresh data dir and the run.sh flags (port 18221, `--breach-check off`, auth budget 1200/min). The debug rust-embed build serves the fresh `admin-ui/dist`. Tests ran in Playwright chromium.
  - `console-orgs.spec.ts`: **passed** (twice).
  - Regression: `console-tenants`, `console-keys`, `console-roles`, `theme`, `console-connections` and `console-registration` **passed**.
  - `console.spec.ts` passed every step until its SMTP test send, which failed only because Mailpit (Docker) was not running ("Connection refused"). This is the same known limit noted in 05-24.
  - The instance was stopped and the scratch dir deleted.

## Not run

- `tests/e2e/run.sh sqlite specs/console-orgs.spec.ts` as written: it needs Docker for Mailpit, and the shared rules say not to depend on Docker. The Postgres variant is also left for CI.
- Invitation email delivery: the plan leaves this to 06-24's invitations spec (the 06-20 template lands this wave).

## Deviations from Plan

### Auto-fixed / interpretation

1. **[Rule 2 - API gap, console-side] User memberships.** The API has no per-user membership list. The "Organizations" card lists the tenant's orgs (up to 10 pages of 200) and calls `GET …/{org}/members/{user_id}/roles` for each, where a 404 means not a member. It also shows the roles the user holds in each org. This is logged in deferred-items.md as a suggested `GET /users/{id}/organizations` endpoint.
2. **[Rule 2 - API gap, console-side] Member lookup by email.** `listUsers` has no email filter, so the lookup pages through users (200 per page, up to 10 000). Past that it asks for the user id, and a user id is accepted directly. This is logged in deferred-items.md as a suggested `?email=` filter.
3. **Org role permissions** are a space-separated text field in `OrgRoleForm` rather than RoleForm's tag input. `PermissionsInput` is private to RoleForm.tsx, which is outside this plan's files. The permission patterns and limits are imported from RoleForm, so there is one source for the rules.
4. **Default roles on create:** the create form explains that default roles can be chosen once the org exists. The API's create DTO takes none, because org roles cannot exist before the org.
5. **Extra helper in console-v10.ts:** `createOrg`, `findOrg`, `orgMemberRoles` and `orgInvitations`, plus the org test-id index in the header comment. That file is listed in files_modified.

No files outside files_modified were changed, except an appended section in the phase's `deferred-items.md`.

## Self-Check: PASSED

- FOUND: admin-ui/src/routes/t/$tenant/organizations/$orgId.tsx (contains `Outlet`), $orgId/invitations.tsx (`/organizations/{org}/invitations`), tests/e2e/specs/console-orgs.spec.ts (`createConsoleAdmin` via setUpConsoleTenant from console-v10/console-v04)
- FOUND commits: 1f22b3e, 518899a
