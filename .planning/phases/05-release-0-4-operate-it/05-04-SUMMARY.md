---
phase: 05-release-0-4-operate-it
plan: 04
subsystem: admin-console
tags: [console, multi-tenant, tenant-switcher, tanstack-router, react, org-01, e2e]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "console pages and patterns (04-19 ProblemAlert/field errors/ConfirmDialog/secret refs, 04-22 branding editor), tenants admin API"
provides:
  - "Every tenant-scoped console page under /console/t/$tenant/... with useTenant() (lib/tenant.ts); no CONSOLE_TENANT"
  - "Tenant layout route: existence check, not-found panel, last-used tenant memory, per-tenant remount"
  - "TenantSwitcher in the header (keeps the section, marks the system tenant, All tenants link)"
  - "/console/tenants (slug, display name, issuer, host, discovery URL + copy, created) and /console/tenants/new"
  - "Delete tenant card on the tenant's Login settings page"
  - "Pre-0.4 deep links redirect to /console/t/default/... (remove in 0.5)"
  - "tests/e2e/specs/console-tenants.spec.ts"
affects: [05-23, 05-27]

tech-stack:
  added: []
  patterns:
    - "Tenant from the route: useTenant() = useParams({ from: '/t/$tenant' }); components outside tenant routes use useOptionalTenant()"
    - "The tenant layout wraps <Outlet/> in a Fragment keyed by slug, so switching tenants remounts pages and no form keeps another tenant's edits"
    - "BrandingScope carries its tenant ({ kind, tenant, clientId? }); module-level query keys became functions of the tenant"
    - "Issuer shown in the console = `issuer` of the tenant's discovery document (server-computed); host tenants add `{scheme}://{host}`"

key-files:
  created:
    - admin-ui/src/lib/tenant.ts
    - admin-ui/src/components/TenantSwitcher.tsx
    - admin-ui/src/routes/t/$tenant.tsx
    - admin-ui/src/routes/t/$tenant/index.tsx
    - admin-ui/src/routes/t/$tenant/** (moved pages)
    - admin-ui/src/routes/tenants/index.tsx
    - admin-ui/src/routes/tenants/new.tsx
    - tests/e2e/specs/console-tenants.spec.ts
  modified:
    - admin-ui/src/api/client.ts
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/components/ThemeEditor.tsx
    - admin-ui/src/components/ThemePreview.tsx
    - admin-ui/src/routes/index.tsx
    - admin-ui/src/routes/{users,clients,connections,sessions,audit,email,branding,settings}/** (now redirects)
    - admin-ui/src/routeTree.gen.ts
    - tests/e2e/lib/console.ts
    - tests/e2e/specs/console.spec.ts
    - tests/e2e/specs/console-connections.spec.ts

key-decisions:
  - "The tenant DTO has no issuer field: the console reads the issuer from the tenant's discovery document (no client-side public URL guess). 05-23 should expose `issuer` (and the host issuer) on TenantView"
  - "The default tenant's discovery URL and issuer are shown at the public URL root (TenantBase::Root), the one relying parties and the e2e helpers use; other tenants use /t/{slug}"
  - "Tenant switcher is a native <select> (keyboard and screen-reader friendly, axe-clean); switching keeps the current section and opens its list page"
  - "/console/ opens the last used tenant (sessionStorage, per tab) or `default`; a deleted or unknown tenant is forgotten"
  - "Create tenant sends only `registration` in settings (other NewTenantSettings fields take the API defaults; the generated type marks defaulted fields required, so the partial is cast with a comment)"
  - "Tenant deletion lives on the tenant's Login settings page; `system` and `default` show an undeletable note (the API refuses them with 403)"

requirements-completed: []

duration: about 75 min
completed: 2026-11-26
---

# Phase 5 Plan 04: Multi-tenant console Summary

**The console now manages any tenant. Every tenant page lives under `/console/t/{tenant}/…` and gets its tenant from the route, not from a constant. A header switcher moves between tenants and keeps the current section. Operators can list tenants with each tenant's issuer and copyable discovery URL, create tenants, and delete them from the tenant's settings page. Old links redirect to the default tenant.**

No requirement checkbox was ticked (shared rule). This is the ORG-01 console half.

## Route map (old -> new)
| Old (0.3) | New (0.4) | Old path now |
|---|---|---|
| `/` -> `/users` | `/` -> `/t/{last used or default}/users` | — |
| — | `/t/$tenant` -> `/t/$tenant/users` | — |
| `/users`, `/users/$userId?tab=` | `/t/$tenant/users`, `/t/$tenant/users/$userId?tab=` | redirect to `/t/default/…` (params and search kept) |
| `/clients`, `/clients/new`, `/clients/$clientId` | `/t/$tenant/clients…` | redirect |
| `/connections`, `/connections/new`, `/connections/$connectionId` | `/t/$tenant/connections…` | redirect |
| `/sessions` | `/t/$tenant/sessions` | redirect |
| `/audit?…` | `/t/$tenant/audit?…` | redirect (filters kept) |
| `/email`, `/email/$kind`, `/email/smtp` | `/t/$tenant/email…` | redirect |
| `/branding`, `/branding/$clientId` | `/t/$tenant/branding…` | redirect |
| `/settings` | `/t/$tenant/settings` (+ Delete tenant card) | redirect |
| — | `/tenants`, `/tenants/new` | — |

The redirect routes are marked "TRANSITIONAL … remove in 0.5" in their files.

## Tenant DTO and issuer
`TenantView` has **no issuer field** (only slug, display_name, host, settings, ids, created_at). The console does not compute the issuer from a guessed public URL. It fetches the tenant's discovery document and shows its `issuer`, so the value comes from `anvil_core::model::issuer` on the server. For a host tenant, the console adds `{scheme of the path issuer}://{host}` as a second line. **Follow-up for 05-23:** expose `issuer` (and the host issuer) on `TenantView` so the list no longer needs one discovery fetch per row.

## Test ids (e2e)
- Shell: `tenant-switcher` (wrapper; the select's label is "Tenant"), `system-tenant-badge`, `all-tenants-link`
- Layout: `tenant-not-found`
- List: `new-tenant`, `tenant-issuer-{slug}`, `tenant-discovery-{slug}`, `copy-discovery-{slug}`
- Create: `tenant-form`, `tenant-slug`, `tenant-display-name`, `tenant-host`, `tenant-registration`, `create-tenant` (labels "Slug", "Display name", "Custom host", "Registration")
- Settings: `delete-tenant` (dialog "Delete this tenant?", confirm "Delete tenant"), `tenant-undeletable`

## Task Commits
1. **Task 1:** `d8b4efc` feat(05-04): route-level tenant for the console (/console/t/$tenant/...)
2. **Task 2:** `5216708` feat(05-04): tenant switcher, tenant list/create pages and console e2e

## Verification
- `npm run typecheck`, `npm run build` and `npm run check:api` all pass (schema.d.ts was not touched). `just console-check` runs the same steps after `npm ci`.
- `grep -rn CONSOLE_TENANT admin-ui/src` finds nothing.
- The route tree was regenerated and committed. A second `npm run build` leaves it unchanged (`git diff --exit-code` is clean).
- `cd tests/e2e && npx tsc --noEmit -p .` is clean.
- **Local browser e2e without Docker:** a debug `anvilid` build, run from a scratch copy with a fresh data dir and the run.sh flags, plus Playwright chromium. Results:
  - `console-tenants.spec.ts`: **passed**.
  - `console-connections.spec.ts`: **passed**.
  - `theme.spec.ts` (uses `consoleLogin`): **passed**.
  - `console.spec.ts`: every step passed, including the axe audits on all console pages and the moved paths, up to "SMTP settings and a test send delivered to Mailpit". That step failed only because Mailpit (Docker) was not running: "Connection refused". The scratch copy was deleted afterwards.

## Not run
- `console.spec.ts`'s Mailpit step and the full `tests/e2e/run.sh sqlite …` (it needs Docker for Mailpit). Postgres variant: CI.
- Lint: admin-ui has no lint script.

## Deviations from Plan

### Auto-fixed Issues
**1. [Rule 3 - Blocking] Forced extra file `tests/e2e/lib/console.ts`**
- `expectConsoleHome` asserted the landing path `/console/users`, which every console spec (and theme.spec.ts) goes through. It now expects `/console/t/{tenant}/users` (default `default`). Commit 5216708.

**2. [Rule 2 - Correctness] Default tenant discovery at the root**
- `/t/default/...` would show the issuer `{public}/t/default`. Relying parties, the docs and the e2e helpers (`tenantIssuer('default')`) use the root issuer. `discoveryPath('default')` therefore returns `/.well-known/openid-configuration`.

**3. [Rule 1 - Bug] Remount pages on tenant switch**
- A page stays mounted when only the `$tenant` param changes, so a form such as the branding editor or the SMTP form would keep the other tenant's state. The layout keys its Outlet by slug.

**4. [Rule 1 - Bug, own code] Switcher section detection**
- The first version matched `useMatches()` fullPaths and fell back to Users during the local e2e run. It now reads the section from the router pathname, and the e2e test passes.

### Notes
- `ConnectionForm.tsx`, `__root.tsx` and `callback.tsx` were in files_modified but needed no change. They have no tenant reference, and the callback's return path `/console/` now goes through the index redirect.
- Prettier (120 columns) was applied only to new files and to moved files that were already Prettier-clean at HEAD. That avoided reformatting unrelated lines.

## Self-Check: PASSED
- Files exist: lib/tenant.ts, components/TenantSwitcher.tsx, routes/t/$tenant.tsx, routes/tenants/{index,new}.tsx, tests/e2e/specs/console-tenants.spec.ts.
- Commits d8b4efc and 5216708 are in the history.
