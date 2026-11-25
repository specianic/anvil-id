---
phase: 04-release-0-3-real-world-logins
plan: 19
subsystem: admin-console
tags: [console, connections, client-settings, tenant-settings, mfa-policy, logout, react, tanstack-router]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-11 connections admin API (ConnectionView.redirect_uri/secret_configured, PUT …/secret), 0.3 client and tenant fields, regenerated schema.d.ts"
provides:
  - "/connections, /connections/new, /connections/$connectionId console routes"
  - "ConnectionForm (provider-aware) with write-only SecretInput (password or Apple .p8 file)"
  - "ClientForm: post-logout redirect URIs, back-channel logout URI + session required, allowed resources, MFA policy override"
  - "/settings tenant login settings page"
  - "console typecheck green again (Phase 4 email kinds and audit actions)"
affects: [04-27]

tech-stack:
  added: []
  patterns:
    - "Write-only secrets reach the request through a ref read once in mutationFn, never through mutation variables, so they do not stay in the TanStack Query mutation cache"
    - "Field-wise tenant PATCH: only changed settings are sent, so unrelated saves never re-trigger the SMTP check"

key-files:
  created:
    - admin-ui/src/components/ConnectionForm.tsx
    - admin-ui/src/routes/connections/index.tsx
    - admin-ui/src/routes/connections/new.tsx
    - admin-ui/src/routes/connections/$connectionId.tsx
    - admin-ui/src/routes/settings/index.tsx
  modified:
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/lib/email.ts
    - admin-ui/src/routes/audit/index.tsx

key-decisions:
  - "Kind and slug are fixed after creation (API rule); the edit form disables slug and has no kind picker"
  - "The redirect URI is shown (copyable) on the connection page; after create the console navigates there"
  - "Social endpoint overrides other than the GitHub Enterprise ones are kept unchanged on edit, so API-set overrides are not lost"
  - "Magic link / email code switches are disabled with an SMTP hint after the API refuses them (422 on email_otp/magic_link); the API is the only source of SMTP availability"
  - "Default language options come from ui_locales_supported of /t/{tenant}/.well-known/openid-configuration; the current value stays selectable"

requirements-completed: []

duration: about 35 min (one interruption)
completed: 2026-11-25
---

# Phase 4 Plan 19: Console pages for connections and 0.3 settings Summary

**Admins can now manage upstream connections in the console, with provider-specific fields, a copyable redirect URI and write-only secret rotation (including the Apple .p8 upload). They can also edit client logout, resource and MFA settings and the tenant's login settings. Console typecheck and build are green again.**

No requirement checkbox was ticked (shared rule). Contributes to AUTH-07, AUTH-08, OIDC-12, OIDC-16, SEC-03.

## Routes
| Route | Content |
|---|---|
| `/connections` | DataTable: name (link), slug, kind, Enabled/Disabled, secret Configured/Not set |
| `/connections/new` | Provider radio picker (Google, Apple, Microsoft, GitHub, Generic OIDC, Generic OAuth2), then ConnectionForm with that kind's defaults (scopes per preset, trust_email_verified true for Google/Apple/GitHub). Microsoft shows the untrusted-email note and an "accept the risk" box when trust is turned on. |
| `/connections/$connectionId` | Redirect URI + Copy, edit form, secret card (Configured badge, rotate/replace, remove with confirmation), delete with ConfirmDialog |
| `/settings` | MFA policy, email one-time code, magic link, auto-link, upstream registration (follow/allow/deny), default language |

Nav entries: "Connections" (after Clients) and "Login settings" (last).

## Test ids for e2e (04-27)
- List/new: `new-connection`, `connection-kind-picker`, `connection-kind-{google|apple|microsoft|github|oidc|oauth2}`
- Form: `connection-form`, `connection-submit`, `connection-secret-input` (password), `connection-secret-file` (Apple), `microsoft-email-note`
- Detail: `connection-redirect-uri`, `copy-redirect-uri`, `connection-secret-status`, `rotate-connection-secret`, `delete-connection`
- Settings: `login-settings-form`, `save-login-settings`, `smtp-missing-hint`
- Form controls also have accessible labels (e.g. "Client ID", "Issuer", "Back-channel logout URI", "MFA policy", "Multi-factor authentication").

API field errors (`slug`, `display_name`, `secret`, `config.client_id`, `config.issuer`, `config.mapping.subject`, `config.apple.team_id`, …) are shown under their controls. Anything else, such as a 409 duplicate slug, is shown in a ProblemAlert.

## Task Commits
1. **Forced extra:** `32bc998` fix(04-19): console labels for Phase 4 email kinds and audit actions
2. **Task 1:** `4125eaf` feat(04-19): console pages for upstream connections
3. **Task 2:** `50e341e` feat(04-19): client logout/resource/MFA fields and tenant login settings page

## Verification
- `npm run typecheck` passes. It failed before this plan on email.ts and audit/index.tsx.
- `npm run build` passes. It includes `tsc -b`, the vite build that regenerates the route tree, and compression.
- `npm run check:api` reports the schema up to date. schema.d.ts was not touched.
- The route tree was regenerated and committed, and `git diff --exit-code -- src/routeTree.gen.ts` is clean after the build (the CI drift check).

## Not run
- **Lint:** admin-ui has no lint script or linter config (no eslint or biome), so there was nothing to run. CI runs only check:api, typecheck and build.
- **Browser / e2e:** there are no console unit tests, and console e2e for connections belongs to 04-27. The pages were not run against a live `anvilid serve`.

## Deviations from Plan

### Auto-fixed Issues
**1. [Rule 3 - Blocking] Forced extra files `admin-ui/src/lib/email.ts` and `admin-ui/src/routes/audit/index.tsx`**
- These caused the pre-existing typecheck/build failure logged in deferred-items.md (04-11). Added labels for `login_code`, `email_change` and `email_changed`, and the 15 Phase 4 audit actions. Commit 32bc998. That deferred item is now resolved.

**2. [Rule 2 - Security] Secrets kept out of the mutation cache**
- Passing the secret as `useMutation` variables would have left it in the query client's mutation state after the submit. The secret now goes through a ref that mutationFn reads once and clears. This applies to create, rotate and Apple .p8.

### Notes
- "SMTP missing" is not exposed by the API ahead of time. The switches are disabled once the PATCH is refused for `email_otp`/`magic_link`, and the refused values are reverted in the form.
- The client detail card in `routes/clients/$clientId.tsx` does not yet list the new client fields read-only. That file was not in this plan, and the edit form shows them.

## Self-Check: PASSED
- Files exist: ConnectionForm.tsx, routes/connections/{index,new,$connectionId}.tsx, routes/settings/index.tsx.
- Commits 32bc998, 4125eaf and 50e341e are in the history.
