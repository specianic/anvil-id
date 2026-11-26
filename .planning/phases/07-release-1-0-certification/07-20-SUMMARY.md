---
phase: 07-release-1-0-certification
plan: 20
subsystem: admin-console
tags: [admin-ui, react, console, import, export, par, headless, agents, ADM-08, ADM-09, OIDC-18, AGT-03, UI-05]
requires:
  - "07-12: ClientView/CreateClient/UpdateClient require_pushed_authorization_requests, client_kind, headless_native; TenantSettings par/headless (schema.d.ts)"
  - "07-17: users/import, users/export, users/{id}/export[?profile=gdpr], password-hash-profiles routes (schema.d.ts)"
provides:
  - "Client form fields: Require pushed authorization requests, Client kind, Native headless client"
  - "Login settings card: Require PAR for all clients + headless allowed origins"
  - "Route /t/$tenant/password-profiles (list, create with write-only signer key, delete with 409 in-use message)"
  - "Route /t/$tenant/users/import (NDJSON upload, client-side caps, dry run/update/source, report)"
  - "Users list: Import link + Export all (NDJSON); user page: Export + GDPR export"
  - "admin-ui/src/lib/export.ts: useGrantedScopes, useCanExportUsers, saveBlob"
affects: [07-22 (docs may mention console import/export), 07-23 (gate ticks ADM-08/ADM-09/OIDC-18/AGT-03/UI-05)]
tech-stack:
  added: []
  patterns:
    - "Non-JSON bodies through openapi-fetch: bodySerializer identity + explicit Content-Type; downloads with parseAs: 'blob' and a Blob URL"
    - "Scope-aware controls from the token's granted scopes (token response scope, else the JWT scope claim)"
key-files:
  created:
    - admin-ui/src/routes/t/$tenant/users/import.tsx
    - admin-ui/src/routes/t/$tenant/password-profiles/index.tsx
    - admin-ui/src/lib/export.ts
    - tests/e2e/specs/console-users-import.spec.ts
    - tests/e2e/specs/console-clients-v10.spec.ts
  modified:
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/routes/t/$tenant/settings/index.tsx
    - admin-ui/src/routes/t/$tenant/users/index.tsx
    - admin-ui/src/routes/t/$tenant/users/$userId.tsx
    - admin-ui/src/routeTree.gen.ts
key-decisions:
  - "Password hash profiles nav entry is added in AppShell (between Signing keys and Login settings), not in lib/tenant.ts TENANT_PAGES (not owned); the tenant switcher therefore does not keep that section. Also linked from Login settings > More settings"
  - "Export scope detection reads the granted scopes (user.scope, falling back to the access token's scope claim) in a new lib/export.ts; auth module untouched"
  - "Bulk export download checks the last bytes for the server's {\"error\":\"export_failed\"} marker and refuses to save a truncated file"
  - "The signer key input is type=password, cleared after success and after any refusal; never rendered back"
  - "Tenant PAR + origins are saved together as one PATCH (both objects replaced whole, as the API defines)"
metrics:
  duration: ~45min
  completed: 2026-11-26
requirements: [ADM-08, ADM-09, OIDC-18, AGT-03, UI-05 (not ticked; the gate 07-23 ticks them)]
---

# Phase 7 Plan 20: Console for the 1.0 admin features Summary

The admin console now manages every Phase 7 admin surface: the client PAR/agent/native-headless
fields, the tenant PAR policy and headless allowed origins, Firebase password hash profiles, user
import with a per-line report, and user export downloads (bulk NDJSON, single, GDPR). Everything
goes through the typed client generated from admin-v1.json; schema.d.ts was not regenerated.

## Pages and components

- **ClientForm** (create and edit): a fieldset "Authorization requests and client kind" with
  `Require pushed authorization requests` (checkbox), `Client kind` (Application/Agent, hint says
  agents always see the consent screen) and `Native headless client` (hint lists the eligibility
  rules: admin-created, application, skip consent, PKCE). The three fields are in `FORM_FIELDS`, so
  422 field errors (`consent_mode` for agent + skip, `headless_native`) show next to the fields.
- **Login settings**: a card "Authorization requests and headless sign-in" with `Require PAR for
  all clients` and an allowed-origins list (add with Enter or button, remove per origin, duplicate
  check locally, API `headless.allowed_origins` errors shown on the input). Saved as
  `{settings: {par, headless}}`. "More settings" links to the profiles page.
- **Password hash profiles** (`/t/$tenant/password-profiles`): table (name, id, kind, rounds,
  mem_cost, salt separator, created), a create dialog (native `<dialog>` Modal) whose signer key is a
  password input sent once and never shown, and delete through `ConfirmDialog`; a 409 shows "This
  profile is in use ..." (`profile-in-use`).
- **Import users** (`/t/$tenant/users/import`): file input with client-side checks (size > 1 MiB,
  more than 1,000 non-blank lines), Dry run (on by default), Update existing users, Source label,
  then the report: counts (created/updated/unchanged/conflict/rejected/weak) and a row per line with
  outcome, reason code plus explanation, weak flag and user link (only after a real run).
- **Users list**: `Import users` link and `Export all (NDJSON)` (downloads `{slug}.users.ndjson`).
- **User page**: `Export` (`user-{id}.json`) and `GDPR export` (`user-{id}.gdpr.json`) next to the heading.

## Scope handling

`lib/export.ts` `useCanExportUsers()` is true when the granted scopes contain `admin:users:export`
or `admin:write` (the token response's `scope`, else the JWT access token's `scope` claim). Without
it the export buttons are disabled, `aria-describedby` points to the explanation
(`export-scope-missing`). The API still decides; a 403 would show through `ProblemAlert`. Downloads
use the console token through the client middleware and save via a Blob URL; the token is never in
a URL.

## E2E evidence

Docker was available, so the plan's verify ran locally:
`tests/e2e/run.sh sqlite specs/console-users-import.spec.ts specs/console-clients-v10.spec.ts`
(console `npm ci` + build, release anvilid, Mailpit): **2 passed** (chromium), `e2e (sqlite): passed`.

- `console-clients-v10.spec.ts`: defaults shown; agent + skip consent refused with `aria-invalid` on
  Consent and nothing stored; PAR + agent saved and persist after reload; first-party application set
  to native headless and persists; tenant PAR + origin with a wildcard origin refused (nothing stored),
  then saved after removing it; origin and PAR removed again; profile created (signer key not in the
  page or the API list) and deleted; axe on the client form, the settings page and the dialog.
- `console-users-import.spec.ts`: dry run of a 3-line file (Openwall bcrypt, weak flag; PBKDF2 at 500
  iterations rejected `weak_parameters`; plain user) reports 2 created / 1 rejected / 1 weak and
  creates nothing; the real run creates two; the bcrypt user signs in on the tenant login page with
  `U*U` (separate browser context); Export all downloads NDJSON with both users and no `$2a$`,
  `$argon2` or `password_hash`; the user page's Export and GDPR export download the user's documents.

## Other verification

- `npm run check:api` (up to date), `npm run typecheck` (clean), `npm run build` (ok, route tree
  regenerated by the router plugin through `vite build`). `just console-check`'s `npm ci` ran as part
  of `run.sh`.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK. `scripts/check-deps.sh`: OK.
- No Rust files touched, so fmt/clippy/`just doc` have nothing to check for this plan.
- Not run: the Postgres variant of the e2e specs (CI).

## Deviations from Plan

1. **[Rule 3 - Blocking] Forced extra file `admin-ui/src/lib/export.ts`.** The scope check and the
   Blob download are shared by users/index.tsx and users/$userId.tsx; route files use automatic code
   splitting, so helpers cannot be exported from them. New file, no other plan touches it.
2. **Nav entry in AppShell only.** `TENANT_PAGES` lives in lib/tenant.ts (not owned), so AppShell
   builds its NAV from TENANT_PAGES plus the profiles entry. The tenant switcher (which keeps the
   current section) does not know the profiles section and falls back as for any other non-listed page.
3. **Route tree generation.** `npm run build` runs `tsc -b` before `vite build`, so a new route fails
   type-checking until the tree exists; `npx vite build` was run first to let the router plugin
   regenerate routeTree.gen.ts (never hand-edited), then `npm run build`.

## Problems seen in other plans' files

- None blocking. During the run the tree held 07-21's uncommitted `crates/anvil-core/src/model/config_doc.rs`,
  `crates/anvil-web/tests/api_compat.rs`, the OpenAPI baselines and `docs/COMPATIBILITY.md`; the release
  build compiled with them.

## Commits

- `5af320e` feat(07-20): console client PAR/agent/headless fields, tenant PAR and origins, hash profiles page
- `d60f74f` feat(07-20): console user import page, export downloads, import e2e

## Self-Check: PASSED

- FOUND: admin-ui/src/routes/t/$tenant/users/import.tsx (contains "dry", calls `users/import`)
- FOUND: admin-ui/src/routes/t/$tenant/password-profiles/index.tsx (contains "signer")
- FOUND: tests/e2e/specs/console-users-import.spec.ts (contains "import")
- FOUND: commits 5af320e, d60f74f
