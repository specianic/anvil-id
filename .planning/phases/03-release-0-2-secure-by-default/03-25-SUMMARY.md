---
phase: 03-release-0-2-secure-by-default
plan: 25
subsystem: admin-console
tags: [admin-console, react, sessions, audit, email-templates, smtp, clients, playwright, axe, csp]
requires:
  - phase: 03-03
    provides: console scaffold (openapi-fetch client, DataTable, AuthProvider)
  - phase: 03-22
    provides: /console/* serving with CSP script-src/style-src 'self'
  - phase: 03-23
    provides: management API 0.2 (sessions, credentials, audit-events, email-templates, smtp, client options)
  - phase: 03-24
    provides: ensure_console_client at startup
provides:
  - "Console v1 pages: Sessions, Audit log, Email (templates + SMTP with test send), user Sessions/Credentials tabs, client create/edit/rotate/delete"
  - "tests/e2e/run.sh builds admin-ui before cargo build --release; the e2e binary embeds the console"
  - "tests/e2e/lib/console.ts (consoleLogin, findInPagedTable, startSampleRp) and specs/console.spec.ts (axe on every page, CSP watch)"
  - "admin-ui/package-lock.json in sync for Node 22 npm ci (CI console job)"
affects: [03-29]
tech-stack:
  added: []
  patterns:
    - "Modals on native <dialog> + showModal() (focus trap, Escape, inert background; no positioning library, no inline styles)"
    - "Audit filters in TanStack Router validateSearch; the table is keyed by the filter set so the cursor stack resets"
    - "422 field errors mapped to controls via fieldErrors(); template errors render as 'Line N: message'"
key-files:
  created:
    - admin-ui/src/routes/sessions/index.tsx
    - admin-ui/src/routes/audit/index.tsx
    - admin-ui/src/routes/email/index.tsx
    - admin-ui/src/routes/email/$kind.tsx
    - admin-ui/src/routes/email/smtp.tsx
    - admin-ui/src/routes/clients/new.tsx
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/components/ConfirmDialog.tsx
    - admin-ui/src/components/form.tsx
    - admin-ui/src/lib/email.ts
    - tests/e2e/lib/console.ts
    - tests/e2e/specs/console.spec.ts
  modified:
    - admin-ui/src/components/AppShell.tsx
    - admin-ui/src/routes/users/$userId.tsx
    - admin-ui/src/routes/clients/$clientId.tsx
    - admin-ui/src/routes/clients/index.tsx
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/auth/oidc.ts
    - admin-ui/package-lock.json
    - tests/e2e/run.sh
key-decisions:
  - "03-25: e2e run.sh builds the console and a release anvilid (rust-embed embeds dist at compile time), adding about 3 min of cold release build"
  - "03-25: After an explicit console sign-out the next sign-in sends prompt=login; token revocation leaves the system-tenant browser session alive until RP-initiated logout ships"
  - "03-25: The e2e console admin is a system-tenant user created through the admin API (completeSetup's admin credentials are not kept in the shared state)"
  - "03-25: Console CSP needs no relaxation: the full console spec reports no CSP violations under script-src 'self'; style-src 'self'"
requirements-completed: []
duration: 75min
completed: 2026-11-25
---

# Phase 3 Plan 25: Console v1 pages and Playwright console spec Summary

**Console v1 now lets admins review and revoke sessions (tenant-wide and per user), remove passkeys and TOTP, query the audit log (filters kept in the URL, cursor paging, detail drawer), edit email templates (validation errors with line numbers, reset to default), configure SMTP with a test send, and create, edit, rotate and delete clients with the 0.2 options. The e2e runner builds the console into a release binary, and a Playwright spec drives it end to end with axe checks and a CSP watch.**

## Task Commits

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Console pages: sessions, audit, email/SMTP, user tabs, client editing | 82c3a6b |
| - | Lockfile fix for Node 22 `npm ci` (coordinator request) | eecc57d |
| 2 | run.sh console + release build, lib/console.ts, console.spec.ts, sign-out prompt=login | 057676d |

## What was built

**Pages**
- **Sessions** (`/sessions`): table of the tenant's active sessions with user, IP, user agent, created and last seen. Each row can be revoked after a confirm dialog.
- **Audit log** (`/audit`):
  - Filters for from/to (datetime-local, sent as RFC 3339), action (every `AuditAction`, checked against the enum at compile time), outcome, actor and target. Filters live in the URL search params.
  - Cursor paging over `next_cursor`, sent back as `cursor`.
  - A side drawer shows each event's details JSON.
- **Email** (`/email`):
  - Template list with a Customized or Default badge.
  - Editor (`/email/$kind`) with subject, HTML and text fields and the list of available variables. A 422 is shown at the field as "Line N: message". Reset to default asks for confirmation first.
  - **SMTP** (`/email/smtp`): host, port, TLS, from, username and a write-only password with a "password set" hint. "Use installation SMTP" removes the tenant settings. The test send reports its outcome in an `aria-live` region.
- **User detail**: WAI-ARIA tabs (Overview / Sessions / Credentials) with arrow, Home and End keys; the active tab is kept in `?tab=`.
  - Sessions tab: revoke one session or all of them.
  - Credentials tab: remove a passkey or TOTP after confirmation. Passwords are not removable.
- **Clients**:
  - `/clients/new` covers type, application type, auth method, JWKS, redirect URIs, grant types, scopes, PKCE, token format, consent mode, ID-token algorithm and `can_introspect`. The algorithm options come from the tenant's `signing_algs`, and `can_introspect` is for confidential clients only. The new secret is shown once.
  - The detail page adds an edit form, secret rotation (secret shown once) and delete.

**Common to every page**
- Every mutation invalidates the queries it affects.
- Each page has loading, empty and error (ProblemAlert) states.

**e2e**
- `run.sh` runs `npm --prefix admin-ui ci`, then `npm --prefix admin-ui run build`, and fails if `admin-ui/dist/index.html` is missing. It then runs `cargo build --release -p anvilid` and uses `target/release/anvilid`.
- The default spec list now also includes passkey, totp, consent, sessions and console. Passkey and totp are picked up by the chromium project; the `nojs` project matches only `nojs*.spec.ts`.
- What `console.spec.ts` checks:
  - **Sign-in:** a system-tenant admin signs in through `/t/system/ui/login`, and nothing is written to localStorage.
  - **Users and sessions:** the users list (paged) shows the new user. The Sessions tab lists the session from the sample RP login in another context; after it is revoked, the RP's `/refresh` fails with `invalid_grant`.
  - **Audit log:** the `action=session_revoked` filter shows the row for that session id, and every row matches the filter. The detail drawer opens, and the filter survives a reload.
  - **Clients:** submitting an empty create form shows the validation message. An opaque client is created and found in the list.
  - **Email template:** an invalid template shows "Line 2"; a valid one gets the Customized badge; reset brings back the default.
  - **SMTP:** settings point at Mailpit, the test send arrives there, then the override is removed.
  - **Sign-out** returns to the login form.
  - **Throughout:** axe runs on every page and on the open dialogs, and no CSP violations are reported.

## Verification

- `cd admin-ui && npm run check:api && npm run typecheck && npm run build`: pass. `schema.d.ts` was already up to date, since 03-23 regenerated it.
- Clean `node:22` container (npm 10.9): `npm ci && npm run check:api && npm run typecheck && npm run build`: pass.
- `cd tests/e2e && npm run typecheck`: pass.
- `tests/e2e/run.sh sqlite specs/console.spec.ts`: 1 passed. Cold release build took 2 min 43 s.
- `tests/e2e/run.sh sqlite` (full default list): **48 passed** (1.4 min).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Files outside files_modified**
- `src/routeTree.gen.ts` is generated and committed, and new routes change it.
- Shared components were added so that route files export only their Route (needed for autoCodeSplitting): `components/{form,ConfirmDialog,ClientForm}.tsx` and `lib/email.ts`.
- `routes/clients/index.tsx` got a "New client" link.
- **Commit:** 82c3a6b

**2. [Rule 1 - Bug] Sign-out did not return to the login screen**
- **Issue:** revoking the refresh token leaves the system-tenant browser session in place, so the auth gate signed the admin straight back in.
- **Fix:** `oidc.ts` sets a sessionStorage flag on sign-out, and the next `signinRedirect` sends `prompt: "login"`.
- **Commit:** 057676d

**3. [Coordinator request] admin-ui/package-lock.json regenerated with npm 10 (node:22)**
- CI `npm ci` was failing because the optional `@emnapi/core` and `@emnapi/runtime` were missing from the lockfile.
- All resolved URLs are on registry.npmjs.org.
- **Commit:** eecc57d

**4. [Coordinator request] run.sh default spec list includes 03-26/03-27 specs**
- Added passkey, totp, consent and sessions.
- **Commit:** 057676d

### Notes
- The e2e admin account is created in the system tenant through the admin API. `lib/anvil.ts` (not editable here) does not keep the setup admin's credentials.
- The console still targets the `default` tenant (tenant switcher in 0.4).
- The spec does not remove passkeys or TOTP through the console, because the plan's spec list does not include it. The Credentials tab is covered by axe and the password row. Removal is covered by the API tests from 03-23.

## Self-Check: PASSED

- FOUND: every created file listed above; commits 82c3a6b, eecc57d, 057676d.
