---
phase: 05-release-0-4-operate-it
plan: 24
subsystem: admin-console
tags: [console, react, tanstack-router, rbac, attributes, webhooks, dcr, cimd, initial-access-token, declarative-config, e2e]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-04 tenant routing (useTenant, TENANT_PAGES), 05-12 role API and claims mapping, 05-20 config export/plan/apply API, 05-23 attribute/webhook/IAT API, DCR/CIMD settings, TenantView.issuer, ClientView.registration_source
provides:
  - Console pages for roles (list/create/edit/delete, holders), user role assignment and user attribute values
  - Attribute definition editor (JSON Schema with parse and input-shape feedback, claim rule)
  - Token claim mapping editor in Login settings, links to Registration, Configuration and Webhooks
  - Webhook endpoints (list/create/detail), enable toggle, secret rotation, test send, delivery log with redelivery
  - Registration settings (DCR + CIMD policies; system tenant read-only) and initial access tokens
  - Configuration page (JSON export download, CLI commands, plan of an uploaded document, apply with prune)
  - Source badge on the clients list; tenants list uses tenant.issuer / discovery_url
  - OneTimeSecret component and the "secret only in component state" mutation pattern
  - e2e specs console-roles, console-webhooks, console-registration and lib/console-v04.ts
affects: [05-28]

tech-stack:
  added: []
  patterns:
    - "Secrets returned once are moved into component state inside mutationFn; the mutation returns the record without the secret, so no TanStack cache ever holds it; OneTimeSecret clears it on 'I have stored it'"
    - "Uploaded config documents (may carry inline secrets) live in a ref, never in mutation variables"
    - "Route files export only Route (autoCodeSplitting); query keys are inline arrays"

key-files:
  created:
    - admin-ui/src/components/RoleForm.tsx
    - admin-ui/src/components/AttributeForm.tsx
    - admin-ui/src/components/WebhookForm.tsx
    - admin-ui/src/components/DeliveryLog.tsx
    - admin-ui/src/routes/t/$tenant/roles/{index,new,$roleName}.tsx
    - admin-ui/src/routes/t/$tenant/attributes/{index,$attributeName}.tsx
    - admin-ui/src/routes/t/$tenant/webhooks/{index,new,$webhookId}.tsx
    - admin-ui/src/routes/t/$tenant/settings/{registration,config}.tsx
    - tests/e2e/lib/console-v04.ts
    - tests/e2e/specs/console-roles.spec.ts
    - tests/e2e/specs/console-webhooks.spec.ts
    - tests/e2e/specs/console-registration.spec.ts
  modified:
    - admin-ui/src/routes/t/$tenant/settings/index.tsx
    - admin-ui/src/routes/t/$tenant/users/$userId.tsx
    - admin-ui/src/routes/t/$tenant/clients/index.tsx
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/lib/tenant.ts (forced: navigation entries live in TENANT_PAGES)
    - admin-ui/src/routes/tenants/index.tsx (forced: deferred issuer item, in scope per the prompt)

key-decisions:
  - "Navigation entries Roles, Attributes and Webhooks were added to TENANT_PAGES (lib/tenant.ts), not AppShell: the shell renders TENANT_PAGES and the tenant switcher keeps the section by matching it. AppShell.tsx needed no change"
  - "Webhooks get a main navigation entry besides the link from Login settings (a top-level route; the switcher would otherwise fall back to Users)"
  - "The nav label stays 'Login settings' (console-tenants.spec clicks it); the page gains Token claims and More settings cards"
  - "Attribute create lives on the attributes index page (no /attributes/new route: 'new' is a valid attribute name)"
  - "User page: Roles and Attributes are tabs (like Sessions and Credentials); boolean attribute values use a Not set / Yes / No select so 'not set' stays expressible"
  - "Last-administrator 409 is detected by status 409 + 'administrator' in the problem detail and explained in RoleProblem (test id last-administrator)"
  - "Config apply status text mirrors the CLI ('Applied: N created, N updated, N deleted.' / 'No changes.' / 'Nothing to apply without prune.')"
  - "The roles e2e signs in through signInForIdToken (lib/account.ts) with the roles scope added by addAuthorizeParams, not the sample RP: the RP requests a fixed scope and shows no ID token, and examples/ is not in this plan's files"

patterns-established:
  - "OneTimeSecret(title, label, value, testId, onDone): value + Copy + dismissal; test ids {testId}, {testId}-panel, {testId}-copy, {testId}-done"

requirements-completed: [ORG-01, ORG-05, AUTH-14, ADM-05, ADM-06, OIDC-17, AGT-02]

duration: ~70min
completed: 2026-11-26
---

# Phase 5 Plan 24: 0.4 console pages Summary

**Every 0.4 admin surface can now be operated from the console. Operators manage roles and assignments, the token claim mapping, attribute definitions and user values, and webhook endpoints with a live delivery log and redelivery. They also set DCR/CIMD policy, issue initial access tokens, and export, plan and apply the tenant configuration. Secrets shown once are never stored in a query or mutation cache.**

No requirement checkbox was ticked (shared rule). The requirement IDs above are the console halves.

## Performance

- **Duration:** about 70 min
- **Completed:** 2026-11-26
- **Tasks:** 3/3, plus two fixes (tenants issuer, user tab navigation)
- **Files:** 12 created, 6 modified

## Pages and test ids

| Route | What | Test ids |
|---|---|---|
| `/t/$tenant/roles` | list | `new-role` |
| `/t/$tenant/roles/new`, `/roles/$roleName` | form, holders (paged), delete | `role-form`, `role-name`, `role-permission-input`, `role-permission-add`, `role-permissions`, `role-submit`, `delete-role`, `last-administrator` |
| `/t/$tenant/users/$userId?tab=roles` | assign/unassign | `assign-role-select`, `assign-role`, `user-role-{name}` |
| `/t/$tenant/users/$userId?tab=attributes` | values (simple shapes or JSON) | `user-attributes-form`, `user-attr-{name}`, `save-user-attributes` |
| `/t/$tenant/attributes`, `/attributes/$attributeName` | definitions | `new-attribute`, `attribute-form`, `attribute-name`, `attribute-schema`, `attribute-schema-feedback`, `attribute-submit`, `delete-attribute` |
| `/t/$tenant/settings` | + Token claims, More settings | `claim-mapping-form`, `claim-rule-{roles,permissions}`, `save-claim-mapping`, `registration-settings-link`, `config-settings-link` |
| `/t/$tenant/webhooks`, `/webhooks/new`, `/webhooks/$webhookId` | endpoints, test, log | `new-webhook`, `webhook-form`, `webhook-name`, `webhook-url`, `webhook-submit`, `webhook-secret*`, `open-webhook`, `webhook-status`, `send-webhook-test`, `toggle-webhook`, `rotate-webhook-secret`, `delete-webhook`, `delivery-log` (rows `tr[data-event][data-status]`), `refresh-deliveries` |
| `/t/$tenant/settings/registration` | DCR/CIMD policies, IATs | `registration-form`, `registration-read-only`, `dcr-policy`, `cimd-policy`, `save-registration`, `iat-form`, `iat-description`, `iat-uses`, `create-iat`, `iat-value*`, `iat-{id}` |
| `/t/$tenant/settings/config` | export, plan, apply | `download-config`, `config-cli`, `config-file`, `config-plan`, `config-plan-empty`, `config-issues`, `apply-config`, `apply-prune` |
| `/t/$tenant/clients` | Source column | `client-source-{client_id}` (Static / Dynamic / CIMD) |

The delivery log refetches every 2 s while any delivery on the page is pending.

## Secret handling (04-19 pattern, extended)

- Webhook create/rotate, IAT create and config apply: `mutationFn` stores the secret in `useState` and returns the record without it (`endpoint`, `token`, or the apply result with `generated_secrets: []`). The query and mutation caches never hold a secret. Clicking "I have stored it", or leaving the page, drops the value. The e2e helper `takeOneTimeSecret` checks that the copied value equals the displayed one, and that the page HTML no longer contains it after dismissal.
- The uploaded config document is kept in a ref. It is cleared after apply and whenever a new file is chosen.

## Task Commits

1. `db0c2c8` fix(05-24): tenants list reads issuer and discovery URL from the tenant view
2. `aa9e18e` feat(05-24): console roles, assignments, claim mapping and attributes (Task 1)
3. `f7a1a12` feat(05-24): console webhooks, registration policies, IATs, config page, client source badges (Task 2)
4. `ae8e747` fix(05-24): user page tabs stay in the current tenant
5. `9b46364` test(05-24): console e2e for roles, webhooks and client registration (Task 3)

## Verification

- `npm run typecheck`, `npm run build` and `npm run check:api` (schema.d.ts up to date, not regenerated) pass. The route tree was regenerated and committed. A second build leaves it byte-identical.
- `cd tests/e2e && npx tsc --noEmit -p .` is clean.
- **Local browser e2e without Docker:** the debug `anvilid` from the main tree (already up to date), run from a scratch copy with a fresh data dir and the run.sh flags (`--public-url http://localhost:18124`, dev mode, `--breach-check off`, auth budget 1200/min), with Playwright chromium:
  - `console-roles.spec.ts`: **passed**. The first run found the user-tab bug below; it passed after the fix.
  - `console-webhooks.spec.ts`: **passed**. The test delivery reached the 05-27 sink, its signature was verified, and the log showed Delivered with HTTP 204. Redelivery and rotation worked (the new secret verified).
  - `console-registration.spec.ts`: **passed** (404 when disabled; 201 when open; under allow_listed 401 without a token, 201 with the IAT, then 401 on reuse; Dynamic badge; system tenant read-only).
  - Regression: `console-tenants`, `console-connections` and `theme` **passed**. `console.spec.ts` passed every step up to "SMTP settings and a test send delivered to Mailpit", which failed only because Mailpit (Docker) was not running ("Connection refused").
  - The scratch instance was stopped and its directory deleted.

## Not run

- `tests/e2e/run.sh sqlite …` as written (it needs Docker for Mailpit) and the Postgres variant: left for CI.
- The nojs project: the new specs are chromium-only (the console needs JavaScript).
- Lint: admin-ui has no lint script.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] User page tabs jumped to the default tenant**
- **Found during:** Task 3 (local e2e run)
- **Issue:** `useNavigate({ from: "/users/$userId" })` resolved tab changes against the pre-0.4 redirect route. On a non-default tenant, selecting a tab redirected to `/t/default/users/...` (pre-existing since 05-04, visible now that the tabs are used in other tenants).
- **Fix:** navigate from `/t/$tenant/users/$userId`.
- **Commit:** ae8e747

**2. [Rule 3 - Blocking] Navigation lives in `lib/tenant.ts` (forced extra file)**
- AppShell renders `TENANT_PAGES`, and the switcher matches sections against it. The new entries went there, and AppShell.tsx (in files_modified) needed no change. The removed `discoveryUrl`/`hostIssuer` helpers and the stale "no issuer field (yet)" comment are in the same file.

**3. [In scope per prompt] Tenants list uses `tenant.issuer`** (forced extra `admin-ui/src/routes/tenants/index.tsx`), resolving the 05-04/05-23 deferred item.

### Other deviations
- The roles spec does not use the sample RP. The RP requests a fixed `openid profile email` and does not show the ID token. The spec instead uses the existing authorization-code helper with the `roles` scope added (see key-decisions). It also covers the claim mapping editor: roles mapped to `app_roles`, then the ID token checked.
- The webhooks spec reuses `tests/e2e/lib/webhook-sink.ts` (05-27, committed in this wave) instead of a second sink in console-v04.ts. Signature verification with node:crypto happens there.
- Task 1's commit leaves out the Webhooks nav entry and the settings links to the Task 2 pages, so each commit typechecks on its own. They arrive in Task 2's commit.

## Deferred items logged
- 05-23 console follow-up marked done (tenants list issuer).
- Client create/rotate pages still keep `client_secret` in the mutation result. They should adopt the 0.4 one-time-secret pattern.
- No server-side defect was found.

## Self-Check: PASSED
- All created files exist: RoleForm/AttributeForm/WebhookForm/DeliveryLog, the roles/attributes/webhooks routes, settings/registration and settings/config, lib/console-v04.ts and the three specs.
- Commits db0c2c8, aa9e18e, f7a1a12, ae8e747 and 9b46364 are in the history.
