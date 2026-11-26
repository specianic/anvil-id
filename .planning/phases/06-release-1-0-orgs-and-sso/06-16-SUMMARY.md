---
phase: 06-release-1-0-orgs-and-sso
plan: 16
subsystem: admin-console
tags: [console, keys, react, tanstack-router, e2e, axe, ADM-02]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-11 keys admin API (listKeys, rotateKey) and console types
provides:
  - Console Signing keys page per tenant (/console/t/$tenant/keys) with a rotate dialog
  - "Signing keys" entry in TENANT_PAGES (after Branding)
  - tests/e2e/lib/console-v10.ts (shared Phase 6 console helpers for 06-21/06-23)
  - tests/e2e/specs/console-keys.spec.ts
affects: [06-21, 06-23]

tech-stack:
  added: []
  patterns:
    - "Form controls inside ConfirmDialog's description for small confirm-with-options dialogs"
    - "console-v10.ts re-exports console-v04 set-up/sign-in instead of duplicating it"

key-files:
  created:
    - admin-ui/src/routes/t/$tenant/keys/index.tsx
    - tests/e2e/lib/console-v10.ts
    - tests/e2e/specs/console-keys.spec.ts
  modified:
    - admin-ui/src/lib/tenant.ts
    - admin-ui/src/routeTree.gen.ts

key-decisions:
  - "Algorithm choices come from the tenant view's settings.signing_algs filtered to the SigningAlg enum; the Rotate button is disabled until they load"
  - "'Activate immediately' is off by default; its hint switches between the prepublish explanation and the compromise warning"
  - "The e2e reads the expected kid from the admin API (the one key not present before) and checks the default tenant's key list is byte-identical afterwards"

requirements-completed: [ADM-02]

duration: ~25min
completed: 2026-11-26
---

# Phase 6 Plan 16: Console signing keys page Summary

**Each tenant's signing keys can now be managed in the console. The table shows kid, algorithm, a state badge and the created/activated/retired/leaves-JWKS dates. "Rotate key" opens a confirmation dialog that offers only the tenant's enabled algorithms and an "Activate immediately" option explaining the JWKS overlap. The page calls the 06-11 keys API through the typed client and never renders private material.**

No requirement checkbox was ticked (shared rule).

## Page and test ids

| Route | Test ids |
|---|---|
| `/t/$tenant/keys` | `rotate-key` (button), `rotate-key-dialog`, `rotate-key-alg`, `rotate-key-immediate`, `key-state` (badge per row) |

- If the list fails (including a 403 for a missing scope), DataTable shows the shared `ProblemAlert`. A failed tenant-view load shows a ProblemAlert above the table. Rotation errors such as 422 (disabled algorithm) or 409 appear inside the dialog.
- On success the dialog closes, the list is invalidated and a status line names the new kid. For an immediate rotation the line says the previous key was retired. Otherwise it says the key becomes active after the prepublish period.
- There are no inline styles: Tailwind classes and existing components only (console CSP).

## Task Commits

1. Task 1, Keys page, nav entry and route tree: `f6355f5` (feat)
2. Task 2, console keys e2e with axe: `13b4ada` (test)

## Verification

- `cd admin-ui && npm run check:api && npm run typecheck && npm run build`: green. `routeTree.gen.ts` is regenerated, committed, and unchanged by a second build.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK.
- **Local browser e2e without Docker (SQLite):** the existing debug `anvilid` (built after the 06-11 commit, so it contains the keys API) was run from a scratch hardlink with a fresh data dir and the run.sh flags (port 18136, `--breach-check off`, auth budget 1200/min). The console was served from the fresh `admin-ui/dist`. Playwright chromium results:
  - `console-keys.spec.ts`: **passed**. A fresh tenant has an active RS256 key. Immediate rotation produced exactly one new RS256 key, shown as Active, with the old row shown as Retired. The tenant JWKS contains the new kid and not the old one. axe was clean on the page, the open dialog and the page after rotation. The default tenant's keys were unchanged.
  - Regression for the new nav entry: `console-tenants.spec.ts` and `theme.spec.ts` **passed**.
  - The instance was stopped and the scratch directory deleted.

## Not run

- `tests/e2e/run.sh sqlite specs/console-keys.spec.ts` as written: it starts Mailpit in Docker and builds a release binary, and the shared rules say not to depend on Docker. The Postgres variant is also left for CI.
- `cargo build -p anvilid` currently fails because peers' in-progress anvil-core files are mid-edit in the shared tree. The run therefore used the already-built debug binary described above. This plan has no Rust changes.

## Deviations from Plan

- `lib/console-v10.ts` re-exports `setUpConsoleTenant` / `openTenantPage` from console-v04 (createConsoleAdmin sign-in) rather than re-implementing them, so no helper is duplicated. It adds `openSectionFromNav`, `listTenantKeys` and `tenantJwksKids`.
- Otherwise the plan was executed as written.

## Self-Check: PASSED
