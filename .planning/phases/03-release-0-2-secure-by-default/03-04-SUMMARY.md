---
phase: 03-release-0-2-secure-by-default
plan: 04
subsystem: e2e, ui-theme
tags: [playwright, axe, wcag-2.2, webauthn, totp, no-js, accessibility]
requires:
  - 02-20 e2e environment (run.sh, lib/anvil.ts, lib/mailpit.ts, examples/node-rp)
provides:
  - tests/e2e/fixtures/webauthn.ts (CDP virtual authenticator fixture for 03-26/03-27)
  - tests/e2e/fixtures/axe.ts (expectNoA11yViolations, WCAG 2.2 A/AA tags)
  - tests/e2e/lib/totp.ts (RFC 6238 SHA-1/6/30 + base32)
  - Playwright `nojs` project (javaScriptEnabled false)
  - WCAG 2.2 AA baseline for every Phase 2 page (UI-02)
affects:
  - themes/default (CSS custom properties gained --anvil-input-border; focus colours changed)
  - tests/e2e/run.sh (accepts spec arguments)
tech-stack:
  added: ["@axe-core/playwright 4.14.1 (e2e devDependency)"]
  patterns:
    - "Fixture specs: specs/fixtures.spec.ts self-tests the helpers without a server"
    - "No-JS specs are named nojs*.spec.ts and run only in the nojs project"
    - "Specs that need an RP spawn examples/node-rp themselves on a free loopback port"
key-files:
  created:
    - tests/e2e/fixtures/webauthn.ts
    - tests/e2e/fixtures/axe.ts
    - tests/e2e/lib/totp.ts
    - tests/e2e/specs/fixtures.spec.ts
    - tests/e2e/specs/a11y.spec.ts
    - tests/e2e/specs/keyboard.spec.ts
    - tests/e2e/specs/nojs.spec.ts
  modified:
    - tests/e2e/package.json
    - tests/e2e/package-lock.json
    - tests/e2e/playwright.config.ts
    - tests/e2e/tsconfig.json
    - tests/e2e/run.sh
    - .github/workflows/e2e.yml
    - themes/default/static/anvil.css
    - themes/default/templates/form.html
key-decisions:
  - "run.sh takes optional spec arguments after the backend (run.sh sqlite specs/a.spec.ts ...); the default list now includes a11y, keyboard, nojs and fixtures specs, so `just e2e` runs both projects in CI"
  - "nojs.spec.ts starts its own examples/node-rp (free port, client created via the admin API) instead of relying on run.sh"
  - "a11y.spec.ts audits the setup form and setup-done page itself when it runs first on a fresh instance (it completes setup and writes E2E_STATE_FILE in the sharedManagementCredential format); otherwise those two pages are skipped with a reason"
  - "axe runs in both light and dark colour schemes in addition to the two viewports"
requirements-completed: []
duration: 55min
completed: 2026-11-25
---

# Phase 3 Plan 04: e2e fixtures and WCAG 2.2 AA for Phase 2 pages Summary

Reusable Playwright fixtures (CDP virtual authenticator, axe with WCAG 2.2 AA tags, RFC 6238 TOTP), a JavaScript-disabled
project, and a verified accessibility baseline: zero axe violations on every Phase 2 page at 375x812 and 1280x800 in light and
dark mode, keyboard and WCAG 3.3.8 checks, and a password login through the sample RP with JavaScript off.

## Tasks

| # | Task | Commit |
|---|------|--------|
| 1 | Playwright fixtures, projects and helper | 612bca0 |
| 2 | Accessible Phase 2 pages + a11y, no-JS and keyboard specs | 7898205 |

## What was built

- **fixtures/webauthn.ts**: a `test.extend` `authenticator` fixture (CDP `WebAuthn.enable {enableUI:false}`,
  `WebAuthn.addVirtualAuthenticator` with ctap2 / ctap2_1 / internal / resident key / UV / automatic presence; removed on
  teardown). The `VirtualAuthenticator` class offers `getCredentials()`, `setSignCount(id, n)` (remove and re-add, because
  Chromium has no set-counter command), `overrideResponse({isBogusSignature, isBadUV, isBadUP})` and `setUserVerified()`.
- **fixtures/axe.ts**: `expectNoA11yViolations(page, {exclude})` with tags wcag2a, wcag2aa, wcag21a, wcag21aa and wcag22aa.
  Failures print one readable line per violation plus the failing node selectors.
- **lib/totp.ts**: `base32Decode`, `base32Encode`, `hotp`, `totp(base32, unixSeconds?)` (node:crypto HMAC-SHA1, 30 s, 6 digits).
  It is self-tested against the RFC 6238 Appendix B SHA-1 vectors (T=59 gives 287082, and the other five vectors).
- **playwright.config.ts** has two projects. `chromium` ignores nojs specs. `nojs` uses Desktop Chrome with
  `javaScriptEnabled: false` and matches `nojs*.spec.ts`.
- **e2e.yml**: Node 22 (unchanged), plus `npm ci --prefix examples/node-rp` in the e2e job for the nojs spec. `just e2e` runs both
  projects through run.sh.

## a11y fixes

The Phase 2 templates already had most of the structure: `<html lang>`, one `<main>` landmark labelled by the `<h1>`, a
`<label for>` on every input, `aria-invalid` and `aria-describedby` on invalid fields, and `role="alert"` on error messages. axe
found no violations in either colour scheme. The explicit checks found these gaps, now fixed:

1. **Target size (2.5.8)**: the account-help links were 21 px tall. `.anvil-links a` now has a 32 px minimum height (inline-flex).
   Buttons and inputs have a 44 px minimum height.
2. **Non-text contrast (1.4.11)**: input borders were #d6dae1 on white (about 1.4:1). A new `--anvil-input-border` is used
   instead: #6b7280 in light mode (4.8:1) and #8a92a1 in dark mode.
3. **Focus indicator contrast**: the light focus ring was #8aa8f0 (about 2.3:1 on white) and is now #1d4ed8. The dark ring was
   #3d5fc4 (under 3:1 on the dark surface) and is now #a9c0ff. The outline offset is 2 px.
4. **Labels or instructions (3.3.2)**: optional fields (the registration Name field) now show "(optional)" in their label.
   Required fields keep the `required` attribute. No id or name changed.
5. **Reflow (1.4.10)**: below 30rem the layout is one column, with less card padding, top-aligned content and stacked links.
   The 320 px horizontal-scroll check passes on every page.
6. **Forced colours and reduced motion**: borders stay visible in forced-colors mode. The reduced-motion rule now also turns
   off animations and smooth scrolling.

The render snapshots were unchanged. The render test fixtures mark every visible field as required, so "(optional)" never
renders there, and the CSS is not part of the snapshots. `cargo test -p anvil-web --test render --test flow_login`: 13 + 9
passed.

## Manual checklist (not automatable with axe; record per release)

- Screen reader pass (NVDA + Firefox, VoiceOver + Safari): error announcement on submit, page title/heading read on load.
- 200% and 400% browser zoom on login and registration (1.4.4, 1.4.10 beyond the 320 px check).
- Text spacing override bookmarklet (1.4.12) on all form pages.
- Windows High Contrast / forced-colors visual check of focus ring and button boundaries.
- Password manager autofill (1Password/Bitwarden/browser) on login, registration and recovery reset (autocomplete purposes).
- Real clipboard paste from a password manager into the password fields (3.3.8; the spec dispatches a synthetic paste event).
- Focus not obscured (2.4.11) on real mobile devices with the on-screen keyboard open.
- Dark mode contrast of the dev banner and callouts by eye (axe covers computed colours, not transparency edge cases).

## Verification

- `cd tests/e2e && npm ci && npm run typecheck && npx playwright test specs/fixtures.spec.ts --project=chromium`: 4 passed.
- `tests/e2e/run.sh sqlite` with the default spec list (19 tests, both projects, setup pages audited): all passed in 50 s.
- `tests/e2e/run.sh sqlite specs/keyboard.spec.ts specs/nojs.spec.ts`: 7 passed.
- **run.sh invocation**: `tests/e2e/run.sh [sqlite|postgres] [spec ...]`. The plan's `./run.sh specs/a11y.spec.ts ...` form would
  pass the spec as the backend argument, so the backend comes first: `tests/e2e/run.sh sqlite specs/a11y.spec.ts
  specs/keyboard.spec.ts specs/nojs.spec.ts specs/fixtures.spec.ts`.
- Plan 03-02 is running in parallel and the shared workspace does not currently compile (anvil-web `TenantSettings` is missing
  fields). Because of that, the Rust render tests and the full e2e run used a scratch git worktree at HEAD with this plan's
  changes copied in. The Postgres e2e variant was not run locally because Docker was busy with parallel plans. CI runs it.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] tsconfig.json include extended to fixtures/**
- **Found during:** Task 1
- **Issue:** `npm run typecheck` did not cover the new `fixtures/` directory (tsconfig was not in files_modified).
- **Fix:** added `fixtures/**/*.ts` to `include`.
- **Files modified:** tests/e2e/tsconfig.json
- **Commit:** 612bca0

**2. [Rule 3 - Blocking] run.sh accepts spec arguments and runs the new specs**
- **Found during:** Task 2
- **Issue:** The plan said not to edit run.sh. But run.sh hard-coded three specs and took only a backend argument, so neither
  the plan's verify command nor CI ("CI e2e ... includes the new projects") could run the new specs. run.sh also does not start
  the sample RP, although the plan's interface notes said it does.
- **Fix:** run.sh now takes optional spec arguments after the backend, and the default list includes the new specs. No other
  behaviour changed. nojs.spec.ts starts examples/node-rp itself.
- **Files modified:** tests/e2e/run.sh
- **Commit:** 7898205

**3. [Rule 1 - Bug] a11y spec timeout under load**
- **Found during:** Task 2 (first full run.sh)
- **Issue:** Five axe passes per page state went over the 30 s default timeout on a loaded machine.
- **Fix:** the spec timeout is now 180 s. The spec no longer uses serial mode, so one failure does not skip the remaining pages.
- **Commit:** 7898205

## Self-Check: PASSED
