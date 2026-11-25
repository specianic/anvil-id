---
phase: 04-release-0-3-real-world-logins
plan: 29
subsystem: e2e
tags: [e2e, playwright, email-otp, magic-link, account, theming, axe, nojs, auth-06, auth-13, ui-03]
requires:
  - phase: 04-03
    provides: e2e helpers (Mailpit, upstream tenant helpers randomSlug/tenantIssuer)
  - phase: 04-15
    provides: account profile/email/password pages and their selectors
  - phase: 04-18
    provides: theme.css, logo route, preview page
  - phase: 04-22
    provides: console theme editor test ids
  - phase: 04-24
    provides: email code / magic link routes and selectors (verified addresses only)
  - phase: 04-25
    provides: linked accounts page
provides:
  - "tests/e2e/specs/email-code.spec.ts (5 tests), nojs-email-code.spec.ts (3), account.spec.ts (4), theme.spec.ts (1)"
  - "tests/e2e/lib/email-code.ts: createEmailSignInTenant, deleteTenant, requestEmailCode, signInEmail, codeFrom, magicLinkFrom, submitEmailCode, expectNoMailTo, expectSession, expectNoSession"
  - "lib/account.ts signInForIdToken(page, client, signIn, issuer = ANVIL_URL)"
affects: [phase 4 verification, CI e2e]
tech-stack:
  added: []
  patterns:
    - "Email sign-in specs run in a tenant of their own (created with email_otp + magic_link, deleted afterwards), so the shared default tenant's sign-in page is unchanged for keyboard/a11y specs"
    - "Theme spec deletes the default tenant's branding through the admin API before and after the file"
    - "A no-JS spec whose name the nojs project regex does not match turns JavaScript off itself with test.use({ javaScriptEnabled: false })"
key-files:
  created:
    - tests/e2e/specs/email-code.spec.ts
    - tests/e2e/specs/nojs-email-code.spec.ts
    - tests/e2e/specs/account.spec.ts
    - tests/e2e/specs/theme.spec.ts
    - tests/e2e/lib/email-code.ts
  modified:
    - tests/e2e/lib/account.ts
key-decisions:
  - "Dedicated tenant instead of toggling email_otp/magic_link on the default tenant and restoring it: no shared state changes if a run is interrupted"
  - "RP sign-in uses signInForIdToken (captured callback + token exchange) so amr [otp] is asserted; it gained an optional issuer parameter"
  - "nojs-email-code.spec.ts sets javaScriptEnabled false itself: playwright.config.ts NOJS_SPECS (/nojs\\..*\\.spec\\.ts|nojs\\.spec\\.ts/) does not match 'nojs-email-code', so it runs in the chromium project"
requirements-completed: []
duration: about 45 min
completed: 2026-11-26
---

# Phase 4 Plan 29: E2E for email sign-in, account pages and live theming Summary

**Browser specs for passwordless email sign-in (code, magic link, other-browser refusal, enumeration), the complete account page (navigation, profile, email change over Mailpit, password change signing out other browsers) and console theming (live preview iframe, publish to the real sign-in page, warnings, line errors, reset), with axe on every new page and a no-JavaScript email sign-in spec. None of them has run yet: Docker (Mailpit) is not available here, so CI runs them.**

## What the specs cover

### email-code.spec.ts (own tenant, email_otp + magic_link on)
- RP sign-in through "Email me a sign-in code": code read from Mailpit, back at the client, ID token `sub` = user and `amr` contains `otp` (not `pwd`). Axe on the sign-in page (email form open) and on "Check your email"; `#code` has `autocomplete=one-time-code`, `inputmode=numeric`.
- Wrong code: `email_code.invalid`, `aria-invalid`, axe; then the right code signs in.
- Magic link, same browser: GET shows only the button (`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, axe), "Continue signing in" ends on `login.signed_in` with a session.
- Magic link, second browser context: `email_code.other_browser` ("browser where you started … type the code"), axe, no session there; the original browser still signs in with the code (nothing consumed).
- Unknown and unverified addresses: same confirmation text as a known address, code form shown, no mail within 3 s.

### nojs-email-code.spec.ts
- Probe that scripts are off; code sign-in and magic link sign-in without JavaScript.

### account.spec.ts (default tenant)
- The seven nav entries in DOM order; each opens its page, has `aria-current="page"` (exactly one), passes axe. Security shows passkeys + TOTP enrolment; Linked accounts shows `linked-none`.
- Profile: name/given/family/locale saved and shown on a fresh GET; invalid locale refused, nothing changed.
- Email change: re-auth if prompted; `account.email_change_sent`; address unchanged until confirmed; the Mailpit link (opened in another context, as from a mail client) only shows the button (axe); confirming gives `account.email_changed`; old address gets the "email address was changed" notice naming the new address; account shows the new verified address; sign-in works with the new address and fails with the old one.
- Password change: "Sign out on all other devices" checked by default; `account.password_changed` (axe); this browser keeps one session, the other context is sent to sign-in; old password gets the generic error, new one signs in.

### theme.spec.ts (console, default tenant branding)
- Console -> Branding (axe), preview on the default theme (`--anvil-primary` #2f5bd3, logo hidden).
- Primary `#1b5e20`: iframe `--anvil-primary` and `#preview-login-submit` background follow.
- 1x1 PNG logo upload: `logo-current`, preview `.anvil-logo` visible.
- Publish: real `/ui/login` in a fresh context has the colour and logo, axe clean, CSP present with `style-src 'self'` and no `unsafe-inline`.
- Text `#777777`: `contrast-warnings-light` and `preview-warnings`; cleared again.
- Custom CSS with `@import` on line 2: `draft-invalid`, field error with "line 2", `aria-invalid`, `preview-errors` names `custom_css`, Publish disabled, preview keeps the last valid draft.
- Reset (confirm "Remove branding"): editor back to defaults and the sign-in page back to #2f5bd3 without logo.

## Task Commits
1. `a804a0c` test(04-29): e2e for email code, magic link and the account pages
2. `50a6bae` test(04-29): e2e for live theming from the console

## Verification
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `npx playwright test --list` on the four specs: 13 tests, all in the chromium project (the no-JS file disables JavaScript itself).
- Scratch probe (deleted afterwards) with the local Playwright chromium: `frameLocator(...).locator('html').evaluate(getComputedStyle ...)` and `toHaveCSS` work inside an iframe sandboxed with `allow-same-origin` only, like the console preview; `setContent` with a script under `javaScriptEnabled: false` leaves the DOM untouched.

## Not run
- `tests/e2e/run.sh sqlite|postgres` for the four specs: needs Docker (Mailpit, Postgres), which is not used here (wave rule). The orchestrator runs them in CI and resumes this plan with any failures.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Forced extra file `tests/e2e/lib/email-code.ts`**
- Two specs (email-code and nojs-email-code) share the tenant setup and the request/read/submit steps; the wave rule puts shared helpers in tests/e2e/lib/.
- Commit: a804a0c

**2. [Rule 3 - Blocking] Forced extra edit `tests/e2e/lib/account.ts`**
- `signInForIdToken` always used the default tenant's discovery. Added an optional `issuer` parameter (default unchanged) so the RP flow can run in the email sign-in tenant.
- Commit: a804a0c

**3. [Rule 1 - Bug] nojs-email-code.spec.ts would have run with JavaScript on**
- The nojs project regex in playwright.config.ts does not match `nojs-email-code.spec.ts`. The spec sets `test.use({ javaScriptEnabled: false })` and proves it with a script probe. playwright.config.ts is outside this plan's files, so it was not changed. Other `nojs-*.spec.ts` files from this wave (e.g. nojs-logout.spec.ts) have the same problem unless they do the same; flagged for the orchestrator.

**4. [Design] Dedicated tenant instead of "enable for the test tenant, restore after"**
- Same coverage; no change to the default tenant that keyboard/a11y specs depend on, and nothing to restore if a run dies.

## Self-Check: PASSED
- FOUND: tests/e2e/specs/email-code.spec.ts, nojs-email-code.spec.ts, account.spec.ts, theme.spec.ts, tests/e2e/lib/email-code.ts
- FOUND: commits a804a0c, 50a6bae
