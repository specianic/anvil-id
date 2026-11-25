---
phase: 03-release-0-2-secure-by-default
plan: 27
subsystem: e2e-a11y
tags: [e2e, playwright, consent, sessions, a11y, axe, wcag22, nojs, keyboard, theme-css]
requires:
  - phase: 03-04
    provides: axe fixture, keyboard/no-JS specs, lib/totp.ts
  - phase: 03-14
    provides: account security, TOTP enrolment, recovery codes pages
  - phase: 03-17
    provides: consent screen and connected apps
  - phase: 03-19
    provides: sessions page
  - phase: 03-20
    provides: passkey button, second-factor page
  - phase: 03-11
    provides: form_post interstitial
provides:
  - consent.spec.ts (remember / revoke / deny / form_post)
  - sessions.spec.ts (two-browser list, sign out other, sign out all others, sign out this browser)
  - axe/no-JS/keyboard coverage of every 0.2 page
  - default-theme CSS for the 0.2 classes, too_many_requests error sentence
affects: [03-25, 03-28, 03-29]
tech-stack:
  added: []
  patterns:
    - "Unserved loopback redirect URIs: form POSTs are answered with page.route; redirect targets are observed with page.waitForRequest (Playwright routes do not see redirect targets)"
    - "Keyboard order check = tabbing visits exactly the visible focusable controls of <main> in DOM order"
key-files:
  created:
    - tests/e2e/specs/consent.spec.ts
    - tests/e2e/specs/sessions.spec.ts
  modified:
    - tests/e2e/specs/a11y.spec.ts
    - tests/e2e/specs/nojs.spec.ts
    - tests/e2e/specs/keyboard.spec.ts
    - themes/default/static/anvil.css
    - themes/default/templates/error.html
    - themes/default/templates/account_sessions.html
    - themes/default/templates/account_security.html
    - themes/default/templates/consent.html
    - themes/default/templates/recovery_codes.html
key-decisions:
  - "03-27: Account pages get a wider card (main:has(> .anvil-account-nav), 50rem); below 30rem tables stack one block per row with cells labelled by data-label (pseudo-element content with empty alt text, so screen readers keep the header association only)"
  - "03-27: The TOTP QR is 13rem max, black modules on a white quiet-zone box in every colour scheme, forced-color-adjust none (scanners need dark-on-light)"
  - "03-27: Consent Deny is styled as a secondary button (class appended after value= so 03-17's markup assertion still holds); ids, names and {form.id}-submit selectors unchanged"
  - "03-27: The recovery-code copy box is 5 rows instead of 10 so focusing it on a 800 px desktop viewport shows it entirely"
requirements-completed: []
metrics:
  duration: 35min
  completed: 2026-11-25
  tasks: 2
  files: 11
---

# Phase 3 Plan 27: Consent/sessions e2e and the 0.2 accessibility audit Summary

**The consent screen (remember, revoke at Connected apps, deny, form_post) and the sessions page are now tested end to end in a browser. axe (WCAG 2.2 AA), no-JavaScript and keyboard checks cover every 0.2 page, and the default theme now has CSS for all of them, including a QR code capped at a scannable size.**

## Performance

- Duration: about 35 minutes
- Tasks: 2, plus the extra items (CSS rules and the `too_many_requests` sentence)
- Files: 11

## Task commits

| # | Task | Commit |
|---|------|--------|
| 1 | Consent and sessions e2e | `fd3d684` |
| extra | error.html: `too_many_requests` sentence | `f8a9603` |
| 2 | axe / no-JS / keyboard audit of the 0.2 pages, theme CSS and template fixes | `50a6dd9` |

## What the specs prove

**consent.spec.ts** runs the sample RP on a free port, using a client created with `consent_mode: required`.
- On first sign-in, the consent page names the client and lists its scopes. Allow returns to the RP's `/me`.
- The second sign-in goes straight back to the RP. The test records every main-frame navigation to prove `/ui/consent` was never shown.
- The RP refresh works (`refresh-count` 1). Then the user removes the app at `/ui/account/apps` and sees `apps.revoked`.
- After the removal, the RP refresh fails with `invalid_grant` and the next sign-in shows the consent page again.
- Deny makes the RP show `access_denied`, and Connected apps is empty afterwards.
- With `response_mode=form_post`, `form_post.js` posts `code`, `state` and `iss` to the redirect URI. A route handler captures the POST.

**sessions.spec.ts** signs one user in from browsers A and B.
- A sees 2 rows; its own row has `data-current` and the "(this device)" marker.
- A signs out B and sees `sessions.revoked`. B's next visit to `/ui/account/sessions` goes to `/ui/login`.
- With browsers C and D added, "Sign out all other sessions" leaves 1 row (`sessions.revoked_others`), and C and D are signed out.
- A then signs out its own row, lands on `/ui/login` and stays signed out.

**a11y.spec.ts** checks each page state with axe in light and dark mode at 375 and 1280 px, plus a 320 px reflow check. New page states:
- login, asserting the passkey button is visible in the JS project
- account security: empty, with a passkey (virtual authenticator fixture), and with an authenticator app
- TOTP enrolment: clean, with a wrong code, plus a QR size check of 150–220 px and square at both widths
- recovery codes
- second factor: clean, with a wrong code, and with the recovery-code disclosure open
- consent
- connected apps: empty and with an app
- form_post interstitial (`form_post.js` blocked so it stays on screen)
- sessions with two browsers, before and after signing one out

**nojs.spec.ts** (JavaScript disabled):
- password plus TOTP second factor through the sample RP (enrolment done through the no-JS account pages; the passkey buttons stay hidden)
- consent Allow
- `form_post` via the Continue button
- signing out another session

**keyboard.spec.ts** (desktop and mobile) covers second factor, consent, account security / TOTP enrolment / recovery codes, sessions and connected apps:
- Tabbing visits exactly the visible controls of `<main>` in DOM order, with a visible focus that is in view and not covered.
- Targets are at least 24 px, including `<summary>`.
- `autocomplete="one-time-code"` and `inputmode="numeric"` are set, and paste is allowed on the code and recovery-code fields (3.3.8).
- The disclosure opens and closes with Enter and Space.
- The wrong-code error is linked through `aria-describedby` and uses `role="alert"`.
- Consent Deny submitted with Enter returns `access_denied`, and the right code submitted with Enter signs in.

## a11y / CSS fixes

axe found no violations on the new pages, but there was no CSS for most 0.2 classes. Added:

1. **`.anvil-qr`**: the QR code is now at most 13rem wide (`min(13rem, 100%)`) and centred. Modules are black on white with a border box in both colour schemes, and `forced-color-adjust: none` keeps it scannable. The SVG scales to the box at a 1:1 ratio. Before, it stretched to the full card width.
2. **`.anvil-table`**: the caption is muted and left-aligned, row separators are drawn, and long user agents wrap (`overflow-wrap: anywhere`). Row actions are compact outlined buttons, 36 px high. Below 30rem each row becomes a block: `thead` is visually hidden, each cell is labelled from its `data-label` (added to the templates) and the action sits underneath. No horizontal scroll at 320 px.
3. **`.anvil-recovery-codes`**: two columns of monospace codes, one column under 30rem. The copy textarea gets the input styling (3:1 border, focus ring) and is now 5 rows.
4. **`.anvil-secret`**: larger monospace text with letter and word spacing, `user-select: all`.
5. **`.anvil-passkey` and `.anvil-secondary`**: a divider above the passkey form and an outlined secondary button. A global `[hidden] { display: none !important }` keeps the passkey trigger hidden until `webauthn.js` reveals it.
6. **`.anvil-disclosure`**: a bordered `<details>` with a 44 px summary in the primary colour, a decorative triangle (`content: … / ""`) and the shared focus ring.
7. **`.anvil-captcha`**: centred; it scrolls inside the card instead of making the page scroll at 320 px.
8. **Consent**: the fieldset is reset, the scope list styled, and the Allow/Deny row wraps, with Deny as a secondary button.
9. **Account pages**:
   - wider card;
   - section nav with 44 px targets; the current page is marked by bold text and a 3 px bar, not by colour alone (1.4.1);
   - section spacing and an app list with separators.
10. **Forced colours**: the textarea, disclosure, table borders and current nav bar stay visible. The existing reduced-motion rule covers everything.
11. **Form spacing**: paragraphs inside forms no longer add margins on top of the form gap.
12. **error.html**: `too_many_requests` now reads "Too many attempts. Please wait a moment and try again."

## Verification

- `npm run typecheck`: clean.
- `run.sh sqlite` with consent, sessions, a11y, nojs and keyboard specs: 33/33 passed. The Postgres run also passed 33/33.
  - These runs used a scratch copy of run.sh with different Mailpit and AnvilID ports and output directory, because other executors were using the default ports. The spec and server behaviour were unchanged, including `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=1200`.
- `cargo test -p anvil-web --test render`: 13 passed, with no snapshot changes (no render snapshot covers the touched templates; `error` uses a different key).
- `--test consent --test security_ratelimit --test account_security --test sessions --test account_apps --test flow_mfa --test security_csp`: all passed.
- Screenshots of the TOTP page (light 1280 px, dark 320 px), sessions (1280 px, 320 px), recovery codes, second factor and login were reviewed by eye.

## Manual checklist (for the PR template)

- [ ] Screen reader (NVDA or VoiceOver): the consent page reads the client name and scopes as the fieldset legend and list; Allow and Deny are announced as buttons.
- [ ] Screen reader: the sessions and passkeys tables are announced as tables with column headers at desktop width; at under 30rem the stacked cells still read header plus value.
- [ ] Screen reader: the second-factor disclosure announces expanded/collapsed; the wrong-code error is announced once.
- [ ] Scan the TOTP QR with two real authenticator apps in light mode, dark mode and Windows High Contrast.
- [ ] Windows High Contrast / forced colours: account nav current item, table rows, disclosure and buttons keep visible boundaries.
- [ ] 200% and 400% zoom on consent, sessions and TOTP enrolment: no loss of content, no two-direction scroll.
- [ ] Password-manager autofill of the one-time code on the second-factor and enrolment pages (3.3.8).
- [ ] Turnstile in managed mode at 320 px (see deferred items: `data-size="flexible"`).

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 - Bug] Recovery-code copy box partly off-screen when focused on desktop.**
- **Found during:** Task 2 (keyboard spec, desktop 1280x800).
- **Issue:** with 10 rows, focusing `#recovery-codes-text` left it partly below the fold. Chromium does not scroll a partly visible element on focus.
- **Fix:** `rows="5"`; the content scrolls inside the box.
- **Files:** `themes/default/templates/recovery_codes.html`. **Commit:** `50a6dd9`.

**2. [Test design] Redirect targets are not intercepted by Playwright routes.**
- In a11y, keyboard and nojs, consent Allow/Deny to an unserved loopback redirect URI is observed with `page.waitForRequest`. The later account page opens in a second tab of the same context, because the error page's navigation would interrupt `goto`.
- The form_post captures, where the POST goes straight to the redirect URI, still use `page.route`.

**3. [Scope] The sample RP is started inside consent.spec.ts**, the same way nojs.spec.ts does it. `run.sh` and `lib/` belong to 03-25/03-26 in this wave.

No product bugs were found: every consent, session, MFA and form_post behaviour matched the 03-11/14/17/19/20 summaries.

## Follow-ups (recorded in deferred-items.md)

- Add `consent.spec.ts` and `sessions.spec.ts` to run.sh's default spec list (03-25 owns run.sh).
- Add `data-size="flexible"` for Turnstile in captcha.html.
- Move the node-rp spawn helpers into lib/.
- Document the new theme classes, `data-label` and the `too_many_requests` sentence in `themes/default/README.md`.

## Self-Check: PASSED

- FOUND: tests/e2e/specs/consent.spec.ts, tests/e2e/specs/sessions.spec.ts, themes/default/static/anvil.css, themes/default/templates/error.html
- FOUND: fd3d684, f8a9603, 50a6dd9
