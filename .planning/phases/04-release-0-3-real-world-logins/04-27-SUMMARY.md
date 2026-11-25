---
phase: 04-release-0-3-real-world-logins
plan: 27
subsystem: e2e
tags: [e2e, playwright, social-login, linking, console, connections, mock-idp, axe, nojs, auth-07, auth-11]
requires:
  - phase: 04-03
    provides: mock IdP (apple/github), upstream helpers
  - phase: 04-19
    provides: console connection pages and test ids
  - phase: 04-21
    provides: upstream start/callback routes, link confirmation page
  - phase: 04-25
    provides: /ui/account/linked page and selectors
provides:
  - "specs/social.spec.ts: AnvilID-as-upstream, Apple-like (form_post), GitHub-like (PKCE) round trips through the sample RP"
  - "specs/linking.spec.ts: auto-link, confirmation link, account page connect/disconnect, last-method refusal"
  - "specs/nojs-linking.spec.ts: linked accounts page connect/disconnect without JavaScript"
  - "specs/console-connections.spec.ts: console create/edit/rotate/delete with write-only secret"
  - "lib/upstream.ts: createTenant, tenantUsers, listConnections, deleteConnection, githubMockConnection, appleMockConnection, signInAtTenant"
  - "lib/console.ts: startSampleRp(token, name, tenant = 'default')"
  - "playwright.config.ts: nojs project also matches nojs-*.spec.ts"
affects: [04-28, 04-29, phase 4 verification]
tech-stack:
  added: []
  patterns:
    - "Upstream specs use a fresh tenant per test, so connection buttons and auto_link never touch the shared default tenant"
    - "Write-only secret proof: every /api/admin response body the console receives is recorded and checked for the secret"
key-files:
  created:
    - tests/e2e/specs/social.spec.ts
    - tests/e2e/specs/linking.spec.ts
    - tests/e2e/specs/nojs-linking.spec.ts
    - tests/e2e/specs/console-connections.spec.ts
  modified:
    - tests/e2e/lib/upstream.ts
    - tests/e2e/lib/console.ts
    - tests/e2e/playwright.config.ts
key-decisions:
  - "Fresh downstream tenant per upstream test (sample RP gets a tenant parameter) instead of connections on the default tenant"
  - "Connect from the account page asserts the current upstream.linked message page, then opens /ui/account/linked; no redirect is asserted"
  - "nojs project regex widened to nojs-*.spec.ts (the naming 04-27/28/29 plans use); the old regex would have run them with JavaScript on"
requirements-completed: []
duration: about 45 min
completed: 2026-11-26
---

# Phase 4 Plan 27: E2E for Social Sign-in, Linking and Console Connections Summary

**Playwright specs for AnvilID-as-upstream, Apple-like form_post and GitHub-like PKCE sign-ins through the sample RP across sites (mock on 127.0.0.1, AnvilID on localhost), for auto, confirmed and account-page linking with the last-method guard, for a no-JS linked accounts page, and for console connection management with a write-only secret. Type-checked only; none of them has run yet.**

No requirement checkbox was ticked (wave rule). Contributes to AUTH-07 and AUTH-11.

## Specs

| Spec | Tests | What it proves |
|---|---|---|
| social.spec.ts | 3 | (a) a second tenant as generic OIDC upstream: its own login page, then back at the RP; the JIT user's email is unverified (untrusted default). (b) Apple-like: cross-site POST from the mock's approval form to the callback, then 303; `response_mode=form_post`, no PKCE, the mock accepted AnvilID's ES256 client secret; given/family name from the first `user` JSON is stored, and a second sign-in (no user JSON, mock-side rename) leaves it unchanged. (c) GitHub-like: account email = verified primary (secondary and unverified addresses present), PKCE S256 with verifier, User-Agent on the REST calls; a forged callback gives the generic `upstream.failed` login form with status 400 and does not reach the provider. axe: login page with buttons, and the error page |
| linking.spec.ts | 3 | (1) auto-link: RP `sub` = existing user id, one user in the tenant, `identity_linked` mode `auto`. (2) auto_link off: `form#upstream-link` + `upstream.link_explain` (axe), nothing linked yet; wrong password gets `login.invalid_credentials` and no link; the right password finishes at the RP as the existing user (mode `confirmed`); a new browser goes straight in. (3) account page (axe): Connect with Apple-like gives the `upstream.linked` message page (axe), mode `account`, no new user; listed on `/ui/account/linked` (axe), Connect button gone; Disconnect gives `linked.unlinked` and `#linked-none`; a link-only JIT user's Disconnect gets 409 `account.last_sign_in_method` (role alert, axe) and keeps the row |
| nojs-linking.spec.ts | 1 (nojs project) | the linked page renders, Connect through the GitHub-like mock, listed, and Disconnect all work without JavaScript |
| console-connections.spec.ts | 1 | Connections list (axe), new Google connection (kind picker, form, axe), detail with `connection-redirect-uri` = `{ANVIL_URL}/ui/login/upstream/{slug}/callback`, Configured badge, disabled slug, no secret field in the edit form (axe), rename ("Connection saved."), rotate ("Secret saved.", field cleared, axe), list row, delete via the alertdialog (axe). Neither secret appears in page HTML or in any `/api/admin/` response body. afterAll deletes the connection if the test stopped half way |

## Task Commits

1. **Forced extra (shared config):** `187375d` fix(04-27): run nojs-*.spec.ts specs in the nojs project
2. **Task 1:** `77af3ce` test(04-27): social sign-in e2e (with the lib/upstream.ts and lib/console.ts helpers)
3. **Task 2:** `d014e6e` test(04-27): linking and console connection e2e specs

## Verification

- `cd tests/e2e && npx tsc --noEmit -p .`: passes.
- `npx playwright test --list` on the four specs: 7 chromium tests plus 1 nojs test. `nojs-linking` is listed only under nojs.
- Selectors were read from the templates (login.html, upstream_link.html, account_linked.html, message.html, form.html), the handlers (ui/upstream.rs, ui/account_linked.rs), the console sources (routes/connections/*, ConnectionForm.tsx, ConfirmDialog, DataTable) and the 04-19/04-21/04-25 summaries.

## Not run

- **Playwright e2e (sqlite and postgres): not run.** run.sh needs Docker (Mailpit, Postgres), and the wave rules leave e2e to CI. The specs are type-checked and listed, nothing more.
- Assumptions that only a real run can confirm:
  - AnvilID resolves `localhost` to the address it listens on (127.0.0.1) when it fetches its own second tenant's discovery.
  - The session survives the cross-site return. The `/authorize/continue` redirect follows a navigation that started on 127.0.0.1, which is exactly the SameSite behaviour the plan wants proved.
  - A direct upstream sign-in without an authorization request ends on the `login.signed_in` message page.
  - The account page shows the email the upstream asserted at link time.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] nojs project regex did not match `nojs-linking.spec.ts`**
- **Found during:** Task 2
- **Issue:** `playwright.config.ts` matched only `nojs.spec.ts` and `nojs.*.spec.ts`, so `nojs-linking.spec.ts` (and 04-28's `nojs-email-code`, 04-29's `nojs-logout`) would have run in the chromium project with JavaScript enabled.
- **Fix:** regex `/nojs([.-][^/]*)?\.spec\.ts$/`; checked with `--list`.
- **Files modified:** tests/e2e/playwright.config.ts (not in files_modified)
- **Commit:** 187375d

**2. [Rule 3] Shared helpers in tests/e2e/lib (forced extras)**
- `lib/upstream.ts`:
  - `createTenant` (with settings), `tenantUsers`, `listConnections`, `deleteConnection`
  - `githubMockConnection` / `appleMockConnection` (start the mock and create the matching connection)
  - `signInAtTenant`
  - `adminRequest` now also does GET/DELETE.
- `lib/console.ts`: `startSampleRp` has an optional `tenant` (default unchanged).
- These are used by more than one spec, so they live in lib rather than being duplicated.
- **Commit:** 77af3ce

### Notes

- Each upstream test uses its own tenant instead of the default tenant the plan implies ("sign in at the sample RP"). This keeps connection buttons off the default login page, which a11y and keyboard specs audit, and lets the confirmation test turn `auto_link` off without restoring shared settings.
- The console only manages the default tenant (`CONSOLE_TENANT`), so console-connections works there and cleans up after itself.
- After Connect, the specs assert the current `upstream.linked` message page and do not assert a redirect to `/ui/account/linked`. That redirect is the 04-25 follow-up. When it lands, change the two `upstream.linked` assertions (linking.spec.ts and nojs-linking.spec.ts) to a URL check.
- The Apple-like approval page is a button the spec clicks (the mock has no auto-submit script). That page belongs to the mock, not AnvilID, so it gets no axe audit.
- axe needs script injection, so the nojs spec does not run it. The same pages are audited in linking.spec.ts.

## Self-Check: PASSED

- FOUND: tests/e2e/specs/social.spec.ts (263 lines), linking.spec.ts (255), nojs-linking.spec.ts (73), console-connections.spec.ts (167)
- FOUND: commits 187375d, 77af3ce, d014e6e

## CI follow-up (run 45720491636)

Three tests failed on both backends. All three causes were in the tests; no product bug was found. The fix is commit `90942c6`, which changes `lib/mock-idp.ts` (forced extra), `specs/mock-idp.spec.ts` and `social.spec.ts`.

- **Apple-like sign-in and account-page Connect** (`upstream.link_failed`):
  - **Cause:** the 04-03 mock signed its ID tokens with ES256. Real Apple signs with RS256, and AnvilID's social presets accept RS256 only (`providers.rs`, `allowed_algs = [RS256]`). The callback therefore rejected the token.
  - **Fix:** the mock now signs ID tokens with RS256 using a per-start RSA key, and its JWKS publishes that key. The ES256 client-secret check is unchanged.
  - The 04-03 summary's "ES256 ID tokens" no longer holds.
- **AnvilID as a generic OIDC upstream:**
  - **Cause:** the audit reason was `email_missing`. AnvilID returns `email` from UserInfo, not in the ID token (OIDC Core 5.4), and the connection had `fetch_userinfo` off.
  - **Fix:** the spec now sets `fetch_userinfo: true`.
  - Possible product follow-up, not done here: fall back to UserInfo when the ID token lacks `email`, or turn `fetch_userinfo` on by default for generic OIDC.
- **Local run without Docker:**
  - Setup: the debug anvilid built at 00:00. The main tree did not compile at that point because of 04-34 work in progress. It ran from a scratch copy with a fresh data dir and the run.sh flags.
  - Result: `social`, `linking`, `nojs-linking` and `mock-idp` all pass (12 passed).
  - `console-connections` was not re-run locally because it needs the console embedded in a release build. It passed in CI.
