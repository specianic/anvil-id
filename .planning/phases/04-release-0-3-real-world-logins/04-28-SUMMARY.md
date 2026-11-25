---
phase: 04-release-0-3-real-world-logins
plan: 28
subsystem: e2e
tags: [e2e, playwright, logout, backchannel-logout, mfa-policy, step-up, prompt, select_account, create, nojs, axe]
requires:
  - phase: 04-03
    provides: sample RP /logout, /logged-out, /backchannel_logout(/received); lib/logout.ts
  - phase: 04-13
    provides: /logout, /ui/logout confirmation, /ui/signed-out, logout.* sentences
  - phase: 04-16
    provides: MFA policy enforcement, in-flow TOTP enrolment, acr_values step-up, session switch
  - phase: 04-17
    provides: back-channel delivery worker
  - phase: 04-20
    provides: prompt=select_account chooser, prompt=create
  - phase: 04-27
    provides: playwright.config.ts routes nojs-*.spec.ts to the nojs project
provides:
  - "tests/e2e/specs/logout.spec.ts, nojs-logout.spec.ts, mfa-policy.spec.ts, prompt.spec.ts"
  - "tests/e2e/lib/logout.ts: startLogoutRp(token, name, extra?) -> LogoutRp {base, clientId, stop}"
  - "tests/e2e/lib/admin.ts: tenantSettings, updateTenantSettings, withTenantSettings (restores patched fields), userSessions"
  - "tests/e2e/lib/authorize.ts: addAuthorizeParams(page, params, issuer?) -> unroute fn (adds prompt/acr_values to RP and code-client authorization requests)"
affects: [04-32, 04-gate]
tech-stack:
  added: []
  patterns:
    - "Authorization parameters the sample RP cannot send are added by intercepting the RP's /login response (route.fetch maxRedirects 0) and rewriting the Location to /authorize; direct /authorize navigations get a 302 to the same URL plus the parameters. Playwright routes only the first request of a redirect chain."
    - "Specs that change default-tenant settings use withTenantSettings, which restores the previous value of every patched field in finally"
key-files:
  created:
    - tests/e2e/specs/logout.spec.ts
    - tests/e2e/specs/nojs-logout.spec.ts
    - tests/e2e/specs/mfa-policy.spec.ts
    - tests/e2e/specs/prompt.spec.ts
    - tests/e2e/lib/admin.ts
    - tests/e2e/lib/authorize.ts
  modified:
    - tests/e2e/lib/logout.ts
key-decisions:
  - "The back-channel entry's sid is checked against the session id from the admin API (listUserSessions): the sample RP hides the ID token, and sid = browser session id"
  - "Step-up is proven on the session itself too: same session ids before/after, and the admin API shows that session with acr mfa and amr otp+mfa"
  - "Off and step-up share one test: under off a TOTP user gets amr [pwd]; acr_values=mfa then asks only for the second factor (off + voluntary acr + factor = SecondFactor in policy::mfa)"
requirements-completed: []
duration: 35min
completed: 2026-11-25
---

# Phase 4 Plan 28: E2E for logout, MFA policy, step-up and prompt Summary

**There are now four Playwright specs (10 tests) covering:**
- RP-initiated logout and verified back-channel logout through the sample RP
- the confirmation page and the unregistered-URI error page
- MFA policy `required`, `off` and the client override
- `acr_values` step-up on the same session
- `prompt=select_account`, including the switch that revokes the old session and delivers a back-channel logout
- `prompt=create`
- no-JavaScript runs of the confirmation page and the chooser

Axe runs on the confirmation, signed-out, error, chooser, enrolment and recovery-codes pages. **All 10 tests pass locally against the real binary on SQLite** (see Verification for how they were run without Docker).

No requirement checkbox was ticked (wave rule).

## Tests

| Spec | Test | Proves |
|---|---|---|
| logout | RP-initiated logout | The RP's Log out link returns to `/logged-out` with only `state`, which the RP verifies. There is exactly one back-channel entry for the sub, with `sid` = the session id (the RP verified the token before recording it). After that there are 0 sessions and the next RP login shows `form#login`. |
| logout | no hint | `{issuer}/logout` leads to `/ui/logout` (axe). The session is still active there. Confirming leads to `/ui/signed-out` with "You have been signed out." (axe). Then the back-channel is delivered and the session is gone. |
| logout | unregistered URI | `/elsewhere`, `?foo=bar` and a trailing `/` each give a 400 at `/logout` with `logout.redirect_uri_not_registered` and its contract sentence (axe). The session stays active, nothing is delivered, and the RP login works without a form. |
| nojs-logout | confirmation | The confirmation flow works with JS off. Afterwards the account pages redirect to the login page. |
| nojs-logout | chooser | With JS off: Continue keeps Alice; "Use another account" leads to Bob. Alice ends with 0 sessions and the back-channel is delivered. |
| mfa-policy | required | Password leads to `form#mfa-enroll` (axe). A wrong code is refused. The right code shows 10 recovery codes (axe), then Continue reaches the RP. The next sign-in asks for the second factor (code of step S+1). |
| mfa-policy | off + step-up | Under `off`, a TOTP user's ID token has `amr ["pwd"]` and acr pwd. Adding `acr_values=urn:anvilid:acr:mfa` shows `form#second-factor` with no `#password`/`#identifier`. The resulting ID token has acr mfa, amr ⊇ otp+mfa and the same `sid`. No new session is created, and the session shows acr mfa. |
| mfa-policy | client override | Tenant `optional`: the plain client reaches the RP without a factor, while the client with `mfa_policy: required` gets the enrolment page. |
| prompt | select_account | Chooser (axe), then Continue keeps Alice (no back-channel yet). Chooser, then Other, then Bob signs in and reaches the RP as Bob. Alice ends with 0 sessions and Bob with 1. A back-channel entry exists for Alice and none for Bob. |
| prompt | create | `registration: open`, `require_verified_email: false` (restored afterwards). `/ui/registration` leads to the RP signed in as the new account, and the user is active. |

## Task Commits

1. **Task 1: Logout specs + helpers:** `ca2bf96` test(04-28): logout e2e: RP-initiated, back-channel, confirmation and no-JS chooser
2. **Task 2: MFA policy and prompt specs:** `585d580` test(04-28): MFA policy, acr_values step-up and prompt e2e specs

## Verification

- `cd tests/e2e && npx tsc --noEmit -p .` passes.
- **Local run without Docker, with real browser runs on SQLite:**
  - Setup: `cargo build -p anvilid` (debug) in the main tree, then a copy of the binary served from a scratch dir with a fresh data dir. The flags match run.sh: `--breach-check off` and `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=1200`. There was no SMTP (none of these specs needs Mailpit).
  - Playwright ran with `--workers=1` on the four specs: **10/10 passed in 26 s**.
  - The scratch dir was deleted afterwards.
- These checks were run in the browser rather than only type-checked:
  - the back-channel token's sid
  - the route-based `prompt`/`acr_values` injection, in both JS and no-JS modes
  - restoring the tenant settings

## Not run

- `tests/e2e/run.sh sqlite|postgres …`: Docker (Mailpit, Postgres) is not used here. **Postgres e2e and the release-build run are left for CI.**
- The full suite was not run together with these specs. The specs restore the tenant settings they change, so other specs should be unaffected; CI will show it.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Shared helpers in tests/e2e/lib (files outside files_modified)**
- `lib/logout.ts`: `startLogoutRp` registers the RP's client with the logout metadata. Three specs use it.
- `lib/admin.ts`: tenant settings (`withTenantSettings` restores in finally) and the user sessions list. Three specs use it.
- `lib/authorize.ts`: `addAuthorizeParams`. The sample RP cannot send `prompt`, and `signInForIdToken` cannot send `acr_values`.
- Commit: ca2bf96

**2. [Rule 1 - Bug] Playwright does not route redirected requests**
- **Found during:** the local run. The first chooser test went straight to `/me`, because the RP's 302 to `/authorize` was never routed.
- **Fix:** `addAuthorizeParams` now intercepts the RP's GET navigation, fetches it without following redirects, and rewrites a `Location` that points to `/authorize`.
- Commit: ca2bf96

**3. [Rule 1 - Test bug] Session count in the step-up test**
- `page.context().clearCookies()` does not end the enrolment browser's session on the server. The assertion now finds the sign-in session by the ID token's `sid` and compares the set of session ids before and after.
- Commit: 585d580

**4. [Design] nojs-logout.spec.ts relies on 04-27's config fix**
- The original `NOJS_SPECS` regex did not match `nojs-logout.spec.ts`. 04-27 (`187375d`) changed it to `nojs([.-][^/]*)?\.spec\.ts$` during this wave, and the no-JS tests ran in the `nojs` project. Each test still asserts that JS is off.

**5. [Scope] Off and step-up combined; tenant settings via withTenantSettings**
- One test covers "off skips the second factor" and then the step-up on that single-factor session.
- The plan's "restore tenant policy at the end" is done per test (in finally), not once in afterAll.

### Found, out of scope (logged in deferred-items.md)
- Only `/logout` and `/ui/logout` wake the back-channel delivery worker. A session switch (and account or admin revocation) waits for the 10 s poll. The switch tests allow 30 s.

## Self-Check: PASSED

- FOUND: tests/e2e/specs/logout.spec.ts (158 lines), mfa-policy.spec.ts (231), prompt.spec.ts (136), nojs-logout.spec.ts (110), lib/admin.ts, lib/authorize.ts
- FOUND: commits ca2bf96, 585d580
