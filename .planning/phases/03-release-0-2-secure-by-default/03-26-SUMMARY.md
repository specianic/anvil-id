---
phase: 03-release-0-2-secure-by-default
plan: 26
subsystem: e2e
tags: [playwright, webauthn, passkeys, cdp-virtual-authenticator, totp, recovery-codes, mailpit, axe]
requires:
  - phase: 03-04
    provides: authenticator fixture (getCredentials, setSignCount, overrideResponse), totp(), expectNoA11yViolations
  - phase: 03-14
    provides: /ui/account/security selectors
  - phase: 03-20
    provides: login passkey button, second-factor page
  - phase: 03-23
    provides: admin audit API
  - phase: 03-24/03-25
    provides: binary wiring, raised e2e auth budget
provides:
  - tests/e2e/lib/account.ts (signInDirect, openAccountSecurity, registerPasskey, enrolTotp, auditEvents, startSampleRp, freePort, signInForIdToken)
  - tests/e2e/specs/passkey.spec.ts (6 tests, Chromium)
  - tests/e2e/specs/totp.spec.ts (1 end-to-end test)
affects: [03-25 (run.sh default spec list), later e2e specs needing an RP or ID token claims]
tech-stack:
  added: []
  patterns:
    - "Sign out in passkey specs = context.clearCookies(): the virtual authenticator lives on the page, so it keeps its credentials"
    - "ID token claims from the browser: a code client whose redirect URI is never served; Playwright captures and fulfils the callback request, the code is exchanged over the back channel"
    - "Deterministic TOTP: enrol with the code of step S, sign in with the code of step S+1 (server window is +-1), replay that code"
key-files:
  created:
    - tests/e2e/lib/account.ts
    - tests/e2e/specs/passkey.spec.ts
    - tests/e2e/specs/totp.spec.ts
  modified: []
key-decisions:
  - "03-26: TOTP replay is made deterministic without waiting: the enrolment code (step S) is rejected at sign-in, the step S+1 code signs in, and the same code is then rejected; only the final account-page check waits (up to one step) for step S+2"
  - "03-26: amr is asserted through a dedicated code client (signInForIdToken) because the sample RP does not expose the ID token; the RP is still used for the usernameless profile check"
  - "03-26: Duplicate registration accepts either the client-side refusal (excludeCredentials -> InvalidStateError -> webauthn.js failed message) or account.passkey_exists, and always asserts exactly one stored passkey and one authenticator credential"
requirements-completed: []
metrics:
  duration: 20min
  completed: 2026-11-25
  tasks: 2
  files: 3
---

# Phase 3 Plan 26: Passkey and TOTP e2e Summary

**This plan adds browser tests for AUTH-04 and AUTH-05. They run against the real anvilid binary with a CDP virtual authenticator. Passkey: a resident credential is registered, usernameless sign-in works through the sample RP with `amr` containing `mfa`, a rolled-back sign counter fails the sign-in and is audited as `passkey_clone_suspected`, and bogus signatures, missing UV and duplicate registration are rejected. TOTP: enrolment uses the code computed from the displayed secret, password + TOTP signs in, a reused code is rejected as a replay, a recovery code works once and triggers the Mailpit notice, and axe runs on the enrolment, recovery-codes and second-factor pages.**

## Performance

- **Duration:** about 20 min
- **Tasks:** 2/2
- **Files:** 3 created

## Accomplishments

- `passkey.spec.ts` (Chromium project, `authenticator` fixture):
  1. Registration on `/ui/account/security` lists the passkey. `getCredentials()` returns one credential with `isResidentCredential: true`, `rpId` = the issuer host and a user handle.
  2. Usernameless sign-in: RP `/login` → "Sign in with a passkey" → RP `/me` shows the user's `sub` and email, with nothing typed. A second sign-in through a code client returns an ID token whose `amr` contains `mfa`. The account page then shows a "last used" date.
  3. Clone detection: after a successful sign-in, `setSignCount(cred, 0)` makes the next sign-in show `login.passkey_failed` and create no session. The admin audit API lists `passkey_clone_suspected` (outcome `failure`) for the user.
  4. and 5. `overrideResponse({isBogusSignature})` and `overrideResponse({isBadUV})` are rejected. After the override is cleared, the same credential signs in again, which shows the failure came from the tampering.
  6. A second registration from the same authenticator is refused, and exactly one passkey stays stored.
- `totp.spec.ts`:
  - Enrolment reads `#totp-secret` and confirms with `totp()`, and 10 recovery codes are collected.
  - The enrolment code is rejected at sign-in. The next-step code signs in through the RP, and the same code is rejected right afterwards.
  - Recovery code #1 signs in, then is rejected the second time. The audit has `recovery_code_used` with `remaining: 9`. Mailpit receives "A recovery code was used ...". The account page shows 9 codes left.
  - axe runs on the enrolment page, the recovery-codes page, the second-factor page and the second-factor error state.
- `lib/account.ts` holds reusable helpers, including a sample-RP launcher (free port, client created by a callback) and `signInForIdToken`, a PKCE code client that returns the ID token claims after checking the nonce.

## Task Commits

1. **Task 1: Passkey e2e:** `c61249a`
2. **Task 2: TOTP e2e:** `c144eb9`

## Verification

- `cd tests/e2e && npm run typecheck`: clean.
- `E2E_PORT=18126 ./run.sh sqlite specs/passkey.spec.ts specs/totp.spec.ts`: 7/7 passed (23 s). Each spec also passed on its own.
- `run.sh` takes the backend as its first argument, so the plan's `./run.sh specs/passkey.spec.ts` has to be written as `./run.sh sqlite specs/...`.

## Deviations from Plan

None in behaviour. `themes/default/static/webauthn.js` needed no fix: registration, usernameless assertion and the error paths all worked as written. Notes:
- The plan says to check `amr` in the ID token. The sample RP does not expose the token, and `lib/rp.ts` and examples/node-rp are outside this plan, so the check uses a dedicated code client built from `lib/account.ts`.
- The test runs used a working tree that also held another parallel plan's uncommitted theme edits (`anvil.css`, `data-label` attributes on account tables). None of the selectors used here changed.

## Follow-ups (outside this plan's files)

- `tests/e2e/run.sh` (owned by 03-25): add `specs/passkey.spec.ts` and `specs/totp.spec.ts` to the default spec list so `just e2e` and CI run them.

## Self-Check: PASSED

- FOUND: tests/e2e/lib/account.ts, tests/e2e/specs/passkey.spec.ts, tests/e2e/specs/totp.spec.ts
- FOUND: c61249a, c144eb9
