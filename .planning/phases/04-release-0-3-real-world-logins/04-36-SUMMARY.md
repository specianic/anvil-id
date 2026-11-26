---
phase: 04-release-0-3-real-world-logins
plan: 36
subsystem: web
tags: [backchannel-logout, wake, upstream, lockout, captcha, passkey, console, body-limit, gap-closure]
requires:
  - phase: 04-17
    provides: LogoutDeliveryWorker, AppState::logout_wake
  - phase: 04-18
    provides: per-request body limit middleware (64 KiB, 400 KiB logo uploads)
  - phase: 04-19
    provides: client form labels for the 0.3 client fields
  - phase: 04-21
    provides: upstream buttons on the sign-in page (upstream_buttons)
  - phase: 04-28
    provides: the wake gap finding (switch, account and admin revocations waited for the 10 s poll)
provides:
  - "AppState::wake_logout_worker: the single place that notifies the back-channel worker"
  - "TestApp::logout_wake() -> Arc<Notify> (tests/support/mod.rs)"
  - "Upstream buttons on lockout (429), CAPTCHA required/failed and passkey failure/lockout pages"
  - "Console client detail card 'Logout and security' (data-testid client-logout-security)"
  - "Security tests for 04-32's map: backchannel_wake, upstream_buttons, security_body_limit"
affects: [04-32, 04-gate]
tech-stack:
  added: []
  patterns:
    - "Revoking handlers call state.wake_logout_worker() after a successful revoking call; read handlers never do"
    - "Sign-in pages re-rendered outside the normal Render path pass Extras.upstream via identify_buttons"
key-files:
  created:
    - crates/anvil-web/tests/backchannel_wake.rs
    - crates/anvil-web/tests/upstream_buttons.rs
    - crates/anvil-web/tests/security_body_limit.rs
  modified:
    - crates/anvil-web/src/state.rs
    - crates/anvil-web/src/ui/logout.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/account_sessions.rs
    - crates/anvil-web/src/ui/account_profile.rs
    - crates/anvil-web/src/ui/recovery.rs
    - crates/anvil-web/src/admin/sessions.rs
    - crates/anvil-web/src/admin/users.rs
    - crates/anvil-web/tests/support/mod.rs
    - admin-ui/src/routes/clients/$clientId.tsx
    - tests/e2e/specs/console.spec.ts
    - tests/e2e/specs/prompt.spec.ts
    - tests/e2e/specs/nojs-logout.spec.ts
key-decisions:
  - "Every sign-in wakes the back-channel worker (signed_in_response): cheaper than threading a revoked flag out of the flow engine; a spurious wake costs one claim query"
  - "Recovery wakes after every reset POST (token present): the flow outcome is opaque behind the page response"
  - "Password change wakes only when 'sign out other sessions' was ticked"
metrics:
  duration: ~95min
  completed: 2026-11-26
---

# Phase 4 Plan 36: Back-channel wake, gated-page upstream buttons, console client card, body-limit test Summary

**Every revocation path now wakes the back-channel worker through one helper, `AppState::wake_logout_worker`, so a session switch delivers within seconds even with a 1 h poll. Locked, CAPTCHA-gated and passkey-failed sign-in pages list the tenant's upstream buttons. The console client card shows the 0.3 logout, resource and MFA fields. A regression test covers the 64 KiB / 400 KiB body limits.**

## Wake call sites (`state.wake_logout_worker()`)

| Path | Handler |
|------|---------|
| RP-initiated `/logout`, `/ui/logout` confirm | `ui/logout.rs::logout_finished` (when `revoked`) |
| Every sign-in (password, passkey, email code, magic link, MFA, upstream), so also the session switch | `ui/login.rs::signed_in_response` |
| Account page: sign out one session (this browser or another) | `ui/account_sessions.rs::revoke_one` |
| Account page: sign out all others | `ui/account_sessions.rs::revoke_others` |
| Password change with "sign out other sessions" | `ui/account_profile.rs` password submit |
| Recovery completion (every POST that carries a reset token) | `ui/recovery.rs::submit` |
| Admin `DELETE …/sessions/{id}` and `DELETE …/users/{id}/sessions` | `admin/sessions.rs` |
| Admin `DELETE …/users/{id}` | `admin/users.rs::delete_user` |

`grep -rn "logout_wake().notify_one" crates/anvil-web/src` returns nothing. `logout_wake()` stays for the binary and tests.
The service grep (`revoke_with_families|revoke_all_for_user|sessions().revoke(|complete_recovery|users().delete(`) found no other web-reachable path. `SessionService::revoke` has no web caller. `SessionService::create(replaces)` runs inside sign-in, which is already covered.

## Tests (for 04-32's security map)

- `backchannel_wake` (8): one test per path listed above; reading the sessions page, the login page and the admin session list leaves no permit; end to end, with a worker on the app's Notify and `poll = 1 h`, Alice signs in, gets an RP session, then Bob signs in in the same browser, and Alice's logout token (her `sid`/`sub`) reaches the wiremock RP within 5 s.
- `upstream_buttons` (6): the enabled connection is listed and the disabled one is not, on: the sign-in page, the password lock after a failed attempt and the pre-flow lock (429), CAPTCHA required and CAPTCHA failed (400 with the widget), a passkey failure (400 sign-in form), the passkey lock after a failure and the pre-flow passkey lock (429). Without connections, the lock and passkey pages have no `anvil-upstream` group.
- `security_body_limit` (3): `BODY_LIMIT + 1` with `Content-Length` gives 413 on `POST /token`, `POST /ui/login?flow=…`, `POST /logout`, admin `PATCH /tenants/default` and `PUT /tenants/default/branding`. The tenant and client logo routes refuse 400 KiB + 1 (413) and accept a 100 KiB PNG (200).

## Verification

- `cargo test -p anvil-web --test backchannel_wake --test upstream_buttons --test security_body_limit`: 17 passed (SQLite)
- `cargo test -p anvil-web --test logout --test security_logout --test sessions --test account_profile --test flow_recovery --test admin_api --test authorize_prompt --test security_bruteforce --test captcha --test flow_passkey --test upstream_login --test render --test i18n --test i18n_catalogs --test admin_branding --test shell --test console --test backchannel`: all green (render snapshots unchanged)
- `cargo test -p anvilid --test backchannel_worker`: 1 passed
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean
- admin-ui: `npm run typecheck`, `npm run check:api`, `npm run build`: green (`npm ci` skipped; node_modules already installed, to keep disk churn low)
- `cd tests/e2e && npx tsc --noEmit -p .`: clean

**Not run:** Postgres backend, Playwright e2e (`console.spec.ts`, `prompt.spec.ts`, `nojs-logout.spec.ts`: Docker unavailable; left to CI).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Body-limit test cannot import `is_logo_upload` / `LOGO_BODY_LIMIT`**
- `admin::branding` is `pub(crate)`, so the test defines `LOGO_BODY_LIMIT = 400 * 1024` locally and checks the route match through HTTP on both logo routes and a non-logo branding route.

**2. [Rule 3 - Blocking] `NewAuthorizationCode.issuer` (04-34 landed mid-plan)**
- `backchannel_wake.rs` sets `issuer: app.issuer(None)` in its code literal.

**3. Console spec placement**
- The sample RP's client is found by its name row in the clients table, because `SampleRp` does not expose its client_id. The card is scoped by `data-testid="client-logout-security"`, because the edit form uses the same labels. The sample RP registers no logout URIs, resources or MFA policy, so the assertions check the defaults ("None", "None: tokens are for this client", "Tenant default") and that the session-required row is absent.

**4. Commit split**
- Task 1's commit contains only the `signed_in_response` wake from login.rs. Task 2's commit has the button changes in the same file.

### Forced extras
None beyond files_modified. No new UI strings in the Rust templates, so no catalog changes. The console strings are inline English, like the rest of the console.

## Deferred Issues / Findings

- A body above the limit sent **without** `Content-Length` (streamed) is still refused before any handler logic. Form pages and the admin API answer **400**, not 413: their extractor rejection maps the length-limit error to their own bad-request answer (admin: `"Failed to buffer the request body: length limit exceeded"`). `/token` and `/logout` answer 413. The test accepts 400 or 413 for the streamed case. Making all of them 413 would mean changing the shared rejection mapping (`admin` error mapping, `ui::login::bad_form`), which is outside this plan. Recorded for the gate.

## Commits

- e65c2e7 feat(04-36): one back-channel wake helper on every revocation path
- 17df47e feat(04-36): upstream buttons on the lockout, CAPTCHA and passkey-failure pages
- 1b540fc feat(04-36): console client card logout/resource/MFA fields and body-limit regression test

## Self-Check: PASSED
