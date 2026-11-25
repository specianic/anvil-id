---
phase: 02-release-0-1-first-login
plan: 15
subsystem: web-ui
tags: [axum, login, registration, verification, recovery, setup, csrf, cookies, csp, enumeration]
requires:
  - phase: 02-09
    provides: FlowService / SessionService / FlowOutcome
  - phase: 02-10
    provides: BootstrapService (peek, complete_setup)
  - phase: 02-12
    provides: web shell, CookiePolicy, Renderer, error pages, Fetch-Metadata layer, TestApp harness
  - phase: 02-22
    provides: sealed outbox payloads (FlowService.kek)
provides:
  - "GET/POST /ui/login, /ui/registration, /ui/verification, /ui/recovery (tenant-relative)"
  - "GET/POST /setup (installation-level, root only)"
  - "AppState::ui_flow_service / ui_session_service / ui_bootstrap_service"
  - "tests/ui_helpers: Client trait, form driving (hidden inputs + CSRF), outbox reading with open_payload, OwnApp (production bootstrap install)"
affects: [02-13, 02-17, 02-18, 02-19]
tech-stack:
  added: []
  patterns:
    - "One shared submit path (login.rs: start_page / submit_page / outcome_response) used by all four tenant pages"
    - "Status rule: form with any error message -> 400, message page -> 200, sign-in bound to a request -> 303 See Other"
key-files:
  created:
    - crates/anvil-web/tests/flow_login.rs
    - crates/anvil-web/tests/flow_registration.rs
    - crates/anvil-web/tests/flow_recovery.rs
    - crates/anvil-web/tests/security_setup.rs
    - crates/anvil-web/tests/security_csrf.rs
    - crates/anvil-web/tests/security_cookies.rs
    - crates/anvil-web/tests/security_csp.rs
    - crates/anvil-web/tests/security_enumeration.rs
    - crates/anvil-web/tests/ui_helpers/mod.rs
    - crates/anvil-web/tests/snapshots/flow_login__login_form.snap
  modified:
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/registration.rs
    - crates/anvil-web/src/ui/verification.rs
    - crates/anvil-web/src/ui/recovery.rs
    - crates/anvil-web/src/ui/setup.rs
key-decisions:
  - "Shared page helpers live in ui/login.rs as pub(super) items because ui/mod.rs is owned by 02-12"
  - "A POST without a parseable ?flow= id or without csrf_token is the csrf 403 page, before any flow lookup"
  - "A malformed ?request= value renders the invalid_request error page (400); request ids are not checked for existence here (authorize/continue does that)"
  - "Login without ?request= renders message.html with body key login.signed_in (200); with ?request= -> 303 to {issuer}/authorize/continue?request=…"
  - "Registration GET with a non-open mode renders the registration.disabled message page and starts no flow"
  - "/setup peeks the token on both GET and POST before any flow or hashing work; the setup token travels as a hidden form field; the page only answers at the root (path/host tenants -> 404)"
  - "Setup flow form action is {public_url}/setup?flow=… (FlowContext.ui_base = public URL), flow row and cookie in the system tenant"
requirements-completed: []
requirements-addressed: [AUTH-01, AUTH-02, AUTH-03, UI-01, ADM-03, SEC-04, QUAL-01, QUAL-02]
duration: 16min
completed: 2026-11-25
---

# Phase 2 Plan 15: Built-in UI pages and browser-security tests Summary

**Users can now log in, register, confirm their email, recover a password and complete first-run setup through plain HTML forms with no JavaScript. Negative tests for CSRF, cookie attributes, CSP and account enumeration pass on both SQLite and Postgres.**

## Performance

- Duration: about 16 min
- Tasks: 2/2
- Files: 5 handler files modified, 10 test files and 1 snapshot created

## Accomplishments

- **Tenant pages** (`ui/login.rs`, `registration.rs`, `verification.rs`, `recovery.rs`):
  - A GET starts a flow, sets the flow cookie (SameSite=Strict) and renders the form.
  - A POST checks the `?flow=` id, the CSRF token, the flow cookie and the current session, then calls `FlowService::submit`.
  - Outcome mapping:
    - `Render` gives 400 if the form carries an error, otherwise 200.
    - `Restarted` sets the new flow cookie and shows `flow.expired`.
    - `Message` clears the flow cookie and shows `message.html`.
    - `SignedIn` sets the rotated session cookie, clears the flow cookie, and answers 303 to `{issuer}/authorize/continue?request=…`, or shows the signed-in message page when no request is bound.
    - `Forbidden` gives the `csrf` 403 page.
- The login page shows the registration link only when registration is `open`. Page links carry `?request=` along.
- **Setup** (`ui/setup.rs`):
  - An invalid, used or expired token gives the 403 `invalid_request` page with no form, on both GET and POST.
  - A valid POST runs the setup flow, then `BootstrapService::complete_setup`, then renders `setup_done.html` with `Cache-Control: no-store`. The page shows the management client id and secret, `token_endpoint = {public_url}/t/system/token` and `admin_api_base = {public_url}/api/admin/v1`.
- **Tests** (49 in total, green on sqlite and postgres):
  - flow_login (9): selector snapshot, 303 and session rotation (the old session is revoked), the 400 wrong-password page echoes only the identifier, a blocked user gets the same page as a wrong password, an expired flow restarts, the path tenant `/t/acme`, the registration link is hidden when registration is disabled, a malformed request id is rejected.
  - flow_registration (5): open registration ends in 303, stores the normalised email and queues a verification email. GETting the verification link does not consume the token; the POST verifies; a second confirm gets `verification.invalid_token`. Also: the disabled page, `email_taken`, `too_short`.
  - flow_recovery (3): the full reset (old password fails, new one works, prior sessions revoked, token single-use, `password_changed` email queued), an unknown email gives the same `recovery.sent` with no email, and a policy failure keeps the token.
  - security_setup (7), security_csrf (9), security_cookies (3), security_csp (1, covering 12 pages), security_enumeration (2).

## Task Commits

1. **Task 1: Login, registration, verification and recovery handlers with flow tests**: `093b56f` (feat)
2. **Task 2: Setup page and the browser-security/enumeration negative tests**: `315f7be` (feat)

Each TDD task was committed once, with its tests alongside, because the handlers and the HTTP-level tests depend on each other.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added a shared test helper module `tests/ui_helpers/mod.rs`**
- **Issue:** The harness (`tests/support`, owned by 02-12) does not expose three things: the storage `Arc` (needed by `TokenService`), the `Argon2Pool` verification counter (the enumeration test needs it), and the setup token printed at install time.
- **Fix:** A new helper module, following the same pattern as the other plans' `tests/authz/` and `tests/token_support/`, with:
  - a `Client` trait implemented for `TestApp` and for `OwnApp`. `OwnApp` installs through the production `BootstrapService::ensure_installed`, so the "no default credentials" check runs against the real first-start path.
  - browser-like form submission (CSRF token plus hidden inputs).
  - outbox reading with `open_payload`.
- **Commits:** 093b56f, 315f7be

**2. [Scope] Session revocation after recovery is checked through `SessionRepo::get_active`, not `/authorize prompt=none`**
- **Issue:** `/authorize` was being built in parallel by 02-13 and was not available while these tests were written.
- **Fix:** The test asserts that the old session cookie's hash no longer resolves to an active session. That is the same state `/authorize` reads. An HTTP-level `prompt=none → login_required` check can be added once 02-13 lands.

**3. [Note] Outbox emails are claimed at `clock.now() + 1s`, not at a far-future time**
- `claim_due` only returns emails with `expires_at > now`, so a far-future `now` would return nothing.

## Issues Encountered

- `cargo clippy -p anvil-web` failed in the shared tree because of another plan's in-progress `admin/auth.rs` (`clone_on_copy`). Clippy and the full `cargo test -p anvil-web` were run in the scratch worktree `target/wt-02-15` at HEAD with this plan's files copied in. Both were clean, and the worktree was then removed.
- One Postgres run got `ConnectionRefused` from the testcontainer, most likely docker contention with the plans running in parallel. A rerun passed.

## Verification

- `INSTA_UPDATE=no cargo test -p anvil-web --test flow_login --test flow_registration --test flow_recovery`: green, on sqlite and with `ANVILID_TEST_DB=postgres`
- `cargo test -p anvil-web --test security_setup --test security_csrf --test security_cookies --test security_csp --test security_enumeration`: green, on sqlite and on postgres
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean (worktree)
- `cargo test -p anvil-web` (all targets, sqlite, worktree): green

## Next Phase Readiness

- 02-13 can rely on login answering 303 to `{issuer}/authorize/continue?request={auth_request_id}` with a fresh session cookie.
- 02-18 (binary wiring) needs nothing more from the UI. Its services are built from `AppState`.

## Self-Check: PASSED
