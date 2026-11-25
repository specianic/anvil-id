---
phase: 04-release-0-3-real-world-logins
plan: 13
subsystem: oidc-logout
tags: [oidc, rp-initiated-logout, end-session, backchannel-logout, csrf, i18n, discovery]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-02 AppState::logout_wake + pre-registered logout modules; 04-04/04-05 revoke_with_families enqueues deliveries; 04-06 i18n API; 04-08 oauth::logout decision table"
provides:
  - "service::logout: LogoutService::{end_session, start_confirmation, confirm}, RawEndSession (+ from_pairs, RepeatedParameter), LogoutOutcome, ConfirmationStart, ConfirmResult, LogoutBinding, StartedLogoutFlow, MAX_HINT_LEN"
  - "flow::logout::LogoutState (FlowKind::Logout state: client_id + validated redirect)"
  - "GET/POST {issuer}/logout; GET/POST /ui/logout; GET /ui/signed-out"
  - "AppState::{ui_logout_service, logout_current_session, logout_finished, logout_error_page, logout_confirm_redirect}"
  - "Discovery: end_session_endpoint, backchannel_logout_supported, backchannel_logout_session_supported"
  - "Templates logout_confirm.html, logged_out.html; catalog locales/en/logout.ftl"
affects: [04-17, 04-23, 04-gate]

tech-stack:
  added: []
  patterns:
    - "The confirmation page re-runs the decision without the hint (it can only confirm or refuse), so the hint never travels to /ui/logout and opening the page never logs out"
    - "Response helpers shared between protocol/ and ui/ live in an `impl AppState` block, so no module visibility change in the shared mod.rs files was needed"

key-files:
  created:
    - crates/anvil-web/tests/logout.rs
    - crates/anvil-web/tests/security_logout.rs
    - crates/anvil-web/tests/logout_support/mod.rs
    - themes/default/templates/logout_confirm.html
    - themes/default/templates/logged_out.html
    - themes/default/locales/en/logout.ftl
  modified:
    - crates/anvil-core/src/service/logout.rs
    - crates/anvil-core/src/flow/logout.rs
    - crates/anvil-web/src/protocol/logout.rs
    - crates/anvil-web/src/ui/logout.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/tests/discovery.rs

key-decisions:
  - "Confirm -> 303 to /ui/logout?client_id=&post_logout_redirect_uri=&state= (validated values, never the hint); GET /ui/logout validates again and creates the flow. Reason: the CSRF token is only known when the flow is created, and the contract needs the page under /ui/logout*"
  - "After confirmation POST /ui/logout redirects to GET /ui/signed-out, so the signed-out page is never under /ui/logout* (contract). /logout with a valid hint and no URI renders the signed-out page directly at /logout"
  - "Refusals use logged_out.html in error mode (role=alert, data-message-key=logout.*), not error.html, so the contract sentences live in logout.ftl only"
  - "The hint must have typ JWT (access and logout tokens are not ID tokens); the hint's client is azp, else the first aud; a hint longer than 16 KiB is invalid without parsing"
  - "LogoutState holds no session_id: confirmation logs out the session presented with the confirming POST (the browser that clicked)"
  - "The logout audit event is written only when a session was actually revoked (user actor, session id target, details client_id); the delivery worker is woken only then"
  - "A known parameter sent twice, and a POST /logout that is not a form body, are the invalid_request page"

patterns-established:
  - "Logout pages: signed-out/error template keyed by data-message-key; confirmation under /ui/logout; signed-out under /ui/signed-out"

requirements-completed: []

duration: about 90 min (with two editor interruptions)
completed: 2026-11-25
---

# Phase 4 Plan 13: RP-Initiated Logout Summary

**`GET`/`POST {issuer}/logout` now implement RP-Initiated Logout 1.0. The `id_token_hint` is verified over the tenant's enabled algorithms with expiry ignored, and the post-logout URI must exactly match a registered one. The redirect carries exactly `state`. Without a valid hint for the current session the user confirms first, through a CSRF-bound `FlowKind::Logout` page under `/ui/logout`. A logout revokes the session and its token families through `revoke_with_families`, which also enqueues back-channel deliveries. It then clears the cookie, audits `logout` and wakes the delivery worker. Discovery advertises the endpoint and the back-channel support.**

`requirements-completed` is empty on purpose. OIDC-12 also needs the back-channel delivery worker (04-17) and the conformance run (04-23). No requirement checkbox was ticked.

## Endpoint behaviour

| Request | Response |
|---|---|
| valid hint for the current session (or no session), registered URI | session + families revoked, deliveries enqueued, `logout` audited, worker woken, session cookie cleared, 303 to `uri` + `state` (only `state` is added; the URI's own query is kept) |
| valid hint, no URI | same, then the signed-out page (200) at `/logout` |
| valid hint, no session | 303/signed-out without any change (idempotent, no audit) |
| expired valid hint | accepted |
| valid hint for another session or user | 303 to `/ui/logout?client_id=…` (confirm, no redirect afterwards) |
| no hint, known `client_id` (+ registered URI, `state`) | 303 to `/ui/logout?…` (confirm, then redirect with `state`) |
| no parameters / only `state` | 303 to `/ui/logout` (confirm, then `/ui/signed-out`) |
| hint `alg: none`, foreign key, other tenant/issuer, tampered, malformed, `typ` not JWT, unknown client | 400 `logout.invalid_id_token_hint` |
| URI not registered (`?foo=bar` added, trailing `/`, case, fragment) | 400 `logout.redirect_uri_not_registered` |
| URI without hint and without `client_id` | 400 `logout.id_token_hint_required` |
| `client_id` not the hint's client | 400 `logout.client_mismatch` |
| unknown `client_id` without hint | 400 `logout.unknown_client` |
| repeated parameter, non-form POST body | 400 `invalid_request` (error.html) |
| `GET /ui/logout?…` | validates again (hand-made URLs cannot add an unregistered URI); flow cookie + page with `#logout-confirm-submit` "Sign out" and "Stay signed in" link to `/ui/account/sessions` |
| `POST /ui/logout?flow=` with flow cookie + CSRF | flow consumed (deleted), current session logged out, 303 to the stored redirect or `/ui/signed-out` |
| same without flow cookie / wrong or missing CSRF / no flow id | 403 `csrf`, nothing changed |
| same, flow expired or already used | 400 `logout.expired` |
| `POST /ui/logout` cross-site | 403 (Fetch-Metadata). `POST /logout` cross-site works (not behind the layer) |

Every response carries `Cache-Control: no-store`. `ui_locales` comes from the query or form. Unknown tags fall back and are never an error.

## Contract sentences (byte-identical to tests/conformance/config.template.json, checked with grep -F)

- `#logout-confirm-submit`: "Sign out"
- `logout.signed_out`: "You have been signed out."
- `logout.invalid_id_token_hint`: "The sign-out request is invalid: the id_token_hint could not be verified."
- `logout.redirect_uri_not_registered`: "The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client."
- `logout.id_token_hint_required`: "The sign-out request is invalid: post_logout_redirect_uri requires id_token_hint or client_id."
- `logout.unknown_client` (key required by the orchestrator): "The sign-out request is invalid: this application is not registered."
- `logout.client_mismatch`: "The sign-out request is invalid: client_id does not match the id_token_hint."

## Task Commits

1. **Task 1: LogoutService + Logout confirmation flow (core)**: `5b5e4fc` (feat)
2. **Task 2: Endpoints, pages, discovery**: `d2aa3e1` (feat). This commit also adds `RawEndSession::from_pairs` with its unit tests in service/logout.rs.
3. **Task 2: Integration + security tests**: `4520965` (test)

## Verification (main tree, at d70d39d plus no local changes)

- `cargo test -p anvil-web --test logout --test security_logout --test discovery`: 12 + 14 + 9 passed.
- `cargo test -p anvil-core --lib`: 527 passed, including 3 `flow::logout` and 3 `service::logout` tests.
- `cargo test -p anvil-web --lib --test i18n --test security_csrf --test consent --test render`: all passed.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings`: clean.
- `rustfmt --edition 2024 --check` on this plan's files: clean.
- The contract sentences were checked in logout.ftl and config.template.json with `grep -F`.

## Not run

- `ANVILID_TEST_DB=postgres` and the e2e/conformance runs, because Docker is unavailable. The tests use only storage ports that 04-05 implements on Postgres. CI covers these.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Contract] The confirmation page is reached by redirect, not rendered at /logout**
- The plan said to render logout_confirm.html from `/logout`. The conformance contract requires the page under `/ui/logout*`, and the CSRF token can only be shown by whoever creates the flow.
- `/logout` now 303s to `/ui/logout` with the validated `client_id`, URI and `state`. The hint is never passed on. `GET /ui/logout` re-runs the decision without a hint and creates the flow.
- Because of this, `end_session` returns `Confirm { client_id, redirect }` rather than a started flow, and `start_confirmation` creates the flow.

**2. [Rule 1 - Contract] The signed-out page after confirmation is `/ui/signed-out`**
- This keeps the signed-out page off `/ui/logout*`. The extra GET route lives in ui/logout.rs.

**3. [Design] Error pages use logged_out.html in error mode**
- error.html only knows fixed keys, and that template is not owned by this plan.

**4. [Rule 2 - Security] Hint hardening**
- The hint must have `typ: JWT`, so access or logout tokens cannot act as hints.
- Hints are capped at 16 KiB.
- A non-string `sid` makes the hint invalid.
- A repeated parameter is rejected (`RawEndSession::from_pairs`).

**5. [Design] No `session_id` in LogoutState**
- Confirmation logs out the session presented by the confirming browser. See the decisions above.

**6. [Note] Core unit tests**
- The only storage double in core is private to session.rs, so the service orchestration is covered by the 26 integration tests. Core unit tests cover the flow state and the parameter parsing.

### Forced extras (files outside files_modified)

- `crates/anvil-web/tests/logout_support/mod.rs`: new shared fixture for the two test files (test code only).
- `crates/anvil-web/tests/discovery.rs`: the three new metadata names were added to `ALLOWED_METADATA`. Without this, `only_registered_metadata_is_published` fails. Committed in 4520965.
- No shared registry file (lib.rs, ui/mod.rs, protocol/mod.rs) was edited. The modules were pre-registered by 04-02, and the cross-module helpers are `AppState` methods.

### Process notes

- Early in the run, `cargo fmt -p anvil-core` was run in the main tree once (not `--check`). That may have reformatted other plans' in-progress anvil-core files at that moment (token.rs, authorize.rs, account.rs and others were modified by their owners then). The change is formatting only, but owners should know. After that, only `rustfmt` on this plan's own files was used.
- A build in the shared worktree target dir (`target/wt-shared`) once reported a stale `anvil-core` (missing `from_pairs`) until the files were touched. All verification reported above was re-run in the main tree. The worktree target/wt-04-13 has been removed.
- Advertising `backchannel_logout_supported` now (as the plan says) means the metadata promises deliveries before the 04-17 worker sends them. The deliveries are enqueued correctly, and 04-17 must land before the release.

## Next Phase Readiness

- 04-17: the worker wakes on `AppState::logout_wake()`, which is notified after every revoking logout. Deliveries carry `sub` = user id and `sid` = browser session id.
- 04-23: the conformance browser contract is met (confirmation page under `/ui/logout*`, signed-out page at `/logout` or `/ui/signed-out`, errors at `/logout`).
- themes/default/README.md should document the logout pages, ids and sentences (docs pass).

## Self-Check: PASSED
