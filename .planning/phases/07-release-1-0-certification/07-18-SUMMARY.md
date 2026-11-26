---
phase: 07-release-1-0-certification
plan: 18
subsystem: headless-flow-api
tags: [headless, native, par, pkce, flow-driver, UI-05]

requires:
  - phase: 07-05
    provides: ui::flow_driver with FlowBinding (enum ready for a second variant)
  - phase: 07-10
    provides: /api/flows/v1 browser mode, DTO, flows-v1.json, headless_support
  - phase: 07-12
    provides: Client.headless_native and validate_client_policy
  - phase: 07-13
    provides: AuthorizeService::resume_pushed_request (single PAR resume path)
provides:
  - "Native mode of /api/flows/v1: PAR-bound start ({client_id, request_uri}), Authorization: AnvilFlow <flow_token>, code returned as JSON"
  - "flow::login::FlowBindingKind and LoginState.binding (\"token\" marker in the flow state)"
  - "service::flow::{binding_kind, check_token_binding, FlowProof}; FlowService::{start_login_bound, submit_bound, identify_bound}"
  - "service::authorize::{native_eligible, NativeStartRefused, Completion}; AuthorizeService::{start_native, complete}"
  - "ui::flow_driver::FlowBinding::Token and start_native_login"
  - "docs/HEADLESS.md 'Native apps' section; flows-v1.json with the flow_token security scheme"
affects: [07-21 (compatibility policy names the native mode), 07-22 (docs pass), 07-23 gate]

tech-stack:
  added: []
  patterns:
    - "Binding kind recorded in the flow state at creation; each check refuses the other kind"
    - "JSON completion reuses continue_request/issue and reads the authorization response parameters"

key-files:
  created:
    - crates/anvil-web/src/api_flows/native.rs
    - crates/anvil-web/tests/headless_native.rs
    - crates/anvil-web/tests/native_support/mod.rs
  modified:
    - crates/anvil-core/src/flow/login.rs (forced extra)
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/ui/flow_driver.rs
    - crates/anvil-web/src/api_flows/browser.rs (forced extra)
    - crates/anvil-web/src/api_flows/mod.rs
    - crates/anvil-web/src/api_flows/dto.rs
    - crates/anvil-web/src/api_flows/openapi.rs
    - crates/anvil-web/tests/security_headless.rs
    - docs/openapi/flows-v1.json
    - docs/HEADLESS.md

key-decisions:
  - "The binding marker lives in LoginState (binding: token, omitted when cookie) so it survives every transition; only a login flow can be token-bound"
  - "A token-bound flow stores hash(token) as cookie_hash and the hash of a discarded random value as csrf_hash (second barrier behind the marker)"
  - "Token-bound flows are never restarted: unknown or expired is 404 flow_not_found"
  - "Eligibility (native_eligible) re-runs validate_client_policy on the stored client and is checked before the PAR request is consumed and again after the resume"
  - "Native completion creates the server-side session the code and token family need (rp_session FK, authorization_code.session_id NOT NULL) but never sends its cookie: no SSO for any browser"
  - "browser.rs Out/Submission are shared by both modes (native flag) instead of a second encoder"
  - "browser_required in native mode points at {issuer}/authorize/continue?request=… (the same request finishes in the system browser)"

requirements-completed: []

duration: ~2h
completed: 2026-11-26
---

# Phase 7 Plan 18: Headless native-app mode Summary

**First-party native apps can sign users in through `/api/flows/v1`: the app pushes its request with PKCE to `/par`, starts a token-bound login flow with the `request_uri`, submits steps with `Authorization: AnvilFlow <flow_token>`, gets `{code, iss, state}` as JSON and redeems the code at `/token` with its verifier. Every step runs through `ui::flow_driver` with `FlowBinding::Token`, so throttling, lockout, CAPTCHA and audit are the UI's own.**

## Binding design

- `flow::login::FlowBindingKind { Cookie (default), Token }` is a field of `LoginState`
  (`#[serde(default, skip_serializing_if = is_cookie)]`), so old flows decode as cookie-bound and
  transitions (which use `..state`) keep the marker. `FlowService::create_flow_bound` sets it at
  creation; `create_flow_with_id` (all existing callers, including `continue_login`) always writes
  `Cookie`, so a login continued in a new browser flow never inherits a token marker.
- Token-bound flow row: `cookie_hash = SHA-256(flow_token)` (token = `random_token()`, 32 bytes from
  aws-lc-rs, 43 base64url chars), `csrf_hash = SHA-256(discarded random)`, forms bound with an empty
  CSRF token. No CHECK-constrained `flow.kind` value was added.
- `check_binding` (cookie + CSRF, every existing caller: consent, account, attribute, upstream,
  saml, session, authorize, logout, flow) now refuses a token-bound flow whatever the values.
  `check_token_binding` refuses a cookie-bound flow. `FlowProof { Cookie{cookie, csrf}, Token }`
  dispatches between them; `FlowService::load` takes a proof, and a token proof on an unknown or
  expired flow is `NotFound` (no restart). `email_link` never treats a token-bound flow as "same
  browser".
- `ui::flow_driver::FlowBinding::Token { token }`: `csrf()` is empty, `current_session()` is
  `None` (no session switch, no step-up), passkey options/finish and the email link return
  `DriveRejection::Binding`. `submit`, `identify` and `current_step` pass `binding.proof(..)` to the
  flow service (`submit_bound`, `identify_bound`, `FlowProof::check`).

## Routes (same paths as browser mode)

| Request | Native when | Handler |
|---|---|---|
| `POST /api/flows/v1/login` | body has `client_id` or `request_uri` (or an AnvilFlow header) | `native::start` |
| `GET /api/flows/v1/login/{flow_id}` | `Authorization: AnvilFlow …` | `native::get_flow` |
| `POST /api/flows/v1/login/{flow_id}` | `Authorization: AnvilFlow …` | `native::submit_flow` -> `browser::dispatch` |

The browser handlers branch to `native` at their top. Native requests are refused with 403
`browser_signals` when they carry `Origin` or `Sec-Fetch-Site`; the CORS layer never applies
(no `Origin`). Start: `AuthorizeService::start_native` (eligibility before and after the resume,
`resume_pushed_request` for the single consume and policy re-check, PKCE challenge present), then
`flow_driver::start_native_login`. `prompt=none` is 400 `login_required`; `prompt=create`, an
org IdP start, upstream/SSO, a CAPTCHA demand and any post-login page answer `browser_required`
with `{issuer}/authorize/continue?request=…`. Completion: `FlowOutcome::SignedIn` in native mode
calls `AuthorizeService::complete` (`continue_request(Stage::AfterLogin)` -> `issue`, the same code
issuance as the redirect) and maps `Completion::{Code, Error, Interaction}`; no cookie is set.

## Tests

- Core unit: `binding_marker_is_read_from_login_state_only`, `token_flow_refuses_the_cookie_binding`,
  `cookie_flow_refuses_the_token_binding`, `token_binding_rejects_wrong_token_and_expiry`
  (service::flow); `completion_carries_the_redirect_responses_parameters`,
  `native_eligibility_follows_the_client_policy` (service::authorize).
- Web unit: `ui::flow_driver::tests::token_binding_presents_only_the_token`;
  `api_flows::native::tests::{the_anvilflow_scheme_selects_native_mode,
  flow_token_must_be_a_single_base64url_value, browser_signals_are_origin_and_fetch_metadata}`.
- `headless_native` (4): `native_login_with_password_returns_a_code_redeemed_with_the_verifier`
  (PAR push with challenge, native start, GET step, password, code JSON, token exchange with the
  verifier, ID token sub/aud/iss/nonce, no session cookie),
  `native_wrong_password_answers_the_form_and_the_flow_continues`,
  `native_login_with_required_totp_returns_the_code_after_the_second_factor` (amr otp+mfa),
  `browser_mode_second_factor_completes_the_sign_in` (the 07-10 deferred item).
- `security_headless` (appended, module `native`, 14): `native_requires_par_request_uri`,
  `native_requires_headless_native_client`, `native_dcr_client_refused`,
  `native_cimd_client_refused`, `native_flow_token_required`, `native_wrong_flow_token_refused`,
  `native_cookie_bound_flow_refused_with_token`, `native_token_flow_refused_with_cookie`,
  `native_browser_signals_refused`, `native_code_requires_code_verifier`,
  `native_request_uri_single_use`, `native_captcha_returns_browser_required`,
  `native_no_sso_session_created`, `native_throttling_shared_with_ui`.

## Mutation checks (recorded, reverted)

1. `native_eligible` without the `client.headless_native` check: `native_requires_headless_native_client`
   FAILED (a normal client's request_uri started a flow: 200 instead of 403).
2. "Accept the cookie binding on token flows":
   - 2a: the marker refusal removed from `check_binding` alone. `native_token_flow_refused_with_cookie`
     still passed, because the token flow's CSRF hash is of a discarded random value (second
     barrier); the core unit test `token_flow_refuses_the_cookie_binding` FAILED (Ok instead of
     Forbidden).
   - 2b: marker refusal removed and the CSRF hash set to the token's hash:
     `native_token_flow_refused_with_cookie` FAILED (the browser-mode submission with the token as
     cookie and CSRF completed the sign-in).

## Evidence

- `cargo test -p anvil-web --locked --no-fail-fast`: 130 test binaries, 1628 passed, 0 failed
  (SQLite; Postgres-backed cases skip without a database).
- `cargo test -p anvil-core --locked`: 1098 passed, 0 failed.
- Plan verify: `service::flow` (25), `service::authorize` (10), `ui::flow_driver` (11),
  `flow_login`, `headless_flows`, `authorize`, `flow_login_factors`, `headless_native` (4),
  `security_headless` (25 = 11 browser + 14 native), `openapi_flows_drift` (2), `par`: all ok.
- `UPDATE_OPENAPI=1 cargo test -p anvil-web --test openapi_flows_drift` regenerated only
  flows-v1.json (admin-v1.json untouched, owned by 07-17); the drift test passes without the flag.
- `cargo clippy -p anvil-core -p anvil-web --all-targets --locked -- -D warnings`: clean.
- `rustfmt --edition 2024 --check` on every touched file: clean.
- `scripts/check-release-graph.sh`: OK. `scripts/check-deps.sh`: OK.
- `just doc` (`-D broken_intra_doc_links -D private_intra_doc_links`): clean after replacing a
  link to the private `FlowBinding::Token` with plain code.
- Not run: Postgres (no Docker); no e2e spec belongs to this plan.

## Task Commits

1. Task 1 (token binding, FlowProof, JSON completion): `9dafb55`
2. Task 2 (native handlers, OpenAPI, tests, docs): `a62b787`

## Deviations from Plan

1. **[Rule 4 flagged, implemented conservatively] A server-side session row is still created.**
   The plan says "No SSO browser session is created" and Task 1 "no browser session row". Code
   issuance needs a session: `authorization_code.session_id` is NOT NULL and `create_code` writes an
   `rp_session` row with a foreign key to `browser_session` (SQLite and Postgres). Removing that is a
   schema change in both backends (outside this plan's files). The native completion therefore uses
   the session the flow's sign-in created, but its cookie secret is never sent, so no browser can
   ever present it (no SSO). `native_no_sso_session_created` proves no `Set-Cookie` on any native
   answer and that a later browser `prompt=none` is `login_required`. The row is visible in the
   user's session list and its revocation revokes the app's grant like any session. **Owner
   decision for the gate:** keep this, or make code issuance session-less (nullable session_id,
   no rp_session) in a later release.
2. **[Rule 3] Forced extra `crates/anvil-core/src/flow/login.rs`:** the `binding` field and
   `FlowBindingKind` enum (the marker must be part of `LoginState` to survive transitions).
3. **[Rule 3] Forced extra `crates/anvil-web/src/api_flows/browser.rs`:** native mode reuses the
   browser encoder and dispatch instead of a second copy (CLAUDE.md one implementation per
   concern): `Out` gained a `native` flag and `reject`, the submission dispatch moved into
   `pub(super) fn dispatch`, the three handlers branch to `native`, a few helpers became
   `pub(super)`, and the utoipa annotations document both modes.
4. **[Rule 3] Forced extra `crates/anvil-web/tests/native_support/mod.rs`:** both test files
   need the native helpers, so they live in a shared test module (07-10's `headless_support` is
   unchanged).
5. **Eligibility lives in core** (`service::authorize::native_eligible`, `start_native`) rather
   than in the handler, and it also requires the `authorization_code` grant.
6. **Throttling test shape:** like browser mode, the gate locks after the sixth failure (the
   attempt that crosses the limit answers 429), so `native_throttling_shared_with_ui` drives six
   failures before checking that the right password is refused.
7. **Passkeys in native mode** are not offered (filtered from `methods`; the passkey sub-routes
   refuse the token binding). A user whose only second factor is a passkey cannot finish natively;
   the documented fallback is the browser.

## Issues seen in other plans' files

- The index had a staged deletion of `crates/anvil-web/tests/skeleton_v10.rs` and uncommitted
  `docs/openapi/admin-v1.json` / admin changes from other wave-4 plans during this run; both 07-18
  commits used `git commit -- <paths>` and contain only this plan's files. Nothing broke the build.
- `deferred-items.md` has two appended 07-18 lines (session-row decision; registering the
  `native_*` negatives in `scripts/check-security-tests.sh`). The file also holds other plans'
  uncommitted lines, so it is left for the orchestrator to commit.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/api_flows/native.rs (516 lines, min 150; uses `FlowBinding::Token`)
- FOUND: crates/anvil-web/tests/headless_native.rs (contains `code_verifier`)
- FOUND: crates/anvil-web/tests/native_support/mod.rs, docs/HEADLESS.md, docs/openapi/flows-v1.json
- FOUND: `fn complete` in crates/anvil-core/src/service/authorize.rs
- FOUND: commits 9dafb55, a62b787
