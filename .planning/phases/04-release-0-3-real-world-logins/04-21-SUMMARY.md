---
phase: 04-release-0-3-real-world-logins
plan: 21
subsystem: auth
tags: [upstream, social-login, oidc, oauth2, account-linking, pkce, state, nonce, rfc9207, form_post, amr-fed, auth-07, auth-11]

requires:
  - phase: 04-07
    provides: "upstream::providers::{resolve, authorization_url, apple_client_secret_claims}, claims::{validate_id_token, normalise_*}, linking::link_decision"
  - phase: 04-11
    provides: "ConnectionService::open_secret; redirect_uri format {issuer}/ui/login/upstream/{slug}/callback"
  - phase: 04-14
    provides: "UpstreamHttp (state.upstream()) implementing UpstreamClient; tests/upstream_support MockProvider"
  - phase: 04-16
    provides: "after_primary_auth / flow_mfa, Enroll and SecondFactor steps, session switch"
provides:
  - "service::upstream::UpstreamService<'a> { flows, accounts, client } with start, form_post, callback; confirm_link (pub(crate)); redirect_uri(issuer, slug)"
  - "StartResult { Redirect(UpstreamRedirect { url, binding_cookie }), Done(Box<UpstreamOutcome>) }; UpstreamOutcome { SignedIn { cookie, continue_to }, Continue { started, request }, Linked, LinkFailed { key } }; CallbackParams"
  - "flow::upstream::{PendingUpstream, PendingLink, PostedResponse, SealedIdentity, UpstreamPurpose { Login, Link { user_id } }, check_callback, split_state, value_hash, upstream_aad, UPSTREAM_TTL, UPSTREAM_*_PURPOSE}"
  - "LoginState.{upstream, pending_link, federated}; SettingsState.upstream (+ with_upstream/take_upstream); login::link_confirmation; UPSTREAM_LINK_FORM_ID = \"upstream-link\""
  - "SessionAuth::{Federated, FederatedSecondFactor} ([fed] pwd-acr; [fed, otp, mfa] mfa-acr)"
  - "FlowService::{upstream_primary, continue_login, restart_login_with, create_flow_with_id} (pub(crate)); AccountService::settings_flow_for (pub(crate))"
  - "CookiePolicy::{upstream_name, upstream_binding_cookie, clear_upstream_binding}: __Host-anvil_upstream_{t}, Lax, 600 s"
  - "Routes POST /ui/login/upstream/{slug}?flow=, GET|POST /ui/login/upstream/{slug}/callback; login.html buttons; upstream_link.html; locales/en/upstream.ftl"
  - "tests/upstream_flow/mod.rs helpers (setup, add_connection, start, post_start, callback, reply_for, sign_in, get_with_cookies, audit, failure_reasons, ...)"
affects: [04-24, 04-25, 04-26, 04-27]

tech-stack:
  added: []
  patterns:
    - "The provider's return carries neither the Strict flow cookie nor the CSRF token: a login that needs another form continues in a fresh flow (new cookie + CSRF), the old flow is deleted"
    - "Pending upstream state holds only hashes and KEK-sealed values (AAD tenant||flow id) and is consumed by compare-and-swap before any provider call"
    - "A failure before the callback is proved to belong to the browser never touches the flow (no restart from it, no deletion)"

key-files:
  created:
    - crates/anvil-web/tests/upstream_login.rs
    - crates/anvil-web/tests/security_linking.rs
    - crates/anvil-web/tests/upstream_flow/mod.rs
    - themes/default/templates/upstream_link.html
    - themes/default/locales/en/upstream.ftl
  modified:
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-core/src/flow/upstream.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/flow/engine.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/flow/settings.rs
    - crates/anvil-core/src/service/account.rs
    - crates/anvil-web/src/ui/upstream.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/cookies.rs
    - themes/default/templates/login.html

key-decisions:
  - "The callback continues in a fresh login flow (second factor, enrolment, link confirmation, generic error) because the flow's CSRF hash cannot be rotated and the Strict flow cookie is absent on the cross-site return"
  - "The purpose follows the flow kind of the start POST: a login flow signs in (Login), the account page's settings flow links (Link); one start route"
  - "Link confirmation is the sign-in form with id upstream-link (same engine transitions, password or passkey); the account proved there gets the link right before CreateSession (mode confirmed), any account the user proves"
  - "A step-up never adds the primary method to amr: [fed] + second factor = [fed, otp, mfa], never pwd"
  - "RFC 9207: required and compared when discovery advertises it; an unexpected iss is also rejected when the issuer is known (generic OIDC)"
  - "Every callback answer clears the binding cookie, including rejections"
  - "Link success shows the message page upstream.linked until 04-25 adds the linked-identities page"

requirements-completed: [AUTH-07, AUTH-11]

duration: about 1h 45min
completed: 2026-11-25
---

# Phase 4 Plan 21: Upstream Sign-in and Safe Account Linking Summary

**Social, generic OIDC and OAuth2 sign-in now runs end to end through the built-in pages:**
- The sign-in page has one button per enabled connection. Each button is a no-JS form that posts the CSRF token.
- The start sends `state` (`{flow_id}.{random}`), a nonce and a PKCE S256 challenge (never for Apple). It stores only their hashes and sealed values in the flow (compare-and-swap) and sets a 10-minute SameSite=Lax `__Host-anvil_upstream_{t}` binding cookie.
- The callback checks `state`, the connection and the binding cookie. It then consumes the pending sign-in once, enforces RFC 9207 `iss` and exchanges the code (Apple: a freshly minted ES256 secret). It validates the ID token (the JWKS is refreshed once for an unknown `kid`) or calls the GitHub/OAuth2 profile APIs, then runs `link_decision`.

**Linking (AUTH-11):**
- Existing link: signs in.
- Verified and trusted email that matches a verified local account, with tenant `auto_link` on: links automatically (`identity_linked`, mode `auto`).
- Any other email match: a confirmation page where the user signs in to the existing account (password or passkey, plus any required second factor). The link is then made with mode `confirmed`.
- No match: just-in-time registration under `upstream_registration`.
- The account page's settings flow links the signed-in user (mode `account`). An identity already linked to another user is refused.

**MFA and failures:**
- An upstream sign-in is `[fed]` with the pwd `acr`. The effective MFA policy then applies, and a second factor gives `[fed, otp, mfa]`.
- Failures are audited as `upstream_login_failed` with reason codes only and shown as one generic error.

## Task Commits

1. **Task 1: core (UpstreamService, flow sub-steps):** `9a9c4bb` feat(04-21): upstream sign-in orchestration, link decisions and flow sub-steps in core
2. **Task 2: web, templates, tests:** `9084127` feat(04-21): upstream start/callback routes, binding cookie, login buttons, link page and tests

## API for 04-24 / 04-25 / 04-26 / 04-27

- **Service:** `UpstreamService { flows: &FlowService, accounts: &AccountService, client: &dyn UpstreamClient }`. The web layer builds it with `AppState::ui_upstream(&flows, &accounts)` (private, in `ui/upstream.rs`).
  - `start(cx, &SettingsBinding { flow_id, cookie_token, csrf_token }, slug, current_session)` returns `StartResult`. Errors: `Forbidden` (binding), `NotFound` (unknown or disabled slug), `InvalidRequest` (not at the identify step).
  - `callback(cx, slug, CallbackParams { state, code, error, iss }, binding_cookie, current_session)` returns `UpstreamOutcome`.
  - `form_post(cx, slug, state, PostedResponse { code, user, error, iss })` returns `bool` (whether the response was kept).
- **Flow state:**
  - `LoginState.upstream: Option<Box<PendingUpstream>>`, `LoginState.pending_link: Option<Box<PendingLink>>` and `LoginState.federated: bool`.
  - `SettingsState.upstream: Option<PendingUpstream>`.
  - All of these fields are serde-default, so older flow JSON still parses (unit tests).
  - `PendingUpstream { connection_id, state_hash, nonce, pkce_sealed, binding_hash, purpose, started_at (unix), expected_iss, response_sealed }`.
  - `PendingLink { connection_id, identity_sealed, candidate_user, provider_name, candidate_email }`.
- **KEK purposes** (AAD `upstream_aad(tenant, flow)`): `anvilid/upstream-pkce/v1`, `anvilid/upstream-identity/v1` and `anvilid/upstream-response/v1`.
- **Cookie:** `CookiePolicy::upstream_binding_cookie` / `clear_upstream_binding`, named `__Host-anvil_upstream_{tenant short id}` (dev mode: without the prefix).
- **Audit reasons** (`upstream_login_failed`): `state_missing`, `state_invalid`, `flow_expired`, `replayed`, `connection_mismatch`, `binding_invalid`, `expired`, `connection_disabled`, `provider_error`, `code_missing`, `discovery_failed`, `configuration`, `iss_mismatch`, `exchange_failed`, `id_token_missing`, `jwks_failed`, `id_token_signature`, `id_token_issuer`, `hosted_domain`, `id_token_audience`, `id_token_time`, `nonce_mismatch`, `claim_missing`, `userinfo_subject`, `profile_failed`, `inactive`, `no_account`, `email_missing`, `conflict`, `link_conflict`, `reauth_required`, `already_linked`, `purpose_mismatch`.
- **Linking from the account page (04-25):** post the settings flow's CSRF token to `/ui/login/upstream/{slug}?flow={settings_flow}`. Success renders `upstream.linked`, and failures render `upstream.link_failed`, `upstream.already_linked` or an AccountFailure key with status 400. 04-25 may redirect to its own page instead.
- **Test helpers (04-26):** `tests/upstream_flow/mod.rs`.
  - `setup(trust)`: prod URL, loopback outbound, auth limit raised, generic OIDC connection `acme-id`.
  - `add_connection(app, slug, name, config, trust)` (secret `test-client-secret`).
  - `start(app, slug)`, `post_start(app, path, csrf)`, `reply_for(u, started, overrides)`, `callback(u, started)`, `sign_in(u, overrides)`.
  - `get_with_cookies` (drop or replace jar cookies), `session`, `links`, `audit` and `failure_reasons`.
  - The Microsoft preset pointed at the mock is shown in `security_linking.rs`.

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 564 passed. New unit tests cover `check_callback` (state/binding/connection/TTL), `split_state`, the AAD, identity sealing round trips, settings JSON backward compatibility, the link form, federated finish, the `[fed]` and `[fed, otp, mfa]` amr values, step-up without `pwd`, sealed values bound to flow/tenant/purpose, and the redirect URI format.
- `cargo test -p anvil-web --test upstream_login` (12) and `--test security_linking` (16): pass.
- Regression runs pass: `flow_login`, `security_csrf`, `security_cookies`, `i18n` (login snapshot unchanged), `render`, `theme`, `security_csp`, `security_theme`, `flow_mfa_policy`, `flow_passkey`, `account_security`, `security_enumeration`, `security_bruteforce`, `flow_login_factors`, `flow_mfa`, `authorize_step_up`, `admin_connections`, `sessions`, `flow_registration`, and `--lib` (131).
- Clippy is clean with `-D warnings`: anvil-core all targets, plus anvil-web lib, `upstream_login` and `security_linking`. `rustfmt --edition 2024` was run on every touched Rust file.
- `ui/mod.rs` was not changed: `callback_routes()` is still merged after `fetch_metadata_layer()`.

## Not run

- `ANVILID_TEST_DB=postgres` for `upstream_login` / `security_linking`: Docker is not used (wave rule), so this is left for CI. The plan adds no SQL; it uses the existing `find_link`, `create_link`, `create_user_with_link`, `touch_link` and `swap_state` intents.
- The Apple path (minted ES256 client secret, `normalise_apple`, first-login names) is implemented but only exercised through the generic `form_post` hop here. The per-provider suites (Apple, Google, GitHub, OAuth2) belong to 04-26.
- e2e/Playwright and conformance: not run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `crates/anvil-core/src/flow/engine.rs` (not in files_modified)**
- `SessionAuth` had no upstream variant. Added `Federated` (`[fed]`, pwd acr) and `FederatedSecondFactor` (`[fed, otp, mfa]`).
- [Rule 1 - Bug] `upgraded_acr_amr` added `pwd` on any second-factor step-up. A stepped-up `[fed]` session would have claimed a password. A step-up now never adds the primary method. The existing test is unchanged and a `[fed]` case was added.
- Commit: 9a9c4bb

**2. [Rule 3] `crates/anvil-web/tests/upstream_flow/mod.rs` (new, not in files_modified)**
- Shared helpers for the two new test binaries, so they are not duplicated. 04-26 can reuse them.
- Commit: 9084127

**3. [Design] Continue in a fresh flow**
- The plan sketched rendering the second-factor, enrolment and confirmation pages from the callback. The flow stores only the CSRF hash, which cannot be rotated, and the Strict flow cookie is not sent on the provider's return. So the callback continues in a new login flow bound to the same authorization request (`FlowService::continue_login`), and `UpstreamOutcome::Continue` carries `request`.

**4. [Design] API shape**
- `start` takes the flow binding and derives the purpose from the flow kind, instead of taking a purpose parameter.
- `confirm_link` is a `pub(crate)` free function in `service::upstream`, called from `FlowService`'s `CreateSession` effect. It is not an `UpstreamService` method, so FlowService does not depend on UpstreamService.
- Sealed values are base64url strings, and the `LoginState` fields are boxed (clippy `large_enum_variant`).
- `PostedResponse` also keeps an `iss`.

**5. [Design] No `tracing` in anvil-core**
- anvil-core has no logging dependency, so failure detail goes to the audit reason codes only.

### Notes and open points (for review)

- An upstream sign-in does not apply `require_verified_email` (a JIT account from an untrusted provider has an unverified email but can sign in via its link). Decide at verification whether to refuse it.
- A GitHub `/user/emails` failure is treated as "no verified email". Sign-in through an existing link still works, and JIT then fails with `email_missing`.
- `login_hint` is forwarded to the provider only when it normalises to an email address.
- The sign-in buttons are rendered on `GET /ui/login`, after a failed password POST and on the upstream error page. The lock and CAPTCHA pages and the passkey failure page do not list them.
- No requirement checkbox was ticked (wave rule).

## Self-Check: PASSED

- Files exist: crates/anvil-core/src/service/upstream.rs (1300 lines), crates/anvil-web/src/ui/upstream.rs (381 lines), crates/anvil-web/tests/security_linking.rs, crates/anvil-web/tests/upstream_login.rs, crates/anvil-web/tests/upstream_flow/mod.rs, themes/default/templates/upstream_link.html, themes/default/locales/en/upstream.ftl
- Commits in history: 9a9c4bb, 9084127
- key_links: `link_decision` and `open_secret` in service/upstream.rs; `upstream_binding_cookie` with `SameSite::Lax` in cookies.rs
