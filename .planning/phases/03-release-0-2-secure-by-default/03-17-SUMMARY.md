---
phase: 03-release-0-2-secure-by-default
plan: 17
subsystem: oauth-consent
tags: [oidc, consent, connected-apps, authorize, audit, id_token_hint]
requires:
  - phase: 03-08
    provides: AuditContext extractor, empty ui::consent / ui::account_apps modules, account_base.html
  - phase: 03-11
    provides: AuthorizeOutcome::Respond(AuthorizationResponse), response modes
  - phase: 03-12
    provides: flow binding helpers (check_binding, FLOW_LIFETIME), foreign-kind flows restart
  - phase: 03-10
    provides: key_rotation::enabled_algs
provides:
  - flow::consent (consent_decision, requested_scopes, scope_description, ConsentState)
  - service::consent::ConsentService {decide, start, start_apps, approve, deny, list, revoke}
  - AuthorizeOutcome::Consent { request_id } and AuthorizeService::finish_consent
  - AppState::authorize_response (shared outcome → HTTP mapping)
  - /ui/consent and /ui/account/apps pages (consent.html, account_apps.html)
affects: [03-27, 03-28, 03-29]
tech-stack:
  added: []
  patterns:
    - "Consent is a separate small state machine (FlowKind::Consent), not a login-engine step"
    - "A decision is taken with FlowRepo::swap_state before any effect, and the authorization request is deleted before the code is issued"
key-files:
  created:
    - crates/anvil-web/tests/consent.rs
    - crates/anvil-web/tests/account_apps.rs
    - themes/default/templates/consent.html
    - themes/default/templates/account_apps.html
  modified:
    - crates/anvil-core/src/flow/consent.rs
    - crates/anvil-core/src/service/consent.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/protocol/authorize.rs
    - crates/anvil-web/src/ui/consent.rs
    - crates/anvil-web/src/ui/account_apps.rs
    - crates/anvil-web/tests/authz/mod.rs
key-decisions:
  - "03-17: Consent is its own state machine (flow/consent.rs + service/consent.rs, FlowKind::Consent) reusing FlowService's check_binding/FLOW_LIFETIME; it never touches the login engine (ARCHITECTURE §9 note)"
  - "03-17: The consent POST continues the request in-process via AuthorizeService::finish_consent and AppState::authorize_response (no extra endpoint); after Allow the decision ignores prompt=consent but still requires the stored grant to cover the request"
  - "03-17: Deny is not audited (no AuditAction for it); Allow audits consent_granted (target client_id, details scopes = stored union); revoke audits consent_revoked"
  - "03-17: The connected-apps page binds revocations with a consent-kind flow whose state has no request (ConsentState::for_apps); revoking needs no recent sign-in"
  - "03-17: id_token_hint is verified with verify_op_token_algs over key_rotation::enabled_algs(tenant)"
  - "03-17: authz test fixture clients are skip_first_party; consent tests switch their client to required"
requirements-completed: []
metrics:
  duration: 75min
  completed: 2026-11-25
  tasks: 2
  files: 11
---

# Phase 3 Plan 17: Consent Summary

**After sign-in, /authorize now decides on consent. `skip_first_party` clients and grants that already cover the requested scopes skip it, `prompt=consent` forces it, and `prompt=none` gets `consent_required`. When consent is needed the user sees a no-JS consent screen bound to a flow cookie and CSRF token. Allow stores the union of scopes, audits `consent_granted` and issues the code; Deny returns `access_denied`. Both answers go through the request's response mode. A connected-apps page lets users revoke a grant, which also revokes that client's token families and audits `consent_revoked`.**

## What was built

### Core

- **`flow/consent.rs`** (pure):
  - `consent_decision(mode, granted, requested, prompt) -> Result<ConsentDecision{Skip,Required}, CoreError>`
  - `requested_scopes(scope)`: split, deduplicated, in request order.
  - `missing_scopes`
  - `scope_description`: openid "Sign you in", profile, email, phone, address, offline_access "Stay signed in". Custom scopes return `None` and are shown by name.
  - `ConsentState { kind: "consent", user, request: Option<PendingConsent{request_id, client_id, scopes}>, decided }`. `decide()` succeeds once.
- **`service/consent.rs`**: `ConsentService { storage, clock }`
  - `decide(tenant, user, client, requested, prompt)`
  - `start(tenant, session, request_id) -> ConsentStart::{Started{flow, page}, RequestExpired}`
  - `start_apps(tenant, session)`
  - `approve` / `deny(tenant, session, binding[, ctx]) -> ConsentSubmission::{Decided(request_id), Expired}`
  - `list(tenant, user) -> Vec<ConnectedApp>`
  - `revoke(tenant, session, binding, client_id, ctx) -> RevokeResult::{Revoked, NoGrant, FlowExpired}`
  - Error mapping:
    - A wrong cookie or CSRF token, another user's flow, or a flow of another kind gives `Forbidden`.
    - An expired, unknown, already-decided or concurrently-lost flow gives `Expired`.
    - A request that is gone also gives `Expired`; the web layer then shows the `flow_expired` page.
- **`service/authorize.rs`**:
  - New `AuthorizeOutcome::Consent { request_id }`.
  - Consent is decided after `UseSession`, both in `authorize` (the request is stored) and in `resume` (the request is kept).
  - `consent_required` is delivered through the response mode. In `resume` the request is also deleted.
  - `finish_consent(tenant, issuer, request_id, session, approved)`:
    - Deny deletes the request and returns `access_denied`.
    - Allow repeats the session checks, then decides consent ignoring `prompt=consent`. If the grant was revoked in between, the screen is shown again. Otherwise it deletes the request and issues the code.

### Web

- `protocol/authorize.rs`: `Consent` → 303 `{issuer}/ui/consent?request={id}`. `AppState::authorize_response(tenant, outcome)` exposes the single outcome mapping (query → 303, form_post page).
- `ui/consent.rs`:
  - `GET /ui/consent?request=` starts a consent flow and sets the flow cookie. Without a session it sends a 303 to `/ui/login?request=`. A malformed request id gives 400; an expired request gives the `flow_expired` page.
  - `POST /ui/consent?flow=&request=` takes `decision=allow|deny`; any other value gives 400.
    - An expired flow re-renders the screen with `consent.expired` (400).
    - A broken binding gives the `csrf` page (403).
  - Responses are `Cache-Control: no-store`.
- `ui/account_apps.rs`:
  - `GET /ui/account/apps` lists the grants and starts a page flow.
  - `POST /ui/account/apps/{client_id}/revoke?flow=` (percent-encoded segment) re-renders the page with `apps.revoked` (200), or `apps.not_found` / `apps.expired` (400).
  - Without a session both routes send a 303 to `/ui/login`.

### Selectors for e2e (03-27)

- **consent.html**:
  - `#consent-form`, `#consent-client` (escaped client name), `#consent-scopes` (fieldset/legend), `#consent-scope-{n}[data-scope=…]`.
  - Buttons `#consent-allow` / `#consent-deny` (`name=decision`).
  - Messages `#consent-messages`, `[data-message-key]`.
  - No `<script>`.
- **account_apps.html** (extends account_base, `account_nav=apps`):
  - `#app-list`, `#app-{n}[data-client-id=…]`, `#app-{n}-name`.
  - Forms `#app-revoke-{n}` with buttons `#app-revoke-{n}-submit` (aria-label "Remove access for {name}").
  - Empty state `#apps-empty`, messages `#account-messages`.

## Extra item: id_token_hint algorithms

The coordinator asked for this, and `crates/anvil-core/src/service/authorize.rs` is in this plan's files_modified. `hint_subject` now calls `verify_op_token_algs(hint, &jwks, &enabled_algs(tenant)?, issuer, None, ExpiryCheck::Ignore, now)` instead of the RS256-only `verify_op_token`. Two tests in `tests/consent.rs` cover it:

- `an_es256_id_token_hint_is_accepted_when_the_tenant_enables_es256`:
  - With `prompt=none`, a matching ES256 hint returns a code.
  - An ES256 hint for another subject returns `login_required`. Before the fix both returned `invalid_request`.
- `an_es256_hint_is_rejected_when_the_tenant_does_not_enable_es256`: once the tenant is back to RS256 only, the hint returns `invalid_request`.

## Tests

- anvil-core:
  - flow::consent: 8 unit tests (decision table, prompt=none, scope parsing, descriptions, single decision, tagged JSON).
  - The authorize unit tests still pass.
- `tests/consent.rs` (13 tests, SQLite and Postgres):
  - Ask → Allow → code, with the grant remembered for the same or fewer scopes.
  - A new scope asks again, and the scopes are merged.
  - form_post Allow.
  - prompt=consent forces the screen.
  - prompt=none gives consent_required (query and form_post), then a code once the grant exists.
  - skip_first_party never asks.
  - Deny gives access_denied with state and iss (query and form_post).
  - Binding rejections: no CSRF, wrong CSRF, no flow cookie, cross-site, another user's session, bad decision value.
  - A double submission gives one code (the second is flow_expired).
  - An expired flow restarts the screen; an expired request gives flow_expired.
  - No session redirects to login.
  - Login, then continue, then consent.
  - ES256 hint tests (2).
- `tests/account_apps.rs` (4 tests, SQLite and Postgres):
  - The list shows escaped names and plain-language scopes.
  - Revoke removes the grant and the revoked client's refresh token returns `invalid_grant`, while the other client's refresh token still works. One `consent_revoked` event with the correct actor and target is recorded.
  - Revoking a second time gives `apps.not_found`.
  - Binding rejections (no CSRF, wrong CSRF, no cookie, cross-site, another user, no session) change nothing.
  - The page needs a session.
- Regression (SQLite): authorize, response_mode, flow_login, security_pkce, security_iss, security_redirect, security_tenant, render, id_token_alg and the anvil-web lib tests pass. On Postgres, authorize, response_mode, flow_login, consent and account_apps pass.
- Clippy: `-D warnings` is clean for anvil-web lib plus the consent, account_apps and authorize tests. The anvil-core lib-test clippy currently fails on `service/bootstrap.rs:614` (`clone` on a Copy type), which belongs to another plan's in-progress work.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `crates/anvil-web/tests/authz/mod.rs` clients set to `skip_first_party`**
- **Found during:** Task 2
- **Issue:** The shared authorize-test fixture created `consent_mode=required` clients, so every existing /authorize test with a session (authorize, response_mode, security_*) would have hit the consent screen.
- **Fix:** A one-line change to `SkipFirstParty`, with a comment. tests/consent.rs switches its client to `required` through `ClientRepo::update`. This file is not in files_modified.
- **Commit:** c14e07f

**2. [Rule 3] Protocol mapping committed with Task 1**
- `protocol/authorize.rs` was committed with Task 1 so the new `AuthorizeOutcome` variant never leaves anvil-web without a match arm. `authorize_response` stayed unused until Task 2.

### Design notes (ARCHITECTURE §9)

- Consent does not use the `FlowState` of the login engine. FlowService's `load()` restarts consent-kind flows (03-12), so a consent flow posted to `/ui/login` cannot be decoded as a login.
- The plan's `start(cx, request) -> StartedFlow` became `start(tenant, session, request_id) -> ConsentStart`. The consent screen has no engine `FormDescription`.

### Process notes

- The TDD tasks were committed as one feat commit each. Tests and implementation were written together, and all tests passed at commit time.
- Core lib tests were verified in a temporary worktree (`target/wt-03-17`), because another plan's in-progress `service/tenant.rs` test did not compile in the main tree. The worktree and the private target dir were removed afterwards.

## Follow-ups / not done

- **e2e and conformance:** clients created through the management API default to `consent_mode=required`, so browser e2e flows (03-27/03-29) and conformance runs (03-28) now see the consent screen unless their clients are created with `skip_first_party`. This matches the plan's note for 03-28.
- `themes/default/README.md` does not document the consent.html / account_apps.html template contracts. That file is not in scope; the variables are listed in each template's header comment.

## Commits

- 26b512b feat(03-17): consent decision, consent flow/service and authorize integration
- c14e07f feat(03-17): consent screen and connected-apps pages with HTTP tests

## Self-Check: PASSED
