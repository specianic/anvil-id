---
phase: 02-release-0-1-first-login
plan: 07
subsystem: oauth-authorize
tags: [oauth, oidc, authorize, pkce, redirect-uri, prompt, max_age, id_token_hint, rfc9207]
requires:
  - phase: 02-01
    provides: anvil-jose (random_token, secret_hash, pkce::is_valid_challenge, Jwks::from_public_jwks, verify_op_token)
  - phase: 02-02
    provides: model (Client, AuthorizationParams, ClaimsRequest, BrowserSession, NewAuthorizationCode, NewTokenFamily), ports, CoreError
provides:
  - "oauth::redirect::{redirect_matches, validate_redirect_uri, MAX_REDIRECT_URI_LEN}"
  - "oauth::authorize_request::{RawParams, parse_raw, validate, ValidatedAuthorize, AuthorizeError, redirect_with}"
  - "oauth::claims_request::{parse_claims, MAX_CLAIMS_LEN}"
  - "oauth::decision::{decide, SessionDecision}"
  - "service::authorize::{AuthorizeService, AuthorizeOutcome, build_code, success_redirect, error_redirect, CODE_TTL, AUTH_REQUEST_TTL, FAMILY_TTL}"
affects: [02-08, 02-10, 02-12, 02-13, 02-14, 02-17]
tech-stack:
  added: []
  patterns:
    - "Error page until client + redirect URI are trusted, redirect afterwards (RFC 6749 §4.1.2.1)"
    - "Exact-string redirect matching; loopback any-port only for native clients, parsed by hand (no Url normalisation)"
    - "Pure decision functions; thin async orchestration in AuthorizeService"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/oauth/redirect.rs
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/oauth/claims_request.rs
    - crates/anvil-core/src/oauth/decision.rs
    - crates/anvil-core/src/service/authorize.rs
key-decisions:
  - "redirect_uri may default to the single registered URI only for error reporting; an OpenID request without an explicit redirect_uri is rejected (OIDC Core §3.1.2.1), so a code is never bound to an implicit redirect URI and the token endpoint can always require redirect_uri"
  - "max_age is also satisfied when auth_time >= request_created_at, so max_age=0 behaves like prompt=login and resume() cannot loop"
  - "id_token_hint subject is compared with BrowserSession.user_id.to_string(); 02-08 must issue sub as the user id string for this to match"
  - "resume() deletes the authorization request before create_code; a lost delete race yields flow_expired (single-use request)"
  - "prompt values limited to none/login/consent/select_account (consent and select_account accepted, no effect in 0.1); unknown values -> invalid_request"
  - "validate_redirect_uri allows http for localhost and loopback IP literals for both web and native clients (dev use), custom schemes for native only, never javascript/data/file/vbscript/blob/about"
requirements-completed: [OIDC-01, OIDC-02, OIDC-24, SEC-01]
duration: 20min
completed: 2026-11-25
---

# Phase 2 Plan 07: Authorization endpoint logic Summary

**This plan delivers the authorization endpoint logic in anvil-core.** It covers exact redirect matching (with the RFC 8252 loopback rule for native clients), validation that is ordered so errors go to an error page or a redirect correctly, PKCE that accepts S256 only, the nonce rule, and the prompt, max_age and id_token_hint decisions as pure functions. It also adds `AuthorizeService`, which issues hash-only codes with a pre-created token family and puts `iss` on every redirect.

## Performance

- **Duration:** about 20 min
- **Completed:** 2026-11-25
- **Tasks:** 2/2
- **Files modified:** 5

## Accomplishments

- `redirect_matches`: web clients get exact string membership only, which a proptest checks. Native clients also accept any port on a registered `http://127.0.0.1/...` or `http://[::1]/...` URI if the host text, path and query are identical. `localhost` gets no port flexibility.
- `validate`:
  - A missing or duplicated `client_id` gives an error page, and so does an unknown client.
  - A duplicated or mismatched `redirect_uri` gives an error page, even when `response_type` is also wrong.
  - Once the redirect URI is trusted, every error is a redirect. That covers duplicates, `response_type`, `request`/`request_uri`, PKCE, scope, the nonce rule, prompt/max_age and claims.
- PKCE: `plain`, a challenge without a method, a method without a challenge and a malformed challenge all give `invalid_request`. `require_pkce` is enforced, and public clients always need PKCE. Confidential clients that do not use PKCE must send a nonce.
- Scope: scopes the client is not allowed to use are dropped. If `openid` is missing, the result is `invalid_scope`.
- `decide` handles prompt=none and prompt=login, `max_age` and `hint_sub`. It returns `Fail(LoginRequired)` only for prompt=none.
- `AuthorizeService::authorize` and `AuthorizeService::resume` are implemented as specified. A blocked user, a revoked session or a session from another tenant counts as no session. An invalid `id_token_hint` gives `invalid_request` with prompt=none and is ignored otherwise. The hint is never logged.
- `build_code`: the plaintext code is 43 characters and only its `secret_hash` is stored. The code expires after 60 s and the family after 30 d. The family id, challenge, nonce and auth context are all bound to the code.

## Task Commits

1. **Task 1: Redirect matcher, request validation, claims parameter**: `5f958b8` (feat)
2. **Task 2: Session decision and AuthorizeService**: `dc431db` (feat)

The TDD tasks were committed as one commit per task, with the tests in each module. There were no separate RED commits.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] redirect_uri required for OpenID requests**
- **Found during:** Task 1
- **Issue:** The plan defaults `redirect_uri` to the single registered URI. OIDC Core §3.1.2.1 makes it REQUIRED. A code bound to a URI the client never sent would also make the token endpoint's RFC 6749 §4.1.3 check ambiguous.
- **Fix:** The default still makes the URI trusted, so errors can be reported by redirect. After the scope check, a missing explicit `redirect_uri` gives a redirect with `invalid_request`.
- **Commit:** 5f958b8

**2. [Rule 1 - Bug prevention] max_age=0 resume loop**
- **Issue:** If `now - auth_time <= max_age` were the only test, `max_age=0` would fail again after the forced login, because some milliseconds pass, and `resume` would loop forever.
- **Fix:** A login performed during the request (`auth_time >= request_created_at`) satisfies `max_age`.
- **Commit:** dc431db

**3. [Rule 2 - Defence] resume re-checks the client's redirect URIs and grant types**
- The client may change while the user signs in. If the redirect URI is no longer registered, the result is an error page. If the grant type was removed, the result is an `unauthorized_client` redirect.
- **Commit:** dc431db

### Additions

- `RawParams::get` and `RawParams::single` are public, so the service and the web layer can read single values. `RawParams` implements `From<Vec<(String, String)>>`.
- `success_redirect` and `error_redirect` are pub helpers, so the iss/state tests run on pure code.
- A `pub(crate)` `#[cfg(test)]` client fixture in `authorize_request::tests` is reused by the service tests.

No model or port types were missing.

## Verification

- At the time of verification, the shared working tree did not compile because of another wave-2 plan's in-progress `flow/engine.rs`, which I did not touch. I verified in a temporary detached worktree at HEAD with my five files copied in:
  - `cargo test -p anvil-core`: 98 passed. The filters `oauth::` (29), `decision` (6) and `authorize` (23) are all green.
  - `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean.
- I ran `rustfmt` on all five files.

## Notes for downstream plans

- **02-08 (token endpoint):** `code.redirect_uri` is always the URI the client sent explicitly, so require it and compare it exactly. `sub` must be `user_id.to_string()` for id_token_hint matching to work.
- **02-13 (web):** build `RawParams` from the query (GET) or the form (POST) with `parse_raw`. Map the `AuthorizeOutcome::ErrorPage` keys `invalid_request`, `unknown_client`, `redirect_uri_mismatch` and `flow_expired` to theme sentences. `Login{request_id}` starts the login flow, then calls `resume`.
- **02-10 (client service):** use `validate_redirect_uri` at registration time.
- **02-17 (fuzz):** `parse_raw` and then `validate` is the entry point.
- `response_mode` is ignored, so responses are always in the query. This is acceptable for Basic OP.

## Self-Check: PASSED
