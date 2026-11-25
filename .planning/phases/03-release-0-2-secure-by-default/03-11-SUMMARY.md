---
phase: 03-release-0-2-secure-by-default
plan: 11
subsystem: oauth-authorization-endpoint
tags: [oidc, response_mode, form_post, csp, authorize]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: pre-declared oauth::response_mode module (03-02), 0.2 schema (03-05/03-06)
provides:
  - ResponseMode {Query, FormPost} + SUPPORTED (for 03-18 discovery)
  - AuthorizationResponse::{success, error, to_redirect_url} — the single authorization-response builder
  - AuthorizeOutcome::Respond(AuthorizationResponse) (replaces Redirect(String))
  - AuthorizationParams.response_mode (serde default Query)
  - form_post page (themes/default/templates/form_post.html + static/form_post.js) with per-response CSP
affects: [03-17, 03-18, 03-28]
tech-stack:
  added: []
  patterns:
    - "One response builder in core; web maps mode → 303 (query) or rendered form (form_post)"
    - "Per-response CSP overrides the global one (insert-if-absent layer) for form_post only"
key-files:
  created:
    - crates/anvil-web/tests/response_mode.rs
    - themes/default/templates/form_post.html
    - themes/default/static/form_post.js
  modified:
    - crates/anvil-core/src/oauth/response_mode.rs
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-core/src/model/grant.rs
    - crates/anvil-web/src/protocol/authorize.rs
    - crates/anvil-storage/src/contract/fixtures.rs
    - crates/anvil-web/tests/token_support/mod.rs
decisions:
  - "response_mode is parsed right after redirect-URI validation; an unsupported or repeated value is invalid_request delivered via query, every later error uses the requested mode"
  - "success_redirect/error_redirect removed (no callers left); AuthorizationResponse is the only builder"
  - "ResponseMode lives in oauth::response_mode and is imported by model::grant (AuthorizationParams field)"
  - "form_post CSP also keeps style-src/img-src 'self' so the page is theme-styled; custom-scheme redirect URIs get form-action '<scheme>:'"
  - "AuthorizationResponse Debug redacts the code"
metrics:
  duration: 25min
  completed: 2026-11-25
  tasks: 2
  files: 10
requirements: [OIDC-25]
---

# Phase 3 Plan 11: form_post response mode Summary

OAuth 2.0 Form Post Response Mode via a single core `AuthorizationResponse` builder used by /authorize and /authorize/continue; the web layer renders it as a 303 (query) or an autoescaped, auto-submitting form with a per-response CSP whose `form-action` allows only the redirect URI's origin.

## What was built

- **Core (`oauth/response_mode.rs`)**: `ResponseMode` (serde `query`/`form_post`, default Query), `SUPPORTED`, `ResponseMode::parse` (case-sensitive; `fragment` and everything else → `invalid_request`), `AuthorizationResponse { redirect_uri, params, mode }` with `success` (code, state?, iss), `error` (error, error_description, state?, iss) and `to_redirect_url` (byte-identical to the 0.1 redirects; regression test).
- **Validation (`authorize_request.rs`)**: response_mode is parsed after the redirect URI is trusted; `AuthorizeError::Redirect` carries `response_mode`. An invalid redirect URI with `response_mode=form_post` is still an error page.
- **Service (`service/authorize.rs`)**: `AuthorizeOutcome::Respond(AuthorizationResponse)` on every path (validation errors, unauthorized_client, prompt=none/login_required, id_token_hint, resume failures, success). The mode is stored in `AuthorizationParams` and reused by `resume`.
- **Web (`protocol/authorize.rs`)**: Query → 303; FormPost → 200 `form_post.html` with `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action <origin>; frame-ancestors 'none'; base-uri 'none'`, `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`.
- **Theme**: `form_post.html` (extends base, "Continuing…" heading, hidden inputs, `<noscript>` Continue button, `<script src="{asset_base}/form_post.js" defer>`, no inline JS); `form_post.js` submits `#form-post` once (DOMContentLoaded or immediately).

## Tests

- anvil-core: response_mode parsing, param order, 0.1 regression URL, long state, no internal leak, Debug redaction, 0.1 stored JSON decodes as Query, validate ordering/mode rules (236 lib tests pass).
- anvil-web `tests/response_mode.rs` (11 tests): success form, static asset served, `"><script>` state escaped and decoded equal, login_required/unsupported_response_type/invalid_scope/duplicate/PKCE errors as POST forms (GET and POST), invalid redirect + unknown client → error page without form and without form-action CSP, unknown/repeated mode → query invalid_request, explicit query = default, continue honours stored form_post (and stays single-use), path tenant asset path, loopback origin with port.
- Regression: authorize, security_redirect, security_iss, security_csp, flow_login (SQLite and Postgres), security_pkce, security_tenant, render, token, web lib tests all pass; clippy clean.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `response_mode` to `AuthorizationParams` in `model/grant.rs` and to two struct literals**
- **Found during:** Task 1
- **Issue:** The plan requires storing the mode in `AuthorizationParams`, which is defined in `crates/anvil-core/src/model/grant.rs` (not in files_modified); adding the field breaks the literals in `crates/anvil-storage/src/contract/fixtures.rs` and `crates/anvil-web/tests/token_support/mod.rs`.
- **Fix:** Added `#[serde(default)] pub response_mode: ResponseMode`; `full_params()` uses `FormPost` so the storage contract round-trips a non-default mode; token_support uses the default. No concurrent plan lists these files.
- **Commit:** 2401194

### Process notes

- TDD tasks were committed as one feat commit each (tests written alongside the implementation, all passing), not separate RED/GREEN commits.
- The main working tree did not compile during Task 2 verification (another plan's in-progress `anvil-core` flow engine changes); verification ran in a temporary worktree (`target/wt-03-11`, removed afterwards).

## Deferred Issues

Logged in `deferred-items.md`: themes/default/README.md lacks the form_post.html contract (not in scope); Chromium applies `form-action` to post-submit redirects, so an RP callback that redirects cross-origin would be blocked (planned behaviour, revisit at 03-28).

## Commits

- 2401194 feat(03-11): core response builder and response_mode parsing
- c4c5c7c feat(03-11): form_post rendering, template, script and HTTP tests

## Self-Check: PASSED
