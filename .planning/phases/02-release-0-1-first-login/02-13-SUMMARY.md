---
phase: 02-release-0-1-first-login
plan: 13
subsystem: web-protocol-authorize
tags: [oidc, discovery, rfc8414, jwks, authorize, pkce, redirect-uri, rfc9207, security-tests]
requires:
  - phase: 02-07
    provides: AuthorizeService, AuthorizeOutcome, parse_raw, validate_redirect_uri
  - phase: 02-08
    provides: KeyService::jwks, open_key
  - phase: 02-12
    provides: app() shell, ResolvedTenant, error_page, CookiePolicy, public_cors, TestApp harness
provides:
  - "GET {issuer}/.well-known/openid-configuration and /.well-known/oauth-authorization-server{base_path} (identical JSON)"
  - "GET {issuer}/jwks (public, max-age=300, CORS)"
  - "GET/POST {issuer}/authorize, GET {issuer}/authorize/continue?request={id}"
  - "AppState::authorize_service(), AppState::authorize_session_service(), AppState::jwks_key_service()"
  - "tests/authz/mod.rs: seeding helpers for clients, users, sessions and authorize requests"
affects: [02-15, 02-17, 02-18, 02-19]
tech-stack:
  added: []
  patterns:
    - "Handlers only map HTTP to AuthorizeService calls and AuthorizeOutcome to 303 / themed 400"
    - "Discovery built per request from ResolvedTenant.issuer (no caching)"
key-files:
  created:
    - crates/anvil-web/tests/discovery.rs
    - crates/anvil-web/tests/authorize.rs
    - crates/anvil-web/tests/security_redirect.rs
    - crates/anvil-web/tests/security_pkce.rs
    - crates/anvil-web/tests/security_iss.rs
    - crates/anvil-web/tests/security_tenant.rs
    - crates/anvil-web/tests/authz/mod.rs
  modified:
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/src/protocol/jwks.rs
    - crates/anvil-web/src/protocol/authorize.rs
key-decisions:
  - "Discovery also gets Cache-Control: public, max-age=300 (like JWKS); every other protocol response keeps the shell's no-store"
  - "POST /authorize requires application/x-www-form-urlencoded; anything else is the invalid_request error page"
  - "/authorize/continue with a missing or malformed request id renders flow_expired (same as an unknown/expired one)"
  - "A CoreError from the service (storage failure) renders the themed error page through core_error_page, never a redirect"
  - "The RFC 8414 allow-list test treats prompt_values_supported as registered (OIDC prompt=create spec)"
requirements-completed: []
duration: 35min
completed: 2026-11-25
---

# Phase 2 Plan 13: Discovery, JWKS and the authorization endpoint over HTTP Summary

**Per-tenant OIDC/RFC 8414 discovery at both well-known paths, a public JWKS, and `/authorize` (GET and POST) plus `/authorize/continue` as thin handlers over `AuthorizeService`. Every authorize-side control from §11 now has a negative HTTP test that passes on SQLite and on Postgres.**

## Performance

- **Duration:** about 35 min
- **Completed:** 2026-11-25
- **Tasks:** 2/2
- **Files:** 10 (3 modified, 7 created)

## Accomplishments

- **Discovery** follows the RESEARCH "Recommended 0.1 discovery document":
  - The issuer has no trailing slash. The only signing alg is RS256, and the only challenge method is S256.
  - `authorization_response_iss_parameter_supported=true` and `request_uri_parameter_supported=false` are both set explicitly. `offline_access` and the `none` alg are not listed.
  - `acr_values_supported=[ACR_PWD]` and `token_endpoint_auth_signing_alg_values_supported=[RS256, PS256, ES256]`.
  - An allow-list test checks every published field against the registered OIDC Discovery / RFC 8414 / RFC 9207 names.
  - For a path tenant, `/t/acme/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server/t/acme` return byte-identical JSON.
- **JWKS** goes through `KeyService::jwks`:
  - It lists the next, active and not-yet-expired retired keys. A retired key past `expires_at` is gone.
  - Each `kid` equals its RFC 7638 thumbprint, and no key has private members.
  - Responses carry `Cache-Control: public, max-age=300` and CORS `*`.
- **/authorize**:
  - Parses the query (GET) or the form body (POST) with `parse_raw` and reads the tenant's session cookie through `SessionService::current`.
  - `Redirect` → 303, `Login` → 303 to `{issuer}/ui/login?request={id}`, `ErrorPage` → themed 400 with no `Location`.
  - No CORS. Not behind the browser CSRF layer, so a cross-site POST works.
- **/authorize/continue** calls `resume`. The request is single-use: a second continue gives `flow_expired`, and so does one after the 15-minute TTL.

## Task Commits

1. **Task 1: Discovery (both paths) and JWKS**: `aa98dad` (feat)
2. **Task 2: /authorize, /authorize/continue and the security tests**: `36f3ce5` (feat)

Each TDD task went in as one commit with its tests. The tests could not compile or pass before the routes existed (every request hit the 404 fallback), so there are no separate RED commits.

## Test coverage (both backends)

| File | Tests | Covers |
|------|-------|--------|
| discovery.rs | 7 | metadata values, both well-known forms, allow-list, CORS, JWKS states/thumbprints, per-tenant JWKS |
| authorize.rs | 13 | login redirect, session reuse, prompt=none/login, 2 KiB state, continue (+ single use, expiry, malformed id), max_age, POST parity, non-form POST, display/ui_locales/unknown params, id_token_hint mismatch/match/invalid, path tenant |
| security_redirect.rs | 7 | unregistered, appended path, added query, case-changed host, fragment, trailing slash, scheme downgrade, web port change (incl. loopback), unknown/missing client, native loopback-IP port change allowed, native localhost port change rejected, POST, redirect error beats response_type error |
| security_pkce.rs | 7 | missing/plain/no-method/malformed/non-base64url/method-only PKCE, public native client always needs PKCE, nonce rule with require_pkce=false, implicit/hybrid → unsupported_response_type, missing response_type, request/request_uri, duplicate params, invalid_scope |
| security_iss.rs | 5 | exactly one iss on success, login_required and invalid_request; path tenant iss; client-supplied iss does not duplicate |
| security_tenant.rs | 2 | another tenant's client is unknown_client; another tenant's session token is not accepted |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Shared seeding module `tests/authz/mod.rs` (not in files_modified)**
- **Found during:** Task 2
- **Issue:** Five test files need the same seeding code (clients, users, sessions, request builders). The plan says to put helpers in the test files and not touch `tests/support`.
- **Fix:** Added a new helper module, `tests/authz/mod.rs`, which only this plan's tests use. No other plan touches it, so it cannot conflict.
- **Commit:** 36f3ce5

**2. [Rule 3 - Blocking] Clients are seeded through `validate_client` and `ClientRepo::create`, not `ClientService::create`**
- **Issue:** `TestApp::storage()` returns `&dyn Storage`, but `ClientService` needs an `Arc<dyn Storage>`, and the harness was off-limits.
- **Fix:** The helper runs the production `validate_client(&input, validate_redirect_uri)` and builds `NewClient` the same way `ClientService::create` does, using `new_client_id`, `new_client_secret` and `require_pkce` defaulting to true. **Harness suggestion:** expose `TestApp::storage_arc()` so tests can construct services directly.

**3. [Rule 2 - Correctness] Non-form POST /authorize is rejected explicitly**
- A POST without `application/x-www-form-urlencoded` gets the `invalid_request` error page. Without this check, a JSON body would be parsed as an empty parameter set.

### Observations (not changed)

- `decide` treats `auth_time >= request_created_at` as a fresh login (02-07 decision). A session that started in the same millisecond as the authorization request therefore satisfies `prompt=login` on resume. This happened in a test where the clock did not move. In practice it would take a sub-millisecond race, so the test now advances the clock and the core is unchanged.
- No `#[ignore = "needs 02-05…"]` markers exist (confirmed with grep).

### Process notes

- In the shared tree, `cargo clippy -p anvil-web --all-targets` failed in another plan's in-progress `admin/auth.rs` (`clone_on_copy`). Clippy ran in a temporary worktree (`target/wt-02-13`) at HEAD plus this plan's files and came back clean. The worktree has been removed.

## Verification

- `cargo test -p anvil-web --test discovery --test authorize --test security_redirect --test security_pkce --test security_iss --test security_tenant --test shell` passes on SQLite and with `ANVILID_TEST_DB=postgres`: 7 + 13 + 7 + 7 + 5 + 2 + 12 tests.
- `cargo clippy -p anvil-web --all-targets -- -D warnings` is clean in the isolated worktree.
- `grep -rn 'needs 02-05' crates/anvil-web/tests` finds nothing.
- `rustfmt --check` passes on every file this plan touched.

## Notes for downstream plans

- **02-15 (login UI):** after a successful login, set the session cookie and redirect to `{issuer}/authorize/continue?request={id}`, using the `request` query parameter from `/ui/login`.
- **02-19 / conformance:** the redirect-URI error page carries `data-error-key="redirect_uri_mismatch"` and the sentence "The redirect URI in this request is not registered for this client."

## Self-Check: PASSED
