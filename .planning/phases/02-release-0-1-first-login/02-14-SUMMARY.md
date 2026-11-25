---
phase: 02-release-0-1-first-login
plan: 14
subsystem: web-token-side
tags: [oidc, token-endpoint, userinfo, client-auth, private_key_jwt, refresh-rotation, rfc6750, rfc9700, axum]
requires: [02-05, 02-06, 02-08, 02-10, 02-12]
provides:
  - "POST /token (protocol/token.rs): form-only, duplicate params -> invalid_request, AppState::token_service()"
  - "GET/POST /userinfo (protocol/userinfo.rs): header or form-body Bearer, never query, AppState::userinfo_service()"
  - "pub(crate) helpers in protocol::token: is_form, parse_form, no_store"
  - "tests/token_support: browserless seeding (client registration rules, user, session, build_code + create_code, acme tenant, client keys)"
affects: [02-16, 02-18, 02-19, 02-20]
tech-stack:
  added: []
  patterns:
    - "Handlers translate HTTP to a core request; every rule stays in TokenService/UserInfoService; errors via errors::oauth_json only"
    - "Token-side tests seed codes without a browser: build_code + GrantRepo::create_code, plaintext code kept for the exchange"
key-files:
  created:
    - crates/anvil-web/tests/token_support/mod.rs
    - crates/anvil-web/tests/token.rs
    - crates/anvil-web/tests/token_client_credentials.rs
    - crates/anvil-web/tests/security_code.rs
    - crates/anvil-web/tests/security_refresh.rs
    - crates/anvil-web/tests/security_client_auth.rs
    - crates/anvil-web/tests/security_private_key_jwt.rs
    - crates/anvil-web/tests/userinfo.rs
    - crates/anvil-web/tests/security_userinfo.rs
  modified:
    - crates/anvil-web/src/protocol/token.rs
    - crates/anvil-web/src/protocol/userinfo.rs
decisions:
  - "Client-credentials ATs at /userinfo get 403 insufficient_scope (they can never carry openid); a hypothetical CC token with openid would still be 401 invalid_token"
  - "A query access_token at /userinfo is refused with 401 invalid_token even when a valid header is also present; missing token is 401 invalid_token"
  - "Empty form parameters are treated as omitted (RFC 6749 §3.1), but a repeated name is invalid_request even if one copy is empty"
  - "/token and /userinfo responses carry Cache-Control: no-store and Pragma: no-cache (success and error)"
metrics:
  duration: 35min
  completed: 2026-11-25
  tasks: 2
  files: 11
---

# Phase 2 Plan 14: /token and /userinfo endpoints Summary

**This plan puts the token side of the OP on HTTP.** `POST /token` covers authorization_code, refresh_token and client_credentials, and `GET/POST /userinfo` accepts a Bearer token from the header or a form body. Both handlers are thin layers over `TokenService` and `UserInfoService`. 76 integration tests prove the token-side security controls on SQLite and on Postgres.

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | /token endpoint with code, refresh, client-credentials and client-auth tests | a03e296 |
| 2 | /userinfo endpoint and token-confusion tests | 7cb85dd |

## What was built

- **protocol/token.rs:**
  - The endpoint accepts only `application/x-www-form-urlencoded` (charset parameter allowed). Any other body is `invalid_request`, and so is a repeated parameter.
  - The raw `Authorization` header goes into `ClientAuthInput.basic`.
  - `AppState::token_service()` builds `TokenService { storage, clock, kek }`.
  - 200 responses carry `Cache-Control: no-store` and `Pragma: no-cache`. Errors go through `oauth_json`, which adds `WWW-Authenticate: Basic` when Basic authentication was used.
  - `public_cors()` is applied. GET gets 405.
- **protocol/userinfo.rs:**
  - The pure `extract_token` picks the token from the header (GET/POST) or the form body (POST only).
  - An `access_token` in the query gets 401. A token sent in both the header and the body gets 400 `invalid_request`. A malformed header gets 401 with `Bearer error="invalid_token"`.
  - `AppState::userinfo_service()` provides the service, and responses are JSON with `no-store`. CORS is enabled.
- **Tests:** these run as integration tests on both backends unless marked as unit tests.

  | File | Tests | What they cover |
  |------|-------|-----------------|
  | token | 8 | Basic, post and public clients. The id_token is verified against the published keys with the right kid, and its iss/sub/aud/azp/nonce/auth_time/acr/amr/at_hash are checked. The AT has `at+jwt`. Refresh token only with the grant, no id_token without openid, tenant path issuer, non-form and duplicate parameters, 405, CORS |
  | token_client_credentials | 7 | AT only (no refresh, no id_token, no fid), scope within the registration, openid is invalid_scope, public and code-only clients are unauthorized_client, password/implicit/device code are unsupported_grant_type, missing grant_type is invalid_request |
  | security_code | 10 | Reuse leads to invalid_grant, then the first AT gets 401 at /userinfo and the RT fails. +61 s, another client, redirect mismatch or missing, challenge without verifier, verifier without challenge, wrong verifier, unknown code, blocked user |
  | security_refresh | 8 | Rotation, reuse revokes the newest RT, another client's RT is rejected without revocation, scope widening is invalid_scope, idle expiry, the refreshed id_token keeps auth_time and has no nonce |
  | security_client_auth | 9 | Wrong secret gets 401 with the Basic challenge, an unknown client gets an identical body, basic plus body secret, wrong method in both directions, no credentials, a public client sending a secret, malformed Basic headers, urlencoded special characters (positive and negative), an acme client at the default /token |
  | security_private_key_jwt | 16 | Typed and untyped assertions accepted. Rejected: token-endpoint aud, multi-valued aud, replay, reused jti, exp over 5 min, expired, missing jti or exp, iss different from sub, HS256, none, unknown kid, an unregistered key under the registered kid, a secret client, an assertion plus a secret, the wrong assertion type |
  | userinfo | 7 | Header GET, header POST and body POST, openid gives only sub, typed scope claims, no leaks across scopes, a claims.userinfo request (absent from the id_token), the tenant path, CORS |
  | security_userinfo | 11 | Query token, header plus body, missing token, ID token, another tenant's AT, a CC AT (403), no openid (403), expired, revoked family, blocked user, malformed or tampered bearers |
  | Unit tests (token.rs, userinfo.rs) | 4 + 7 | Form parsing, content type, raw Authorization pass-through; token extraction rules |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Shared test helper module `tests/token_support/mod.rs` (not in files_modified)**
- **Issue:** Eight test binaries need the same seeding code: client registration, user, session, code, the acme tenant and client keys. The plan forbids editing the harness, and copying the helpers into each file would duplicate about 400 lines eight times.
- **Fix:** I added a new helper module that is used only by this plan's tests. Other wave-3 plans did the same (`admin_support/`, `ui_helpers/`, `authz/`), and the unique name avoids conflicts.
- **Commits:** a03e296, 7cb85dd

**2. [Rule 3 - Blocking] Clients registered with the ClientService rules, not the ClientService struct**
- **Issue:** `ClientService` needs `Arc<dyn Storage>`, but `TestApp` exposes storage only as `&dyn Storage`, and the harness must not be edited.
- **Fix:** The `register` helper runs what `ClientService::create` runs: `validate_client(&input, validate_redirect_uri)`, then `new_client_id`, then `new_client_secret`, then `ClientRepo::create`.

**3. ID token verified against `published_jwks`, not the `/jwks` endpoint**
- `/jwks` is built by 02-13 in parallel and had not landed. The tests verify against `service::key::published_jwks`, the same function the endpoint serves, and check the header kid against the installed key. The full `/jwks` round trip is covered by conformance (02-19).

**4. The /userinfo assertion in security_code landed in Task 2**
- /userinfo did not exist during Task 1, so Task 1 proved family revocation through the refresh token. Task 2 added the "first AT gets 401 at /userinfo" check to security_code.rs.

### Process notes

- TDD: the handlers were written next to the tests. RED would have been a 404 for every request, because the routes did not exist yet.
- At the time of this plan, 02-16's uncommitted `admin/auth.rs` (clone_on_copy) and 02-15's committed `tests/ui_helpers/mod.rs` (manual_pattern_char_comparison) break `cargo clippy -p anvil-web --all-targets -- -D warnings`. I ran clippy in a temporary worktree (target/wt-02-14) at HEAD with this plan's files, scoped to `--lib` plus this plan's eight test targets with `-D warnings`. It was clean, and I removed the worktree afterwards. I did not touch either file.

## Verification

- `cargo test -p anvil-web --test token --test token_client_credentials --test security_code --test security_refresh --test security_client_auth --test security_private_key_jwt --test userinfo --test security_userinfo`: all green.
- `ANVILID_TEST_DB=postgres` with the same targets: all green.
- `cargo test -p anvil-web --lib protocol::`: 11 passed.
- clippy `-D warnings` on the lib and this plan's targets is clean in the worktree. `rustfmt --check` is clean on every file of this plan.

## Self-Check: PASSED
