---
phase: 02-release-0-1-first-login
plan: 08
subsystem: core-token-side
tags: [oidc, token-endpoint, client-auth, jwt, userinfo, pkce, refresh-rotation, rfc9068, rfc9700]
requires: [02-01, 02-02]
provides:
  - "service::client_auth: ClientAuthenticator (single client-auth impl), parse_basic, select_method, check_method, secret_matches, verify_assertion"
  - "service::key: KeyService::{signer, jwks}, open_key, jwks_from_rows, published_jwks"
  - "service::claims: scope_claims, requested_claims, id_token_claims, access_token_claims, ID_TOKEN_TTL, ACCESS_TOKEN_TTL"
  - "service::token: TokenService::token, TokenRequest/TokenResponse, pure grant rules, sign_access_token/sign_id_token"
  - "service::userinfo: AccessTokenVerifier (single AT validator, reused by 02-16), UserInfoService, verify_access_token_jwt"
affects: [02-14, 02-16, anvil-web]
tech-stack:
  added: []
  patterns:
    - "Every rule a pure function, async services only orchestrate ports"
    - "One generic error description per failure class (invalid_client, invalid_grant, invalid_token)"
    - "Redacting Debug on every struct holding secrets or tokens"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/client_auth.rs
    - crates/anvil-core/src/service/key.rs
    - crates/anvil-core/src/service/claims.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/src/service/userinfo.rs
decisions:
  - "KeyService gained a clock field (published keys need now); published_jwks(storage, clock, tenant) is the shared JWKS path so the AT verifier needs no KEK"
  - "Every client-credential failure (unknown client, wrong secret, method mismatch, bad assertion, replay) uses the one description 'client authentication failed'; CoreError::description() returns the reason, so it cannot be specific"
  - "The method none requires client_type Public and every secret/JWT method requires Confidential, on top of auth_method equality"
  - "Assertion jti recorded until exp + 30 s leeway (assertions are accepted while exp > now - leeway)"
  - "validate_refresh lets an already-consumed token from the right client pass (skipping scope checks) so rotate_refresh's reuse detection revokes the family; wrong client is always rejected before consume"
  - "A code without a challenge is refused for require_pkce or public clients (defence in depth beyond the authorize endpoint)"
  - "Token grants check the user still exists and is Active (invalid_grant); UserInfo does the same (invalid_token)"
  - "client_credentials without a scope gets every registered scope except openid"
  - "UserInfo order: missing openid -> insufficient_scope first, then missing fid (client-credentials token) -> invalid_token"
metrics:
  duration: 30min
  completed: 2026-11-25
requirements-completed: [OIDC-03, OIDC-04, OIDC-05, OIDC-06, OIDC-07, OIDC-08, OIDC-09, SEC-01]
---

# Phase 2 Plan 08: Token side of the OP Summary

**This plan adds the token side of the OP in anvil-core.** Client authentication covers basic, post, private_key_jwt with a jti replay guard, and none. KeyService opens the active RS256 key with the KEK. The token endpoint handles authorization_code, refresh_token and client_credentials, including code-reuse family revocation and the PKCE downgrade defence. ID tokens and RFC 9068 `at+jwt` access tokens are minted, and one AccessTokenVerifier is shared by UserInfo and the admin API. Each rule is a pure function with unit tests.

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | KeyService, claims builders, ClientAuthenticator | cde7a94 |
| 2 | TokenService grants, AccessTokenVerifier, UserInfoService | 862ffff |

## What was built

- **client_auth.rs** has three parts:
  - **Parsing.** `parse_basic` follows RFC 6749 §2.3.1: a case-insensitive scheme, strict standard base64 (hand-written, because anvil-core has no base64 dependency), and form-urldecoding of the id and the secret.
  - **Method checks.** `select_method` rejects a request that presents more than one method, a body client_id that contradicts the credentials, and any foreign assertion type. For private_key_jwt the client is looked up by the unverified `sub` of the assertion. `check_method` compares the method used with the registered one and also checks the client type.
  - **Authentication.** `secret_matches` compares hashes in constant time and uses a dummy hash when the client is unknown. `verify_assertion` uses `Jwks::parse`, which rejects private members, then `verify_client_assertion`, and returns the replay hash `secret_hash(client_id ‖ "\0" ‖ jti)`. `ClientAuthenticator::authenticate` ties these together and calls `record_jti`.
- **key.rs**: `open_key` uses `Kek::open` with `SIGNING_KEY_PURPOSE` and `signing_key_aad(id)`, then `SigningKey::from_pkcs8`. Every failure becomes `Internal`. `jwks_from_rows` and `published_jwks` assemble the published key set. `KeyService::{signer, jwks}`.
- **claims.rs**: scope claims follow OIDC Core §5.4. They use typed booleans, an address object and a numeric `updated_at`, and omit absent values. The `claims` parameter requests are honoured. The ID token builder stops `claims.id_token` extras from overriding protocol claims. The AT builder sets `aud` and `client_id`, adds `fid` only for user tokens, and adds `auth_time`/`acr` when a user is present.
- **token.rs**: the pure rules are `parse_grant_type`, `check_client_grant`, `validate_code_exchange`, `validate_refresh`, `check_client_credentials`, `refresh_expiry` (min(now + 14 d, family absolute)), `check_user` and `family_id_token_input`. `TokenService::token` orchestrates them over the ports.
- **userinfo.rs**: `verify_access_token_jwt` is the pure check: typ at+jwt, iss, exp and the claim shapes. `check_family` and `userinfo_requirements` cover the family and scope rules. `AccessTokenVerifier::verify` and `UserInfoService::userinfo` are built on them.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] KeyService needs a clock**
- **Found during:** Task 1
- **Issue:** `KeyRepo::published(tenant, now)` needs the current time, but the planned `KeyService { storage, kek }` has no clock, and core code must not call `now_utc()`.
- **Fix:** Added a `clock: Arc<dyn Clock>` field. The free function `published_jwks(storage, clock, tenant)` is shared with AccessTokenVerifier and UserInfoService, so neither needs the KEK.
- **Commit:** cde7a94

**2. [Rule 2 - Security] Generic invalid_client / invalid_grant / invalid_token descriptions**
- **Issue:** The interface calls `InvalidClient.reason` "internal only", but `CoreError::description()` returns it to the client.
- **Fix:** Every credential failure uses one fixed reason. Grant and token failures also use one description per class, so a response never reveals which check failed.
- **Commits:** cde7a94, 862ffff

**3. [Rule 2 - Security] Extra defensive checks**
- A consumed refresh token from the right client goes to `rotate_refresh` even when it asks for a wider scope. Without this, an attacker could avoid family revocation by asking for more scope.
- A code without a challenge is refused for public clients and for clients with require_pkce.
- A user who is blocked or deleted cannot exchange or refresh tokens.
- The AT family must belong to the token's client.

### Process notes

- Wave-2 plans running at the same time left `flow/engine.rs` uncompilable for a while. Verification therefore ran in an isolated `git archive HEAD` snapshot plus this plan's files, using a separate target dir. The live tree was then green too: `cargo test -p anvil-core service::` passed 95 tests.
- Async orchestration has no unit tests here because anvil-core has no async runtime dev-dependency. As the plan says, it gets HTTP end-to-end tests on both backends in 02-14.

## Verification

- `cargo test -p anvil-core`: 182 passed in the snapshot. This plan adds 46 tests: claims 10, key 3, client_auth 12, token 15, userinfo 6.
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean for these files.

## Notes for downstream plans

- **02-14 / anvil-web:** build `TokenService { storage, clock, kek }`. Map `CoreError::InvalidClient { basic_auth_used: true }` to `WWW-Authenticate: Basic`, and set `Cache-Control: no-store` on token responses. `TokenResponse` serialises without `id_token` or `refresh_token` when they are absent.
- **02-16:** reuse `AccessTokenVerifier::verify(tenant, issuer, token)`. Do not write a second validator.
- **02-10:** store `Client.secret_hash` as `SecretHash(anvil_jose::encoding::secret_hash(secret))`, and seal keys with `SIGNING_KEY_PURPOSE` and `signing_key_aad(id)`. The test helper `key::tests::sealed_row` shows the exact pairing.

## Self-Check: PASSED
