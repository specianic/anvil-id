---
phase: 03-release-0-2-secure-by-default
plan: 18
subsystem: oauth-token-lifecycle
tags: [oauth, introspection, revocation, opaque-tokens, rfc7662, rfc7009, rfc9068, discovery, audit]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "03-02 access-token ports/model (TokenFormat, can_introspect, RevokeReason::TokenRevoked, UnsupportedTokenType); 03-08 protocol::{introspect,revoke} route modules; 03-10 enabled_algs; 03-11 response_mode::SUPPORTED; 03-13 token-class rate limiting on /introspect and /revoke"
provides:
  - Opaque (256-bit, SHA-256-stored) access tokens for token_format=opaque clients, for all three grants
  - AccessTokenVerifier opaque path (single verifier for UserInfo, introspection, admin API)
  - IntrospectionService (RFC 7662) + POST /introspect
  - RevocationService (RFC 7009) + POST /revoke
  - Audit of token_revoked, code_reuse_detected, refresh_reuse_detected
  - Phase 3 discovery fields (introspection/revocation endpoints + auth methods, response_modes [query, form_post], tenant ID token algs)
affects: [03-23, 03-24, 03-25, 03-28, docs]
tech-stack:
  added: []
  patterns:
    - "Back-channel client-form helper (protocol::introspect::client_form_request / authenticated) shared by /introspect and /revoke"
    - "Token-kind lookup order by token_type_hint (introspect: unknown hint ignored; revoke: unknown hint -> unsupported_token_type)"
key-files:
  created:
    - crates/anvil-web/tests/access_token_format.rs
    - crates/anvil-web/tests/security_introspect_revoke.rs
  modified:
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/src/service/userinfo.rs
    - crates/anvil-core/src/service/introspect.rs
    - crates/anvil-core/src/service/revoke.rs
    - crates/anvil-web/src/protocol/introspect.rs
    - crates/anvil-web/src/protocol/revoke.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/tests/discovery.rs
key-decisions:
  - "OQ1: access-token aud stays = client_id until RFC 8707 resource indicators (Phase 4); the family claim is fid (OQ4)"
  - "OQ3: revoking another client's token returns 200 and changes nothing (no oracle); can_introspect grants visibility only, never revocation"
  - "JWT client-credentials access tokens (no fid, nothing server-side) cannot be revoked: /revoke answers unsupported_token_type; opaque client-credentials tokens can be revoked"
  - "introspection_endpoint_auth_methods_supported omits none (public clients get invalid_client); revocation_endpoint_auth_methods_supported = token endpoint list incl. none"
  - "Reuse audit events from TokenService carry an empty RequestContext: protocol/token.rs (not editable here) builds TokenRequest without request data"
requirements-completed: [OIDC-10, OIDC-15, OIDC-11, OIDC-25, ADM-04]
duration: 75min
completed: 2026-11-25
---

# Phase 3 Plan 18: Token lifecycle (opaque/JWT access tokens, /introspect, /revoke, discovery) Summary

**Each client now gets either RFC 9068 JWT or opaque SHA-256-stored access tokens. RFC 7662 introspection enforces caller visibility, RFC 7009 revocation revokes the whole family, revocations and reuse detections are audited, and discovery publishes the Phase 3 metadata.**

## Performance

- **Duration:** ~75 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- **Opaque access tokens.** `TokenService` branches on `client.token_format` for code exchange, refresh and client credentials. An opaque token is `random_token()` (43 base64url chars, 256 bits), stored via `create_access_token` as SHA-256 only. It is linked to the family (none for client credentials), with the 600 s lifetime. The response shape is unchanged, and `at_hash` covers the opaque value.
- **Single verifier.** `AccessTokenVerifier::verify` sends non-JWT-shaped tokens to an opaque path: hash lookup plus the pure `opaque_claims` check (not revoked, not expired, live family of the same client and user). `UserInfoService` now uses the verifier. `AccessTokenClaims` gained `iat` and `jti`.
- **IntrospectionService.**
  - Public callers get `invalid_client`.
  - `is_visible` lets a caller see its own tokens, and any token of the tenant only with `can_introspect`.
  - `refresh_active` covers refresh tokens.
  - Inactive answers serialise to exactly `{"active":false}`.
  - Active answers carry active, scope, client_id, sub, aud, iss, exp, iat, token_type (`Bearer` or `refresh_token`), plus jti for JWTs.
- **RevocationService.**
  - Refresh token: the family is revoked.
  - Opaque AT: the token and its family are revoked.
  - JWT AT with fid: the family is revoked.
  - JWT AT without fid: `unsupported_token_type`.
  - Another client's token or an unknown token: Ok with no effect.
  - The hint is strict.
  - `token_revoked` is audited with the family as target, never the token. A family that was already revoked is not audited twice.
- **Reuse audit.** `code_reuse_detected` and `refresh_reuse_detected` are recorded in `TokenService`, with the client as actor and the family as target.
- **HTTP.** `POST /introspect` and `POST /revoke` follow the /token conventions: form only, a repeated parameter is invalid_request, an empty value counts as omitted, and responses carry no-store plus Pragma. Both use the single `ClientAuthenticator`. Other methods get 405.
- **Discovery.** Now publishes:
  - `introspection_endpoint` and `revocation_endpoint`, with their auth methods and signing algs
  - `response_modes_supported` = `response_mode::SUPPORTED`
  - `id_token_signing_alg_values_supported` from `enabled_algs(tenant)`

## Task Commits

1. **Task 1: Opaque ATs, verifier, introspection and revocation services**: `7c27ad3` (feat)
2. **Task 2: /introspect, /revoke handlers, discovery, HTTP security tests**: `7b5bb69` (feat)

## Decisions Made

- OQ1: `aud` = client_id until resource indicators arrive in Phase 4. OQ4: the family claim is `fid`.
- OQ3: revoking another client's token returns 200 and changes nothing. `can_introspect` never grants revocation.
- JWT client-credentials access tokens cannot be revoked and get `unsupported_token_type` (to be documented). Opaque CC tokens can be revoked.
- Introspection does not advertise the `none` auth method; revocation does.
- RFC 8414 requires `*_auth_signing_alg_values_supported` when `private_key_jwt` is listed, so introspection and revocation publish the token endpoint's list (RS256, PS256, ES256).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] Introspection auth methods omit `none`**
- **Found during:** Task 2
- **Issue:** The plan said `*_auth_methods_supported` = the token endpoint's list. But introspection refuses public clients, so advertising `none` would describe a capability that does not exist.
- **Fix:** Introspection lists basic, post and private_key_jwt. Revocation lists the full token list. Tests assert both.
- **Files modified:** crates/anvil-web/src/protocol/discovery.rs, crates/anvil-web/tests/discovery.rs
- **Commit:** 7b5bb69

**2. [Rule 2 - Correctness] Signing-alg metadata for introspection and revocation**
- **Found during:** Task 2
- **Issue:** RFC 8414 §2 makes the `*_auth_signing_alg_values_supported` entries mandatory when `private_key_jwt` is listed.
- **Fix:** Both endpoints publish the token endpoint's list. Both names are already in the discovery allow-list.
- **Commit:** 7b5bb69

**3. [Scope] Unit tests on pure rules instead of storage fakes**
- **Issue:** anvil-core has no in-memory `Storage` fake.
- **Fix:** Pure functions are unit-tested in core: `opaque_claims`, `is_jwt_shaped`, `is_visible`, `require_confidential`, `refresh_active`, `lookup_order`, `introspection_hint`, `revocation_hint`, `jwt_revocation_target`, `owned_by`, `new_opaque_access_token` and the response serialisation. The orchestration matrix (visibility, revocation effects, audit) is covered over HTTP on SQLite and Postgres. This follows the existing token.rs convention.

None of the other behaviour deviates from the plan.

## Issues Encountered

- Other plans' in-progress consent edits broke the shared build, so all verification ran in a dedicated worktree (`target/wt-03-18`) with its own target dir. Both were removed afterwards.

## Verification

- `cargo test -p anvil-core -p anvil-web` (SQLite): all green, including `security_admin`, `userinfo`, `token` and `discovery`.
- `ANVILID_TEST_DB=postgres cargo test -p anvil-web --test security_introspect_revoke --test access_token_format --test discovery`: all green.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings` and `cargo fmt --check`: clean.

## Next Phase Readiness

- Docs: record the JWT client-credentials `unsupported_token_type` behaviour and the opaque/JWT trade-off.
- Admin API/console (03-23/03-24) can expose `token_format` and `can_introspect` on clients. Both are already persisted.

## Self-Check: PASSED
