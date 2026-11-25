---
phase: 04-release-0-3-real-world-logins
plan: 12
subsystem: oauth
tags: [rfc8707, resource-indicators, audience, introspection, userinfo, consent, oidc-16]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01: AuthorizationParams.resource, resource on code/family/access token, Client.allowed_resources, CoreError::InvalidTarget; 04-04/04-05: storage of those columns; 04-06: t() and per-feature .ftl; 04-08: oauth::resource"
provides:
  - "/authorize and /token accept a repeated `resource` (the only repeatable parameter), validated against allowed_resources, invalid_target otherwise"
  - "Granted resources stored on code, family and opaque access-token rows; code, refresh and client_credentials downscoping"
  - "Access-token aud = selected resource(s) (string for one, array for several), client_id without one; ID-token aud unchanged"
  - "AccessTokenClaims.aud (JWT aud required); introspection aud string|array for JWT and opaque tokens"
  - "UserInfo audience rule (aud must contain client_id or {issuer}/userinfo, else invalid_token)"
  - "ConsentPage.resources + consent screen 'Access to' list"
  - "token::refresh_resources, token::client_credentials_resources, RawParams::all"
affects: [04-16, 05-agt-01]

tech-stack:
  added: []
  patterns:
    - "Malformed resources are refused before a code is consumed; a downscope failure after consumption revokes the code's family"
    - "A consumed refresh token skips resource downscoping so rotate_refresh still detects the reuse"

key-files:
  created:
    - crates/anvil-web/tests/resource_indicators.rs
    - themes/default/locales/en/resource.ftl
  modified:
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/src/service/claims.rs
    - crates/anvil-core/src/service/introspect.rs
    - crates/anvil-core/src/service/userinfo.rs
    - crates/anvil-core/src/service/consent.rs
    - crates/anvil-web/src/protocol/token.rs
    - crates/anvil-web/src/ui/consent.rs
    - themes/default/templates/consent.html

key-decisions:
  - "Multi-value rule: only `resource` may repeat. Empty values are treated as omitted and duplicates are removed (first occurrence kept). Every other repeated parameter is still invalid_request. Other form endpoints (parse_form) still reject a repeated `resource`."
  - "/authorize checks resources last (after claims), so a bad resource is a redirect with error=invalid_target, state and iss. Before the redirect URI is trusted it is still an error page."
  - "aud serialisation: one value is a JSON string, several are an array in request order, none is client_id (oauth::resource::audience). Introspection uses the same shape. A refresh token's introspection aud stays client_id."
  - "JWT access tokens must carry a non-empty aud (string or array of non-empty strings), otherwise invalid_token. Every token this OP mints has one."
  - "UserInfo rule: the audience check runs right after token verification and before the scope check. A token bound only to other resources is invalid_token (401), not insufficient_scope."
  - "Token endpoint order: client authentication first, then parse_resources (before anything is consumed), then grant-specific downscope or validate."
  - "A code whose exchange asks for a resource outside the grant is burned and its family revoked (RevokeReason::CodeReuse, the same as other post-consume exchange failures)."
  - "Grants (stored consent) stay scope-only, so a remembered consent does not prompt again for a different allowed resource of the same client. This is a documented Phase 5 gap on ConsentPage.resources."

patterns-established:
  - "Add per-grant resource selection through pure helpers in service::token, unit-tested, with the service only orchestrating"

requirements-completed: [OIDC-16]

duration: about 2h (including two session interruptions)
completed: 2026-11-25
---

# Phase 4 Plan 12: RFC 8707 Resource Indicators Summary

**Repeated `resource` at /authorize and /token, checked against each client's allowed_resources, with invalid_target for anything else. Resources are stored on the code, the family and opaque tokens. The code, refresh and client_credentials grants can only downscope. Access-token aud is the selected resource(s), introspection returns aud, UserInfo enforces the locked audience rule, and the consent screen lists the resources.**

Note: `requirements-completed` lists OIDC-16 as delivered by this plan. No requirement checkbox was ticked (wave rule).

## Accomplishments
- `authorize_request::validate`: `first_duplicate` skips `resource`. `RawParams::all("resource")` goes through `parse_resources` and `validate_resources` into `AuthorizationParams.resource`. `build_code` copies the result onto the code and the family.
- `TokenRequest.resource`. Parsing happens after client authentication. Code grant: `resource::downscope(code.resource, requested)`. Refresh: `refresh_resources` (downscope against family.resource; the family and the refresh token keep the full grant). client_credentials: `client_credentials_resources` (validate against allowed_resources). The selected resources go to `AccessTokenInput.resource` and to `new_opaque_access_token`.
- `access_token_claims`: aud = `audience(resource, client_id)`. `id_token_claims` is unchanged (`[client_id]`).
- `AccessTokenClaims.aud`: the JWT `aud`, or `audience(record.resource, client_id)` for opaque rows. `IntrospectionResponse.aud` is now `Option<Audience>`.
- `UserInfoService::userinfo` calls `userinfo_audience_ok` before anything else.
- `/token` form parser: `parse_form_with_repeatable(body, Some("resource"))`. `parse_form` is unchanged for the other endpoints.
- Consent: `ConsentPage.resources`. The template adds an `Access to` section (`consent.resources` in `locales/en/resource.ftl`) with `<bdi><code>` values, rendered only when resources were requested. The existing consent markup and tests are unchanged.

## Task Commits
1. **Task 1: Core parse/store/downscope/audience/introspection/UserInfo** in `3157e9a` (feat). It also contains the `/token` parser change (Task 2's file) so the workspace kept building for the parallel plans.
2. **Task 2: Consent display + integration tests** in `90e0f74` (feat)

## Verification
- `cargo test -p anvil-core --lib`: 527 passed (main tree, after the other wave-3 commits). New unit tests:
  - authorize_request: resource may repeat, empty and none, other repeats still rejected, bad resources give invalid_target, untrusted redirect still gives a page
  - build_code: resources copied
  - claims: aud shapes, ID-token aud
  - token: refresh downscope, consumed refresh reaches reuse detection, client_credentials allow-list, opaque row resource, debug output
  - userinfo: aud string or array read, missing or malformed aud rejected, opaque aud and rule
  - introspect: aud shapes
  - protocol/token: only resource repeats
- `cargo test -p anvil-web` with `--test resource_indicators` (15 tests) plus token, authorize, userinfo, consent, access_token_format, security_introspect_revoke, security_userinfo, token_client_credentials, security_setup, admin_api, i18n, render, security_refresh, security_code, sessions and response_mode: all green on SQLite.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings`: clean (run in an isolated worktree while other plans' in-progress files broke the main tree).

## Not run
- `ANVILID_TEST_DB=postgres` for resource_indicators, because Docker is unavailable. CI will verify it.
- Fuzz build: `fuzz/fuzz_targets/authorize_parse.rs` uses `parse_raw`/`validate`/`Client`, whose signatures did not change. Not built (nightly toolchain; disk rule).
- The full `cargo test -p anvil-web` suite: only the targeted binaries above were run (disk rule).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra files the build forced**
- `crates/anvil-core/src/service/revoke.rs` (test fixture: the new `AccessTokenClaims.aud`)
- `crates/anvil-web/tests/admin_support/mod.rs` (`AccessTokenInput.resource: &[]`)
- `crates/anvil-web/tests/security_setup.rs` (`TokenRequest.resource: vec![]`)
- No shared registry file (lib.rs, ui/mod.rs, route tables, locales index) needed an edit: `.ftl` files are discovered per directory.
- Commit: 3157e9a

**2. [Rule 2 - Correctness] Reuse detection kept for resource-downscoped refresh**
- A consumed refresh token presented with an out-of-grant resource would otherwise get invalid_target and skip family revocation. `refresh_resources` returns the family's resources for consumed tokens, so `rotate_refresh` still revokes. Unit-tested.

**3. [Rule 2 - Correctness] Malformed resources at /token checked before the code is consumed**
- An out-of-grant resource can only be detected after consumption, so in that case the family is revoked. Integration-tested: the code is burned, and malformed attempts leave the code usable.

**4. [Design] JWT access tokens now need `aud`**
- The rule needs the audience, so a JWT access token without a valid `aud` is invalid_token. Every token this OP mints has one, and no existing test changed.

## Next Phase Readiness
- Phase 5 AGT-01 (MCP) can rely on aud containing the requested resource.
- Open gap: resource-aware stored consent (Phase 5).

## Self-Check: PASSED
- Files exist: crates/anvil-web/tests/resource_indicators.rs, themes/default/locales/en/resource.ftl
- Commits in history: 3157e9a, 90e0f74
