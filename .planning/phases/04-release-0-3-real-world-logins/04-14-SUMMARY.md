---
phase: 04-release-0-3-real-world-logins
plan: 14
subsystem: upstream-idp
tags: [upstream, oidc, oauth2, jwks, ssrf, github, wiremock]
requires:
  - phase: 04-01
    provides: UpstreamClient port, UpstreamError, ApiProfile, TokenEndpointAuth
  - phase: 04-02
    provides: guarded OutboundClient (SSRF policy, timeouts, body limits)
  - phase: 04-07
    provides: anvil_jose RS256/ES256 keys and JWK types used by the test MockProvider
provides:
  - UpstreamHttp (impl UpstreamClient) with discovery, JWKS cache, code exchange, bearer API calls
  - From<OutboundError> for UpstreamError
  - tests/upstream_support MockProvider reused by 04-21 and 04-26
affects: [04-21, 04-26]
tech-stack:
  added: []
  patterns:
    - every upstream request goes through the one guarded OutboundClient
    - moka caches (discovery 1 h per issuer, JWKS per URI with max-age TTL) that never cache failures
key-files:
  created:
    - crates/anvil-web/src/adapters/upstream/discovery.rs
    - crates/anvil-web/src/adapters/upstream/jwks.rs
    - crates/anvil-web/src/adapters/upstream/token.rs
    - crates/anvil-web/src/adapters/upstream/api.rs
    - crates/anvil-web/tests/upstream_adapter.rs
    - crates/anvil-web/tests/upstream_support/mod.rs
  modified:
    - crates/anvil-web/src/adapters/upstream/mod.rs
    - crates/anvil-web/src/adapters/outbound.rs
key-decisions:
  - "A throttled forced JWKS refresh returns the cached set (or fetches when nothing is cached), so tokens with random kids cannot cause an upstream request flood"
  - "Cache-Control no-store/no-cache on a JWKS counts as the 5 min minimum TTL; a missing header gives 1 h"
  - "A 200 token response carrying error (GitHub style) is InvalidResponse; a non-2xx is Status(code) and the body is not echoed"
  - "OutboundError::InvalidUrl maps to UpstreamError::Blocked (an unusable destination is a refused destination)"
  - "Signed (JWT) userinfo responses are not supported; API responses must be JSON"
requirements-completed: [AUTH-07, SEC-03]
duration: multi-session (interrupted twice)
completed: 2026-11-25
---

# Phase 4 Plan 14: Upstream IdP HTTP Adapter Summary

`UpstreamHttp` implements the `UpstreamClient` port, and every request goes through the SSRF-guarded `OutboundClient`. It covers four pieces:

- **OIDC discovery:** the issuer must match exactly, and every endpoint must be a URL the outbound policy allows.
- **JWKS cache:** the TTL is the response's max-age clamped to 5 min to 24 h, forced refresh is limited to once per minute per URI, failed fetches fail closed, and keys with private members are rejected.
- **Code exchange:** supports basic or post client auth, sends PKCE verifiers, and always sends `Accept: application/json`.
- **Bearer API calls:** the GitHub profile adds the headers the GitHub REST API needs.

A wiremock MockProvider is included for the downstream login plans.

## Tasks

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | UpstreamHttp adapter (discovery, JWKS cache, token, API) | 9336ebe |
| 2 | MockProvider support + transport tests | 44a4b52 |

## What was built

- `upstream/mod.rs`: `UpstreamHttp::new(Arc<OutboundClient>)` and `impl UpstreamClient for UpstreamHttp`. Logs go at debug level and name only the host. Codes, secrets and tokens are never logged.
- `discovery.rs`: fetches `{issuer}/.well-known/openid-configuration` without doubling a trailing slash. The issuer must match exactly (OIDC Discovery 1.0 §4.3), endpoints must be https (plain http only where the outbound policy allows it), and accepted documents are cached for 1 h.
- `jwks.rs`: `ttl_from_cache_control` clamps the TTL to [`MIN_TTL`, `MAX_TTL`] and limits forced refreshes with `REFRESH_THROTTLE`. Failed fetches fail closed, and a JWKS carrying `d`/`p`/`k`/... members is rejected.
- `token.rs`: `client_secret_basic` (form-urlencoded credentials in the Basic header), `client_secret_post`, and public clients (sends only `client_id`). Also sends the PKCE verifier, reads at most `LIMIT_TOKEN` (64 KiB), and handles GitHub's 200-with-error responses.
- `api.rs`: Standard profile versus GitHub profile. The GitHub profile sends `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28` and a `User-Agent`. Responses are limited to `LIMIT_DOCUMENT` (1 MiB).
- `outbound.rs`: `From<OutboundError> for UpstreamError`.
- `tests/upstream_support/mod.rs`: MockProvider with Oidc, Google, Microsoft, Apple, Github and Oauth2 kinds. It generates RS256 and ES256 keys at runtime and builds id_token helpers, including `alg: none` and HS256 key-confusion tokens. It also supports `rotate_key`, configurable JWKS/token/userinfo/GitHub replies, and recorded token requests.
- `tests/upstream_adapter.rs`: tests for discovery (including issuer mismatch and a disallowed endpoint), the JWKS cache, clamp, throttle, fail-closed and private-member rejection, basic vs post auth, PKCE, the JSON Accept header, TooLarge, Status, GitHub's 200-with-error, the GitHub headers, and SSRF Blocked.

## Verification (at afe15dd, main tree)

- `cargo test -p anvil-web --test upstream_adapter`: 18 passed
- `cargo test -p anvil-web --test security_ssrf`: 9 passed, 1 ignored (the ignored test is the proxy child process, which its parent test runs)
- `cargo test -p anvil-web --lib upstream`: 5 passed
- `cargo clippy -p anvil-web --lib --test upstream_adapter --test security_ssrf -- -D warnings`: clean
- `rustfmt --check --edition 2024` on all plan files: clean

## Deviations from Plan

None. The plan was executed as written.

## Deferred Issues

- `cargo clippy -p anvil-web --all-targets` currently fails on unused imports in the untracked `crates/anvil-web/tests/account_profile.rs`. That file is another plan's uncommitted work in progress, so it is out of scope here.

## Notes

- Execution was interrupted twice. Task 2 was committed after confirming that the main-tree files were byte-identical to the verified worktree copies. The worktree `target/wt-04-14` has been removed. Final verification ran in the main tree, with no per-worktree target dir.

## Self-Check: PASSED

- All 8 key files exist; commits 9336ebe and 44a4b52 are in history.
