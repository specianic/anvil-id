---
phase: 04-release-0-3-real-world-logins
plan: 26
subsystem: upstream-idp
tags: [upstream, social-login, google, microsoft, apple, github, oauth2, wiremock, mock-idp, auth-07, auth-11, sec-03]
requires:
  - phase: 04-14
    provides: tests/upstream_support MockProvider, UpstreamHttp
  - phase: 04-21
    provides: upstream start/callback routes, tests/upstream_flow helpers
provides:
  - per-provider mock IdP suites (upstream_google, upstream_microsoft, upstream_apple, upstream_github, upstream_oauth2)
  - MockProvider Apple client-secret verification, attack_tokens builder, GHES API paths
affects: [04-31, 04-33]
tech-stack:
  added: []
  patterns:
    - provider suites drive the real routes against wiremock through per-connection endpoint overrides; provider hosts appear only as issuer strings
key-files:
  created:
    - crates/anvil-web/tests/upstream_google.rs
    - crates/anvil-web/tests/upstream_microsoft.rs
    - crates/anvil-web/tests/upstream_apple.rs
    - crates/anvil-web/tests/upstream_github.rs
    - crates/anvil-web/tests/upstream_oauth2.rs
  modified:
    - crates/anvil-web/tests/upstream_support/mod.rs
    - crates/anvil-core/src/upstream/providers.rs
    - crates/anvil-core/src/upstream/claims.rs
key-decisions:
  - "A single-tenant Microsoft connection accepts only its own tid (resolve pins allowed_tenants to the tenant; an admin list that excludes it is kept and refuses everything)"
  - "Shared attack cases are a TestApp-free token builder in upstream_support (MockProvider::attack_tokens); each suite drives them through its own callback shape (query or Apple form_post)"
requirements-completed: []
duration: about 1h 15min (including waits for concurrent plans' broken builds)
completed: 2026-11-25
---

# Phase 4 Plan 26: Per-provider Mock IdP Suites Summary

**Five wiremock-backed provider suites (34 tests) run Google, Microsoft, Apple, GitHub and generic OAuth2 sign-ins through AnvilID's real start, form_post and callback routes. They found one real defect: a single-tenant Microsoft connection accepted a token whose `tid` named another tenant. It is fixed in `resolve`.**

## Tasks

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Google, Microsoft and Apple suites, MockProvider extensions, Microsoft single-tenant fix | 97f4905 |
| 2 | GitHub and generic OAuth2 suites | b4eab28 |

## MockProvider extensions (tests/upstream_support)

- **Token endpoint responder:** when `expect_apple_client_secret(AppleSecretCheck)` is set, it verifies the ES256 client secret the way Apple does: header `kid`/`alg`, `iss` = team, `sub` = services id = `client_id`, `aud`, `iat` not in the future, `exp` after now and no more than 6 months after `iat`. Otherwise it answers `400 invalid_client`. Accepted claims are recorded (`apple_client_secrets()`).
- **Apple form_post:** `apple_authorization_response(state, first, last)` adds the `user` JSON only on the first authorization.
- **Apple and Google claims:** Apple default claims have `email_verified: "true"` and no name claims. Google tokens carry `iss` = `accounts.google.com` (`token_issuer()`).
- **Attacks:** `attack_tokens(nonce)` builds alg none, HS256 keyed with the public key, ES256 (off the presets' RS256 allow-list), unknown kid, expired, wrong aud and wrong nonce, each with its expected audit reason. `id_token_with_unknown_kid` is also public.
- **GitHub routes:** also served under `/api/v3` (GitHub Enterprise Server), header-gated, with a 401 fallback.

## Coverage matrix

| Case | Google | Microsoft | Apple | GitHub | OAuth2 |
|---|---|---|---|---|---|
| Full sign-in via real routes, endpoint overrides | yes | yes | yes (form_post -> 303 -> GET) | yes | yes |
| Authorization request params | scope, S256 | S256, nonce | form_post, `name email`, no PKCE | scope, S256, no nonce | scopes, S256, no nonce |
| Token auth | basic + verifier | basic | post + minted ES256 secret, no verifier | post + verifier, Accept json | basic + verifier |
| Issuer rules | scheme-less and https accepted; 5 others rejected | tid substitution; iss/tid mismatch, missing, non-UUID, uppercase, braced, numeric tid, raw template rejected; allow-list; single tenant | exact (override) | n/a | n/a |
| Provider quirk | hd allow-list (other, missing, non-string rejected; case-insensitive) | email never trusted, never auto-links; tid/oid in link metadata | string email_verified; names only from first `user` JSON (later and forged ignored); private relay; secret per request; wrong aud / wrong key refused | numeric id subject (rename keeps link); verified primary only; REST headers; 200-with-error; GHES base; non-numeric id rejected | pointer mapping; untrusted by default; only boolean true; missing/empty/object/fraction subject rejected; ID token ignored |
| Auto-link policy | trusted + allowed only (untrusted, auto_link off -> confirmation) | never | n/a | verified primary auto-links | trusted + mapped true only |
| Shared attacks (7) | yes | yes | yes (via form_post) | n/a (OAuth2) | n/a |
| Key rotation: one refresh succeeds, unknown kid then fails without refetch | yes | yes | yes | n/a | n/a |

Every rejection asserts the generic error page (`upstream.failed` on a fresh `login` form, status 400), no session, and the specific audit reason.

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test upstream_google --test upstream_microsoft --test upstream_apple --test upstream_github --test upstream_oauth2`: 7 + 7 + 6 + 8 + 6 = 34 passed
- `cargo test -p anvil-web --test upstream_login --test security_linking --test upstream_adapter`: 12 + 16 + 18 passed
- `cargo test -p anvil-core --lib upstream`: 76 passed (including the new `microsoft_single_tenant_pins_tid_to_its_tenant` and an extended `microsoft_single_tenant_still_checks_tid`)
- `cargo clippy -D warnings`: clean for the eight upstream test targets and for anvil-core lib + tests
- `rustfmt --edition 2024 --check`: clean on every touched file
- Grep for provider hosts in `crates/anvil-web/tests`: only issuer strings and doc comments, never a network destination

## Not run

- `ANVILID_TEST_DB=postgres` for these suites (Docker is not used under the wave rules; left for CI). No SQL was added.
- e2e/conformance: not run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Security bug] A single-tenant Microsoft connection accepted another tenant's `tid`**
- **Found during:** Task 1 (`single_tenant_connection_accepts_only_its_tenant`)
- **Issue:** With `microsoft_tenant` = a tenant UUID, the issuer rule is Exact, so only the `iss` string was compared. A token with the connection's own `iss` but the `tid` of another tenant was accepted, and that foreign `tid` was recorded in the link metadata.
- **Fix:** `providers.rs` now has `microsoft_allowed_tenants`. For a UUID tenant it pins `allowed_tenants` to that tenant. An admin allow-list that excludes the tenant is kept as is, so it still refuses everything, as before. Unit tests are in providers.rs and claims.rs, and the regression test is the Microsoft suite.
- **Commit:** 97f4905

### Notes

- The shared attack helper is a token builder in `upstream_support`, not a TestApp-driven function. `upstream_adapter.rs` includes that module without the `support` harness, so it cannot depend on it. Each suite has a short attack loop for its own callback shape.
- Apple client secret lifetime: AnvilID mints 300 s secrets. The mock enforces Apple's 6-month ceiling, and the test asserts `exp = iat + 300` at the app clock.
- The planned adapter files (`adapters/upstream/*`, `service/upstream.rs`, `claims.rs` normalisers) needed no changes. No defect was found in GitHub email selection, Apple naming or OAuth2 mapping.
- Concurrent plans' in-progress edits broke the anvil-core/anvil-web build twice for a few minutes. I waited for the build to recover and did not work around it.

## Self-Check: PASSED

- The 5 suites and the support module exist. Commits 97f4905 and b4eab28 are in history.
