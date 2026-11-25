---
phase: 02-release-0-1-first-login
verified: 2026-11-25T05:00:00Z
status: human_needed
score: 5/5 success criteria verified (26/26 requirements satisfied as scoped; 1 needs a scope confirmation)
re_verification: null
human_verification:
  - test: "Confirm the OPS-01 scope for release 0.1"
    expected: "The owner accepts that 0.1 ships a gated container image (18.4 MiB, built locally with `just docker-image`) and static linux musl amd64/arm64 binaries as CI artifacts only. No macOS build exists and nothing is published to a registry or GitHub release yet; ARCHITECTURE §13 assigns that to cargo-dist later. The README says so honestly."
    why_human: "The requirement text says 'Operator can download one static binary (linux amd64/arm64, macOS) or a container image under 50 MB'. The 'or' clause is met in substance, but 'download' (publishing) and macOS are not. This is a scope call, not a code defect."
  - test: "Visual and no-JS walkthrough of /setup, /ui/login, /ui/registration, /ui/verification, /ui/recovery in a browser"
    expected: "Pages are legible, the dev-mode banner shows on http, error and message texts read well, every form works with JavaScript disabled"
    why_human: "Automated tests check headers, selectors, CSP and the flows (Playwright), but not visual quality or wording"
  - test: "Review the 4 conformance modules that the suite reports as REVIEW (oidcc-prompt-login, oidcc-max-age-1, oidcc-ensure-registered-redirect-uri, oidcc-ensure-request-object-with-redirect-uri)"
    expected: "Screenshots and logs in the conformance-results artifact show the expected login prompt or error page"
    why_human: "The suite exits 0 and the CI gate passes (31 PASSED, 1 expected SKIPPED, 0 FAILED). REVIEW modules need screenshot review before certification (Phase 7), not for this gate"
---

# Phase 2: Release 0.1 "First login" Verification Report

**Phase Goal:** Anyone can start one binary with zero configuration and have a sample app log users in through a standards-correct OIDC provider, with every in-scope security control enforced and covered by a negative test.
**Verified:** 2026-11-25
**Status:** human_needed (all automated checks pass; one requirement-scope confirmation and routine visual review)
**Re-verification:** No, initial verification

## Checks run by the verifier (not taken from SUMMARYs)

| Check | Result |
| ----- | ------ |
| `cargo test --workspace --locked` (SQLite + Postgres storage contract) | 793 passed, 0 failed |
| `ANVILID_TEST_DB=postgres cargo test -p anvil-web -p anvilid --locked` | First run: 1 failure, `security_iss::login_required_redirect_has_iss` panicked in the harness with testcontainers `PortNotExposed`. That is a local Docker/WSL flake, not a product failure. Rerun with `--no-fail-fast`: 33 binaries, 299 passed, 0 failed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 (2 cargo manifest notes: unused workspace deps `anvil-cache`, `anvilid`. Not lints) |
| `cargo fmt --all --check` | clean |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `scripts/check-deps.sh` / `--self-test` | OK / OK |
| `scripts/check-release-graph.sh` / `--self-test` | OK / OK (rejects test crate in normal graph and TestClock in src) |
| `scripts/check-security-tests.sh` / `--self-test` | OK, 107 control/test pairs present and registered / OK |
| GitHub `ci` 45548158998 (HEAD 67dd7f8) | success: fmt+clippy, deny, dep rules, sqlx offline, release graph, tests (sqlite) + security map + self-test, tests (postgres) |
| GitHub `conformance` 45548159024 (HEAD) | success. 45547127850 log: Basic OP + Config OP, 31 PASSED, 1 SKIPPED (expected: unsigned request object), 4 REVIEW, 0 FAILED. expected-failures.json is `[]` |
| GitHub `e2e` 45548159120 (HEAD) | success: image size gate (19,274,086 bytes = 18.4 MiB < 50 MiB, nonroot, setup URL logged), QUAL-04 sqlite (4 s) and postgres (10 s) against the 120 s limit, Playwright sqlite + postgres |
| GitHub `release-build` 45548159000 (HEAD) | success: musl x86_64 + aarch64 |
| GitHub `fuzz` 45547147420 (dispatch on f16e726; HEAD only adds docs) | success: jwt_decode, client_assertion, authorize_parse, redirect_match, 5 min each. Nightly cron is configured; the smoke job runs only on PRs |

## Goal Achievement: Success Criteria

| # | Truth (ROADMAP SC) | Status | Evidence |
|---|---|---|---|
| 1 | The sample app logs in with code + PKCE S256, refreshes with rotation and calls UserInfo, on SQLite and Postgres | VERIFIED | `examples/node-rp/server.js` (calculatePKCECodeChallenge, refreshTokenGrant, which fails if no rotated RT comes back, then fetchUserInfo). `tests/e2e/specs/qual04.spec.ts` asserts refreshCount and sub/email after rotation. CI e2e QUAL-04 sqlite + postgres green |
| 2 | OpenID conformance Basic OP and Config OP pass in CI | VERIFIED | `.github/workflows/conformance.yml` → `tests/conformance/run.sh` (both plans over TLS). Expected-failures is empty, one reviewed skip. Green on HEAD |
| 3 | Zero-config `docker run` to completed login in ≤ 2 min; one-time setup URL; no default credentials | VERIFIED | `scripts/qual04.sh` (LIMIT=120, fails over the limit). CI 4 s / 10 s. `crates/anvilid/tests/zero_config.rs` (prints the setup URL once, KEK 0600, dev warning, `admin setup-url` next to a running server). `security_setup::fresh_install_has_no_users_and_no_default_credentials` |
| 4 | Every in-scope §11 control has a passing negative test on both backends | VERIFIED | `scripts/check-security-tests.sh` maps 107 pairs: redirect (`security_redirect.rs`), missing/plain PKCE (`security_pkce::pkce_violations_are_invalid_request`), code reuse (`security_code::code_reuse_is_rejected_and_revokes_the_family`), refresh reuse (`security_refresh::reuse_revokes_the_whole_family`), bad secret (`security_client_auth::wrong_secret_with_basic_is_401_with_challenge`), replayed jti (`security_private_key_jwt::replayed_assertion_is_rejected`, `reused_jti_in_a_new_assertion_is_rejected`), CSRF (`security_csrf.rs`). anvil-web tests ran green on both backends (local + CI). Rate limiting and SSRF are explicitly out of 0.1 scope (nothing to test yet) |
| 5 | Self-register, verify email, password login, recovery via built-in pages without external assets; admin manages tenants/clients/users via the OpenAPI API | VERIFIED | `crates/anvil-web/src/ui/{login,registration,verification,recovery,setup}.rs`. `flow_registration.rs` (GET does not consume the token, POST verifies), `flow_recovery.rs`. Playwright `registration.spec.ts` / `recovery.spec.ts` over real SMTP (Mailpit). `security_csp::every_ui_page_has_the_strict_headers_and_no_external_references`. Admin API `crates/anvil-web/src/admin/` (tenants/clients/users CRUD + rotate secret), `docs/openapi/admin-v1.json` (3.1) + `openapi_drift.rs`, `security_admin.rs` |

**Score:** 5/5 success criteria verified

## Plan must_haves (02-01 .. 02-22)

All declared artifacts exist, are substantive (61–987 lines) and contain their required markers. Key-link patterns were checked with a script against the real files. Three mechanical misses were investigated and are fine:

- 02-02 link `sqlite/lib.rs → pending.rs (Unsupported)`: transitional by design and removed by 02-05 as planned. No `Unsupported` remains in either backend.
- 02-03 link `login.html` pattern `form\.id`: login.html calls `forms.render(form, …)`. `form.html` renders `id="{{ form.id }}"` and `{{ form.id }}-submit`.
- 02-18 `config.rs` contains `Env::prefixed(ENV_PREFIX)` with `ENV_PREFIX = "ANVILID_"`. The link `main.rs → anvil_web::app` is in `startup.rs:110`, which main calls.
- 02-19 `expected-skips.json` no longer lists `oidcc-idtoken-unsigned` (that module now passes). The list is shorter than planned, which is better.

The plan truths I spot-checked in code all hold: AuthorizeService plus redirect_matches (error page with no Location), the single ClientAuthenticator with record_jti, the single AccessTokenVerifier used by UserInfo and AdminAuth (both wrap `verify_op_token`), KeyService JWKS from next/active/retired (`discovery::jwks_lists_published_public_keys`), FlowService dummy-hash path, BootstrapService install/complete_setup, OutboxWorker with lettre SMTP, the capturing transport only in `crates/anvil-mail/tests/support`, figment precedence and redaction, TLS listener, purge job, Postgres `FOR UPDATE SKIP LOCKED`, and the sealed outbox (see below).

## Requirements Coverage

| Requirement | Source Plans | Status | Evidence |
|---|---|---|---|
| OIDC-01 (C1 amended: confidential `require_pkce=false` clients may omit nonce) | 01,07,10,13,16,19 | SATISFIED | `oauth/authorize_request.rs` (S256 only, nonce optional per amendment). `security_pkce::{pkce_violations_are_invalid_request, public_native_client_always_needs_pkce, opted_out_confidential_client_may_omit_pkce_and_nonce, pkce_required_client_without_pkce_is_rejected_even_with_nonce}`. `client.rs::public_client_may_not_disable_pkce`. `admin_api::client_registration_rules_are_enforced`. REQUIREMENTS.md wording updated (C1 note line 263) |
| OIDC-02 | 07,13,19 | SATISFIED | `oauth/redirect.rs`. `security_redirect.rs` (6 mapped tests, no Location header, native loopback IP only) |
| OIDC-03 | 02,05,06,08,14,19 | SATISFIED | `token.rs` CodeReuse → revoke_family. `security_code.rs` (reuse revokes the AT via /userinfo, 61 s expiry, other client, redirect mismatch). Contract `consume_code_concurrent_single_winner` on both backends |
| OIDC-04 | 01,08,10,14 | SATISFIED | `service/client_auth.rs` (basic/post/private_key_jwt/none, constant-time hash). `security_client_auth.rs`, `security_private_key_jwt.rs` (aud = issuer, jti replay, alg, kid). `record_jti_concurrent_single_winner` |
| OIDC-05 | 02,05,06,08,14,19 | SATISFIED | rotate_refresh with family revocation (both backends). `security_refresh.rs`. `rotate_refresh_concurrent`. Conformance `oidcc-refresh-token` PASSED |
| OIDC-06 | 08,14 | SATISFIED | `token_client_credentials.rs` (public refused, openid refused, no RT) |
| OIDC-07 | 01,08,14,19 | SATISFIED | `claims.rs::id_token_has_all_protocol_claims_with_types`, `encoding.rs::at_hash_vector`, `tests/token.rs::code_exchange_with_basic_returns_verified_tokens` (verified against /jwks, kid) |
| OIDC-08 | 08,13,18,19 | SATISFIED (rotation scheduling is Phase 3) | `protocol/discovery.rs` (both paths identical, `discovery::path_tenant_both_forms_are_identical`, `only_registered_metadata_is_published`). JWKS publishes next/active/retired keys, which is the overlap structure. Config OP passes. The scheduled rotator is 03-10 |
| OIDC-09 | 08,14,19 | SATISFIED | `protocol/userinfo.rs`, `tests/userinfo.rs`, `security_userinfo.rs`. RP calls UserInfo in QUAL-04 |
| OIDC-24 | 07,13,19 | SATISFIED | `security_iss.rs` (4 tests incl. login_required, iss overrides client-sent iss). Discovery advertises `authorization_response_iss_parameter_supported` |
| OIDC-14 (subset, C2) | 07,13 | SHIPPED EARLY (owned by Phase 4) | prompt=none/login, max_age, id_token_hint in `service/authorize.rs`. Conformance oidcc-prompt-login / max-age modules run (REVIEW, needs screenshot review). REQUIREMENTS.md note lines 258-262 |
| AUTH-01 | 09,12,15 | SATISFIED | Argon2Pool (`adapters/argon2.rs`, OWASP params, bounded, dummy hash), HIBP `breach_checker` wired in `anvilid/src/startup.rs:107`. `flow_login.rs`, `security_enumeration.rs` |
| AUTH-02 | 09,11,15,20,22 | SATISFIED | `flow_registration.rs` (open, disabled, system tenant disabled, duplicate, short password, verification POST-only). `flow/registration.rs` unit test covers Disabled + InviteOnly. Playwright `registration.spec.ts` via Mailpit |
| AUTH-03 | 09,11,15,20,22 | SATISFIED | `flow_recovery.rs` (single use, revokes sessions, unknown email answers the same). `security_enumeration::recovery_for_an_existing_and_an_unknown_email_is_identical`. Playwright `recovery.spec.ts` (old password fails) |
| UI-01 (0.1 subset: no consent/MFA/account pages yet) | 03,12,15 | SATISFIED for 0.1 | `themes/default/templates` embedded. `security_csp` checks no external host. Insta snapshots in `tests/render.rs` |
| ADM-01 | 10,16 | SATISFIED | `/api/admin/v1` tenants/clients/users. OpenAPI 3.1 served and drift-tested. Admin scopes in `admin_scope.rs`. `security_admin.rs` (401/403 matrix, other-tenant token, deleted client) |
| ADM-03 | 10,15,18 | SATISFIED | BootstrapService single-transaction install. `security_setup.rs` (no users, invalid/expired token, single use, concurrent once). Setup URL printed once (`zero_config.rs`) |
| OPS-01 | 20 | SATISFIED AS SCOPED, needs human confirmation | Distroless image 18.4 MiB, nonroot, CI size gate. Static musl amd64/arm64 built in `release-build` as CI artifacts. **No macOS binary and nothing published** (README: "No container images are published yet") |
| OPS-02 | 05,06,18 | SATISFIED | SQLite default (`serve.rs::defaults_to_data_dir_sqlite`), Postgres via `postgres://`. Contract suite green on both |
| OPS-05 | 18 | SATISFIED | `zero_config.rs`. `cli.rs::{serve_refuses_plain_http_on_a_public_host, serve_with_postgres_and_no_kek_refuses_to_start, config_show_prints_sources_and_hides_secrets}` |
| SEC-01 | 07,08,13,14,19,21,22 | SATISFIED | RFC 9700 set mapped in check-security-tests.sh (no implicit/hybrid/ROPC, PKCE S256, exact redirect, sender-bound codes, RT rotation, iss, no-store) |
| SEC-04 | 12,15 | SATISFIED | `security_csrf.rs`, `layers/csrf.rs` unit tests, `security_cookies.rs` (__Host-, Secure, HttpOnly, SameSite), `security_csp.rs`, `layers/security_headers.rs::headers_with_and_without_hsts` |
| SEC-06 | 17,21 | SATISFIED | `scripts/check-release-graph.sh` + self-test pass locally and in CI. All `#[cfg(test)]` sites in `crates/*/src` are test modules |
| SEC-07 | 01,17,21 | SATISFIED | cargo deny in ci. 4 fuzz targets, nightly cron + PR smoke, green dispatch run (an earlier fuzz finding, float claims round-trip, was fixed in f16e726) |
| QUAL-01 | 13,14,15,16,21 | SATISFIED | check-security-tests.sh, 107 pairs, registration verified via `--list`. Runs in CI |
| QUAL-02 | 02,05,06,12,14,15,16,20,21 | SATISFIED | TestApp selects the backend through `ANVILID_TEST_DB`. CI matrix sqlite/postgres. Playwright on both |
| QUAL-04 | 04,20 | SATISFIED | `scripts/qual04.sh` + `qual04.spec.ts`. CI 4 s (sqlite) / 10 s (postgres) |

No orphaned requirements: every Phase 2 ID in REQUIREMENTS.md is claimed by at least one plan. The REQUIREMENTS.md checkboxes and traceability rows still say "Pending" for all 26 IDs. The orchestrator should flip them when the phase closes.

## CLAUDE.md compliance probes

| Rule | Finding |
|---|---|
| No test hooks / mock fallbacks in production paths | Clean. Mocks (wiremock) and fakes appear only inside `#[cfg(test)] mod tests`. The capturing mail transport is in `anvil-mail/tests/support`. The release-graph gate proves this mechanically. `anvil-storage` `contract` is feature-gated and not in the anvilid graph |
| No stubs returning success | Clean. `todo!`/`unimplemented!` absent. Backends have no `StorageError::Unsupported`. Unsupported features return explicit errors (`request_not_supported`, `UnsupportedGrantType`, jwks_uri rejected at registration). The admin router has an explicit unknown-route handler |
| No hardcoded users/tenants | Clean. Only the architectural `system`/`default` tenant slugs exist. No users or credentials until /setup. `@example.com` appears only in tests |
| One implementation per concern | Clean. One `/token` route, one `ClientAuthenticator`, one AT validator (`verify_access_token_jwt` → `verify_op_token`, shared by UserInfo and AdminAuth), one `redirect_matches`, one CoreError→HTTP mapping (`errors.rs`), one KEK passed to web and worker (`startup.rs:26`) |
| Handlers never touch the DB directly | No sqlx in anvil-web/core/mail. Three web call sites read through storage **ports** without a service: `health.rs:26` (readiness), `tenant.rs:157` (tenant resolution middleware), `ui/setup.rs:81` (system tenant lookup). That is allowed by the rule (persistence via traits). Info: a `TenantService::get_by_slug` could absorb the setup lookup later |
| Secrets not stored or logged in plaintext | Codes, RTs, session ids, client secrets, setup and self-service tokens are stored as 32-byte hashes (`plaintext.rs` on both backends). Signing keys are KEK-sealed. Outbox payloads are sealed (02-22): every `NewEmail` construction site (`service/flow.rs:617,637`, `service/user.rs:128`) calls `seal_payload`. `open_payload` has no plaintext fallback. The worker records a generic error and never sends on open failure (`anvil-mail/tests/worker.rs`). Both backends' plaintext tests seed a link marker in a sealed payload. Logs: no bodies, links or secrets. The setup URL is printed and logged by design (one-time, 1 h TTL, ADM-03 operator flow) |

## Known deferred items: assessment

| Item | Assessment |
|---|---|
| Async core service methods with few unit tests (authorize 4, session 3, key 3, user 4) | Acceptable. Each async path is exercised end to end by the anvil-web HTTP integration suites (authorize.rs, token*.rs, flow_*.rs, admin_api.rs, security_*.rs) on both backends. The pure decision logic (authorize_request, decision, engine, flows, claims) has dense unit tests |
| UserRepo/ClientRepo::delete stamp `revoked_at` with the DB/wall clock (`now()` in Postgres, `now_ms()` in SQLite) instead of the injected Clock | Acceptable, not a security gap. Revocation checks use only `revoked_at IS [NOT] NULL`. The timestamp is informational, and the settable test clock only affects that value. Fix when audit (Phase 3) starts reading it: pass `now` through `delete(tenant, id, now)` |
| Password-changed notice enqueued after the recovery transaction (`service/flow.rs:534-542`, `complete_recovery(…, None)`) | Acceptable. A crash between the two writes can lose one notice email. The password change, session and family revocation remain atomic. Already scheduled: 03-12 truth "notice enqueued inside the recovery transaction (RecoveryNotice)" with a test |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `Cargo.toml` (workspace) | — | unused workspace deps `anvil-cache`, `anvilid` (cargo warning) | Info | anvil-cache is the Phase 3 limiter crate (03-07). Harmless |
| `crates/anvilid/src/jobs.rs` | 57 | Without `smtp_url`, emails are queued but not sent (warning logged) | Info | Zero-config users see "check your email" while nothing is sent until SMTP is configured. Documented and logged, not a fake success. Consider surfacing it on the setup-done page |
| `crates/anvil-web/src/ui/setup.rs` | 81 | handler reads `storage().tenants()` directly | Info | Allowed (port access). Could move into a service |

No blockers, no TODO/FIXME/placeholder in production sources.

## Human Verification Required

### 1. OPS-01 scope
**Test:** Decide whether 0.1 needs a published image/binary and a macOS build.
**Expected:** Either accept "built and gated, published later via cargo-dist" (current README) or add a release/publish task.
**Why human:** This is a requirement-wording and scope decision. The code meets the size and static-binary gates.

### 2. UI walkthrough
**Test:** Run `cargo run -p anvilid -- serve`, open the setup URL, then go through registration, verification, login and recovery with JS disabled.
**Expected:** Pages render cleanly with no console or network requests to external hosts, and the texts are clear.
**Why human:** Visual quality and wording.

### 3. Conformance REVIEW modules
**Test:** Open the `conformance-results` artifact of run 45548159024 and review the 4 REVIEW modules.
**Expected:** Screenshots show the login page (prompt=login, max_age=1) and the error page (unregistered redirect URI).
**Why human:** The suite requires manual screenshot review. It does not affect the CI gate.

## Gaps Summary

No gaps block the phase goal. Every success criterion is backed by code and tests I ran (793 workspace tests, 299 Postgres web/binary tests, all gates and self-tests) and by green GitHub workflows on HEAD (ci, conformance, e2e, release-build) plus a green fuzz run on the last code commit. The three known deferred items are acceptable and either scheduled (03-12) or harmless. The one open point is whether OPS-01's "download … macOS" wording must be met in 0.1.

---

_Verified: 2026-11-25_
_Verifier: Claude (gsd-verifier)_
