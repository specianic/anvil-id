---
phase: 03-release-0-2-secure-by-default
verified: 2026-11-25T10:04:01Z
status: gaps_found
score: 5/5 success criteria verified (16/16 requirements satisfied); 1 CLAUDE.md rule gap
re_verification: false
gaps:
  - truth: "One implementation per concern (CLAUDE.md non-negotiable): base64/base64url encoding lives only in anvil_jose::encoding"
    status: partial
    reason: "Plan 03-32 moved SQLite onto the shared anvil-jose base64url, but Phase 3 code added two more base64 code paths, and one older hand-rolled decoder is still there. Behaviour is correct; the rule is not met."
    artifacts:
      - path: "crates/anvil-web/src/adapters/captcha.rs"
        issue: "open_secret (line ~109) decodes secret_sealed with base64::engine::general_purpose::URL_SAFE_NO_PAD and .trim_end_matches('='). That is a second, more lenient base64url decoder. The value is written by anvil_core::service::tenant with anvil_jose::encoding::b64url (line 270), and the test helper at line 356 also encodes with the raw crate. anvil-web lists base64 in [dependencies] for this one call site."
      - path: "crates/anvil-mail/src/tester.rs"
        issue: "Hand-rolled standard base64 encoder `fn base64` (lines 95-115, added in 03-15) builds the SMTP AUTH redaction needles."
      - path: "crates/anvil-core/src/service/client_auth.rs"
        issue: "Hand-rolled strict standard-base64 decoder `b64_std_decode` (line 74, from Phase 2 plan 02-08) for HTTP Basic client auth. It predates Phase 3 but belongs to the same concern."
    missing:
      - "captcha.rs open_secret: call anvil_jose::encoding::b64url_decode(&settings.secret_sealed) and drop the trim_end_matches('='). Change the test at line 356 to use anvil_jose::encoding::b64url. Remove `base64` from crates/anvil-web/Cargo.toml [dependencies]."
      - "Add strict standard-alphabet helpers to anvil_jose::encoding (b64std(&[u8]) -> String and b64std_decode(&str) -> Result<Vec<u8>, JoseError>, both padded and canonical). Use them in anvil-mail tester.rs, replacing fn base64, and in anvil-core client_auth.rs, replacing b64_std_decode. Move the RFC 4648 vector and strictness tests to anvil-jose."
      - "Optional guard: make scripts/check-deps.sh (or check-release-graph.sh) reject `base64::` outside crates/anvil-jose/src so this cannot come back."
---

# Phase 3: Release 0.2 "Secure by default" Verification Report

**Phase Goal:** Users can sign in with modern, phishing-resistant methods under hardened defaults, and admins can see and control what happens in their tenant.
**Verified:** 2026-11-25T10:04:01Z
**Status:** gaps_found (functional goal achieved; one CLAUDE.md "one implementation per concern" gap)
**Re-verification:** No (initial verification)

## Checks run

| Check | Where | Result |
|-------|-------|--------|
| `cargo test --workspace --locked` | local | Every non-Postgres crate passes: 1426 passed, 0 failed (rerun with `--no-fail-fast --exclude anvil-storage-postgres`). The 8 `anvil-storage-postgres` lib tests fail locally only with "docker must be running" (Docker is unavailable on this machine). |
| `cargo clippy --workspace --all-targets -- -D warnings` | local | exit 0. Cargo prints manifest-level warnings: unused workspace dep `anvilid`, and `tokio` unused in anvil-cache `[dependencies]` (it is also in dev-deps). |
| `scripts/check-security-tests.sh` / `--self-test` | local | OK (230 control/test pairs) / self-test OK |
| `scripts/check-release-graph.sh` | local | OK |
| `scripts/check-deps.sh` | local | OK |
| `scripts/check-migrations.sh` / `--self-test` | local | OK / self-test OK |
| ci 45583760917 (commit 177b7f4) | GitHub | all 8 jobs green. tests (sqlite): 1672 passed, 0 failed, including the `anvil-storage-postgres` lib tests and `tests/upgrade.rs` via testcontainers. tests (postgres): 584 passed (`ANVILID_TEST_DB=postgres`, anvil-web + anvilid). |
| conformance 45583761038 | GitHub | Basic: 1910 successes, 0 failures, 0 warnings. Config: green. **Form Post basic**: 36 modules, 2066 successes, 0 failures, 0 warnings. |
| e2e 45583760967 | GitHub | Playwright sqlite: 48 passed. Playwright postgres: green. QUAL-04 both backends: green. Container size gate: green. |
| release-build 45583760772 | GitHub | console build + musl x86_64/aarch64 green, console-embedded check enforced |
| fuzz 45583817466 | GitHub | 4 targets green |
| `gh release view v0.2.0` | GitHub | Published 2026-11-25. Linux musl + macOS tarballs with .sha256 and attestation instructions. |

Note: the local `conformance-results/run-test-plan.log` shows a failing run (10 failures). It is gitignored and stale, from an interrupted local run after the Docker crash. CI run 45583761038 is the authoritative result.

## Goal Achievement: Observable Truths (ROADMAP success criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Passkey (incl. usernameless) and TOTP enrolment and login e2e pass with a virtual authenticator | VERIFIED | CI e2e: `passkey.spec.ts` covers resident credential, usernameless sign-in through the sample RP, counter rollback treated as a clone, bogus signature, no UV, and duplicate authenticator. `totp.spec.ts` covers enrolment, sign-in, replay rejection and single-use recovery codes. The virtual authenticator is CDP-based (`tests/e2e/fixtures/webauthn.ts`). |
| 2 | Form Post conformance passes; introspect/revoke; RS256/ES256/Ed25519; scheduled rotation with JWKS overlap | VERIFIED | Conformance Form Post plan: 0 failures and 0 warnings. `security_introspect_revoke.rs` has 15+ tests. `id_token_alg.rs` covers ES256, Ed25519 and the RS256 default. `jwks_rotation.rs` `full_rotation_cycle_over_a_fake_clock` checks that the next key is published for at least `JWKS_MAX_AGE` before promotion, that both kids are in JWKS, and that the old key is retired after the overlap. The leased hourly rotation job is in `crates/anvilid/src/jobs.rs`, and `anvilid/tests/jobs.rs` (`production_jobs_rotate_purge_and_apply_audit_retention`) tests it. |
| 3 | Brute-force/rate-limit tests pass (per-account, per-IP, trusted proxy); axe clean; password flow without JS | VERIFIED | `security_bruteforce.rs` covers the progressive lock, (identifier, IP) and identifier-only tiers, CAPTCHA escalation, fail-closed, second-factor and passkey throttling. `security_ratelimit.rs` includes `varying_x_forwarded_for_from_an_untrusted_peer_does_not_bypass` and `trusted_proxy_clients_are_limited_independently`. `client_ip.rs` has `client_ip_untrusted_peer_ignores_spoofed_xff` plus proptests. CI `a11y.spec.ts` runs 11 audits with the WCAG 2.0/2.1/2.2 A+AA tags over 2 viewports × 2 colour schemes + reflow. `keyboard.spec.ts` (14) and `nojs.spec.ts` (5, including password login and password+TOTP without JS) pass. |
| 4 | Consent remembered/revocable; users list/revoke sessions; admin console v1 for users, clients, sessions, audit | VERIFIED | `consent.rs` (remembered, prompt=consent, skip for first-party, deny, double submit gives one code) and the e2e `consent.spec.ts`. `sessions.rs` (list, revoke other/all others/current, idle timeout) and the e2e `sessions.spec.ts`. Console routes `admin-ui/src/routes/{users,clients,sessions,audit,email}`, embedded at `/console/*`. The e2e `console.spec.ts` (users, sessions, audit, clients, email, SMTP) passes. |
| 5 | 0.1 to 0.2 upgrade test in CI without data loss; destructive migrations refuse without an explicit flag | VERIFIED | `upgrade_from_0_1_keeps_every_row_and_defaults_new_columns` and `..._is_idempotent_on_restart` pass on SQLite (local) and Postgres (CI, testcontainers). `migration_0003_upgrades_a_populated_0_1_database` passes in CI. `migrate_refuses_pending_destructive_migration_and_changes_nothing` passes on both backends. The `--allow-destructive-migrations` flag is in `anvilid/src/config.rs` and `main.rs:213`. Migration lint and immutability come from `check-migrations.sh` + `released-migrations.sha256`. |

**Score:** 5/5 truths verified

## Specific confirmations requested

| Item | Status | Evidence |
|------|--------|----------|
| Exactly one rate limiter | CONFIRMED | `governor` is a dependency of anvil-cache only. The `RateLimiter` trait and `InProcessLimiter` live in `crates/anvil-cache/src/limiter/`. The only consumer is `anvil-web/src/state.rs`. The route-class layer and brute-force helpers in `layers/ratelimit.rs` call that limiter. There are no other lockout or throttle implementations. Limits are on by default (`config.rs` test `rate_limits_are_on_by_default`). |
| Passkey clone detection | CONFIRMED | `service/flow.rs:1069` maps `PasskeyError::PossibleClone` (webauthn-rs `CredentialPossibleCompromise`) and `CounterOutcome::Stale` to `passkey_clone_suspected`. Storage does a CAS: `UPDATE ... AND (counter < ?4 OR (?4 = 0 AND counter = 0))`. The e2e clone-rollback test passes. |
| TOTP replay prevention | CONFIRMED | `advance_totp_step` runs a conditional UPDATE `counter IS NULL OR counter < step`. Contract tests `totp_step_accepted_once` and `totp_step_concurrent_single_winner` pass. Web test `totp_code_signs_in_once_and_a_replay_is_rejected`. Seed is KEK-sealed (`TOTP_SEED_PURPOSE`). |
| Recovery codes single-use | CONFIRMED | `consume_recovery_code` runs `UPDATE ... AND used_at IS NULL` in a transaction with the sealed notice. Contract tests `recovery_code_consumed_once` and `recovery_code_concurrent_single_winner`. Codes are stored as KEK-peppered hashes (`recovery_code_hash`). |
| Consent single-use code issuance | CONFIRMED | `service/consent.rs` `take_decision` uses `FlowRepo::swap_state` CAS, and the auth request is deleted before the code is issued. Test `consent.rs::a_double_submission_issues_one_code`. |
| Key rotation with JWKS overlap | CONFIRMED | See truth 2. `concurrent_runs_promote_exactly_once` and `immediate_rotation_drops_the_old_key_from_jwks_at_once` (explicit emergency path). |
| Destructive-migration guard | CONFIRMED | `run_guarded` (SQLite) and the Postgres equivalent refuse before applying anything. The checker self-test rejects unmarked DROP, DELETE, TRUNCATE and ALTER TYPE. |
| Trusted-proxy client IP ignores spoofed headers | CONFIRMED | `anvil-web/src/client_ip.rs` is the only implementation. It trusts nobody by default, and dev mode trusts loopback only. It walks one configured header right to left and never takes the scheme or host from headers. Tests listed under truth 3, plus `client_ip_forwarded_proto_and_host_do_not_change_issuer_or_cookies`. |
| WCAG audit evidence | CONFIRMED (automated) | axe fixture `tests/e2e/fixtures/axe.ts` uses tags `wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa`, fails on any violation and has no excludes in the specs. CI shows 11 a11y + 14 keyboard + 5 no-JS tests passing. The criteria axe cannot check (2.4.11, 3.3.8, target size) are covered by `keyboard.spec.ts` assertions. A manual checklist is referenced in 03-27-SUMMARY (human item below). |

## Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|----------------|-------------|--------|----------|
| OIDC-10 | 03-18 | Introspection (RFC 7662) and revocation (RFC 7009) | SATISFIED | `anvil-core/src/service/{introspect,revoke}.rs`, `anvil-web/src/protocol/{introspect,revoke}.rs`, `tests/security_introspect_revoke.rs` (auth required, visibility, family revocation, inactive cases) |
| OIDC-11 | 03-01, 03-10 | RS256, ES256 or Ed25519 signing | SATISFIED | `anvil-jose/src/{jws,jwk,keys}.rs`, per-alg `at_hash`, `tests/id_token_alg.rs`, `admin_api_v02::disabling_a_signing_algorithm_in_use_is_refused_with_the_client_ids` |
| OIDC-13 | 03-17 | Consent screen, skippable for first party, remembered, revocable | SATISFIED | `service/consent.rs`, `ui/consent.rs`, `ui/account_apps.rs`, `tests/consent.rs`, `tests/account_apps.rs`, e2e `consent.spec.ts` |
| OIDC-15 | 03-18 | RFC 9068 JWT access tokens by default, opaque per client, audience-restricted | SATISFIED | `service/token.rs` (`sign_access_token` with `at+jwt`, `new_opaque_access_token` stored as SHA-256), `tests/access_token_format.rs`, `AccessTokenVerifier` (single validator, shared by userinfo/introspect/revoke) |
| OIDC-25 | 03-11, 03-31 | `query` and `form_post` response modes | SATISFIED | `oauth/response_mode.rs`, `tests/response_mode.rs` (escaping, errors via form_post, request-object fallback), conformance Form Post plan 0 failures |
| AUTH-04 | 03-09, 03-12, 03-14, 03-26 | Passkeys incl. usernameless; clone detection | SATISFIED | `adapters/passkey.rs`, `service/flow.rs`, `tests/flow_passkey.rs`, `tests/passkey_adapter.rs`, e2e `passkey.spec.ts` |
| AUTH-05 | 03-01, 03-12, 03-14, 03-26 | TOTP with recovery codes as second factor | SATISFIED | `anvil-jose/src/{otp,recovery_code}.rs`, `tests/flow_login_factors.rs`, `tests/flow_mfa.rs`, `tests/account_security.rs`, e2e `totp.spec.ts` |
| AUTH-09 | 03-07, 03-13, 03-20 | Per-account/per-IP progressive throttling; CAPTCHA | SATISFIED | `anvil-cache/src/limiter/*`, `layers/ratelimit.rs`, `adapters/captcha.rs` (Turnstile/hCaptcha, fail closed), `tests/security_bruteforce.rs`, `tests/captcha.rs` |
| AUTH-10 | 03-19, 03-23 | Users list/revoke sessions; idle/absolute timeouts; admin revoke | SATISFIED | `service/session.rs`, `ui/account_sessions.rs`, `admin/sessions.rs`, `tests/sessions.rs` (idle timeout etc.), `admin_api_v02::admins_list_and_revoke_sessions`, e2e `sessions.spec.ts` |
| UI-02 | 03-04, 03-20, 03-27 | WCAG 2.2 AA, responsive, password flow without JS | SATISFIED (automated); manual checklist is a human item | e2e `a11y.spec.ts`, `keyboard.spec.ts` (desktop and mobile), `nojs.spec.ts` |
| UI-07 | 03-15, 03-23, 03-25 | Per-tenant email templates, SMTP with test send | SATISFIED | `service/mail_settings.rs` (SMTP password sealed with `SMTP_PASSWORD_PURPOSE`), `anvil-mail/src/{check,tester}.rs`, `admin/email.rs`, `admin_api_v02::email_templates_default_override_validation_and_reset`, `smtp_settings_password_is_write_only_and_test_send_reports_the_outcome`, console email page in e2e |
| ADM-04 | 03-02, 03-21, 03-23, 03-24, 03-30 | Security events and admin actions audited, queryable in console, streamable as JSON | SATISFIED | `service/audit.rs`, `tests/admin_audit.rs`, `admin_api_v02::audit_events_are_queryable_with_filters_and_cursor_paging`, `anvilid/src/main.rs` `AuditStdout` layer, `anvilid/tests/config_phase3.rs::serve_reconciles_console_client_and_keys_and_streams_audit_json`, console audit route |
| SEC-02 | 03-10, 03-24 | Keys generated at first start, KEK-encrypted, rotated on schedule with overlap | SATISFIED | `service/key_rotation.rs`, `anvilid/src/jobs.rs` (hourly leased job), `anvilid/tests/keys_cli.rs` (`keys rotate`), `tests/jwks_rotation.rs` |
| SEC-05 | 03-07, 03-13, 03-24 | Auth and token endpoints rate limited by default | SATISFIED | `layers/ratelimit.rs` classify table (Auth/Token/Admin/Default), on by default, `tests/security_ratelimit.rs` (themed/OAuth/problem 429s, per-client token limit) |
| OPS-04 | 03-05, 03-06, 03-16, 03-29 | Automatic migrations, tested between minors, never destructive without a flag | SATISFIED | See truth 5. CI evidence on both backends. |
| OPS-06 | 03-08, 03-24 | Correct behaviour behind reverse proxies via trusted-proxy config | SATISFIED | `client_ip.rs`, `anvilid/src/config.rs` trusted proxy settings, `tests/client_ip.rs`, `tests/security_ratelimit.rs` |

No orphaned requirements: all 16 Phase 3 IDs in REQUIREMENTS.md are claimed by plans, and every one has evidence in code or tests. The REQUIREMENTS.md checkboxes and traceability rows still say "Pending". Updating them is bookkeeping for the orchestrator.

## Plan must_haves

`gsd-tools verify artifacts/key-links` could not parse the must_haves frontmatter of any of the 33 plans ("No must_haves.artifacts found"), even though the blocks are present (for example in 03-07). I verified the must_haves by hand against the code for the security-relevant plans: 03-01, 03-07, 03-08, 03-10, 03-11, 03-12, 03-13, 03-14, 03-15, 03-16, 03-17, 03-18, 03-19, 03-22, 03-24, 03-30, 03-31, 03-32 and 03-33. For the other plans I relied on their test, e2e and CI evidence. All the entries in `deferred-items.md` (harness ConnectInfo, recovery notice in transaction, account_security audit filtering) are resolved: the tests pass and 03-30 closed the transaction item. 03-33's dedupe claims hold: there is a single `http_cache.rs` for ETag/If-None-Match, and the release workflow has `artifact-metadata: write`.

## CLAUDE.md compliance probes

| Probe | Result |
|-------|--------|
| Test hooks / mocks in production paths | None. Fakes (`FakeChecker`, session `Fake`) are inside `#[cfg(test)]` modules. `check-release-graph.sh` confirms no test crates are reachable from the binary. |
| Stubs returning success / TRANSITIONAL code | No `TRANSITIONAL`, `TODO`, `FIXME`, `todo!` or `unimplemented!` in crates or admin-ui. `FlowEngine::initial` for Settings/Consent returns an explicit `CoreError::Internal` error, which is allowed (consent has its own state machine). The `/console/` placeholder only appears in builds without `admin-ui/dist`, and release CI enforces the embedded console (`check-console-embedded.sh`). |
| Hardcoded users/tenants | None in production paths. `SYSTEM_TENANT_SLUG` is the documented installation tenant. |
| Duplicate implementations | Rate limiter: one. Access-token validator: one (`AccessTokenVerifier`). Client auth: one (`ClientAuthenticator`, used by token, introspect and revoke). ETag helpers: one (`http_cache.rs`). **base64/base64url: not unique** (see the gap). |
| Handlers touching the DB directly | None. `anvil-web` has sqlx only as a dev-dependency. Handlers use the `Storage` traits. |
| Secrets in plaintext | TOTP seeds are KEK-sealed. Recovery codes are stored as peppered hashes. The SMTP password is sealed, write-only in the API and redacted in Debug and in test-send transcripts. The CAPTCHA secret is sealed and write-only. Outbox payloads are sealed (`unsealed_or_tampered_payload_is_failed_and_never_sent`). No secret values are logged. The setup URL is logged by design (Phase 2). |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| crates/anvil-web/src/adapters/captcha.rs | 109, 356 | Second base64url decoder/encoder (raw `base64` crate, lenient `=` trim) | Warning (CLAUDE.md rule) | Violates "one implementation per concern"; the same class of issue 03-32 fixed for SQLite |
| crates/anvil-mail/src/tester.rs | 95-115 | Hand-rolled base64 encoder | Warning (CLAUDE.md rule) | Duplicate encoding implementation |
| crates/anvil-core/src/service/client_auth.rs | 74 | Hand-rolled base64 decoder (Phase 2) | Info/Warning | Pre-existing duplicate; same fix |
| crates/anvil-cache/Cargo.toml | 18 | `tokio` in `[dependencies]`, unused outside tests | Info | Cargo `unused_dependencies` warning; remove from `[dependencies]` |
| Cargo.toml | 30 | Unused workspace dependency `anvilid` | Info | Cargo warning only |
| crates/anvil-core/src/flow/engine.rs | 96 | Doc says Consent flow "not implemented by this engine yet" | Info | Stale wording; consent is implemented in `flow::consent` |

## Human Verification (advisory, not blocking)

1. **Manual WCAG 2.2 AA checklist.** Test: screen reader (NVDA/VoiceOver) walkthrough of login, second factor, consent, account security and sessions. Expected: the items in the 03-27 summary checklist hold. Why human: axe and the keyboard specs cannot judge announcement quality or meaning.
2. **Conformance REVIEW modules.** Test: review the screenshots for `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri` and `oidcc-ensure-request-object-with-redirect-uri` in the Form Post (and Basic) plan exports. Expected: the error and login pages are shown as required. Why human: the suite marks these REVIEW for manual certification.
3. **Real CAPTCHA provider.** Test: enable Turnstile or hCaptcha with real keys and trigger the identifier-tier lock. Expected: the widget renders, and a solved challenge lets the password attempt through. Why human: CI uses wiremock for siteverify.

## Gaps Summary

Phase 3's functional goal is achieved, and CI on commit 177b7f4 and the published v0.2.0 release back it up:
- All five ROADMAP success criteria are verified.
- All 16 requirements have code and test evidence.
- Every security-critical control asked about holds and is tested for rejection: single limiter, clone detection, TOTP replay, single-use recovery codes, single consent decision, rotation overlap, destructive guard, spoof-resistant client IP and the WCAG audit.

The one gap is the CLAUDE.md non-negotiable "one implementation per concern" for base64 encoding. Phase 3 added a raw-crate base64url decode in the CAPTCHA adapter (lenient, unlike the strict shared `anvil_jose::encoding::b64url_decode` that encodes the same value) and a hand-rolled base64 encoder in the SMTP tester. An older hand-rolled decoder in client auth is still there too. The fix is small and mechanical: route all three through `anvil_jose::encoding`, add the standard-alphabet helpers there, drop `base64` from anvil-web's dependencies, and optionally add a lint against `base64::` outside anvil-jose. Once that is done this phase can be marked passed. The human items above are advisory.

---

_Verified: 2026-11-25T10:04:01Z_
_Verifier: Claude (gsd-verifier)_
