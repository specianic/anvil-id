---
phase: 04-release-0-3-real-world-logins
plan: 24
subsystem: auth
tags: [email-otp, magic-link, passwordless, login-flow, limiter, enumeration, amr-otp, auth-06, oidc-14]

requires:
  - phase: 04-01
    provides: "anvil_jose::email_code::{generate_email_code, normalize_email_code, email_code_hash}, EmailKind::LoginCode, AuditAction::EmailCodeSent, TenantSettings.{email_otp, magic_link}"
  - phase: 04-15
    provides: "login_code email template and contract {tenant_name, code, link, expires_minutes}"
  - phase: 04-16
    provides: "after_primary_auth, flow_mfa, Enroll/SecondFactor steps, login_hint prefill"
  - phase: 04-21
    provides: "upstream_primary / continue_login (continue in a fresh flow), SessionAuth::Federated*"
provides:
  - "flow::email_code: EmailCodeState, Check, check_code, check_link, code_hash, link_hash, link_csrf, limit_subject, form/sent_form, EMAIL_CODE_FORM_ID (\"email-code\"), EMAIL_CODE_TTL (10 min), MAX_SENDS (3), MAX_FAILED_ATTEMPTS (5), message keys"
  - "LoginStep::EmailCode, LoginState.{email_code, email_primary}; FlowEnv.email_code"
  - "FlowInput::{EmailCodeRequest, EmailCode, EmailLink}; Effect::{SendEmailCode, VerifyEmailCode, ConsumeEmailLink}"
  - "SessionAuth::EmailCode ([otp], pwd acr) and EmailCodeSecondFactor ([otp, mfa], mfa acr)"
  - "FlowService::email_link -> EmailLinkOutcome {Done, Continue, OtherBrowser, Rejected}; service::flow::email_code_enabled; AuthAttempt::{EmailCodeSent, EmailCodeFailed, EmailCodeSucceeded}"
  - "FlowService::primary_without_form (shared by the upstream callback and the magic link)"
  - "Routes POST /ui/login/email-code, POST /ui/login/email-code/verify, GET+POST /ui/login/email-link"
  - "Templates email_code.html, magic_link.html; login.html email form; locales/en/email_code.ftl"
affects: [04-29, 04-33]

tech-stack:
  added: []
  patterns:
    - "An effect that must store a compare-and-swap verdict and answer with its own form returns Step::Done(Render) instead of a Failure (no new Failure variant, so other flows' exhaustive matches stay untouched)"
    - "A page that cannot know the flow's CSRF token (emailed link) uses a CSRF token derived with the KEK from the flow id and the link token; the flow cookie still proves the browser"

key-files:
  created:
    - crates/anvil-web/tests/flow_email_code.rs
    - crates/anvil-web/tests/security_email_code.rs
    - crates/anvil-web/tests/email_code_support/mod.rs
    - themes/default/templates/email_code.html
    - themes/default/templates/magic_link.html
    - themes/default/locales/en/email_code.ftl
  modified:
    - crates/anvil-core/src/flow/email_code.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/flow/engine.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/src/ui/email_code.rs
    - crates/anvil-web/src/ui/login.rs
    - themes/default/templates/login.html

key-decisions:
  - "Email sign-in is offered only to active accounts with a verified address (coordinator decision). An unverified address answers exactly like an unknown one and gets no email; verification is checked again when the code or link is used."
  - "Either tenant setting (email_otp or magic_link) enables the method. The login_code email always carries both the code and the link, as its contract requires."
  - "The magic link POST is bound by the flow cookie plus a KEK-derived CSRF token (HKDF over flow id and token). A POST without the right flow cookie is 'another browser' and consumes nothing."
  - "A second factor or enrolment after the magic link continues in a fresh flow (like the upstream callback). After a code it stays in the same flow."
  - "Verify attempts are throttled with LimitKey::User, shared with the TOTP step. An address without an account uses a KEK-keyed pseudo user id, so throttling looks the same either way."
  - "Sends are counted on their own limiter namespace (identifier hash of 'email-code:{address}'): strict (address, IP) and loose (address). They never count against the password sign-in of the same identifier."
  - "An email code or link does not mark the address verified and is refused for unverified addresses. It cannot confirm an upstream link (the method is not offered while a link confirmation is pending) and cannot be used in step-up flows."

requirements-completed: [AUTH-06, OIDC-14]

duration: about 2h
completed: 2026-11-25
---

# Phase 4 Plan 24: Email One-time Code and Magic Link Sign-in Summary

**Passwordless sign-in is now built into the login flow.**

- The sign-in page offers "Email me a sign-in code".
- Every address gets the same "if an account exists for that address, we sent a code" page.
- Only an active account with a verified address gets one sealed `login_code` email (a 6-digit code and a magic link, valid 10 minutes).
- The code or the link signs in single-factor: `amr [otp]`, pwd `acr`. The effective MFA policy then applies as after a password.

**Protections:**
- The code is stored only as a flow-bound HMAC and the link token only as SHA-256.
- Both are consumed together, once, by compare-and-swap. Five wrong codes invalidate both, and a flow sends at most three emails.
- The magic link GET only renders a button. Only the same-browser POST consumes it.

## Routes and selectors (for e2e)

| Route | Notes |
|---|---|
| `POST /ui/login/email-code?flow=` | `email` + `csrf_token` (sign-in page), or `factor_token` only ("Send a new code") |
| `POST /ui/login/email-code/verify?flow=` | `code`, `factor_token`, `csrf_token` |
| `GET /ui/login/email-link?flow=&token=` | button page, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| `POST /ui/login/email-link?flow=` | `token` + the page's `csrf_token` |

All four answer 404 when neither `email_otp` nor `magic_link` is on.

Selectors:
- Sign-in page: disclosure `email-code-toggle` (open when an address is prefilled from `login_hint`), form `email-code-request`, input `email-code-email`, button `email-code-request-submit`.
- "Check your email" page: form `email-code`, input `code` (`inputmode=numeric`, `autocomplete=one-time-code`), button `email-code-submit`, messages `email-code-msg-N`. Resend: form `email-code-resend`, button `email-code-resend-submit`. Link `link-login`.
- Magic link page: form `magic-link`, button `magic-link-submit`, link `link-login`.

Message keys: `email_code.{sent, invalid, expired, invalidated, too_many_sends, link_invalid, other_browser}`. Audit events: `email_code_sent` (target user, no address), `login_succeeded` with method `email_code` / `magic_link`, and `login_failed` with method `email_code` / `magic_link`.

## Task Commits

1. **Task 1: core login method:** `7cfeb9d` feat(04-24): email one-time code and magic link login method in core
2. **Task 2: routes, pages, limiter, tests (and the verified-address rule):** `26443fe` feat(04-24): email code and magic link routes, pages, limiter and tests

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 579 passed. New tests cover each transition (request, resend, send cap, verify, link, disabled/step-up/link-confirmation refusal), single use, flow and KEK binding, the attempt cap, TTL, the state JSON holding no code or token, the link CSRF and subject keying, `[otp]` and `[otp, mfa]`, and step-up from `[otp]`.
- `cargo test -p anvil-web --test flow_email_code` (5) and `--test security_email_code` (16): pass. The security tests cover:
  - enumeration: unknown, unverified and blocked addresses get byte-identical pages and no email
  - an address unverified after the send
  - reuse, and a concurrent double submit that signs in once
  - five wrong codes invalidating the code and the link
  - the per-user lock across new codes
  - the 11-minute expiry and the fourth send
  - link GETs consuming nothing, a second link POST, and other-browser or forged-cookie POSTs
  - 403 without or with a wrong CSRF token
  - the code at rest
  - per-address escalation from varied peers
  - no `mfa` in `amr`
- Regressions pass: `flow_login`, `security_enumeration`, `i18n` (login snapshot unchanged), `render`, `flow_mfa_policy`, `flow_mfa`, `upstream_login`, `security_linking`, `security_csrf`, `security_bruteforce`, `flow_login_factors`, `authorize_step_up`, `security_csp`, `flow_passkey`, and anvil-web `--lib` (135).
- Clippy is clean with `-D warnings`: anvil-core all targets, plus anvil-web lib and the two new test binaries. `rustfmt --edition 2024` was run on every touched Rust file.

## Not run

- `ANVILID_TEST_DB=postgres` for the two new binaries: Docker is not used (wave rule), so this is left for CI. No SQL was added; the plan uses the existing `swap_state`, `outbox().enqueue`, `get_by_email` and session intents.
- e2e/Playwright and conformance: not run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] New test helper module `crates/anvil-web/tests/email_code_support/mod.rs` (not in files_modified)**
- Shared by the two new test binaries, so the helpers are not duplicated (the same pattern as 04-21's `upstream_flow`).
- Commit: 26443fe

**2. [Rule 2 - Security] Verified address required (coordinator instruction during execution)**
- An unverified address may not belong to the account holder, so the plan's "active user" rule was tightened to active and verified. An unverified address gets the same page, no email and no audit event.
- It is re-checked at code or link use. Negative tests: `unknown_unverified_and_blocked_addresses_look_the_same_and_get_nothing` and `an_address_unverified_after_the_send_cannot_use_its_code_or_link`.
- Commit: 26443fe

**3. [Design] No new `Failure` or `FlowOutcome` variants**
- `registration::on_failure` and `ui/setup.rs` match these exhaustively and are outside this plan. The email effects store their compare-and-swap verdict and answer with their own bound form (`Step::Done(Render)`), and the link has its own `EmailLinkOutcome`.

**4. [Design] Magic link CSRF**
- The flow stores only the hash of its form CSRF token, so the link page cannot show it. The link page uses `link_csrf` (HKDF from the KEK over flow id and token) instead. The flow cookie is still required.

**5. [Design] HKDF instead of HMAC for the derived values**
- anvil-core has no aws-lc-rs dependency. `link_csrf` and `limit_subject` use `Kek::derive_key` with length-prefixed parts in the info string (a KEK-keyed PRF). The code hash itself is the plan's `email_code_hash`.

**6. [Refactor] Shared continuation**
- `upstream_primary` now delegates to `primary_without_form(auth, method)`, which the magic link uses too. Upstream behaviour is unchanged: `upstream_login` (12) and `security_linking` (16) pass.

### Notes and open points

- Either setting enables both the code and the link. If `email_otp` and `magic_link` must mean different things (code only versus link only), the `login_code` contract needs optional variables. This is a follow-up decision.
- The link and other-browser answers are the message page with status 400 and `Cache-Control: no-store`.
- No requirement checkbox was ticked (wave rule).

## Self-Check: PASSED

- Files exist: crates/anvil-core/src/flow/email_code.rs (675 lines), crates/anvil-web/tests/security_email_code.rs (446 lines), crates/anvil-web/tests/flow_email_code.rs, crates/anvil-web/src/ui/email_code.rs, themes/default/templates/email_code.html, themes/default/templates/magic_link.html, themes/default/locales/en/email_code.ftl
- Commits in history: 7cfeb9d, 26443fe
- key_links: `email_code_hash` in flow/email_code.rs; `LimitKey` in ui/email_code.rs
