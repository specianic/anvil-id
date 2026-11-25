---
phase: 03-release-0-2-secure-by-default
plan: 14
subsystem: account-security
tags: [passkeys, webauthn, totp, recovery-codes, settings-flow, audit, ui]
requires:
  - phase: 03-01
    provides: TotpSecret/otpauth_uri/check_code, recovery-code generation/normalisation/peppered hash
  - phase: 03-02
    provides: credential ports, FlowRepo::swap_state, AuditService, PasskeyCeremonies
  - phase: 03-05/03-06
    provides: credential storage on SQLite and Postgres
  - phase: 03-08
    provides: account_base.html, AuditContext, registered empty ui::account_security module
  - phase: 03-09
    provides: WebauthnPasskeys, relying_party (Result), qr_svg, webauthn.js DOM contract
provides:
  - anvil_core::flow::settings (SettingsState, REAUTH_WINDOW, SETTINGS_TOTP_PURPOSE, settings_totp_aad, normalize_label, is_recent_auth)
  - anvil_core::service::account::AccountService (self-service + admin_list/admin_remove for 03-23)
  - /ui/account/security pages (passkeys, TOTP enrolment, recovery codes, removal)
affects: [03-20, 03-23, 03-26]
tech-stack:
  added: []
  patterns:
    - "Settings flow = ordinary flow row (FlowKind::Settings) whose state is a tagged SettingsState managed by AccountService (not the engine); every state change is a swap_state CAS"
    - "Account pages set their own CSP (default + script-src/connect-src 'self') because the global CSP has no script-src"
key-files:
  created:
    - crates/anvil-web/tests/account_security.rs
    - themes/default/templates/account_security.html
    - themes/default/templates/totp_enroll.html
    - themes/default/templates/recovery_codes.html
  modified:
    - crates/anvil-core/src/flow/settings.rs
    - crates/anvil-core/src/service/account.rs
    - crates/anvil-web/src/ui/account_security.rs
key-decisions:
  - "Settings flows are created and advanced by AccountService directly (FlowState::initial still refuses Settings; engine.rs untouched). SettingsState carries kind=settings and the owning user id; a session of another user is Forbidden"
  - "Order of checks on every change: flow exists/unexpired (else account.flow_expired) -> kind Settings -> cookie+CSRF (Forbidden) -> flow owner = session user (Forbidden) -> auth_time within 15 min (account.reauth_required)"
  - "Pending passkey challenge and TOTP secret are consumed with swap_state BEFORE use; a lost race or replay is account.passkey_failed / account.totp_not_pending"
  - "Pending TOTP secret sealed with purpose anvilid/settings-totp/v1 and AAD flow:{id}; the enrolled seed is re-sealed with TOTP_SEED_PURPOSE and credential_aad(new id)"
  - "Recovery-code regeneration requires an enrolled TOTP (account.totp_required); removing TOTP deletes the codes (storage)"
  - "Passkey label: trimmed, empty -> 'Passkey', >64 chars or control characters -> account.invalid_label (checked before the challenge is consumed)"
  - "Refusals re-render the overview with 400 and a data-message-key; CSRF/binding failures are the csrf page (403); options endpoint answers JSON (401 login_required without a session, 400 {error: key} on refusal)"
requirements-completed: []
duration: 55min
completed: 2026-11-25
---

# Phase 3 Plan 14: Account security (passkeys, TOTP, recovery codes) Summary

**A user-bound settings flow and `AccountService` for passkey registration, TOTP enrolment with 10 recovery codes, code regeneration and credential removal (plus admin list/remove), served at `/ui/account/security` with flow-bound, re-auth-guarded, audited POSTs**

## Performance

- **Duration:** about 55 min
- **Tasks:** 2/2
- **Files:** 7 (3 modified, 4 created)

## Accomplishments

- `SettingsState { kind: "settings", user, pending_passkey, pending_totp }` with pure single-use transitions (`with_passkey_challenge`/`take_passkey`, `with_totp_secret`/`take_totp`), and the helpers `is_recent_auth` (15 min), `normalize_label` and `settings_totp_aad`.
- `AccountService` performs every change in a settings flow. Each change is re-authentication guarded, compare-and-swap protected and audited (`passkey_registered`, `passkey_removed`, `totp_enrolled`, `totp_removed`, `recovery_codes_regenerated`, with the request context).
- TOTP confirmation runs in this order: (1) consume the pending secret; (2) seal the seed under the credential AAD; (3) `create_totp` stores the seed and 10 HMAC'd codes in one call; (4) `advance_totp_step(step)` so the enrolment code cannot sign in later; (5) return the plaintext codes once, as `SecretString`.
- `/ui/account/security` shows:
  - passkeys with label, added date and last used, each with a remove form;
  - TOTP status and the number of recovery codes left.

  Everything except adding a passkey works without JavaScript. Passkey registration follows the webauthn.js contract (`data-webauthn="register"`, `data-options-url`, hidden `response`).

## AccountService API (for 03-23 and later plans)

```rust
AccountService { storage, clock, kek: Arc<Kek>, passkeys: Arc<dyn PasskeyCeremonies> }
start(tenant_id, &BrowserSession) -> Result<StartedSettings { flow_id, cookie_token, csrf_token }, CoreError>
overview(tenant_id, &BrowserSession) -> Result<AccountOverview { passkeys, totp, recovery_codes_remaining, recent_auth }, CoreError>
begin_passkey(&Tenant, &BrowserSession, &SettingsBinding, &RelyingParty) -> Result<String /*options JSON*/, AccountError>
finish_passkey(&Tenant, &BrowserSession, &SettingsBinding, &RelyingParty, response_json, label, &RequestContext) -> Result<CredentialId, AccountError>
begin_totp(&Tenant, &BrowserSession, &SettingsBinding) -> Result<TotpEnrolment { otpauth_uri, secret_base32 }, AccountError>
pending_totp(..same..) -> Result<TotpEnrolment, AccountError>          // redisplay after a wrong code
confirm_totp(.., code, &RequestContext) -> Result<Vec<SecretString>, AccountError>
regenerate_recovery_codes(.., &RequestContext) -> Result<Vec<SecretString>, AccountError>
remove_credential(.., CredentialId, &RequestContext) -> Result<CredentialKind, AccountError>
admin_list(tenant_id, user_id) -> Result<Vec<CredentialSummary>, CoreError>          // NotFound for unknown user; includes the password summary
admin_remove(tenant_id, user_id, CredentialId, admin_id: &str, &RequestContext) -> Result<CredentialKind, CoreError>  // NotFound for unknown/other user's/password; audits actor Admin(admin_id)
```

`AccountError = Failure(AccountFailure) | Core(CoreError)`. `AccountFailure::key()` gives the message keys `account.reauth_required`, `account.flow_expired`, `account.invalid_label`, `account.passkey_failed`, `account.passkey_exists`, `account.totp_exists`, `account.totp_not_pending`, `account.totp_invalid_code`, `account.totp_required`, `account.credential_not_found` and `account.try_again`. Text comes from `account::message_text(key)`. Success keys are `account.passkey_registered`, `account.passkey_removed`, `account.totp_removed`, `account.totp_enrolled` and `account.recovery_codes_regenerated`. `new_recovery_codes(&Kek)` is public.

## Routes

| Method | Path | Notes |
|---|---|---|
| GET | `/ui/account/security` | 303 to `/ui/login` without a session; starts a settings flow (flow cookie) |
| POST | `/ui/account/security/passkey/options?flow=` | JSON creation options; CSRF via `csrf_token` field or `X-CSRF-Token` header |
| POST | `/ui/account/security/passkey?flow=` | `response`, `label` |
| POST | `/ui/account/security/totp?flow=` | renders `totp_enroll.html` |
| POST | `/ui/account/security/totp/confirm?flow=` | `code`; renders `recovery_codes.html` once |
| POST | `/ui/account/security/recovery-codes?flow=` | new set, renders `recovery_codes.html` |
| POST | `/ui/account/security/credentials/{id}/delete?flow=` | passkey or TOTP |

All responses send `Cache-Control: no-store` and `ACCOUNT_CSP` = the default CSP plus `script-src 'self'; connect-src 'self'`.

## Selectors (for e2e, 03-26)

- Overview:
  - message area `#account-messages`, with `#account-msg-N[data-message-key]`
  - re-auth notice `#account-reauth` with link `#link-reauth`
  - passkey table `#passkey-list` (rows `#passkey-{id}`) or empty text `#passkeys-empty`
  - registration form `#passkey-register`: input `#label`, hidden `#response`, trigger `#passkey-register-submit` (hidden until WebAuthn is available), status `#passkey-register-status`
  - TOTP: `#totp-status`; form `#totp-begin` with button `#totp-begin-submit`; when enrolled, `#recovery-codes-count`, form `#recovery-codes-regenerate` with `#recovery-codes-regenerate-submit`, and remove form `#credential-delete-{id}` with `#credential-delete-{id}-submit`
- `totp_enroll.html`: `#totp-qr` (inline SVG), `#totp-secret` (base32 in groups of 4), form `#totp-confirm` with input `#code` (`autocomplete="one-time-code"`, `inputmode="numeric"`), `#totp-confirm-submit`, error `#code-msg-1`, cancel `#link-account-security`.
- `recovery_codes.html`: `#account-msg-1`, list `#recovery-codes` (`<li><code>`), copy box `#recovery-codes-text` (`readonly autocomplete="off"`), `#link-account-security`.

## Task Commits

1. **Task 1: Settings state machine and AccountService:** `7ebd8f5`
2. **Task 2: /ui/account/security pages and HTTP tests:** `c2f6584`

## Verification

- `cargo test -p anvil-core flow::settings` (7) and `service::account` (4): pass.
- `cargo test -p anvil-web --test account_security`: 12/12 on SQLite and on Postgres (testcontainers).
- `cargo test -p anvil-web --test render --lib`: 13 and 83 pass.
- `cargo clippy -p anvil-core --all-targets` and `-p anvil-web --lib --test account_security` with `-D warnings`: clean. `cargo fmt --check`: clean.
- The main tree did not build because of other plans' in-progress files, so verification ran in the worktree `target/wt-03-14` at main HEAD with this plan's files copied in. The worktree was removed afterwards.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Service behaviour tests live in the anvil-web integration test**
- **Found during:** Task 1
- **Issue:** anvil-core has no async runtime dev-dependency, and the `Storage` trait is too large for an in-crate fake. Cargo.toml is not in this plan's files.
- **Fix:** anvil-core unit tests cover the pure parts: transitions, re-auth window, labels, failure keys, recovery-code hashing, the seal binding, and that the state JSON holds no secret. The async behaviours listed in Task 1 (single-use and concurrent challenges, Conflict mapped to `passkey_exists`, wrong/right TOTP code, regeneration, other users' credentials, admin actor) are tested in `tests/account_security.rs`. Those tests run `AccountService` on both real backends with a `PasskeyCeremonies` test double (test code only).
- **Commits:** 7ebd8f5, c2f6584

**2. [Rule 3 - Blocking] Account pages set their own CSP**
- **Issue:** The global CSP is `default-src 'none'` with no `script-src`, so webauthn.js and its options fetch would be blocked.
- **Fix:** Handlers in this module set `ACCOUNT_CSP`: the default plus `script-src 'self'` and `connect-src 'self'`. The security headers layer keeps headers that a handler sets. A unit test checks that the policy only adds those two directives.
- **Commit:** c2f6584

**3. [Rule 2 - Correctness] Settings flow bound to its user**
- **Issue:** The plan's state did not name the owner.
- **Fix:** `SettingsState.user` is checked against the session on every submission, which also guards against a mixed-up session cookie.
- **Commit:** 7ebd8f5

TDD note: tests and implementation were written together in each task's commit. There are no separate RED commits.

## Issues Encountered / Follow-ups

- `anvil.css` (not in this plan) has no rules for `.anvil-qr`, `.anvil-table`, `.anvil-recovery-codes` or `.anvil-secret`. Without styling, the QR SVG scales to the container width. 03-20 (or whichever plan owns the stylesheet) should size `.anvil-qr svg`.
- If someone posts their own settings flow id to an engine page (for example `/ui/login?flow=<settings id>`) with that flow's cookie and CSRF, `FlowService` fails to parse the state and answers 500. Only the user's own flow is affected, and nothing changes. A kind check in `FlowService::submit` before parsing would turn this into a restart.
- `tests/ui_helpers` `OwnApp` still does not insert `ConnectInfo`. These tests use `TestApp`, so no change was needed.
- The first Postgres run under heavy parallel testcontainer load reported one failure, and its output was cut off. Three later full Postgres runs and an isolated run all passed.
- `cargo clippy -p anvil-web --tests` fails in `tests/security_ratelimit.rs` (03-13, in progress). That is out of scope.

## Self-Check: PASSED

- FOUND: crates/anvil-core/src/flow/settings.rs, crates/anvil-core/src/service/account.rs, crates/anvil-web/src/ui/account_security.rs, crates/anvil-web/tests/account_security.rs, themes/default/templates/{account_security,totp_enroll,recovery_codes}.html
- FOUND: 7ebd8f5, c2f6584
