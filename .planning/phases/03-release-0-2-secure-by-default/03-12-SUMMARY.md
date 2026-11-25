---
phase: 03-release-0-2-secure-by-default
plan: 12
subsystem: auth
tags: [login, passkeys, webauthn, totp, recovery-codes, mfa, amr, audit, rate-limit-attempts]
requires:
  - phase: 03-02
    provides: PasskeyCeremonies port, credential/audit model, FlowRepo::swap_state, UserRepo TOTP/recovery/passkey methods
  - phase: 03-05/03-06
    provides: storage implementations of the Phase 3 ports
  - phase: 03-08
    provides: AuditContext extractor
  - phase: 03-09
    provides: WebauthnPasskeys adapter, relying_party(tenant, issuer) -> Result
provides:
  - LoginStep::{Identify, SecondFactor}, passkey challenge in login flow state
  - FlowService::passkey_options, passkey/TOTP/recovery-code execution
  - SubmitResult { outcome, attempt: Option<AuthAttempt> } for the 03-20 limiter wiring
  - Sessions with method-specific acr/amr plus client IP and user agent
  - Login-related audit events
affects: [03-19, 03-20, 03-26]
tech-stack:
  added: []
  patterns:
    - "Single-use flow-state secrets: the pure transition removes the challenge; the service swaps the stored state (CAS) before verifying"
    - "Effects report attempts through a per-submission Exec context, not by re-deriving them in the web layer"
key-files:
  created:
    - crates/anvil-web/tests/flow_login_factors.rs
    - themes/default/emails/recovery_code_used.txt
    - themes/default/emails/recovery_code_used.html
  modified:
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/flow/engine.rs
    - crates/anvil-core/src/flow/registration.rs
    - crates/anvil-core/src/flow/recovery.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/session.rs
    - crates/anvil-web/src/ui/{login,registration,recovery,verification,setup}.rs
    - crates/anvil-web/tests/flow_recovery.rs
key-decisions:
  - "03-12: The password_changed notice is still enqueued right after the recovery transaction. Its template contract (03-15 check.rs and the default templates) needs `email`, which is only known once the token is consumed, so a RecoveryNotice built before the call cannot carry it. Needs a decision: the mail worker supplies `email` from the recipient, or `email` is dropped from the password_changed contract"
  - "03-12: CheckSecondFactor is a unit effect (the user is unknown when the transition runs). The service answers with the pure engine::second_factor_required(state, user, methods)"
  - "03-12: FlowContext.rp is &Result<RelyingParty, CoreError>. Only passkey effects propagate the error, so password sign-in keeps working on issuers that cannot be an RP (IP literals)"
  - "03-12: Every passkey failure renders login.passkey_failed (no challenge, bad response, wrong user handle, unknown credential, clone, stale counter, blocked user)"
  - "03-12: Flows of kinds the engine does not run (settings, consent) are restarted like unknown flows, never decoded (bug report from 03-14)"
requirements-completed: []
metrics:
  duration: 150min
  completed: 2026-11-25
---

# Phase 3 Plan 12: Passkey and second-factor login core Summary

**The login state machine and FlowService now support usernameless passkey sign-in (single-use CAS challenge, user-handle binding, counter CAS, clone audit) and a TOTP or recovery-code second factor (replay-proof step CAS, atomic code use with a sealed notice). Sessions get method-specific amr/acr plus client IP and user agent, every submission reports an `AuthAttempt` for the limiter, and the login-related audit events are recorded.**

## Performance

- Duration: about 150 min
- Tasks: 3/3
- Files: 16

## API for 03-20

### Engine (`anvil_core::flow::engine`)

- `LoginState { identifier, step: LoginStep, passkey_challenge: Option<String> }`. Every field has a serde default, so 0.1 flow JSON still decodes (tested).
- `LoginStep::{Identify, SecondFactor { user_id, methods: SecondFactorMethods { totp, recovery } }}`
- New `FlowInput` variants (all of kind Login):
  - `PasskeyOptions`: only through `FlowService::passkey_options`. `submit` refuses it with InvalidRequest.
  - `PasskeyAssertion { response_json }`
  - `Totp { code }`
  - `RecoveryCode { code }`
- New `Effect` variants:
  - `CheckSecondFactor` (after VerifyPassword)
  - `StartPasskey`
  - `FinishPasskey { response_json, challenge }`
  - `VerifyTotp { user_id, code }`
  - `ConsumeRecoveryCode { user_id, code }`
  - `CreateSession(SessionAuth::{Password, SecondFactor, Passkey})` replaces the unit `CreateSession`.
- `session_acr_amr(auth, backup_eligible)` gives:
  - password: `[pwd]`, ACR_PWD
  - password plus TOTP or recovery code: `[pwd, otp, mfa]`, ACR_MFA
  - passkey: `[hwk|swk, user, mfa]`, ACR_MFA (`swk` when the passkey is backup eligible)
- New failures: `SecondFactorInvalid`, `PasskeyInvalid`.
- New message keys: `login.second_factor_invalid`, `login.passkey_failed`, `login.recovery_code_used`.
- Second-factor form: id `second-factor`, action `login`. Fields:
  - `code`: Text, `autocomplete=one-time-code`. Themes add `inputmode=numeric`, because FormField has no inputmode.
  - `recovery_code`: Text, `autocomplete=off`. Only present when unused codes remain.
- An input that does not belong to the current step renders that step's form with `flow.invalid_input` and plans no effects.

### Service (`anvil_core::service::flow`)

- `FlowContext { tenant, issuer, ui_base, rp: &Result<RelyingParty, CoreError>, ctx: &RequestContext }`
- `FlowService { .., passkeys: Arc<dyn PasskeyCeremonies> }`
- `submit(..) -> Result<SubmitResult, CoreError>`, where `SubmitResult { outcome: FlowOutcome, attempt: Option<AuthAttempt> }`.
- `AuthAttempt` variants:
  - `PasswordFailed { ident_hash }`
  - `PasswordSucceeded { ident_hash, user }`: the password was correct, even if a second factor follows.
  - `SecondFactorFailed { user }`
  - `SecondFactorSucceeded { user }`
  - `PasskeyFailed`
  - `PasskeySucceeded { user }`
  - `ident_hash = identifier_hash(normalised email)` (SHA-256).
- No attempt (`None`) for: email not verified, an overloaded hasher, malformed input, registration, recovery, verification.
- `passkey_options(cx, flow_id, cookie, csrf) -> Result<String /* options JSON */, CoreError>` errors:
  - Forbidden: the binding check failed.
  - InvalidRequest: the flow expired, is unknown, is not in the identify step, or changed concurrently.
  - Internal: the issuer cannot be a relying party.
- `SessionService::create(.., ctx: &RequestContext)` stores the IP and user agent.
- Pure helpers with tests: `bound_passkey`, `totp_step`, `recovery_code_lookup`, `identifier_hash`, `session_client`.

### Audit

| Event | Recorded when |
| --- | --- |
| `login_succeeded` | Sign-in. Details `method` = password, totp, recovery_code or passkey. |
| `login_failed` | Anonymous actor. Target is the user id when the account exists, else none. Never the identifier. Reason `email_not_verified` where it applies. |
| `second_factor_failed` | A rejected TOTP or recovery code. |
| `passkey_clone_suspected` | PossibleClone, or a Stale counter CAS. |
| `recovery_code_used` | A recovery code was consumed. Details `remaining`. |
| `password_changed` | Recovery reset. Reason `recovery`. |
| `user_registered` | Self-registration. |
| `email_verified` | Email verification. |

### Web (minimal; 03-20 owns the pages)

- POSTs to login, registration, recovery and verification extract `AuditContext`.
- GET flow start and setup pass `RequestContext::default()`. They record nothing.
- `tenant_relying_party(tenant)` is passed into every FlowContext.
- The login POST maps a non-empty `recovery_code` to RecoveryCode, a present `code` to Totp, and anything else to Login.
- The `second-factor` form renders with `login.html` until 03-20 adds `second_factor.html`.
- `result.attempt` is not used yet. The limiter wiring is 03-20.

## Task Commits

1. Task 1, login state machine: `ea8fa14`. It also carried a temporary fail-closed service shim for TOTP users, replaced in Task 2.
2. Task 2, FlowService execution, sessions, templates: `5977adc`
3. Task 3, web call sites and tests: `1c6b348`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Compile fixes in flow/registration.rs and flow/recovery.rs**
- The new `Failure` variants broke their exhaustive matches, and `CreateSession` became a tuple variant. Only minimal arm and test edits were made. Commit ea8fa14.

**2. [Rule 2 - Correctness] Foreign-kind flows restart instead of returning 500**
- This was a coordinator bug report from 03-14. `load()` restarts flows whose kind has no engine state, and `passkey_options` answers them with InvalidRequest. Tests: `only_engine_flow_kinds_are_decoded` and `a_flow_of_another_service_posted_to_login_restarts_instead_of_failing`. Commit 5977adc/1c6b348.

**3. [Rule 2 - Missing tests] New test file `crates/anvil-web/tests/flow_login_factors.rs`**
- This file is not in files_modified. anvil-core has no storage fakes, so CLAUDE.md's "every security check has a rejecting test" is met with a FlowService driven over real storage and a scripted PasskeyCeremonies test double.
- It covers: TOTP replay, second-factor inputs without a verified password, single-use recovery codes plus the sealed notice, single-use challenges (a failed finish consumes it, and of two concurrent finishes exactly one wins), wrong user handle, unknown credential, PossibleClone and Stale counter audits, and amr/acr/IP/UA on sessions.
- 9 tests. They pass on SQLite and Postgres.

**4. [Rule 1] flow_recovery hit the 03-13 rate limiter (429)**
- The test now advances the clock 60 s before the later auth POSTs, as the coordinator asked. The limiter stays enabled.

## Not done / needs decision

- **RecoveryNotice is not used.** The `password_changed` notice is still enqueued after `complete_recovery`.
  - The payload contract needs `email`: 03-15's `check::variables`, the default templates, and the `renders_every_default_email` test all expect it.
  - A notice sealed before the token is consumed cannot contain the address, and storage cannot add it to a sealed payload.
  - Fix options: (a) the mail worker sets `email` from the row recipient when the payload lacks it, then FlowService switches to `complete_recovery(.., Some(&notice))` with `{tenant_name}`; or (b) drop `email` from the password_changed contract and templates.
  - The flow_recovery tests already assert the sealed notice addressed to the token's email, and that an invalid token creates no outbox row. Those assertions hold for either fix.

## Issues Encountered

- The shared `target/` was being overwritten by parallel builds, so tests ran stale binaries. All verification used a private `CARGO_TARGET_DIR=target/t-03-12`.
- Failures that also occur at HEAD without this plan (checked in the worktree target/wt-03-12, since removed):
  - security_enumeration, security_setup and security_csp: the ui_helpers OwnApp harness has no ConnectInfo now that rate limiting is on. The orchestrator is fixing this.
  - 03-14's untracked `tests/account_security.rs` asserts an empty audit log after sign-in. With this plan, sign-in records `user_registered` and `login_succeeded`, so that test must filter to its own actions.

## Verification

- `cargo test -p anvil-core --lib`: 282 passed.
- `cargo test -p anvil-web`: flow_login, flow_registration, flow_recovery and flow_login_factors pass on SQLite. The last three plus flow_login_factors also pass with `ANVILID_TEST_DB=postgres`. The remaining failures are the pre-existing ones listed above.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings`: clean.
- `grep -n "outbox().enqueue" crates/anvil-core/src/service/flow.rs`: one hit, the post-transaction password_changed enqueue. It stays until the decision above is made.

## Self-Check: PASSED
