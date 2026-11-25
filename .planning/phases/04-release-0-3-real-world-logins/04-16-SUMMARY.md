---
phase: 04-release-0-3-real-world-logins
plan: 16
subsystem: auth
tags: [mfa-policy, step-up, acr, amr, totp, enrolment, session-switch, login-hint, oidc-14, auth-08]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01: TenantSettings.mfa_policy, Client.mfa_policy, SessionRepo::upgrade_auth/revoke_with_families, CoreError::UnmetAuthenticationRequirements, AuditAction::StepUpCompleted; 04-06: t()/per-feature .ftl; 04-08: policy::mfa; 04-11: admin fields; 04-12/04-15 (sibling authorize/account changes)"
provides:
  - "oauth::decision::{MfaContext, requested_acr, session_is_mfa}, SessionDecision::StepUp, decide(.., mfa: MfaContext)"
  - "service::authorize::mfa_context (pub(crate)): effective policy + requested acr + user_has_factor"
  - "flow::login: LoginStep::Enroll { user_id }, LoginState.{step_up_session, pending_totp}, AfterPrimary, after_primary_auth, enroll_required, step_up, ENROLL_FORM_ID (\"mfa-enroll\")"
  - "flow::engine: Effect::ConfirmTotpEnrolment, Effect::UpgradeSession { session, auth }, upgraded_acr_amr"
  - "service::flow: FlowService::start_login, FlowOutcome::{Enroll, SteppedUp}, SignedIn.recovery_codes, StartedFlow.{factor_user, totp}; session switch via revoke_with_families"
  - "service::account (pub(crate)): seal_pending_totp, open_pending_totp, pending_totp_step, create_confirmed_totp, enrolment"
  - "mfa_enroll.html + locales/en/mfa.ftl; login_hint prefill"
affects: [04-20, 04-21, 04-24]

tech-stack:
  added: []
  patterns:
    - "Step-up decided by the one pure decide(); FlowService::start_login reuses it with the stored request, so authorize and the login page cannot disagree"
    - "A step-up ends in UpgradeSession (same session id and cookie), never a second session"

key-files:
  created:
    - crates/anvil-web/tests/flow_mfa_policy.rs
    - crates/anvil-web/tests/authorize_step_up.rs
    - themes/default/templates/mfa_enroll.html
    - themes/default/locales/en/mfa.ftl
  modified:
    - crates/anvil-core/src/oauth/decision.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/flow/engine.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/account.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/mfa.rs
    - crates/anvil-web/src/ui/setup.rs
    - crates/anvil-web/src/ui/account_security.rs
    - crates/anvil-web/tests/account_security.rs

key-decisions:
  - "An existing single-factor session is checked for MFA only when acr is requested or the effective policy is Required. Optional prompts at sign-in, not on every authorization request."
  - "Unmet essential acr at sign-in still signs the user in single-factor (truthful acr). resume() then answers unmet_authentication_requirements through the response mode. No login.mfa_unmet page."
  - "prompt=none when a step-up is needed: interaction_required, or unmet_authentication_requirements if the acr is essential."
  - "user_has_factor means TOTP (the factor the second-factor step accepts). Passkey sign-in already counts as MFA, so it satisfies Required."
  - "Session switch: when the current session belongs to another user, it is revoked with revoke_with_families and audited session_revoked (reason session_switch). A same-user sign-in still only rotates the session (plain revoke)."
  - "In-flow enrolment creates a recovery-code set and shows it once (no-store) before continuing."
  - "The pending in-flow TOTP secret reuses the account page's sealing (SETTINGS_TOTP_PURPOSE, AAD = flow id). Flow ids are unique, so a sealed secret cannot be used in another flow."

requirements-completed: [AUTH-08, OIDC-14]

duration: about 2h 30min (one interruption)
completed: 2026-11-25
---

# Phase 4 Plan 16: MFA Policy Enforcement and acr_values Step-up Summary

**The login flow now enforces the strictest of the tenant and client MFA policy:**
- `off` never prompts.
- `optional` prompts users who have a factor.
- `required` prompts, or makes the user enrol an authenticator app during sign-in.

**Other changes:**
- `acr_values=urn:anvilid:acr:mfa` steps up a single-factor session in place, with no password re-entry (same session id, `amr` gains `otp` and `mfa`, `auth_time` is set to now, audited `step_up_completed`).
- An essential `acr` that cannot be met answers `unmet_authentication_requirements`.
- When a second user signs in, the browser's previous user's session is logged out together with its token families.
- `login_hint` prefills the identifier only when it is an email address.

Note: no requirement checkbox was ticked (wave rule). `requirements-completed` lists what this plan delivers.

## Decision table (decide, usable single-factor session, MFA wanted)
| mfa_requirement | prompt=none | Decision |
|---|---|---|
| None (voluntary, no factor) | any | UseSession (lower acr issued) |
| SecondFactor / Enroll | no | StepUp -> `AuthorizeOutcome::Login` |
| SecondFactor / Enroll | yes | interaction_required (essential: unmet_authentication_requirements) |
| Unmet | any | unmet_authentication_requirements |

"MFA wanted" means `acr != None || policy == Required`. If the session is unusable (`prompt=login`, `max_age` exceeded, a hint mismatch), the answer is still RequireLogin. The full sign-in then applies the policy.

## For 04-20 / 04-21 / 04-24
- Email-OTP and upstream sign-ins should call `after_primary_auth(policy, acr, methods)` (or `mfa_requirement`) after their primary step. `FlowService::flow_mfa` already returns `(policy, acr)` for a flow's stored request.
- New login steps must handle `LoginStep::Enroll` in `on_failure`/`current_form`, and must end in `UpgradeSession` when `LoginState.step_up_session` is set.
- `FlowOutcome::SignedIn` now has a `recovery_codes` field, and there are two new variants, `Enroll` and `SteppedUp`. Exhaustive matches need all of them.
- `upgraded_acr_amr(existing, auth, backup_eligible)` builds the step-up `amr` union.

## Task Commits
1. **Task 1 (core):** `4e25667` feat(04-16): MFA policy enforcement, in-flow enrolment, acr step-up and session switch in core
2. **Task 2 (web, templates, tests):** `b7860eb` feat(04-16): enrolment page, step-up start, login_hint prefill and MFA policy tests

Between the two commits, anvil-web did not compile: `FlowOutcome` changed in Task 1 and `ui/login.rs` was fixed in Task 2. Both commits landed within minutes.

## Verification (main tree, SQLite)
- `cargo test -p anvil-core --lib`: 544 passed. New tests cover:
  - the step-up decision table
  - `requested_acr`
  - `after_primary_auth`
  - the enrolment step
  - the step-up `UpgradeSession` effect
  - the `amr` union
- `cargo test -p anvil-web --test flow_mfa_policy` (9) and `--test authorize_step_up` (9): pass.
- All 64 other anvil-web integration test binaries pass, including flow_login, flow_mfa, flow_login_factors, authorize, consent, sessions, logout and account_security. `--lib` passes (130).
- Clippy is clean with `-D warnings`: anvil-core all targets, plus anvil-web lib and the touched test binaries. `rustfmt --check` is clean on every touched file.

## Not run
- `ANVILID_TEST_DB=postgres` for flow_mfa_policy and authorize_step_up: Docker is unavailable, so this is left for CI. The plan adds no SQL; it uses the existing `upgrade_auth` and `revoke_with_families` intents.
- `crates/anvil-web/tests/backchannel.rs` (04-17's, still in progress) did not compile in the shared tree (`AuditDetails: Serialize`). It is not mine and was excluded from my runs.
- e2e/Playwright: Docker is unavailable.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra files**
- `service/account.rs`: the TOTP sealing, step check and credential creation were extracted to `pub(crate)` functions and are shared by `confirm_totp` and in-flow enrolment, so there is no duplicate verification code. This follows the plan's "reuse AccountService pieces".
- `ui/setup.rs`: one match arm for the new `FlowOutcome` variants.
- `ui/account_security.rs`: `grouped` is now `pub(super)` (reused for the key display).
- Commits: 4e25667, b7860eb

**2. [Intended behaviour, test updated] account_security `removing_a_passkey_works_without_javascript_and_only_for_its_owner`**
- 04-18 reported it; the cause is this plan. The test registers Bob in a browser that still holds the first user's session. The new session switch revokes that session and audits `session_revoked`. Passkey removal revokes nothing.
- Fix: the test's sign-in-event filter now also skips `SessionRevoked`. No other assertion in that file uses it. Commit b7860eb.

**3. [Design] Unmet essential acr during sign-in**
- The plan sketched a `login.mfa_unmet` failure. Instead the user is signed in single-factor and `resume` answers `unmet_authentication_requirements`. The RP gets the same error through the response mode, and there is no extra failure page or key.

**4. [Design] FlowService::start_login instead of a flag in the URL**
- The login page does not trust any step-up parameter. It recomputes `decide()` from the stored request and the session.

### Plan items not done
- **In-flow passkey registration** as an enrolment option. Only TOTP enrolment is implemented. A passkey sign-in already satisfies `required` (amr `mfa`). Passkey registration during sign-in needs a registration ceremony bound to the login flow (options route, webauthn.js register form, registration effect). Left for a follow-up (04-20/04-21 or a gap plan).
- `second_factor.html` and `login.html` were not changed. The step-up reuses the second-factor page unchanged, and the `login_hint` prefill goes through the existing field value.

## Self-Check: PASSED
- Files exist: crates/anvil-web/tests/flow_mfa_policy.rs (473 lines), crates/anvil-web/tests/authorize_step_up.rs (519 lines), themes/default/templates/mfa_enroll.html, themes/default/locales/en/mfa.ftl
- Commits in history: 4e25667, b7860eb
- key_links: `mfa_requirement` in flow/login.rs; `upgrade_auth` in service/flow.rs
