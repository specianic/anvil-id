---
phase: 05-release-0-4-operate-it
plan: 30
subsystem: auth
tags: [mfa-policy, passkey, webauthn, second-factor, step-up, gap-closure, auth-08]

requires:
  - phase: 05-11
    provides: "in-flow passkey enrolment, FlowService::passkey_enrolment_*, tests/passkey_support"
  - phase: 04-16
    provides: "MFA policy engine, LoginStep::SecondFactor, step-up flows, mfa_context"
provides:
  - "SecondFactorMethods.passkey (serde default) + SecondFactorMethods::any()"
  - "service::authorize::second_factor_methods: the one 'has a second factor' answer (engine, step-up, mfa_context)"
  - "LoginState.second_factor_passkey, second_factor_passkey_user / with_second_factor_passkey / take_second_factor_passkey / second_factor_passkey_failed, SECOND_FACTOR_PASSKEY_FAILED, SECOND_FACTOR_PASSKEY_FIELD"
  - "FlowService::passkey_second_factor_options / passkey_second_factor_finish; shared check_assertion / record_assertion (one verification path with the sign-in passkey)"
  - "Routes POST /ui/login/second-factor/passkey/start|finish?flow="
  - "second_factor.html passkey section (template variable passkey_second_factor)"
affects: [05-28]

tech-stack:
  added: []
  patterns:
    - "Core tells the presentation layer that a step offers a passkey through a hidden marker field in the form description (never rendered or submitted), so every path that renders the second-factor page gets the option without extra plumbing"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/tests/flow_mfa_policy.rs
    - crates/anvil-web/tests/account_security.rs
    - themes/default/templates/second_factor.html
    - themes/default/locales/en/main.ftl
    - themes/default/locales/de/main.ftl
    - themes/default/README.md
    - tests/e2e/specs/mfa-policy.spec.ts
    - docs/ARCHITECTURE.md

key-decisions:
  - "A passkey counts as a second factor everywhere (SecondFactorMethods::any = totp || passkey; recovery codes only back up TOTP). Consequence: under `optional`, a user with a passkey who signs in with a password is now asked for the passkey, the same rule as for TOTP (replaces the 04-16 decision 'user_has_factor means TOTP')"
  - "The second-factor challenge has its own state field (LoginState.second_factor_passkey); an identify-step challenge is dropped on entering the step and never read there"
  - "User binding is checked before any signature check: the assertion's user handle must be the step user, and the credential must be a stored passkey bound to that handle"
  - "The passkey option reaches the page as a hidden marker field `passkey` on the second-factor form (FormDescription has no other channel and form.rs is not this plan's file)"
  - "A verified second-factor passkey signs in as SessionAuth::Passkey ([hwk|swk, user, mfa]) or upgrades the step-up session, through the effect runner like 05-11; login_failed (method passkey_second_factor) is audited only when an assertion was checked against a pending challenge"

requirements-completed: []

duration: about 1h 20min
completed: 2026-11-26
---

# Phase 5 Plan 30: Passkey as the Second Factor Summary

**Under MFA `required`, a user whose only second factor is a passkey (for example one enrolled in-flow) who signs in with a password, an email code or an upstream login now reaches the second-factor step with a passkey option instead of being sent back to enrolment. An assertion from one of that user's own passkeys signs them in with `[hwk|swk, user, mfa]` and the MFA `acr`, or upgrades a step-up session in place. Another user's passkey, an unknown credential, a replayed, cross-flow or identify-step challenge, and a finish with no challenge pending are all refused.**

Traceability: AUTH-08 gap closure (05-11 deferred item). No requirement checkbox was ticked (wave rule).

## Routes and selectors

| Route | Notes |
|---|---|
| `POST /ui/login/second-factor/passkey/start?flow=` | `csrf_token` + flow cookie. Discoverable request options as JSON (`no-store`). Errors are JSON `{"error"}`: 403 `csrf`, 400 `second_factor.passkey_failed` (expired flow, not a second-factor step with a passkey, inactive user), 500 |
| `POST /ui/login/second-factor/passkey/finish?flow=` | `csrf_token`, `factor_token` (handed back), `response`. Success: 303 continue or the signed-in page. Refusal: 400 second-factor page |

Second-factor page: section `second-factor-passkey`, form `second-factor-passkey-form` (`data-webauthn="authenticate"`), button `second-factor-passkey-submit` (hidden until webauthn.js runs), status `second-factor-passkey-status`, messages `second-factor-passkey-msg-N`, noscript note `second-factor-passkey-nojs`. The authenticator-app form (`second-factor`) is rendered only when it has fields, and it stays first. A TOTP-only user's page is unchanged. New keys (en, de): `second_factor.{passkey_heading, passkey_help, passkey_button, passkey_nojs, passkey_failed}` and `second_factor.webauthn.{cancelled, failed}`.

## Negative tests (05-28 security map)

`crates/anvil-web/tests/flow_mfa_policy.rs`:
- `second_factor_passkey_of_another_user_is_refused`: a valid assertion from user B's passkey on user A's step. Result: 400 with `second_factor.passkey_failed`, no session, audited once. A's step stays usable: a fresh challenge with A's passkey succeeds.
- `second_factor_passkey_unknown_credential_is_refused`: A's user handle with a credential that was never registered.
- `second_factor_passkey_challenge_cannot_be_replayed`: a failed finish uses up the challenge, so the valid assertion is refused afterwards. Re-posting a successful POST, with or without the new session, signs nobody in. Exactly one passkey `login_succeeded`.
- `second_factor_passkey_cross_flow_challenge_is_refused`: an assertion for flow X's challenge, posted to flow Y.
- `identify_step_passkey_challenge_is_not_accepted_at_second_factor`: options from the sign-in page, then the password, then the finish with that assertion. Refused with nothing pending (not audited), refused again with a second-factor challenge pending (audited), and the identify route refuses it too.
- `second_factor_passkey_finish_without_challenge_is_refused`: an assertion for a challenge this flow never issued. It is not audited, and the step still works afterwards.
- `second_factor_passkey_options_refused_outside_the_second_factor_step`: the identify step, a TOTP-only user's second-factor step and the enrolment step each return JSON 400 and leave the flow row unchanged. No or wrong CSRF, or no flow cookie, gives 403.

Positive tests: `passkey_only_user_gets_the_passkey_second_factor_not_enrolment` (in-flow enrolment, then password plus passkey through an RP; the ID token has `acr` mfa and `amr [hwk, user, mfa]`; `login_succeeded` with method passkey), `totp_and_passkey_user_sees_both_options`, `totp_only_user_page_unchanged`, `step_up_with_passkey_only_user_offers_passkey` (acr_values, same session upgraded to `[pwd, hwk, user, mfa]`).

Unit tests in `flow::login`: `a_passkey_counts_as_a_second_factor_like_totp`, `second_factor_methods_from_before_passkeys_decode_without_a_passkey`, `passkey_only_second_factor_form_has_no_code_fields_but_the_passkey_marker`, `second_factor_passkey_challenge_is_taken_out_once_and_only_in_its_step`, `a_totp_code_at_a_passkey_only_step_is_invalid_input`, `a_second_factor_passkey_signs_in_as_a_passkey_or_upgrades_the_step_up_session`.

### Mutation checks (each guard removed, then restored)
1. The user check in `check_assertion` was dropped (`expected_user` ignored). `second_factor_passkey_of_another_user_is_refused` failed: A was signed in with B's passkey.
2. `take_second_factor_passkey` was made to fall back to `passkey_challenge`, and `second_factor_required` stopped clearing it. `identify_step_passkey_challenge_is_not_accepted_at_second_factor` failed.
3. The compare-and-swap before verification was skipped in `passkey_second_factor_finish`. `second_factor_passkey_challenge_cannot_be_replayed` failed.
4. `mfa_context` was put back to TOTP only. `step_up_with_passkey_only_user_offers_passkey` failed.

## Task Commits

1. **Task 1 (core):** `3af13a7` feat(05-30): passkeys count as a second factor; second-factor passkey ceremony
2. **Task 2 (routes, page, locales, tests, e2e, docs, account_security fix):** `8bb3f85` feat(05-30): passkey option on the second-factor page

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 808 passed (`flow::login` 35).
- `cargo test -p anvil-web --test flow_mfa_policy`: 31 passed (11 new). `--test account_security`: 12 passed (whole file).
- Regression tests pass: `flow_mfa`, `flow_passkey`, `authorize_step_up`, `flow_login_factors`, `i18n_catalogs` (en/de parity), `i18n`, `render` (snapshots unchanged), `theme`, `security_csp`, `flow_email_code`, `upstream_login`, `flow_login`, `security_csrf`.
- `cargo clippy -p anvil-core --all-targets -D warnings` and `cargo clippy -p anvil-web --all-targets -D warnings`: clean. `rustfmt --edition 2024` was run on the touched Rust files.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- **e2e run locally without Docker:** the debug `anvilid` ran from a scratch copy with the run.sh flags. `specs/mfa-policy.spec.ts` passed 4/4, including the new password-plus-passkey second-factor step with the virtual authenticator and the axe check on the second-factor page. `passkey`, `i18n`, `keyboard`, `nojs` and most of `a11y`/`account` also passed. The only 4 failures need Mailpit (ECONNREFUSED :8025: a11y registration and recovery, account email change, totp), which this environment does not have. The scratch dir and `e2e-results/` were deleted afterwards.

## Not run

- `ANVILID_TEST_DB=postgres` for `flow_mfa_policy`: Docker is not used here. No SQL was added; only the existing `swap_state`, `passkeys`, `find_passkey` and `update_passkey` are used.
- `tests/e2e/run.sh sqlite|postgres` itself, and the Mailpit-dependent specs (CI).

## Deviations from Plan

### Design choices (no Rule 4 needed)

**1. Passkey option signalled by a hidden marker field**
- The web layer renders the second-factor page from a `FormDescription` on many paths: password, email code, upstream continuation, step-up start and refusals. It needs to know that the step offers a passkey. `form.rs` and `FlowOutcome` matches in other UI files are not this plan's files. So `second_factor_form` adds a hidden field `passkey` when `methods.passkey` is set. The template never renders it, and nothing submits it.

**2. `with_second_factor_passkey` returns `Option<LoginState>`**
- It returns `None` outside a second-factor step that offers a passkey. The plan's "refuses other steps" is then enforced by the type.

**3. Shared start/finish handler bodies**
- The two enrolment routes and the two new routes share `flow_passkey_options` / `flow_passkey_finish`, selected by `FlowPasskey`, so there is no second copy of the binding, 413 and JSON error handling.

**4. Behaviour change under `optional`** (follows from "count passkeys everywhere")
- A password sign-in by a user who has a passkey is now asked for the passkey under `optional`, as it already was for TOTP users. The CI default tenant policy is `optional`.

### Auto-fixed Issues

**1. [Rule 1 - Test] `account_security::a_stale_session_must_sign_in_again_and_changes_nothing`** (reported by 05-33 through the coordinator)
- The test stores a fake passkey (no authenticator) and then signs in again with only a password. Under this change that user is sent to the second-factor step.
- Fix: the tenant MFA policy is set to `off` just before the re-sign-in, and the test now asserts `login.signed_in`. What the test is about is unchanged: a stale session is refused and changes nothing.
- Commit `8bb3f85`.

### Forced extras (outside files_modified)
- `crates/anvil-web/tests/account_security.rs`: the item above.
- `crates/anvil-web/tests/passkey_support/mod.rs` (listed) needed no change. The helpers (`enrol_passkey`, `assertion`, `sf_passkey_form`) are specific to the harness and live in `flow_mfa_policy.rs`.

### Process note
- Task 1 was committed as one feat commit with its unit tests, not as separate RED/GREEN commits.

## Deferred Issues
- The discoverable second-factor challenge carries no `allowCredentials`, so the browser picker can offer other accounts' passkeys for the RP. They are refused server-side. Narrowing the picker would need a new port method (`start_authentication` with the user's credentials), which this plan ruled out.

## Self-Check: PASSED
- Files exist: crates/anvil-core/src/flow/login.rs (contains `second_factor_passkey`), crates/anvil-web/tests/flow_mfa_policy.rs (contains `second_factor_passkey_of_another_user_is_refused`), themes/default/templates/second_factor.html (contains `second-factor-passkey`)
- Commits in history: 3af13a7, 8bb3f85
- key_links: `mfa_context` sets `user_has_factor` from `second_factor_methods(..).any()`; ui/login.rs registers `/ui/login/second-factor/passkey/start|finish` calling `FlowService::passkey_second_factor_options/finish`
