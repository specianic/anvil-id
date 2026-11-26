---
phase: 05-release-0-4-operate-it
plan: 11
subsystem: auth
tags: [mfa-policy, passkey, webauthn, enrolment, login-flow, carry-over]

requires:
  - phase: 04-16
    provides: "LoginStep::Enroll, sealed pending_totp, FlowOutcome::Enroll, step-up flows, mfa_enroll.html"
  - phase: 03 (passkeys)
    provides: "PasskeyCeremonies::start_registration/finish_registration, webauthn.js, amr [hwk|swk, user, mfa]"
  - phase: 05-03
    provides: "rejected_form (413 unification) used by the new finish handler"
provides:
  - "flow::login: LoginState.enroll_passkey, passkey_enrolment_user, with_passkey_enrolment, take_passkey_enrolment, passkey_enrolment_finish, passkey_enrolment_failed, PASSKEY_ENROLMENT_FAILED (\"mfa_enroll.passkey_failed\")"
  - "FlowService::passkey_enrolment_options / passkey_enrolment_finish"
  - "Routes POST /ui/login/enroll/passkey/start?flow= (JSON options) and POST /ui/login/enroll/passkey/finish?flow= (form POST, `response`)"
  - "mfa_enroll.html: sections mfa-enroll-totp (first) and mfa-enroll-passkey; template variable passkey_enroll"
  - "tests/passkey_support/mod.rs: shared software authenticator for integration tests"
affects: [05-24]

tech-stack:
  added: []
  patterns:
    - "A ceremony that is not an engine input (like passkey_options) runs in a dedicated FlowService method, reusing the effect runner only for the terminal CreateSession/UpgradeSession"
    - "A refused finish renders without writing flow state, so a lost compare-and-swap never overwrites the winner"

key-files:
  created:
    - crates/anvil-web/tests/passkey_support/mod.rs
  modified:
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/src/ui/login.rs
    - themes/default/templates/mfa_enroll.html
    - themes/default/locales/en/mfa.ftl
    - themes/default/locales/de/mfa.ftl
    - crates/anvil-web/tests/flow_mfa_policy.rs
    - tests/e2e/specs/mfa-policy.spec.ts
    - themes/default/README.md

key-decisions:
  - "One enrolment page with both choices (authenticator app first, passkey second) instead of a separate choice form: the TOTP branch keeps working without JavaScript, existing pages/tests/helpers that take the first form stay valid, and every route that lands on enrolment (password, email code, upstream continuation, step-up) gets the choice for free"
  - "The passkey registration state is its own field (LoginState.enroll_passkey) next to pending_totp, not an exclusive EnrollChoice enum: abandoning the passkey dialog leaves the authenticator-app QR code valid"
  - "The registration state is stored unsealed in the flow row, like the login passkey challenge and the account page's registration state (not a secret; the security property is server-side single use)"
  - "A stored in-flow passkey signs in as SessionAuth::Passkey ([hwk|swk, user, mfa], MFA acr), also after an upstream or email-code primary; a step-up upgrades the session in place ([pwd, hwk, user, mfa])"
  - "A refused registration that was actually verified is audited login_failed (method passkey_enrolment); a finish with nothing pending is not audited. Success audits passkey_registered and login_succeeded (method passkey)"
  - "No recovery codes for a passkey enrolment (they belong to the TOTP credential); passkey enrolment finishes are not rate limited (nothing is guessed; every attempt needs a fresh flow-bound challenge)"

requirements-completed: []

duration: about 1h 30min
completed: 2026-11-26
---

# Phase 5 Plan 11: In-flow Passkey Enrolment under MFA `required` Summary

**Under MFA policy `required`, a user without a second factor now picks an authenticator app or a passkey on the enrolment page. A passkey registered there is stored, audited `passkey_registered`, and signs the user in with `amr [hwk|swk, user, mfa]` and the MFA `acr`. A step-up session is upgraded in place. Abandoned, replayed, cross-flow and never-requested registration challenges are refused, and the user stays on the enrolment step.**

Traceability: this carry-over is filed under AUTH-14 but does not deliver it (05-19/05-23 do). No requirement was marked complete.

## Routes and selectors (for e2e and themes)

| Route | Notes |
|---|---|
| `POST /ui/login/enroll/passkey/start?flow=` | `csrf_token` + flow cookie. Returns creation options as JSON (`no-store`), excluding the user's existing passkeys. Errors as JSON `{"error"}`: 403 `csrf`, 400 `mfa_enroll.passkey_failed` (wrong step or expired flow), 500 |
| `POST /ui/login/enroll/passkey/finish?flow=` | `csrf_token`, `factor_token` (handed back to the re-rendered page), `response`. Success: 303 continue or the signed-in page. Refusal: 400 enrolment page |

Enrolment page selectors:
- Authenticator app (the page's first form, unchanged): section `mfa-enroll-totp`, `totp-qr`, `totp-secret`, form `mfa-enroll`, input `code`, button `mfa-enroll-submit`.
- Passkey: section `mfa-enroll-passkey`, form `mfa-enroll-passkey-form` (`data-webauthn="register"`), button `mfa-enroll-passkey-submit` (hidden until webauthn.js runs), status `mfa-enroll-passkey-status`, messages `mfa-enroll-passkey-msg-N`, noscript note `mfa-enroll-passkey-nojs`.

New keys (en and de): `mfa_enroll.{passkey_heading, passkey_help, passkey_button, passkey_nojs, passkey_failed, totp_heading}`, `mfa_enroll.webauthn.{cancelled, failed}`. `mfa_enroll.required` now names both choices.

## Negative tests (security map)

`crates/anvil-web/tests/flow_mfa_policy.rs`:
- `a_replayed_passkey_enrolment_challenge_is_refused`: a failed finish uses up the challenge, so the valid response for it is refused. The TOTP choice still completes afterwards. A replay after sign-in signs nobody in.
- `a_successful_passkey_enrolment_cannot_be_replayed`: the same POST again, with or without the session, is refused. Exactly one passkey and one `passkey_registered` event.
- `an_abandoned_passkey_enrolment_challenge_is_refused`: a response for a superseded challenge is refused, and only a fresh ceremony succeeds.
- `a_passkey_enrolment_challenge_from_another_flow_is_refused`: flow A's response posted to flow B is refused.
- `a_passkey_finish_without_a_pending_challenge_is_refused`: the user went the authenticator-app way. A registration for a challenge this flow never issued is refused, and TOTP still works.
- `passkey_enrolment_routes_are_bound_to_the_flow_and_its_enrolment_step`: no CSRF token, a wrong one, or no flow cookie gives 403 on both routes. A login flow at the identify step gets 400, with nothing stored.
- `optional_and_off_never_show_the_enrolment_choice`

Positive tests: `required_enrolment_offers_a_passkey_and_an_authenticator_app` (markup, order, CSP), `passkey_enrolment_signs_in_with_passkey_amr_and_stores_the_passkey` (also signs in again with the new passkey), `passkey_enrolment_continues_the_authorization_request`, `step_up_into_enrolment_can_be_satisfied_with_a_passkey_in_place`.

Unit tests in `flow::login`: `passkey_enrolment_is_offered_only_in_the_enrolment_step`, `passkey_enrolment_challenge_is_taken_out_once`, `a_fresh_enrolment_drops_an_earlier_passkey_challenge`, `passkey_enrolment_signs_in_as_a_passkey_or_upgrades_the_step_up_session`, `enrolment_state_with_a_passkey_challenge_round_trips_and_old_json_decodes`.

## Task Commits

1. **Task 1 (engine, service, routes, template, locales, integration tests):** `665aa92` feat(05-11): passkey as an enrolment choice under MFA policy required
2. **Task 2 (e2e):** `33599f1` test(05-11): e2e passkey enrolment under MFA policy required
3. Deferred item: `abebbd7` docs(05): deferred items: passkey as second factor after a password (05-11)

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test flow_mfa_policy`: 20 passed (11 new).
- `cargo test -p anvil-web --test flow_passkey --test flow_mfa --test i18n_catalogs`: pass (en/de parity green).
- `cargo test -p anvil-core --lib flow::login`: 29 passed. `service::flow`: 16 passed.
- Regressions pass: `i18n`, `render` (snapshots unchanged), `flow_email_code`, `upstream_login`, `authorize_step_up`, `security_csp`, `account_security`, `flow_login`, `security_csrf`, `theme`, `security_theme`.
- Clippy `-D warnings`: clean for anvil-core (lib + tests) and for the anvil-web lib + `flow_mfa_policy`. `rustfmt --edition 2024` was run on the touched Rust files.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- **e2e run locally without Docker:** the debug `anvilid` was copied to a scratch dir with a fresh data dir and run with the run.sh flags (no Mailpit; these specs send no email). `specs/mfa-policy.spec.ts` passed 4/4, including the new virtual-authenticator test and its axe check on the enrolment page. `specs/passkey.spec.ts` (6) and `specs/i18n.spec.ts` (6) also passed. The scratch dir was deleted afterwards.

## Not run

- `ANVILID_TEST_DB=postgres` for `flow_mfa_policy`: Docker is not used. No SQL was added; the plan uses the existing `swap_state`, `passkeys`, `create_passkey` and session intents.
- `tests/e2e/run.sh sqlite|postgres` itself (it needs Docker for Mailpit/Postgres). The local run above covers the SQLite browser journey; CI runs both backends.
- Full-workspace test run (other wave-2 plans had work in progress in the tree).

## Deviations from Plan

### Design changes (documented, no Rule 4 needed)

**1. No separate choice form or exclusive `EnrollChoice` enum**
- The plan sketched `EnrollChoice { Totp(pending_totp), Passkey(sealed state) }`. Instead the enrolment page shows both choices, and the passkey registration state is its own field, `LoginState.enroll_passkey`, next to `pending_totp`.
- Why: if the passkey dialog is cancelled, the authenticator-app secret the user may already have scanned stays valid. Old flow JSON still decodes. Every path that lands on enrolment (password, email code, upstream continuation, step-up) gets the choice without its own change.
- "Finish after choosing TOTP" still fails: no registration is pending, so the finish is refused. After a TOTP sign-in the flow no longer exists.

**2. Registration state not sealed**
- It is stored like the existing login passkey challenge and the account page's registration state. It is not a secret; what protects it is server-side single use (compare-and-swap).

**3. No engine input/effect variants**
- `flow/engine.rs` is not in this plan's files. Like `passkey_options`, the ceremony runs in dedicated `FlowService` methods, with pure helpers in `flow/login.rs`. Only the terminal `CreateSession`/`UpgradeSession` goes through the existing effect runner, so the session switch, link confirmation, audit and step-up checks are not duplicated.

**4. Section order: authenticator app first**
- With the passkey section first, the test helpers that post "the page's first form" (`form_action`) broke. The authenticator-app form stays first; the passkey section follows it.

**5. e2e "second sign-in uses the passkey as second factor"**
- The second sign-in uses the enrolled passkey from the sign-in page (usernameless), which satisfies `required` on its own (acr mfa).
- A password sign-in by a passkey-only user is sent back to enrolment, because the second-factor step accepts only TOTP and recovery codes. Recorded in `deferred-items.md` with a proposed follow-up.

### Auto-fixed Issues

**1. [Rule 1 - Lint] `clippy::result_large_err` on `take_passkey_enrolment`**
- It now takes `&mut LoginState` and returns `Option<(UserId, String)>`. Commit 665aa92.

### Forced extras (outside files_modified)
- `crates/anvil-web/tests/passkey_support/mod.rs` (new): the software authenticator, so the new tests don't add another inline copy. `flow_passkey.rs` and `passkey_adapter.rs` still have their own copies (not this plan's files; they could switch to the module later).
- `themes/default/README.md`: the `mfa_enroll.html` row of the template-variable table now lists `passkey_enroll`.
- `.planning/phases/05-release-0-4-operate-it/deferred-items.md`: one entry.
- `themes/default/templates/totp_enroll.html` (listed in files_modified) needed no change.

## Deferred Issues
- Passkey as a second factor after a password (see deferred-items.md).
- The `PasskeyUser` construction (name = email, display name = name or email) now exists in both `service::account::begin_passkey` and `service::flow::passkey_user`. `account.rs` is not this plan's file; a later edit there can call one shared helper.

## Self-Check: PASSED
- Files exist: crates/anvil-web/tests/passkey_support/mod.rs, crates/anvil-core/src/flow/login.rs (contains `Passkey`), tests/e2e/specs/mfa-policy.spec.ts
- Commits in history: 665aa92, 33599f1, abebbd7
- key_link: the enrolment handlers in ui/login.rs call `FlowService::passkey_enrolment_options/finish`, and those call `PasskeyCeremonies::start_registration/finish_registration` (the call sits in the service, not the handler, per the layering rule)
