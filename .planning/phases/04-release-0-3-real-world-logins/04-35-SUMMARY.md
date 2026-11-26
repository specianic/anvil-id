---
phase: 04-release-0-3-real-world-logins
plan: 35
subsystem: auth
tags: [email-otp, magic-link, email-templates, gap-closure, auth-06]
requires:
  - phase: 04-15
    provides: login_code template contract and default templates
  - phase: 04-24
    provides: email code / magic link login method, routes and pages
  - phase: 04-30
    provides: German catalogs and the catalog parity test
provides:
  - "anvil_mail::check::{optional_variables, sample_variants}: login_code `code`? and `link`? (at least one present)"
  - "EmailCodeState.{code, link} (what the email carried), EmailCodeState::with_methods, flow::email_code::form_for, sent_form(&EmailCodeState)"
  - "Per-toggle route guards and core refusal; link-only 'check your email' page (`link-hint`)"
affects: [04-32, 04-37]
tech-stack:
  added: []
  patterns:
    - "A template variable can be optional: the checker renders every override against one sample per optional variable (the others removed); templates guard with `is defined`"
key-files:
  created: []
  modified:
    - crates/anvil-mail/src/check.rs
    - crates/anvil-mail/src/render.rs
    - crates/anvil-mail/tests/templates.rs
    - themes/default/emails/login_code.txt
    - themes/default/emails/login_code.html
    - crates/anvil-web/tests/admin_api_v02.rs
    - crates/anvil-core/src/flow/email_code.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/src/ui/email_code.rs
    - themes/default/templates/email_code.html
    - themes/default/locales/en/email_code.ftl
    - themes/default/locales/de/email_code.ftl
    - crates/anvil-web/tests/email_code_support/mod.rs
    - crates/anvil-web/tests/flow_email_code.rs
    - crates/anvil-web/tests/security_email_code.rs
key-decisions:
  - "email_code_enabled keeps meaning 'email sign-in is offered' (either toggle); each method is enforced on its own at the route and in core"
  - "The send does the same work in every configuration (code, link token, both hashes); only the email payload differs, so timing does not reveal the configuration"
  - "The state records what the email carried: a method switched on after the send still cannot use that email (core refuses), a method switched off after the send is 404 at the route"
  - "A refused code is CoreError::NotFound (404) before any attempt is counted; a refused link is Rejected(link_invalid) (400) or 404 at the route, and consumes nothing"
  - "EmailRenderer::render_with refuses a login_code payload with neither code nor link (an email that signs nobody in)"
requirements-completed: [AUTH-06]
duration: about 1h 15min (including ~20 min waiting for concurrent plans' build breaks)
completed: 2026-11-26
---

# Phase 4 Plan 35: Independent email_otp and magic_link Summary

**`email_otp` now means the 6-digit code and `magic_link` means the link. The `login_code` email, the "check your email" page and the accepted inputs follow whichever is enabled: code only, link only, or both. Tenant template overrides that print `{{ code }}` or `{{ link }}` without a guard are refused on save.**

Note: no requirement checkbox was ticked (wave rule). `requirements-completed` records the scope only.

## Template contract (doc facts for 04-37: theme README email table, ARCHITECTURE §9.3)

- `login_code`: `tenant_name`, `code`?, `link`?, `expires_minutes`. `?` means optional; at least one of `code`/`link` is always present. The email carries `code` when `email_otp` is on and `link` when `magic_link` is on.
- `variables(kind)` and the admin API `variables` list are unchanged (code and link stay allowed). The optionality is a checker and docs concern only: no API/OpenAPI change.
- The checker (`TemplateChecker::check`) renders each part against `sample_variants(kind)`: the full sample, then for login_code a code-only sample and a link-only sample. The first failure wins, with the usual `subject: ` / `body_text: ` / `body_html: ` prefix. An unguarded optional variable gives "`code` is optional and absent from some emails; guard it with `{% if code is defined %}…{% endif %}`", with the line number.
- Rendering stays strict. A bare `{% if code %}` is also rejected when `code` is absent (tested). Templates must use `{% if code is defined %}`.
- The shipped default subject is "Your {tenant} sign-in code" when there is a code, otherwise "Your {tenant} sign-in link". Code-only emails never mention a link or button, and link-only emails never mention a code. The expiry sentence fits each shape.
- ARCHITECTURE line ~646 ("In 0.3 either setting enables the method, and the login_code email always carries both") and theme README line ~374 ("The login_code email carries both the code and the ...") are now out of date. 04-37 should reword them: either setting offers email sign-in, and each setting controls its own method in the email, at the route and in core.

## Routes

| Route | 404 unless |
|---|---|
| `POST /ui/login/email-code` (send, "Send a new email") | `email_otp` or `magic_link` |
| `POST /ui/login/email-code/verify` | `email_otp` (core also needs the email to have carried a code) |
| `GET` and `POST /ui/login/email-link` | `magic_link` (core also needs the email to have carried a link, otherwise 400 `email_code.link_invalid`) |

## Page and catalogs

- In link-only mode, `email_code.html` leaves out `code-hint`, `#code` and `#email-code-submit`, and shows `<p id="link-hint">` (`email_code.link_hint`). The `email-code` form (csrf, factor_token), the resend form `email-code-resend` and `link-login` stay. The page reads `form.fields` to decide: the core form has no `code` field when the email had none.
- New key: `email_code-link_hint`.
- Reworded to fit both methods (en + de): `request_toggle` ("Sign in with email"), `request` ("Email me a way to sign in"), `request_hint`, `sent` ("...we sent a sign-in email to it..."), `code_hint` (no longer mentions the link), `resend` ("Send a new email"), `expired`, `invalidated`, `too_many_sends`, `link_invalid`. No snapshot contained these strings. `other_browser` is unchanged because `email-code.spec.ts` matches "type the code".

## Tests (for 04-32's map)

- anvil-mail `tests/templates.rs`:
  - `login_code_optional_variables_and_variants`
  - `login_code_unguarded_code_is_rejected`
  - `login_code_unguarded_link_is_rejected`
  - `login_code_bare_if_is_rejected_because_rendering_is_strict`
  - `login_code_guarded_template_passes`
  - `login_code_default_renders_every_payload_shape`
  - `phase4_missing_variable_fails_rendering`: now also covers a payload with neither code nor link
  - `every_kind_accepts_a_template_using_all_its_variables`: optional variables are guarded
- anvil-web `admin_api_v02::email_templates_default_override_validation_and_reset`: unguarded login_code override returns 422 with field `body_text` (line 2) or `body_html`; the default saves unchanged.
- anvil-core `flow::email_code` unit tests:
  - `code_is_refused_when_the_email_carried_none`
  - `link_is_refused_when_the_email_carried_none`
  - `state_without_method_flags_parses_as_both`
  - `link_only_form_has_no_code_field`
- anvil-web `flow_email_code`:
  - `code_only_tenant_emails_only_the_code_and_the_code_signs_in`
  - `link_only_tenant_emails_only_the_link_and_the_link_signs_in`
  - `both_methods_email_the_code_and_the_link`
- anvil-web `security_email_code`:
  - `code_only_tenant_refuses_the_link_routes`
  - `link_only_tenant_refuses_the_code_route`
  - `a_method_switched_off_after_the_send_is_refused`
  - `core_refuses_a_code_the_email_did_not_carry`
  - `core_refuses_a_link_the_email_did_not_carry`
- `email_code_support`:
  - `enable(app, on)` now sets both toggles. It used to set `email_otp` only, and the magic-link tests passed only because either toggle enabled both.
  - New `set_email_methods(app, code, link)`.
  - `LoginCode` has the raw `payload`; `code`/`link` are empty when absent.

## Task Commits

1. `2033d12` feat(04-35): optional code and link in the login_code template contract
2. `3de99ab` feat(04-35): email_otp and magic_link enforced separately

## Verification (main tree, SQLite)

- `cargo test -p anvil-mail`: all pass (templates 21).
- `cargo test -p anvil-core --lib`: 583 pass (`flow::email_code` 16).
- `cargo test -p anvil-web` passed for each of these:
  - `admin_api_v02` (9)
  - `admin_api_v03` (4)
  - `flow_email_code` (8)
  - `security_email_code` (21)
  - `i18n` (18)
  - `i18n_catalogs` (4)
  - `render` (13)
  - `flow_login` (9)
  - `security_enumeration` (2)
  - `account_linked` (14)
- Clippy with `-D warnings` is clean on anvil-mail all targets, anvil-core all targets, and anvil-web lib + `flow_email_code`, `security_email_code`, `admin_api_v02`. A full `--all-targets` run of anvil-web hit another plan's in-progress `backchannel_wake.rs`, which is missing `issuer`.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean. No e2e spec change was needed: the e2e email tenant enables both toggles, specs use test ids, and the subject still matches /sign-in code/.
- The grep for `email_otp || magic_link` in service/flow.rs finds only `email_code_enabled`.

## Not run

- Postgres (`ANVILID_TEST_DB=postgres`) and e2e/Playwright (Docker). There are no SQL changes.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Forced extra edit: `crates/anvil-core/src/flow/login.rs` (2 lines)**
- `current_form` and `on_failure` for `LoginStep::EmailCode` build the "check your email" form, so they now call `email_code::form_for(state.email_code.as_deref(), …)` and the link-only page has no code field after a failure. Neither 04-36 nor anyone else had touched this file in this wave (04-36 owns `ui/login.rs`). `engine.rs` was not touched.
- Commit: 3de99ab

**2. [Rule 2 - Missing critical] render_with refuses a login_code payload with neither code nor link**
- With guarded defaults, an empty payload would render a valid-looking email that signs nobody in. The renderer now errors instead. `render.rs` was in the plan's files.
- Commit: 2033d12

**3. [Rule 1 - Bug] Test helper `enable()` enabled only `email_otp`**
- The existing magic-link tests depended on the bug being fixed here. `enable(on)` now sets both toggles, which matches "both on: today's behaviour".
- Commit: 3de99ab

**4. [Scope] Extra catalog rewording**
- `code_hint`, `invalidated`, `too_many_sends` and `link_invalid` were also reworded so they fit both methods and match the renamed "Send a new email" button. The German catalog mirrors every change.

## Self-Check: PASSED
- FOUND: commits 2033d12, 3de99ab
- FOUND: all modified files listed above
