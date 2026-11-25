---
phase: 04-release-0-3-real-world-logins
plan: 20
subsystem: oidc-authorize
tags: [oidc-14, prompt, select_account, create, initiating-user-registration, discovery, acr]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-16: decide(.., MfaContext), SessionDecision::StepUp, session switch via revoke_with_families, login_hint prefill; 04-13: flow-bound confirmation page pattern; 03-17 consent screen (ConsentState::for_apps, check_binding); ui/registration.rs ?request= resume"
provides:
  - "oauth::authorize_request::{PROMPT_VALUES, PROMPT_CREATE, supported_prompt_values}; validate(raw, client, registration)"
  - "oauth::decision::SessionDecision::SelectAccount; create needs a sign-in during the request (like login)"
  - "service::authorize: AuthorizeOutcome::{SelectAccount, Register}; AccountChoice, AccountChoiceBinding, SelectAccountPage, SelectAccountStart; AuthorizeService::{start_select_account, choose_account}"
  - "GET/POST /ui/select-account?request= (select_account.html, locales/en/select_account.ftl)"
  - "Discovery: per-tenant prompt_values_supported, acr_values_supported [pwd, mfa]"
affects: [04-23, 04-24, 04-gate, docs]

tech-stack:
  added: []
  patterns:
    - "One list of prompt values (supported_prompt_values) feeds both validation and discovery, so what is advertised is exactly what /authorize accepts"
    - "Each continuation stage drops the prompt values it already answered (Stage::prompt): select_account after the chooser, select_account + consent after the consent screen"

key-files:
  created:
    - crates/anvil-web/tests/authorize_prompt.rs
    - themes/default/templates/select_account.html
    - themes/default/locales/en/select_account.ftl
  modified:
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/oauth/decision.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/protocol/authorize.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/src/ui/select_account.rs
    - crates/anvil-web/tests/discovery.rs

key-decisions:
  - "select_account shows the chooser only for a usable session signed in before the request; a sign-in during the request satisfies it (no second chooser after 'Use another account' + login). It is decided before step-up, so the chooser picks whose session is stepped up"
  - "'Use another account' does not change the stored request: it only answers to a fresh sign-in, or to a later 'Continue' on the chooser. Going back to /authorize/continue without signing in shows the chooser again"
  - "prompt=create answers Register whether or not a session exists; on resume create needs a session signed in during the request (like login), so an older session never answers a request for a new account"
  - "create is valid only for tenants with open registration (invite_only and disabled: invalid_request 'unsupported prompt value create'); create with none or select_account is invalid_request; create with login/consent is allowed"
  - "The chooser flow is a FlowKind::Consent flow in its connected-apps form (ConsentState::for_apps: user-bound, no pending consent), also bound to the request through auth_request_id. No new FlowKind (would need a migration on both backends). That state cannot approve consent (the consent screen refuses a flow without a request)"
  - "The chooser flow is used up (deleted) before the choice is applied; a re-post shows the chooser again with select_account.expired, or flow_expired when the request was already used"

requirements-completed: [OIDC-14]

duration: about 1h 30min (including about 15 min waiting for another plan's in-progress anvil-core files to compile)
completed: 2026-11-25
---

# Phase 4 Plan 20: Full prompt handling (select_account, create) Summary

**`prompt=select_account` now shows an account chooser ("Continue with this account" / "Use another account") in front of the single browser session. `prompt=create` sends the user to registration and resumes the authorization with a code once the account is signed in. Both are accepted only where they apply: `create` only for open-registration tenants, never with `none` or `select_account`. Discovery advertises the per-tenant `prompt` values and both `acr` values.**

No requirement checkbox was ticked (wave rule). `requirements-completed` lists what this plan delivers. OIDC-14 is now complete with 04-16 (step-up, `login_hint`).

## Behaviour

| Request | Result |
|---|---|
| `prompt=select_account`, session from before the request | 303 `/ui/select-account?request=` (chooser) |
| chooser "Continue" | the request continues as that user: consent and step-up still apply, never a second chooser; code for the same user |
| chooser "Use another account" | 303 `/ui/login?request=`. Signing in as Bob issues Bob's code and revokes Alice's session (04-16 session switch) |
| `prompt=select_account`, no usable session (none, `max_age` exceeded, hint mismatch) | login page, as before; after sign-in a code with no chooser |
| `prompt=none select_account` | `invalid_request` (existing none rule) |
| `prompt=create`, open tenant (with or without a session) | 303 `/ui/registration?request=`. Registering signs in and resumes to the RP with a code for the new account |
| `prompt=create`, invite_only / disabled tenant | `error=invalid_request` ("unsupported prompt value create") to the redirect URI with `state` and `iss` |
| `prompt=create none`, `create select_account` | `invalid_request` |
| `create` abandoned, `/authorize/continue` with an older session | login page (never answered by the old session) |
| chooser POST: missing/wrong CSRF, no flow id, no flow cookie, another user's flow | 403 `csrf`, nothing used up |
| chooser POST again after a choice | chooser shown again with `select_account.expired` (400), or `flow_expired` if the request was used |

When the tenant requires email verification before sign-in, a `create` request cannot resume. The RP gets no answer until the user verifies and signs in, and the stored request expires normally (documented in service/authorize.rs).

Discovery: `prompt_values_supported` = `none, login, consent, select_account` plus `create` when registration is open. `acr_values_supported` = `urn:anvilid:acr:pwd, urn:anvilid:acr:mfa`.

## Task Commits

1. **Task 1: Core prompt handling**: `d461639` feat(04-20): select_account and create prompt handling in core (this commit also includes the protocol/authorize.rs redirect mapping, see Deviations)
2. **Task 2: Chooser page, discovery, tests**: `b6926d1` feat(04-20): account chooser page, per-tenant prompt discovery and prompt tests

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 552 passed (before 04-21's in-progress files landed in the tree). New tests:
  - validation: create on open/closed tenants; create with none or select_account; select_account with none; `supported_prompt_values`
  - decision: the chooser with a session, without a usable one, after a sign-in during the request, before step-up; create's freshness
  - service: `Stage::prompt` filtering; the decision after the chooser
- `cargo test -p anvil-web --lib --test authorize_prompt --test authorize --test discovery --test consent --test authorize_step_up --test flow_registration --test i18n --test render --test security_csrf --test response_mode --test flow_login`: all pass. authorize_prompt has 18 tests (684 lines).
- `cargo clippy -p anvil-core --lib --tests -D warnings`: clean at Task 1. `cargo clippy -p anvil-web --no-deps --lib --test authorize_prompt --test discovery -D warnings`: clean.
- `rustfmt --edition 2024 --check` on every touched file: clean.

## Not run

- `ANVILID_TEST_DB=postgres` for authorize_prompt / authorize_step_up / authorize: Docker is not available, so these are left for CI. The plan adds no SQL. The chooser uses the existing flow and authorization-request ports, and FlowKind `consent` is already allowed by both schemas.
- At the end, a full clippy on anvil-core was blocked by 04-21's uncommitted files (`large_enum_variant` in flow/engine.rs, service/flow.rs, service/upstream.rs). None of those are mine.
- e2e/Playwright and conformance runs.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The protocol/authorize.rs mapping went into the Task 1 commit**
- The new `AuthorizeOutcome` variants break the exhaustive match in protocol/authorize.rs. Other plans build in the same tree, so the two redirect arms were committed with the core change to keep anvil-web compiling. Commit d461639.

**2. [Rule 3 - Blocking] crates/anvil-web/tests/discovery.rs (outside files_modified)**
- `default_tenant_discovery` asserted the old `["none","login"]` and `[ACR_PWD]`. It now expects the open-tenant list and both acr values. Commit b6926d1.

**3. [Rule 1 - Loop] Stage-aware prompt filtering**
- Without it, "Continue" followed by consent or a step-up would show the chooser again: the session still predates the request.
- `Stage::prompt` drops `select_account` after the chooser and after the consent screen.
- Step-up needs no filtering: `upgrade_auth` sets `auth_time` to now.

**4. [Design] Chooser flow binding without a new FlowKind**
- Explained under key-decisions. A dedicated `FlowKind::SelectAccount` would need a migration on both backends while other plans may add migrations. A later plan can add one if wanted.

**5. [Design] "Other" does not rewrite the stored request to prompt=login**
- The freshness rule already gives the same guarantee: only a sign-in during the request answers it. "Other" therefore changes no stored state.

**6. [Note] Core unit tests**
- There is no storage double in core for AuthorizeService (same as 04-13/04-16), so `start_select_account` and `choose_account` are covered over HTTP in authorize_prompt.rs. The pure parts have unit tests.

### Follow-ups (not done)
- docs/ARCHITECTURE.md line 478 still describes 0.1's `prompt_values_supported: ["none", "login"]`. It is a historical "built in 0.1" paragraph, but the docs pass should add the 0.3 values. themes/default/README.md should list select_account.html and its selectors.

## Self-Check: PASSED
