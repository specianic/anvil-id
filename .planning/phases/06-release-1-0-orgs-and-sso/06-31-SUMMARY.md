---
phase: 06-release-1-0-orgs-and-sso
plan: 31
subsystem: sign-in / organizations
tags: [invitations, return-to, open-redirect, kek, session, i18n, docs, gap-closure, org-02]

requires:
  - phase: 06-20
    provides: invitation pages, OrgInvitationService::accept_with_registration (RegisterOutcome::Registered { user })
  - phase: 06-28
    provides: flag-aware identify step in flow/login.rs and service/flow.rs (built on, unchanged)
  - phase: 06-29
    provides: listUserOrganizations and listUsers ?email= (documented here)
provides:
  - policy::return_to (ReturnTarget, parse_return_target): exact allowlist /ui/invitation?token=<1..128 base64url>
  - LoginState.return_to_sealed (KEK purpose anvilid/login-return-to/v1, AAD tenant id + flow id)
  - service::flow::Continue { Authorize, Return } and the one FlowService::continuation helper
  - FlowService::create_signed_in_session (shared) and FlowService::sign_in_registered_user
  - GET /ui/login?return_to=, invitation sign-in link with return_to, registration signs in
affects: [06-26 (security test map, plaintext scan)]

tech-stack:
  added: []
  patterns:
    - "Continuation read from the stored flow row (auth request first, then the sealed target), so state transitions cannot drop it"
    - "A value sealed under the flow id moves with the login: continue_login opens it under the old id and reseals under the new"

key-files:
  created:
    - crates/anvil-core/src/policy/return_to.rs
  modified:
    - crates/anvil-core/src/policy.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/invitation.rs
    - crates/anvil-web/tests/org_invitations.rs
    - themes/default/templates/invitation.html
    - themes/default/locales/en/invitation.ftl
    - themes/default/locales/de/invitation.ftl
    - themes/default/README.md
    - tests/e2e/specs/invitations.spec.ts
    - docs/ORGANIZATIONS.md
    - docs/ARCHITECTURE.md

key-decisions:
  - "The continuation is computed from the stored Flow (flow.auth_request_id, then flow.state's return_to_sealed opened under cx.tenant + flow.id), not from the post-transition state: one helper, robust against any transition that rebuilds LoginState"
  - "continue_login carries the target into the new flow (resealed under the new id); this covers the second factor or enrolment after an upstream/SAML/magic-link primary, link confirmation and restart_login_with after an upstream error. restart() after expiry (create_flow) drops it, as planned"
  - "The opened plaintext is re-validated with parse_return_target (defence in depth); a value that does not open or is not allowlisted gives None (signed-in page), never an error page"
  - "The registered page's continue link goes to /ui/account/profile: there is no /ui/account route"
  - "sign_in_registered_user ignores a current session of another tenant or a revoked one before switch_session; audit method invitation_registration"

requirements-completed: []

duration: about 1h30m
completed: 2026-11-26
---

# Phase 6 Plan 31: Invitation return-to after sign-in, sign-in after invitation registration Summary

**A signed-out invitee with an account follows the invitation's sign-in link, signs in by any method and lands back on `/ui/invitation?token=…` of the same tenant, where one click accepts. The target is an exact allowlist, stored only KEK-sealed in the login flow, and an authorization request always wins. Registering through an invitation now signs the new user in through the same session code as every sign-in. The two remaining invitation and API-gap limitations are gone from the docs.**

ORG-02 is served, not ticked (wave rule: the gate ticks REQUIREMENTS.md).

## Task Commits

1. **Task 1, core return target, continuation helper, shared session creation (plus the minimal login.rs wiring so the workspace kept compiling):** `ee9521e`
2. **Task 2, invitation page wiring, sign-in after registration, en/de strings, tests, e2e, docs:** `5732925`

TDD: tests were written with each task and run before each commit (no separate RED commit, shared tree), with mutation checks standing in for RED (below).

## What changed

- **Policy (`policy/return_to.rs`).** `parse_return_target(raw) -> Option<ReturnTarget>` accepts only `/ui/invitation?token=` followed by 1 to `MAX_TOKEN_LEN` (128, re-exported from `service::org_invitation`, one constant) characters of `[A-Za-z0-9_-]`. `ReturnTarget::as_path()`. `Debug` redacts the token.
- **Flow state.** `LoginState.return_to_sealed: Option<String>`, serde default and skipped when `None` (old rows decode).
- **Sealing.** `seal_return_target` and `return_target_of` use the same scheme as the SAML identity: `kek.seal(purpose, upstream_aad(tenant, flow), …)`, base64url. The purpose is `RETURN_TO_PURPOSE = "anvilid/login-return-to/v1"`.
- **`start_login(cx, auth_request, current, return_to)`.** The target is dropped when there is an authorization request. Otherwise `create_login_flow` seals it under the new flow id, on all three creation paths (combined form, email-first page, `login_hint`-routed form or IdP start). Step-up flows never get it.
- **`Continue { Authorize(AuthRequestId), Return(ReturnTarget) }`.** It replaces `Option<AuthRequestId>` in `FlowOutcome::SignedIn` / `SteppedUp`, `UpstreamPrimary::SignedIn` and `UpstreamOutcome::SignedIn`. Every construction site calls `FlowService::continuation(cx, flow)`: `Effect::CreateSession` (password, passkey, second factor, enrolment, email code), `upgrade_session`, and `primary_without_form` (upstream OIDC, SAML through `complete_identity`, magic link).
- **One session path.** `create_signed_in_session(cx, user, auth, backup_eligible, current, method)` runs switch_session, sessions().create, record_login and the `login_succeeded` audit. `Effect::CreateSession`, `primary_without_form` and `sign_in_registered_user` all use it. The one ordering change: the flow is deleted after the audit event instead of before it.
- **Web.** `UiQuery.return_to` and `UiQuery::return_target()`; an invalid value is ignored silently. `signed_in_response` maps `Continue::Return(t)` to a 303 to `carry_ui_locales(tenant.ui_url(t.as_path()))`, the tenant's own origin; on the recovery-codes page the same URL is the `continue_url`. `ui/upstream.rs` needed no edit, because it passes the value through.
- **Invitation page.**
  - `login_url` is `/ui/login?return_to=<percent-encoded /ui/invitation?token=…>` on the `signed_out` and `email_taken` views (`email_taken` now carries the token for this).
  - `register` calls `sign_in_registered_user`, sets the session cookie with the same builder as `signed_in_response`, wakes the logout worker, and renders `registered` with `#invitation-continue` pointing at `/ui/account/profile`.
- **Strings (en/de).**
  - `invitation-sign_in_hint` and `invitation-email_taken` now say "Sign in to continue; you will come back here."
  - `invitation-registered` now says "… You are signed in."
  - `invitation-continue` is new: "Continue" / "Weiter".
- **Docs.**
  - ORGANIZATIONS.md: the Invitations section describes the return after sign-in and the sign-in after registration; Members documents the two 06-29 lookups with their scopes; both limitation bullets are removed.
  - ARCHITECTURE.md: the M5 open item is dropped; §10.2 lists `GET /ui/login?return_to=` and the registration sign-in; §10.3 lists the two 06-29 endpoints (123 operations).
  - The theme README and the login.rs / invitation.rs module docs are updated.

## For the 06-26 security map

Negative tests (file::fn):
- `org_invitations::return_to_rejects_open_redirects`: 23 values, each URL-encoded into `/ui/login?return_to=`. Every one stores nothing in the flow and ends on the signed-in page with no `Location`. They cover:
  - an absolute URL, `//host`, backslashes, `javascript:`;
  - a foreign path (`/ui/account`, `/ui/invitation/register`), `/UI/…`, `..`;
  - extra or leading parameters, a fragment, `%2F`;
  - `+`, `/`, `=`, a space, CR/LF header injection and non-ASCII in the token;
  - an empty token and a 129-character token.
- `org_invitations::return_to_tampered_or_moved_sealed_value_is_ignored`: a sealed value copied from another login flow, and the same value with one character changed. Both end on the signed-in page.
- `org_invitations::return_to_ignored_with_authorization_request`: nothing is sealed, and the sign-in continues the authorization request.
- `org_invitations::return_to_token_not_stored_in_plaintext`: neither the flow row nor the page contains the token or `/ui/invitation`.
- `org_invitations::invitation_registration_failures_set_no_session`: no session cookie for any of email_taken (whose sign-in link carries `return_to`), a short password, a forged CSRF token, registration disabled, or an expired invitation.
- `org_invitations::invitation_registration_replaces_other_users_session`: B's session is revoked, and the account is the invited address.
- Unit tests:
  - `policy::return_to::tests::rejects_everything_else` (37 values);
  - `policy::return_to::tests::debug_redacts_the_token`;
  - `service::flow::tests::return_target_does_not_open_elsewhere_or_tampered` (another flow id, tenant or KEK; a flipped byte; garbage; empty; a sealed non-allowlisted URL; a non-login state);
  - `service::flow::tests::return_target_is_sealed_never_plaintext`;
  - `service::flow::tests::continuation_prefers_the_authorization_request`.

Positive tests:
- `invitation_sign_in_returns_to_invitation`, which also asserts `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on the login page.
- `invitation_sign_in_with_second_factor_returns_to_invitation` (TOTP).
- `invitation_sso_sign_in_returns_to_invitation`: the upstream button, once directly and once with TOTP. The second run proves the target is resealed into the new flow.
- `invitation_registration_signs_in`: amr `["pwd"]`; the profile page opens; one `login_succeeded` with method `invitation_registration`.
- `flow::login::tests::return_to_sealed_is_optional_and_survives_the_steps`, `policy::return_to::tests::accepts_invitation_paths_with_a_base64url_token`.

**New sealed value in flow state, for the 06-26 plaintext scan:** `LoginState.return_to_sealed` (login flow JSON key `return_to_sealed`), KEK purpose `anvilid/login-return-to/v1`, AAD `tenant_id ‖ flow_id`. Its plaintext is `/ui/invitation?token=<invitation token>`.

## Mutation checks (guard disabled, then restored; `git diff` empty afterwards)

| Guard disabled | Test that failed |
|---|---|
| allowlist (`parse_return_target` accepts anything) | `return_to_rejects_open_redirects` |
| request wins (target kept with a request, continuation prefers the target) | `return_to_ignored_with_authorization_request` |

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 1007 passed.
- `cargo test -p anvil-web` with:
  - the plan's list (`--test org_invitations` (25), `flow_login`, `flow_mfa`, `flow_passkey`, `enterprise_oidc`, `saml_login`, `hrd_login`, `upstream_login`, `i18n_catalogs`, `i18n`, `render`, `theme`): all passed;
  - also `security_csrf`, `flow_registration`, `flow_email_code`, `security_linking`, `flow_login_factors`, `authorize_step_up` and `--lib invitation`: all passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- The plan's greps pass: `invitation-continue` is in de; the ORGANIZATIONS / ARCHITECTURE phrases are gone.
- `scripts/check-release-graph.sh`: OK.
- `rustfmt --edition 2024` was run on the touched Rust files only.

## Not run

- e2e `invitations.spec.ts` (both journeys), `login.spec.ts`, `hrd.spec.ts`, `saml.spec.ts`: they need Docker (Mailpit). The specs are type-checked only and left for CI on both backends.
- Postgres runs (`ANVILID_TEST_DB=postgres`, `just test-pg`): Docker, so CI. No storage or schema change in this plan (the new field is flow JSON).
- `cargo test --workspace` as one run. I ran targeted suites instead (wave rule).
- The passkey and email-code/magic-link sign-ins were not driven through the return-to in integration tests. They reach the same `Effect::CreateSession` / `primary_without_form` sites, which take the target from the one `continuation` helper; the unit tests prove that helper.

## Deviations from Plan

1. **[Rule 3] `policy/mod.rs` does not exist.** The module root is `crates/anvil-core/src/policy.rs`, so `pub mod return_to;` was added there.
2. **[Rule 3] The login.rs wiring went into the Task 1 commit.** Changing the core types broke the anvil-web build, and the orchestrator was testing the same tree at that moment, so the `UiQuery.return_to` / `signed_in_response(Continue)` wiring was committed with Task 1. The module doc followed in Task 2.
3. **No debug log on a failed open.** anvil-core has no `tracing` dependency, and Cargo manifests are single-owner. A failed open silently gives `None`; the value is never logged anyway.
4. **`continuation(cx, flow)` instead of `(flow, state)`.** It reads the stored flow row (see key decisions).
5. **The continue link goes to `/ui/account/profile`, not `/ui/account`.** The plan named `/ui/account`, which has no route (404). The e2e step waits for `form#profile-form`.
6. **The SSO test uses the tenant connection's upstream button.** The plan allowed either; org connections reach the same `primary_without_form`, and the test's second half also covers the reseal path.
7. **Added test** `return_to_tampered_or_moved_sealed_value_is_ignored`. The orchestrator asked for a tampered sealed value as an integration negative.
8. `ui/upstream.rs` (in files_modified) needed no change.

## Self-Check: PASSED
