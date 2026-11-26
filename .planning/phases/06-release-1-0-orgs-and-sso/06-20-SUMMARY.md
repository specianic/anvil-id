---
phase: 06-release-1-0-orgs-and-sso
plan: 20
subsystem: organizations
tags: [organizations, invitations, email, domain-verification, jobs, csrf, i18n, org-02, org-04]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-04 accept_invitation / accept_invitation_with_new_user intents, due_for_recheck / record_check / unverify; 06-07/06-08 single-transaction accepts; 06-10 check_domain; 06-12 OrgInvitationService::create and the sealed org_invitation email"
provides:
  - "org_invitation email template contract and default templates (TRANSITIONAL(06-20) removed)"
  - "OrgInvitationService::{preview, accept, accept_with_registration}"
  - "GET/POST /ui/invitation, POST /ui/invitation/register (themes/default/templates/invitation.html, invitation.ftl en/de)"
  - "DomainRecheckService::recheck_due and the leased daily job domain_recheck"
affects: [06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "Browser-bound CSRF without a flow: a random nonce in an HttpOnly SameSite=Strict cookie, the form carries HMAC(KEK-derived key, tenant || nonce || token)"
    - "One template with a `view` variable for every outcome of a page, each with a stable data-message-key"

key-files:
  created:
    - themes/default/emails/org_invitation.html
    - themes/default/emails/org_invitation.txt
    - themes/default/templates/invitation.html
    - themes/default/locales/en/invitation.ftl
    - themes/default/locales/de/invitation.ftl
    - crates/anvil-web/tests/org_invitations.rs
  modified:
    - crates/anvil-mail/src/check.rs
    - crates/anvil-mail/src/render.rs
    - crates/anvil-mail/tests/templates.rs
    - crates/anvil-core/src/service/org_invitation.rs
    - crates/anvil-core/src/service/domain_recheck.rs
    - crates/anvil-web/src/ui/invitation.rs
    - crates/anvil-web/src/admin/email.rs
    - crates/anvil-web/tests/admin_api_v02.rs
    - crates/anvilid/src/jobs.rs
    - crates/anvilid/src/main.rs
    - crates/anvilid/tests/jobs.rs

key-decisions:
  - "has_contract/no_contract_message are removed: every email kind has a contract, so the admin email-template API now lists and serves org_invitation"
  - "Acceptance audits org_invitation_accepted (target invitation) and org_member_added (target user, so the organization.member_added webhook fires, as JIT does); registration also audits user_registered"
  - "An unverified account is told to confirm its email only if it is the invited address; any other account gets the wrong-account page"
  - "Registering through an invitation does not sign in; the page links to sign-in. The signed-out sign-in path is: sign in, then open the link again (login.rs/flow.rs are not ours, and they have no return-to)"
  - "Re-check cutoff is 23 h (not 24 h) so the start jitter of the daily run never pushes a domain to the next day; a run loops over batches of 200 (at most 50 batches)"
  - "JobsConfig gains domain_txt (main.rs passes AppState::domain_txt_arc), so the job uses the same resolver configuration as verification"

requirements-completed: []

duration: ~50min
completed: 2026-11-26
---

# Phase 6 Plan 20: Invitation acceptance and the daily domain re-check Summary

**Invited users can now open the emailed link, see the organization name and accept. The token is used up only by a POST bound to the browser, and only for a signed-in account whose verified email is the invited address, or for a new account registered for that address. Every invalid token gets one identical page. Separately, verified domains are re-checked daily and drop back to pending after 7 days of failed checks; that change is audited and sent as a webhook.**

ORG-02 (invitations) and ORG-04 (re-validation) are implemented here. Nothing is ticked: the gate (06-26) ticks REQUIREMENTS.md.

## Performance

- **Duration:** about 50 min
- **Tasks:** 2/2
- **Files:** 6 created, 11 modified

## Task Commits

1. **Task 1, email contract, acceptance service, pages and tests:** `aaffb4a` (feat)
2. **Task 2, daily domain re-check job and tests:** `6c18b46` (feat)

## `org_invitation` template contract

| Kind | Variables |
|---|---|
| `org_invitation` | `tenant_name`, `org_name`, `inviter`, `email`, `link`, `expires_in` |

- `inviter` is a display string: the inviting org admin's address, or the tenant's name when a tenant administrator sent it.
- The default templates (`themes/default/emails/org_invitation.{txt,html}`) use every variable, and they pass their own `TemplateChecker` check, so saving the default unchanged as an override works.
- Tenant overrides are compile-checked like every other kind: unknown variables, fuel limit and strict rendering.
- The admin email-template API lists the kind (9 kinds now) and serves `GET/PUT/DELETE …/email-templates/org_invitation`.

## Routes (crates/anvil-web/src/ui/invitation.rs)

| Route | Behaviour |
|---|---|
| `GET /ui/invitation?token=` | open invitation: org name and an accept button, sets the CSRF nonce cookie. Reads only |
| `POST /ui/invitation` | signed in: accept (`accepted`, `wrong_account`, `verify_email`, `already_member`, `invalid`). Signed out: the sign-in link and the registration form |
| `POST /ui/invitation/register` | `password`, optional `name`: new verified user + membership in one intent (`registered`, `email_taken`, password error 400, 403 under `disabled`, `invalid`) |

- Every response has `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. The page keeps the default CSP and needs no JavaScript.
- CSRF: the GET sets `__Host-anvil_invitation` (no prefix on http), with HttpOnly, SameSite=Strict and a 1 h lifetime. The form carries `HMAC(kek.derive_key("anvilid/invitation-csrf/v1"), tenant ‖ len ‖ nonce ‖ token)`. An existing nonce is reused, so several invitation tabs stay valid. All of this sits in front of the Fetch-Metadata layer.
- The invited address on the signed-out form comes from the invitation. It is shown read-only and is never a form field; a posted `email` is ignored.
- Status codes: invalid gives 400 (identical body for every invalid token), CSRF failure gives 403, password refused gives 400, registration disabled gives 403, overloaded gives 503, and everything else gives 200.

### Stable selectors (invitation.html)

- **Message:** `#invitation-message`, whose `data-message-key` is `invitation.{offer|invalid|signed_out|wrong_account|verify_email|already_member|accepted|registered|email_taken}`.
- **Accept:** form `#invitation-accept`, button `#invitation-accept-submit`.
- **Register:** form `#invitation-register-form`, inputs `#invitation-email` (read-only), `#password`, `#name`, button `#invitation-register-submit`, and `#invitation-password-error` (`data-message-key` `password.too_short|too_long|breached` or `service.overloaded`).
- **Links:** `#invitation-sign-in`, `#invitation-sign-out`, `#invitation-registration-disabled`, `#invitation-sign-in-hint`.

New en/de strings are in `themes/default/locales/{en,de}/invitation.ftl` (22 keys each).

## Core (crates/anvil-core/src/service/)

- **`OrgInvitationService::preview(tenant, token) -> Option<InvitationPreview { org_name, email }>`.** It reads only, and returns a value only for an open invitation (not accepted, not revoked, `expires_at > now`) whose org exists.
- **`accept(tenant, token, user, ctx) -> AcceptOutcome`.** Order of checks:
  1. the token is hashed (at most 128 characters) and must be open, else `Invalid`;
  2. the user must exist and be active, else `WrongAccount`;
  3. an unverified email gets `VerifyEmailFirst` when it equals the invited address, `WrongAccount` otherwise;
  4. `OrgRepo::accept_invitation(…, verified email, now)` then maps `Accepted`, `Invalid`, `EmailMismatch` (to `WrongAccount`) and `AlreadyMember`.
- **`accept_with_registration(tenant, token, password, name, &RegistrationChecks { policy, hasher, breach }, ctx) -> RegisterOutcome`.** Order of checks:
  1. the token must be open, else `Invalid`;
  2. registration mode `disabled` gives `RegistrationDisabled`;
  3. the password policy (the self-registration keys);
  4. the breach check;
  5. the hash;
  6. `accept_invitation_with_new_user` with `email_verified = true` and the invitation's address; a `Conflict` gives `EmailTaken`.
- **`DomainRecheckService { storage, clock, lookup }::recheck_due(limit) -> RecheckReport`.**
  - It re-checks claims returned by `due_for_recheck(now - 23h, limit)`, in batches.
  - The check is `check_domain` followed by `record_check`.
  - Once `failing_since` is at least `DOMAIN_RECHECK_GRACE` old, it calls `unverify`, then audits `org_domain_unverified` (actor system, target the domain id, org and domain in the details).
  - Per-claim storage errors go into `report.failures`, and the walk continues.

## Job (crates/anvilid/src/jobs.rs)

- `DomainRecheckJob` has lease name `domain_recheck` and runs on `JobIntervals::domain_recheck` (default 24 h, `RECHECK_INTERVAL`). Like every periodic job, it is leased through `LeaseRunner` and spawned by `spawn_periodic`.
- The re-validation frequency is documented in the job's doc comment and in the core module docs. The user docs are 06-25's.
- `spawn_periodic` gains a `domain_txt` argument, and `JobsConfig` gains `domain_txt`.

## Tests

**crates/anvil-web/tests/org_invitations.rs (15, SQLite):**
- `org_invitation_email_renders`: created through the admin API; the payload is sealed at rest; the outbox worker delivers to a capturing transport; the link opens the offer page.
- `invitation_get_consumes_nothing`, `invitation_accept_signed_in_matching_verified_email` (roles, audit, second use gets the invalid page), `invitation_accept_concurrent_posts_one_winner` (8 parallel POSTs: 1 accepted, 7 invalid, one audit event).
- `invitation_accept_wrong_account_keeps_token` (neither address in the page), `invitation_unverified_email_account_cannot_accept`, `invitation_already_member_keeps_token`.
- Registration: `invitation_signed_out_registration_creates_verified_user_and_membership`, `invitation_registration_allowed_under_invite_only`, `invitation_registration_refused_when_registration_disabled`, `invitation_registration_existing_email_offers_sign_in`, `invitation_registration_password_policy_applies`, `invitation_registration_breached_password_refused`.
- `invitation_invalid_tokens_share_one_page`: unknown, used, revoked, expired and another tenant's token. GETs and CSRF-valid POSTs return the same status and body.
- `invitation_page_csrf_required`: no token, a forged token, another invitation's token, no nonce cookie and a cross-site request all get 403, and nothing is consumed.

**crates/anvilid/tests/jobs.rs (+4, real SQLite, `FakeTxt` defined in the file):**
- `recheck_keeps_passing_domain`, `recheck_failure_starts_streak_without_unverifying` (routing kept; 6 more daily failures keep the streak start), `recheck_unverifies_after_grace` (pending, routing off, audited, one webhook delivery to a subscribed endpoint), `recheck_job_is_leased`.
- The existing production-jobs test now also schedules the re-check and checks that its lease is released.

**Other:**
- anvil-mail: `org_invitation_renders_from_defaults_and_overrides` (lib); `every_kind_has_a_contract_and_default_templates_that_pass_the_check` and `org_invitation_contract_is_exact` (tests/templates.rs).
- Unit tests: `presented_tokens_are_bounded`, `password_problems_use_the_registration_keys`, `the_cutoff_is_under_the_interval_and_the_grace_is_a_week`, `views_have_distinct_message_keys_and_one_invalid_status`.

**Negative test names for scripts/check-security-tests.sh (gate 06-26):**
- `invitation_get_consumes_nothing`
- `invitation_accept_concurrent_posts_one_winner`
- `invitation_accept_wrong_account_keeps_token`
- `invitation_unverified_email_account_cannot_accept`
- `invitation_registration_refused_when_registration_disabled`
- `invitation_registration_existing_email_offers_sign_in`
- `invitation_registration_password_policy_applies`
- `invitation_registration_breached_password_refused`
- `invitation_invalid_tokens_share_one_page`
- `invitation_page_csrf_required`
- `recheck_failure_starts_streak_without_unverifying`

### Mutation checks (guard disabled, then restored)

| Guard disabled | Test that failed |
|---|---|
| CSRF binding check (invitation.rs) | `invitation_page_csrf_required` |
| verified-email check (accept) | `invitation_unverified_email_account_cannot_accept` |
| `disabled` registration check | `invitation_registration_refused_when_registration_disabled` |
| 7-day grace comparison (domain_recheck.rs) | `recheck_failure_starts_streak_without_unverifying` |

## Verification

- `cargo test -p anvil-mail`: 21 + 5 + 23 + 16 passed.
- `cargo test -p anvil-web --test org_invitations --test i18n_catalogs --test render --test admin_api_v02`: 15 + 4 + 9 + 13 passed.
- `cargo test -p anvil-web --test security_csrf --test flow_registration`: passed. `cargo test -p anvil-web --lib invitation`: passed.
- `cargo test -p anvil-core --lib service::`: 348 passed.
- `cargo test -p anvilid --test jobs`: 7 passed.
- `cargo build -p anvil-core --all-targets` and `cargo build -p anvilid`: OK.
- Clippy with `-D warnings`:
  - anvil-mail (all targets): clean.
  - anvil-web (lib, `org_invitations`, `admin_api_v02`): clean.
  - anvilid (bin, `jobs`): clean.
  - anvil-core: no lint in the two files here. The only core warning is the peer's unused import in `service/org_domain.rs` (06-17, in progress).
- `grep -rn "TRANSITIONAL(06-20)" crates/`: no match.
- `scripts/check-release-graph.sh`: OK.
- `rustfmt --edition 2024` was run on the changed files only.

## Not run here

- The Postgres variant (`ANVILID_TEST_DB=postgres`) of `org_invitations`: needs Docker, so it is left for CI. The concurrent-accept intent itself is proven on Postgres by 06-08's contract test.
- No e2e spec. The plan has none, and the selectors above are what a later spec should use.
- Real DNS for the re-check: the tests use the TXT fake only, by design.
- `scripts/check-security-tests.sh`: the names are mapped at the gate.

## Deviations from Plan

### Forced extra files (outside files_modified)

1. **[Rule 3 - Blocking] `crates/anvil-web/src/admin/email.rs`.** The verify step requires no `TRANSITIONAL(06-20)` under `crates/`, and that marker and the `has_contract` filter lived here. The kind is now listed and served. Commit `aaffb4a`.
2. **[Rule 3 - Blocking] `crates/anvil-web/tests/admin_api_v02.rs`.** `email_templates_default_override_validation_and_reset` asserts the exact kind list, which now ends with `org_invitation`. Commit `aaffb4a`.
3. **[Rule 3 - Blocking] `crates/anvil-mail/tests/templates.rs`.** It imported `has_contract` and asserted that `org_invitation` is refused. It now proves that every kind has a contract and that its defaults pass the check. Commit `aaffb4a`.
4. **[Rule 3 - Blocking] `crates/anvilid/src/main.rs` (one line).** It passes `started.state.domain_txt_arc()` into `JobsConfig`, so the job uses the binary's resolver. No peer in wave 5 owns main.rs. Commit `6c18b46`.

### Not touched

- **`crates/anvil-mail/src/worker.rs`.** It holds no `TRANSITIONAL(06-20)` refusal; the refusal was in check.rs and render.rs. The worker renders `org_invitation` unchanged, as `org_invitation_email_renders` shows.

### Interpretations

- **The CSRF design is my own:** a nonce cookie plus an HMAC over the token. The magic-link precedent binds CSRF to a flow, and the invitation page has no flow.
- **`OrgInvitationService` keeps its fields** `{storage, clock, kek}`. Changing them would touch admin/auth.rs, which belongs to 06-12. Registration takes a `RegistrationChecks` argument instead, with the policy, hasher and breach check.
- **After registering, the user is not signed in,** and signed-out users who already have an account sign in and then reopen the link. A return-to after sign-in would need login.rs or flow.rs, which this plan may not edit.
- **The plan's artifact signature was `recheck_due(now, limit)`.** It is a method on `DomainRecheckService`, whose clock supplies `now`.
- **Re-check cutoff:** the plan said `now - 24h`; the code uses 23 h (see key decisions).
- **The breach test calls the core service with a test-double checker.** The web harness runs with the breach check off.

### Process

- TDD: each task went into one commit (no separate RED commit), as in the peers' plans, because the wave shares one working tree.
- During Task 2, a peer's half-finished `theme.rs` (06-17) broke the anvil-web build for a few minutes. I waited for it rather than working around it.

## Self-Check: PASSED
