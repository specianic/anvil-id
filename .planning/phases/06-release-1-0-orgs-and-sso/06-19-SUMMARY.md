---
phase: 06-release-1-0-orgs-and-sso
plan: 19
subsystem: oauth-authorize
tags: [organizations, org-switcher, mfa, step-up, authorize, ui, i18n]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-05 effective_policy_for; 06-13 bind_active_org / OrgRefusal::SelectionRequired, active org on code and family; 06-04 pre-declared ui/select_organization.rs"
provides:
  - "AuthorizeOutcome::SelectOrganization { request_id } (303 to /ui/select-organization?request=)"
  - "AuthorizeService::start_select_organization / choose_organization, OrgChoice, SelectOrganizationPage, OrgOption, SelectOrganizationStart"
  - "mfa_context: effective_policy_for(tenant, active org, client)"
  - "GET/POST /ui/select-organization, select_organization.html, select_organization.ftl (en, de)"
affects: [06-22, 06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "Chooser and switcher share one bound-flow implementation (open_request_flow / bound_request_flow)"
    - "One membership lookup for an authorization (active_org_of) feeds both the MFA policy and the org bound to the code"

key-files:
  created:
    - crates/anvil-web/tests/org_switch.rs
    - themes/default/templates/select_organization.html
    - themes/default/locales/en/select_organization.ftl
    - themes/default/locales/de/select_organization.ftl
  modified:
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/protocol/authorize.rs
    - crates/anvil-web/src/ui/select_organization.rs
    - crates/anvil-web/tests/org_claims.rs

key-decisions:
  - "The choice is written into the stored request by compare-and-swap through the existing GrantRepo calls: delete (only one submission wins) and re-create under the same id with params.organization = org id, keeping created_at and expires_at. No new storage method (ports.rs is not this plan's)."
  - "The switcher is offered only for a request whose client policy is `required` and that names no org; any other request is the flow_expired page, so the switcher cannot add an org to an optional client's request."
  - "continue_request decides the org before using the request up, so the switcher keeps the request; an org refusal deletes it."
  - "A foreign or malformed org id re-renders the switcher with 403 and select_organization.not_member (fresh flow), checked after the binding and before the flow is used up; the request is unchanged."
  - "The org MFA policy counts once the session's user, the request's `organization` and the client's policy select an org. During the initial password login (no session yet) the org is unknown, so a stricter org adds its second factor as a step-up right after login, before any code."
  - "Stage::AfterOrganizationChosen drops select_account and consent (the switcher comes after the consent decision)."

requirements-completed: []

duration: ~50min
completed: 2026-11-26
---

# Phase 6 Plan 19: Org switcher and org-aware MFA Summary

**When a client requires an org and the user belongs to several, `/authorize` now sends the user to `/ui/select-organization`. The page lists only the user's own memberships. The choice is written into the stored authorization request, so the normal resolution binds that org to the code and its token family. To switch orgs, the RP sends a new request with `organization=<other>` (`prompt=none` works with the existing session). The effective MFA policy is now the strictest of tenant, active org and client, so choosing or requesting a stricter org triggers the existing step-up before any code is issued.**

ORG-02 is not ticked here. Only the gate (06-26) ticks REQUIREMENTS.md.

## Task Commits

1. **Task 1: switcher outcome and org-aware MFA in AuthorizeService** `996dc37` (feat). The 06-13 test update in org_claims.rs is in this commit too.
2. **Task 2: switcher page, en/de strings, tests** `e89d866` (feat)

## Flow

- `authorize` (direct path): when the consent decision is Skip and the result is `NeedsChoice` without `prompt=none`, the request is stored and the outcome is `SelectOrganization`.
- `continue_request` (after login, consent or chooser): the org is decided before the request is deleted. `Choose` keeps the request and answers `SelectOrganization`.
- `GET /ui/select-organization?request=`: without a session it redirects to `/ui/login?request=`. Otherwise it opens a bound flow (`FlowKind::Consent`, apps form, `auth_request_id` = the request; no flow.kind change) and renders the memberships, sorted by display name.
- `POST /ui/select-organization?flow=&request=` with `organization=<org id>`: the binding is checked (cookie, CSRF, the session's user, this request), then membership, then the flow is used up, then the stored request is CAS-updated. After that comes `continue_request(Stage::AfterOrganizationChosen)`, where the org MFA can answer `Login` (step-up). Otherwise the code is issued through the response mode.
- `prompt=none` with several orgs still answers `interaction_required`. Never the switcher.

## Selectors (template `select_organization.html`)

- form `select-organization-form` (POST, no JavaScript); messages `select-organization-messages`, `select-organization-msg-{n}` with `data-message-key`
- fieldset `select-organization-list` with a legend; client name `select-organization-client`
- one radio per membership: `organization-{slug}` (`name="organization"`, `value` = org id, the first one checked), label `organization-{slug}-label` (`for=` the radio), showing the display name and the slug
- submit `select-organization-form-submit`
- message keys: `select_organization.expired`, `select_organization.not_member`; title key `title.select_organization`

## Negative tests (for the 06-26 security map)

crates/anvil-web/tests/org_switch.rs:
- `switcher_refuses_foreign_org`: another member's org, an unknown id, a slug and an empty value each give 403 and the switcher again with `not_member`. No code, no other org revealed, stored request unchanged. Afterwards a valid choice still works.
- `switcher_refuses_bad_csrf`: no token, a wrong token, no flow cookie, no flow id, and a cross-site post (Fetch-Metadata) each give 403 and change nothing. The intact binding still works.
- `switcher_choice_cannot_be_replayed`: the same post again, also with the other org, gives 400 `flow_expired` with no second code. The page itself is then `flow_expired`.
- `switcher_foreign_flow_refused`: a flow bound to another request of the same user gives 403. Alice's flow with Bob's session gives 403. Neither request changes.
- `switcher_lists_only_own_memberships`: another org of the tenant (slug, name, id) is not on the page, nothing is picked silently, and without a session the page goes to sign-in.
- `prompt_none_with_organization_for_member_issues_code_without_ui`: also covers non-member + `prompt=none`, which gives `access_denied`.
- `stricter_org_mfa_triggers_step_up`: tenant off, acme required. With beta, `prompt=none` issues `acr` pwd. With acme, `prompt=none` gives an error and no code. Choosing acme on the switcher leads to the second-factor step (no password), and the code carries `acr` mfa and acme's `org_id`. The session is upgraded in place.

Positive tests: `switcher_choice_issues_tokens_for_that_org`, `switching_with_new_request_changes_org` (the old refresh token keeps beta), `switcher_page_no_js_and_axe_selectors_present` (fieldset/legend, a label per radio, no script, German with `ui_locales=de`).

Unit tests (anvil-core `service::authorize`): `org_mfa_policy_is_part_of_the_strictest_policy` (org required raises tenant optional; org off never weakens tenant required or client optional; no org until one is selected), `switcher_lists_memberships_by_display_name`, `after_the_switcher_select_account_and_consent_are_answered`. Lib render test: `ui::select_organization::tests::switcher_page_renders_without_script`.

## Files Created/Modified (beyond files_modified)

- `crates/anvil-web/tests/org_claims.rs`: `prompt_none_multi_org_required_is_interaction_required` now expects the 303 to the switcher (no code), and its TRANSITIONAL(06-19) comment is gone. 06-13's SUMMARY asked for this change.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] No storage method to update a stored authorization request**
- **Issue:** The plan asks for a compare-and-swap on the stored request params. `GrantRepo` has only create/get/delete, and ports.rs is not this plan's.
- **Fix:** Delete, then re-create under the same id (the winner of the delete writes the choice), keeping `created_at` (needed for `max_age`/`prompt=login`) and `expires_at`. The flow is used up before that, so a replay never reaches it.
- **Commit:** 996dc37

**2. [Rule 2 - Critical] Switcher limited to requests that actually await a choice**
- Without this check, anyone with a stored request id for an `optional` client could add an org through the switcher. `start_select_organization` and `choose_organization` now accept only a request whose client is `required` and whose request names no org.
- **Commit:** 996dc37

**3. [Refactor, one implementation] Shared bound-flow code**
- The account chooser and the switcher use the same `open_request_flow` / `bound_request_flow`. `choose_account` behaves as before, and its suites are green.

**4. [Process] TDD commits**
- Tests were written together with each change and run before committing. Each task is one `feat` commit, because peers build the same tree.

### Not done as written

- **`effective_policy` kept.** The plan says to remove it if it has no other caller. It now has none outside `policy/mfa.rs`, but it is a one-line delegation to `effective_policy_for`, not a second implementation. Its own tests use it, and `policy/mfa.rs` (plus the doc reference in `oauth/decision.rs`) is not this plan's. Left for the 06-26 cleanup or a one-line follow-up.
- **The flow's `flow_mfa` (flow.rs, not this plan's) still sees tenant + client only during the first password login**, because the user is not known yet. Org MFA is applied as a step-up right after login (see the decisions above). `stricter_org_mfa_triggers_step_up` proves no code is issued before the second factor.

## Verification

- `cargo test -p anvil-core --lib -- service::authorize policy::mfa`: 17 passed
- `cargo test -p anvil-web --test org_switch`: 10 passed
- `--test org_claims` 13, `--test authorize_step_up` 13, `--test i18n_catalogs` 4, `--test render` 13, `--test authorize` 33, `--test authorize_prompt` 19, `--test consent` 18, `--test flow_mfa_policy` 9: all green
- `cargo test -p anvil-web --lib ui::`: 22 passed (including the new render test)
- `cargo clippy -p anvil-web --lib --test org_switch --test org_claims -- -D warnings`: clean
- `cargo clippy -p anvil-core --lib --tests -- -D warnings`: clean at Task 1
- `! grep -rn "TRANSITIONAL(06-19)" crates/`: no matches
- `scripts/check-release-graph.sh`: OK
- rustfmt (edition 2024) on every touched Rust file

## Not run here

- `cargo clippy -p anvil-web --all-targets -- -D warnings`: stopped by peers' in-progress wave-5 test files (`admin_org_sso.rs` `cloned_ref_to_slice_refs`, `org_invitations.rs` compile errors). It never reached a lint in this plan's files. A later `cargo clippy -p anvil-core --all-targets` stopped in a peer's `service/org_domain.rs` (unused import).
- Postgres, e2e, axe (browser) and conformance runs were left for CI. The page's accessibility basics are asserted in the render test. A real axe run belongs to the e2e suite.

## Next Phase Readiness

- 06-25 (theme README): document `select_organization.html` with the selectors and variables above.
- 06-26 (security map): the negative test names are listed above.
- `effective_policy` can be removed in `policy/mfa.rs` together with the doc line in `oauth/decision.rs`.

## Self-Check: PASSED
