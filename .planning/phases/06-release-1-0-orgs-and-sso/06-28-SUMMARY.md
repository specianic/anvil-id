---
phase: 06-release-1-0-orgs-and-sso
plan: 28
subsystem: sign-in / organizations
tags: [hrd, identifier-first, brute-force, captcha, saml-flag, jit, org-sso, gap-closure]

requires:
  - phase: 06-14
    provides: org OIDC JIT membership, enterprise_email_trust
  - phase: 06-18
    provides: SAML sign-in through the shared completion path
  - phase: 06-22
    provides: identifier-first sign-in, FlowService::idp_routable, posted_login_form
provides:
  - OrgRepo::routing_connections (replaces tenant_has_routing) on SQLite and Postgres
  - flag-aware email-first decision (one rule with routing)
  - FlowService::initial_login_form; lock/CAPTCHA pages render the email-first form in routed tenants
  - upstream::linking::jit_allowed (org-trusted JIT regardless of tenant registration)
affects: [06-26 security map, 06-31 (same files: flow.rs, login.rs, upstream.rs, flow/login.rs, docs)]

tech-stack:
  added: []
  patterns:
    - "Storage returns candidates, the core applies the policy (routing_connections + idp_routable)"
    - "The web layer asks the flow service for the initial login form; it never decides email-first itself"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-storage-sqlite/src/organizations.rs
    - crates/anvil-storage-sqlite/.sqlx (1 removed, 1 added)
    - crates/anvil-storage-postgres/src/organizations.rs
    - crates/anvil-storage-postgres/.sqlx (1 removed, 1 added)
    - crates/anvil-storage/src/contract/org_domains.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/flow/login.rs (forced extra)
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-core/src/upstream/linking.rs
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-web/tests/hrd_login.rs
    - crates/anvil-web/tests/enterprise_oidc.rs
    - crates/anvil-web/tests/saml_login.rs
    - docs/ORGANIZATIONS.md
    - docs/ARCHITECTURE.md
    - docs/UPGRADING.md

key-decisions:
  - "routing_connections returns the enabled same-org routing connections of verified routed claims (deduplicated by an EXISTS join, connection id order); email_first_enabled = any(idp_routable)"
  - "The email-first form also answers from the password step after it (step Identify with email_first): the email is routed again, as after 'change'. Without this the lock/CAPTCHA page form would post into an invalid-input error"
  - "The password step reached through POST /ui/login/identify carries the CAPTCHA widget when the address's brute-force tier asks for one (read-only gate check, same keys as the password POST); otherwise a routed tenant in the CAPTCHA tier could loop between the email page and the CAPTCHA demand"
  - "The CAPTCHA page passes the widget only with the combined form (form id login): the email-first page posts no CAPTCHA response, so non-routed tenants keep the old page exactly and routed tenants show the widget on the password step"
  - "The 429 of the failure that crosses the threshold still renders the flow's own form (the password step with the lock message); only the gate's answers before the flow runs (posted_login_form) use the initial form"
  - "JIT interpretation: the bypass needs the email to be trusted for the org (enterprise_email_trust: verified org domain, and OIDC email_verified true); outside its domains an org IdP falls back to upstream_registration"

requirements-completed: []

duration: about 1h20m
completed: 2026-11-26
---

# Phase 6 Plan 28: Flag-aware email-first, email-first lock/CAPTCHA page, org JIT under closed registration Summary

**Email-first now uses the same flag-aware rule as home-realm routing. The brute-force lock and CAPTCHA pages of a routed tenant render the email-first form for the posted flow. Org connections create accounts just in time for their verified domains even under closed tenant registration. `tenant_has_routing` is gone, and the three limitations have been removed from the docs.**

ORG-03 and ORG-04 are touched but not ticked (wave rule: the gate ticks REQUIREMENTS.md).

## Task Commits

1. **Task 1, flag-aware email-first, routing_connections port (both backends, .sqlx), lock/CAPTCHA page:** `78fb06d`
2. **Task 2, jit_allowed, service wiring, JIT tests, docs (plus the login.rs module doc and a test rename left from Task 1):** `ae65e15`

TDD: the tests were written alongside each task and run before committing, with no separate RED commit, because peers build the same tree (same practice as 06-14/06-18/06-22). Mutation checks stand in for RED (below).

## What changed

- **Port.** `OrgRepo::routing_connections(tenant) -> Vec<Connection>`: the connections that a verified claim with `routing = true` references, provided they exist, belong to the claim's org and are enabled. The result has no duplicates and is ordered by connection id. SQLite and Postgres map through the existing `ConnectionRow` conversion. The contract (`org_domains.rs`) asserts this in place: one connection, no duplicate for a second claim, empty after pending, routing off, disabled, and for another tenant. No new contract functions, and `contract/mod.rs` is untouched.
- **Flow.** `email_first_enabled` now returns `routing_connections(..).any(idp_routable)`. `initial_login_form(cx)` returns the form of `initial(cx, Login, None)`.
- **Web.** `posted_login_form` is async and takes its form from `initial_login_form`, then binds it and echoes the identifier. All three call sites (password lock, CAPTCHA failure, passkey lock) await it.
- **Linking.** `jit_allowed(settings, org_trusted_email)`. `service::upstream` computes `org_trusted_email = org.is_some() && identity.email_verified` right after the enterprise trust step.

## Tests for the 06-26 security map

New negative tests (file::fn):
- `hrd_login::email_first_not_shown_when_only_route_is_saml_with_flag_off`
- `hrd_login::email_first_not_shown_for_disabled_or_unverified_route`
- `hrd_login::locked_page_in_routed_tenant_shows_email_first_form`
- `hrd_login::captcha_page_in_routed_tenant_shows_email_first_form`
- `hrd_login::locked_page_identical_for_known_and_unknown_identifiers_in_routed_tenant`
- `enterprise_oidc::org_jit_refused_for_email_outside_org_domains_under_closed_registration` (another domain, a pending domain, and an IdP `email_verified: false` on the verified domain)
- `enterprise_oidc::tenant_connection_jit_still_follows_upstream_registration`
- `saml_login::saml_org_jit_allowed_under_closed_registration` (its second half refuses an outsider address with `no_account`)
- `linking::tests::jit_follows_the_tenant_rule_without_an_org_trusted_email` (unit)

Positive tests: `hrd_login::email_first_shown_when_only_route_is_saml_with_flag_on`, `enterprise_oidc::org_jit_allowed_under_closed_registration` (unset and `Some(false)`), `linking::tests::jit_allowed_for_org_trusted_email_whatever_the_tenant_setting`, `flow::login::tests::email_first_form_answers_from_the_password_step`.

Changed: `hrd_login::routing_ignored_for_saml_when_flag_off` now adds an OIDC route on a second domain so the email page still shows. It keeps its intent: the SAML domain gets the password step. `email_first_page_when_tenant_has_routing` was renamed to `email_first_page_when_tenant_has_a_routable_domain`, so that `grep tenant_has_routing crates` is empty.

## Mutation checks

- I temporarily replaced `email_first_enabled`'s `any(idp_routable)` with `any(|c| c.enabled)`, which ignores the flag. `email_first_not_shown_when_only_route_is_saml_with_flag_off` FAILED and the other six email-first tests passed. Restored.
- `org_trusted_email = org.is_some()` (the domain trust ignored): `org_jit_refused_for_email_outside_org_domains_under_closed_registration` FAILED. Restored.
- `org_trusted_email = false` (the old rule): `org_jit_allowed_under_closed_registration` FAILED. Restored.

## JIT interpretation

The orchestrator decided that JIT through an org-owned connection is allowed whatever the tenant's registration setting. I read that together with its stated reason: an admin configured the connection and verified the domain. So the exception needs the asserted email to be trusted for that org: on one of the org's verified domains, and for OIDC with `email_verified: true` (the existing `enterprise_email_trust` result). An org IdP therefore cannot create accounts for arbitrary addresses in a closed tenant; outside its domains it falls back to `upstream_registration`. Tenant-level connections are unchanged.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The email-first form on the lock page posted into an invalid-input error.** Found during Task 1. The lock/CAPTCHA page binds the email-first form to the posted flow, which sits at the password step (`Identify` with `email_first`). `identify_input` accepted an email only at `EmailFirst`, so submitting that form re-rendered the password step with `flow.invalid_input`. Fix: `identify_input` also takes an email at the password step of an email-first flow. It resets the step to `EmailFirst`, as "change" does, and routes again. The combined form, with `email_first = false`, still refuses it (the existing unit test is unchanged). File: `crates/anvil-core/src/flow/login.rs`, a forced extra not in files_modified. No wave-8 peer owns it; 06-31 changes it later. Commit `78fb06d`.

**2. [Rule 2 - Missing functionality] CAPTCHA loop in routed tenants.** Found during Task 1. The email-first page has no widget, and the identify step is not gated. A user sent back to the email page by a CAPTCHA demand would then reach a password step without the widget and get the CAPTCHA demand again, forever. Fix: `POST /ui/login/identify` adds the widget to the password step when the address's brute-force tier answers `RequireCaptcha`. This is a read-only check (`guard_attempt` with the same `attempt_keys` as the password POST, so nothing is recorded), and the answer depends on attempts, never on whether an account exists. The CAPTCHA-failure page sends the widget only with the combined form. Non-routed tenants are byte-identical to before (`security_bruteforce` is unchanged and green). File: `crates/anvil-web/src/ui/login.rs` (owned). Commit `78fb06d`.

**3. [Rule 3] Test name containing `tenant_has_routing`.** The plan's check `! grep -rn tenant_has_routing crates` would have matched the existing positive test name, so I renamed it (see above).

### Interpretations

- The plan says the 429 lock page shows the email-first form. That holds for the gate's answer before the flow runs (`posted_login_form`). The POST whose failure crosses the threshold renders the flow's own current form, which is the password step with the lock message, as before. The tests assert both.
- On the CAPTCHA page the email-first form carries the CAPTCHA error but no widget (the theme's `login_identify.html` has no widget partial, and changing themes was out of scope). The widget appears on the password step after it, and the test signs in with a verified CAPTCHA through that path.
- In UPGRADING.md only the "What to configure next" bullet changed. The 0.2 → 0.3 defaults table is historical and was left unchanged.

## Verification (main tree)

- `cargo test -p anvil-core --lib`: 1000 passed (includes `service::flow`, `flow::login`, `upstream::linking`, `service::upstream`).
- `cargo test -p anvil-storage-sqlite --test contract`: 470 passed.
- `cargo test -p anvil-web` with `--test hrd_login` (21), `enterprise_oidc` (10), `saml_login` (20), `security_bruteforce`, `captcha`, `security_enumeration`, `flow_login`, `flow_passkey`, `security_linking` (24), `upstream_login` (15), `org_claims`, `org_invitations`, `flow_login_factors`, `security_email_code`, `flow_email_code`, `upstream_buttons`, `render`, `security_domains`, `authorize_step_up`, `org_switch`: all passed.
- **Postgres on a local PostgreSQL 14 cluster** (scratchpad data dir, 127.0.0.1:55432, trust auth, no unix socket), as 06-08 did:
  - `.sqlx` was regenerated with `cargo sqlx prepare` (the invocation `scripts/sqlx.sh` uses) against a migrated `anvil_dev`. `cargo sqlx prepare --check` is clean. No file was edited by hand.
  - `cargo test -p anvil-storage-postgres --test contract` passed 235, through an uncommitted `server_url()` patch in `tests/support/mod.rs`. I reverted the patch before committing (`git diff` is empty).
  - I stopped the cluster and deleted its data dir.
- `scripts/sqlx.sh check crates/anvil-storage-sqlite`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `scripts/check-release-graph.sh`: OK.
- `grep -rn tenant_has_routing crates`: no match. The doc greps from the plan's verify block pass.
- `rustfmt --edition 2024` was run on every touched Rust file.

## Not run

- PG18 testcontainers runs (`just test-pg`, `ANVILID_TEST_DB=postgres` for `hrd_login` / `enterprise_oidc` / `saml_login`) and `scripts/sqlx.sh check crates/anvil-storage-postgres` against the Docker dev container. Docker is not used under the wave rules, so CI covers these.
- `cargo test --workspace` as one run. I ran targeted suites instead, per the wave rules.
- e2e (`hrd.spec.ts`, `nojs-hrd.spec.ts`, `saml.spec.ts`): Docker. The suite runs with `ANVILID_SAML_EXPERIMENTAL=true`, and no spec exercises the lock/CAPTCHA page of a routed tenant, so no spec change is expected.

## Open items

- 06-26: map the negative tests listed above.
- 06-31 edits the same files (flow.rs, login.rs, flow/login.rs, upstream.rs, ORGANIZATIONS.md, ARCHITECTURE.md). The M5 open item "invitation return-to after sign-in" and the invitation limitation bullet were left for it.

## Self-Check: PASSED
