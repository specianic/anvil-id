---
phase: 06-release-1-0-orgs-and-sso
plan: 22
subsystem: auth
tags: [organizations, home-realm-discovery, identifier-first, enterprise-sso, saml, oidc, enumeration, org-04]

requires:
  - phase: 06-05
    provides: "policy::home_realm (email_domain, RoutedDomain::from_org_domain, route)"
  - phase: 06-14
    provides: "UpstreamService::start for org OIDC connections by slug; complete_identity (JIT + membership)"
  - phase: 06-17
    provides: "OrgRepo::routed_domain / tenant_has_routing data set by the domain routing API; allow_local_password default true"
  - phase: 06-18
    provides: "SamlService::start (POST start with flow binding), with_saml"
provides:
  - "LoginStep::EmailFirst, LoginStep::SsoChoice { connection_id }, LoginStep::is_primary, LoginState.email_first"
  - "flow::login: email_first, identify_input, routed, HrdRoute, IdentifyInput, IdentifyStep, Identified, form_with, IDENTIFY_FORM_ID, SSO_CHOICE_FORM_ID, USE_SSO"
  - "FlowService::identify, FlowService::start_login -> LoginStart, FlowService.saml_enabled, service::flow::{start_idp, IdpStart, IdentifyOutcome, LoginStart}"
  - "POST /ui/login/identify?flow= (identifier, choice=sso|password|change)"
  - "themes/default/templates/login_identify.html, locales {en,de}/hrd.ftl"
affects: [06-24 (HRD browser spec), 06-25 (docs, theme README), 06-26 (security map)]

tech-stack:
  added: []
  patterns:
    - "Routing as pure functions (identify_input / routed) around one storage lookup (hrd_route); no account lookup anywhere in routing"
    - "One local-method refusal helper (local_sign_in_refused) used by the password, email-code and magic-link entry points"
    - "One IdP dispatch (start_idp) by connection kind into the existing OIDC and SAML starts"

key-files:
  created:
    - crates/anvil-web/tests/hrd_login.rs
    - themes/default/templates/login_identify.html
    - themes/default/locales/en/hrd.ftl
    - themes/default/locales/de/hrd.ftl
  modified:
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/upstream.rs
    - themes/default/templates/login.html
    - crates/anvil-web/tests/security_enumeration.rs
    - crates/anvil-web/tests/flow_login_factors.rs
    - crates/anvil-web/tests/saml_login.rs

key-decisions:
  - "Email-first turns on only when OrgRepo::tenant_has_routing is true; every other tenant (the default one too) keeps the byte-identical combined form, pinned by a normalized-page comparison"
  - "The password step after the email page reuses form id `login` and login.html, with the identifier in a hidden field (`email_first` state flag); every existing selector and the password POST route stay the same"
  - "The single-sign-on choice posts back to /ui/login/identify (choice=sso), and the service routes the stored email again, so a domain unrouted in between falls back to the password step instead of a dead IdP start"
  - "The `organization` shortcut applies whenever the named org (canonical id first, then slug) has exactly one enabled routable connection, even in a tenant without routed domains: the org is named explicitly"
  - "SAML targets count only while saml_experimental is on, for routing and for the refusal alike (so the flag never locks a domain out); tenant_has_routing ignores the flag, so the email page may show with nothing routable (documented)"
  - "The local-method refusal answers before any account lookup or hashing (decided by the domain only) and is audited login_failed with reason sso_required and no target"
  - "Email-code requests, email-code verification and magic-link posts are all refused for a domain that forces SSO, covering codes and links sent before the org turned passwords off; a refused link consumes nothing"

requirements-completed: []

duration: about 45 min
completed: 2026-11-26
---

# Phase 6 Plan 22: Identifier-first login with home-realm discovery Summary

**A tenant with a verified, routed domain now asks for the email first and routes it by its domain only. A domain whose org turned passwords off goes straight to the org's OIDC or SAML IdP. A domain that still allows passwords (the Q6/Q7 default) offers "Continue with single sign-on" and "Use password instead". Every other address, known or unknown, gets the same password step. Password, email-code and magic-link sign-in are refused for a domain that forces SSO, and passkeys stay allowed. Tenants without routing keep the unchanged combined form.**

ORG-04 is prepared, not ticked (wave rule; the gate ticks REQUIREMENTS.md).

## Task Commits

1. **Task 1, engine (EmailFirst/SsoChoice, domain-only routing, local-method policy, IdP dispatch), plus the web wiring the build needed:** `db92ea7`
2. **Task 2, pages, strings, routing and enumeration tests:** `80eb50d`

TDD: the tests were written with each task and run before committing, with no separate RED commit, because peers build the same tree (same practice as 06-05, 06-14 and 06-18).

## Flow

| Step | Page / form id | Inputs (POST /ui/login/identify?flow=) | Next |
|---|---|---|---|
| `EmailFirst` | `login_identify.html`, `login-identify` | `identifier` | `hrd_route(email)`: IdP (303), `SsoChoice`, or the password step |
| `SsoChoice { connection_id }` | `login_identify.html`, `login-sso-choice` | `choice=sso` / `password` / `change` | IdP (routed again) / password step / email page |
| `Identify` + `email_first` | `login.html`, `login` (identifier hidden) | password POST as before; `choice=change` | sign-in / email page |

- `login_hint` (an email) skips the email page. It is routed at `GET /ui/login?request=`, and the browser gets a 303 to the IdP with both the flow cookie and the binding cookie, or lands on the choice or the password step.
- `organization` naming an org with exactly one enabled routable connection gives a 303 to that IdP.
- Passkey and upstream starts are accepted in every primary step (`LoginStep::is_primary`: Identify, EmailFirst, SsoChoice). The SAML start (`with_saml`) and the upstream start (`service/upstream.rs`) use the same check.
- The IdP starts go through `service::flow::start_idp`. SAML connections use `SamlService::start`, everything else `UpstreamService::start`, with the same flow binding (cookie and CSRF) as the page.

## Selectors (for 06-24 and the theme README, 06-25)

- Email page: form `login-identify-form`, input `identifier` (type email, autocomplete username), button `login-identify-submit`. Upstream buttons `upstream-{slug}` and the passkey form `login-passkey` are as on login.html.
- Choice: info message `hrd.sso_explain`, `login-email-locked`, form `login-sso-form` with button `login-sso-continue`, form `login-use-password-form` with button `login-use-password`, form `login-change-email-form` with button `login-change-email`.
- Password step after the email page: form `login` (as before) with a hidden `identifier`, `login-email-locked` above it, and `login-change-email-form` / `login-change-email` after it. The email-code form is prefilled with the locked address.
- Refusal message key: `hrd.use_sso` (400 on the form; 400 message page for the magic link).
- New strings (en, de): `hrd.sso_explain`, `hrd.continue_sso`, `hrd.use_password`, `hrd.signing_in_as` (`$email`), `hrd.change_email`, `hrd.use_sso`. The email page reuses `form.continue` and `email.invalid`.

## Tests

`hrd_login.rs` (15, SQLite):
- `combined_form_unchanged_without_routing`: the page is byte-identical (normalized) to a tenant without orgs, even with a pending routed claim and a verified routing-off claim. The selectors are asserted.
- `email_first_page_when_tenant_has_routing`: passkey and the tenant's social button are present, the org connection has no button, and the social button starts from the page.
- `routed_domain_redirects_to_org_idp` (allow_local_password=false; JIT sign-in completes through the org IdP)
- `routed_saml_domain_redirects_with_saml_request`
- `routed_domain_with_local_password_offers_choice`: change, SSO, then "Use password instead" and the password signs in.
- Negative tests:
  - `password_refused_for_routed_domain_without_local_password`: a combined form opened before the switch, a tampered hidden identifier on another address's password step, and mixed case. All are refused with the right password, and no session is created.
  - `email_code_refused_for_routed_domain_without_local_password`: a code sent before the switch is refused at verify, its magic link is refused, and a new request is refused before anything is sent.
  - `subdomain_of_routed_domain_is_not_routed`
  - `routing_ignored_for_saml_when_flag_off`: password step, and the password is not refused.
  - `unverified_or_routing_off_domain_is_local`: both sign in with the password.
  - `identify_requires_the_flow_binding`: wrong CSRF gives 403, no flow cookie gives 403.
- `login_hint_routes_immediately`: the IdP sign-in then continues the authorization request. A non-routed hint gives the password step.
- `organization_param_with_single_connection_goes_to_idp`: by slug and by id. Two connections give the sign-in page. One of the two disabled gives the IdP. An unknown org gives the page.
- `disabled_target_connection_restores_password_sign_in` (moved here from 06-17): routed while enabled. After a tenant admin disables the connection (storage intent), the normal password form signs the user in.
- `email_first_flow_works_without_javascript`: plain posts, 200/303 only. The only script is the passkey enhancement. A malformed email gives 400 on the email page.

`security_enumeration.rs` (+1): `non_routed_known_and_unknown_emails_get_identical_password_step`. Known and unknown addresses give the same status and the same normalized page (email masked). The page is the password step, and the Argon2 verification counter is unchanged, so routing hashes nothing and looks up no account.

Core unit tests in `flow::login` (+10): `email_first_page_asks_for_the_email_alone`, `submitting_the_email_routes_its_normalised_address_only`, `local_route_is_the_password_step_with_the_email_locked`, `local_route_page_is_identical_for_every_address_but_the_echo`, `routed_domain_without_local_password_starts_the_idp`, `routed_domain_with_local_password_offers_the_choice`, `identify_inputs_outside_their_step_are_invalid`, `passkeys_and_saml_starts_are_accepted_in_every_primary_step`, `new_steps_round_trip_and_old_rows_decode`, `failures_on_the_email_page_keep_the_page`.

"submit never reads the user table for routing": this holds by construction. `identify_input` and `routed` are pure, `hrd_route` reads only `OrgRepo::routed_domain`, and the enumeration test pins it with the hasher counter. No storage spy was written.

**Mutation checks** (guard disabled, then restored; `git diff` empty afterwards):

| Guard disabled | Tests that failed |
|---|---|
| `local_sign_in_refused` always false | `password_refused_…`, `email_code_refused_…` |
| SAML counted as routable with the flag off | `routing_ignored_for_saml_when_flag_off` |

## Local-method trade-off (text for the docs, 06-25)

> With `allow_local_password: true` (the default), a verified, routed domain offers single sign-on
> first but keeps password, email-code and magic-link sign-in. Nobody is locked out while the
> organization's IdP is being set up, at the cost that an ex-employee whose IdP account was
> disabled can still sign in with a local password until the org turns passwords off or the
> account is blocked. With `allow_local_password: false`, addresses on that domain go straight to
> the IdP, and password, email-code and magic-link sign-in are refused with "use your
> organization's sign-in". Passkeys stay allowed in both modes: a passkey is bound to the account
> and phishing-resistant, and it is what an admin or a user locked out by a broken IdP can still
> use. Organizations that want IdP-only access should also remove members' passkeys or block
> accounts at offboarding. The refusal looks only at the email's domain, so it reveals nothing
> about which accounts exist. Recovery: set `routing: false, allow_local_password: true` (org
> admin or tenant admin). Disabling the org's connection also stops routing and restores local
> sign-in.

## Files Created/Modified (beyond files_modified)

- `crates/anvil-web/src/ui/upstream.rs` (one condition): `upstream_buttons` also lists buttons for the email-first form (`login-identify`). The must-have "passkey and social buttons stay on it" needs it, including on restarted flows rendered by `outcome_page`.
- `crates/anvil-web/tests/saml_login.rs` (one line): `saml_enabled: false` in its `FlowService` literal. This was forced by the new field.
- `ui/login.rs` went into the Task 1 commit. The changed `FlowService` field and `start_login` result would otherwise have left HEAD unbuildable for the peers sharing the tree.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Test domains under `.example` never route.** `home_realm::email_domain` uses `normalize_domain`, which refuses reserved names (`.example`, `.test`). The routing tests therefore use `acme-corp.com`, the precedent from `security_domains.rs`. The enterprise trust rule in 06-14 uses `normalize_email` and is unaffected.

**2. [Rule 2] Codes and links sent before the switch.** Besides the request, the email-code verify and the magic-link post are refused too, so a code requested while passwords were allowed cannot be used after the org turned them off.

**3. [Rule 2] Restarted login flows.** `restart`, `restart_login_with_message` and `start` all build the initial state through one `FlowService::initial`. A routed tenant's expired or failed flows therefore restart at the email page, not the combined form.

### Interpretations

- `FlowInput` / `engine.rs` are unchanged (not in files_modified). The email-first submission is a separate `FlowService::identify` with its own binding check through the shared `load`.
- The plan's "Route::Sso(conn) -> StartIdp(conn) when allow_local_password=false, SsoChoice(conn) when true" is implemented as `routed(state, HrdRoute, chose_sso)`. `HrdRoute` carries `allow_local_password` from the domain row.
- `posted_login_form` (the page a brute-force lock or a CAPTCHA demand renders before the flow runs) still uses the combined form, so a locked password POST in a routed tenant shows the combined form with the echoed address. It is identical for known and unknown accounts, so there is no enumeration impact. Noted for 06-25/06-26.
- `tenant_has_routing` does not know the SAML flag. A tenant whose only routed domain points at a SAML connection with the flag off shows the email page, and every address then goes to the password step.

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib -- flow::login service::flow`: 66 passed. `flow:: service::flow service::upstream`: 142 passed.
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean.
- `cargo test -p anvil-web --test hrd_login --test security_enumeration --test flow_login --test flow_email_code --test flow_passkey --test upstream_buttons --test i18n_catalogs --test render`: 15 + 3 + 9 + 8 + 4 + 7 + 4 + 13, all passed.
- Regression: `enterprise_oidc` 7, `saml_login` 19, `upstream_login` 15, `security_linking` 24, `org_claims` 13, `admin_branding` 9, `theme` 6, `flow_login_factors` 9, `security_email_code` 21, `authorize_step_up` 9, `security_domains` 17: all passed. `cargo test -p anvil-web --lib`: 179 passed.
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean. `cargo check -p anvilid`: builds.
- `scripts/check-release-graph.sh`: OK. `scripts/check-security-tests.sh`: OK (632 pairs; the new negatives are for the gate).
- `rustfmt --edition 2024` was run on every touched Rust file.

## Not run

- `ANVILID_TEST_DB=postgres` for `hrd_login` / `security_enumeration` (Docker is not used under the wave rules; left for CI). No SQL was added. `routed_domain` / `tenant_has_routing` are covered by the 06-04/06-08 contract suite.
- e2e/Playwright: no spec here (06-24 owns the HRD browser spec). The existing login and no-JS specs run on the default tenant, which never gets a routed domain (06-23 rule), so they see the unchanged combined form.

## Open items

- 06-26 security map: `hrd_login::password_refused_for_routed_domain_without_local_password`, `hrd_login::email_code_refused_for_routed_domain_without_local_password`, `hrd_login::subdomain_of_routed_domain_is_not_routed`, `hrd_login::routing_ignored_for_saml_when_flag_off`, `hrd_login::unverified_or_routing_off_domain_is_local`, `hrd_login::identify_requires_the_flow_binding`, `security_enumeration::non_routed_known_and_unknown_emails_get_identical_password_step`.
- 06-25: theme README entries for `login_identify.html` and the `change_email` variable of login.html (selectors above). Also the trade-off text above.
- Possible follow-ups: pass the typed email as `login_hint` to the org's OIDC IdP; use the email-first form for the brute-force lock page in routed tenants.

## Self-Check: PASSED
