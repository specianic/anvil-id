---
phase: 07-release-1-0-certification
plan: 16
subsystem: consent
tags: [consent, agents, step-up, i18n, e2e, AGT-03]
requires:
  - "07-03: Client.client_kind (ClientKind::{Application, Agent})"
  - "07-08: SQLite client columns (client_kind persists)"
  - "07-12: client_kind exposed through the admin API; validate_client_policy refuses agent + skip_first_party"
provides:
  - "flow::consent::{Provenance, RequestSplit, ConsentView} (no display text)"
  - "service::consent::ConsentPage { request_id, client_id, view: ConsentView } (ConsentStart::Started.page is Box<ConsentPage>)"
  - "Consent template ids: consent-agent, consent-provenance (data-provenance), consent-new-scopes, consent-granted-scopes (+ consent-granted-scope-{n}, consent-granted-resources, consent-granted-resource-{n})"
  - "Fluent keys consent-agent_badge, consent-provenance_static|dynamic|cimd, consent-new_permissions, consent-already_allowed (en, de)"
affects: [07-21 (UPGRADING: ConsentPage shape changed for anyone embedding anvil-core), 07-22 (docs: consent screen ids), 07-23 gate]
tech-stack:
  added: []
  patterns:
    - "Core view struct without display text; web layer maps it to template context"
    - "Consent page split: new items under the existing #consent-scopes fieldset, already allowed ones in a collapsed <details>"
key-files:
  created:
    - crates/anvil-web/tests/consent_agent.rs
    - tests/e2e/specs/consent-agent.spec.ts
  modified:
    - crates/anvil-core/src/flow/consent.rs
    - crates/anvil-core/src/service/consent.rs
    - crates/anvil-web/src/ui/consent.rs
    - themes/default/templates/consent.html
    - themes/default/locales/en/main.ftl
    - themes/default/locales/de/main.ftl
key-decisions:
  - "ConsentPage now carries only request_id, client_id and the ConsentView; the old scopes/resources/client_name/cimd_host fields are folded into the view (cimd host lives in Provenance::Cimd, ConsentView::cimd_host() reads it). One place for the CIMD host"
  - "The granted lists show requested items already covered by the grant, not the whole grant (a grant item the request does not ask for is not shown)"
  - "New scopes stay inside the existing #consent-scopes fieldset with the existing consent-scope-{n}/data-scope ids, so first-request markup and existing selectors (consent.spec.ts, i18n.spec.ts) are unchanged; granted items use data-granted-scope so #consent-scopes [data-scope] only ever matches new scopes"
  - "The already-allowed <details> is open when nothing is new (prompt=consent with a covering grant), collapsed otherwise"
  - "The agent badge reuses the existing anvil-message-info styling (no CSS change; anvil.css is not in this plan)"
  - "Deny already stored nothing; the code path was verified, documented and tested rather than changed"
metrics:
  duration: ~75min
  completed: 2026-11-26
---

# Phase 7 Plan 16: Agent consent and incremental step-up Summary

The consent screen now shows an "AI agent / automated client" badge for agent clients and a provenance note for
every client. With a stored grant, it lists only the new scopes and resources; the ones already allowed are folded
into a collapsed block. Denying a step-up leaves the stored grant byte-identical.

## Core view (anvil-core)

`flow::consent`:
- `Provenance { Static, Dynamic, Cimd { host } }`: who vouches for the client, taken from `registration_source`.
- `RequestSplit::of(granted, requested) -> { new, granted }`: built on `missing_scopes`, keeps request order.
- `ConsentView { client_name, client_kind, provenance, new_scopes, granted_scopes, new_resources, granted_resources }`
  and `ConsentView::new(name, kind, provenance, grant: Option<ConsentCoverage>, requested: ConsentCoverage)`, plus
  `cimd_host()`.

`service::consent`:
- The consent step's page type is **`ConsentPage`**. It is now `{ request_id, client_id, view: ConsentView }`.
  `ConsentStart::Started.page` is a `Box<ConsentPage>` because clippy flagged the large variant. No other flow page,
  `FormDescription` or headless DTO changed.
- `ConsentService::start` loads the user's stored grant (`GrantRepo::consent`) and builds the view. A CIMD client
  whose `client_id` is not a URL is reported as `CoreError::Internal` rather than shown with a made-up host.
- Deny: verified that it never touches grants (`take_decision` only swaps the flow state). This is now documented on
  `deny` and in the module docs.

Core tests: 5 new in `flow::consent` (view split, granted lists only requested items, CIMD host, prompt=none with a
new scope gives consent_required). 4 new in `service::consent`, run against an in-module storage fake (clients,
flows, grants, audit):
- `step_up_page_shows_only_the_new_scopes_and_resources`
- `provenance_follows_the_registration_source`
- `step_up_deny_leaves_the_grant_untouched`: the grant equals its earlier value and the fake records no grant writes
- `step_up_allow_stores_the_union`

## Template ids (consent.html)

| Id | Content |
| --- | --- |
| `consent-agent` | badge, only for `client_kind = agent` |
| `consent-provenance` | `data-provenance="static\|dynamic\|cimd"`, localized text (CIMD text includes the escaped host) |
| `consent-new-scopes` | `<ul>` inside the `#consent-scopes` fieldset, items `consent-scope-{n}` with `data-scope` (only when there are new scopes) |
| `consent-new-heading` | "New permissions:" (only when there are both new and granted scopes) |
| `consent-resources` | new resources only, items `consent-resource-{n}` with `data-resource` |
| `consent-granted-scopes` | `<details class="anvil-disclosure">`, `open` when nothing is new; items `consent-granted-scope-{n}` with `data-granted-scope` |
| `consent-granted-resources` | list inside it, items `consent-granted-resource-{n}` with `data-granted-resource` |

The existing ids are kept: `consent-form`, `consent-client`, `consent-scopes`, `consent-allow`, `consent-deny`,
`consent-cimd*` and `consent-avatar`. Still no JavaScript.

## Fluent keys (themes/default/locales/{en,de}/main.ftl, "Consent screen and form_post" section)

`consent-agent_badge`, `consent-provenance_static`, `consent-provenance_dynamic`,
`consent-provenance_cimd = Identified by its metadata document at { $host }. Its name is not verified.`,
`consent-new_permissions`, `consent-already_allowed`. The German strings are written in German, not copied from
English. The key names use the catalog's existing `consent-xxx_yyy` style (`t("consent.agent_badge")`). The plan
suggested names like `consent-agent-badge`; I used the catalog's style instead. I added no separate
`consent-name-unverified` key: the existing `consent-cimd_unverified` note and the CIMD provenance sentence both mark
the name as unverified.

## Integration tests (crates/anvil-web/tests/consent_agent.rs): 9 of 9 pass on SQLite

`consent_shows_agent_badge_for_agent_clients`, `consent_provenance_static_dynamic_cimd`,
`consent_cimd_name_marked_unverified`, `step_up_shows_only_new_scopes`, `step_up_shows_only_new_resources`,
`step_up_allow_stores_union`, `step_up_deny_keeps_existing_grant`, `step_up_prompt_none_new_scope_is_consent_required`,
`agent_client_always_sees_consent`.

The last test covers three things end to end: the badge on first use, the normal rule (a covering grant skips the
screen and `prompt=consent` asks again), and a management API PATCH to `skip_first_party` on the stored agent, which
is refused with a 422 on `consent_mode` while storage still holds `required`.

**Mutation check (recorded):** I changed `ui/consent.rs` to render granted plus new scopes as new.
`step_up_shows_only_new_scopes` then failed (panic at the `new_scopes == ["email"]` assertion). I restored the code
afterwards.

Other suites, all passing: consent (19), i18n (14), i18n_catalogs (4, parity included), render (18), theme (13),
account_apps, resource_indicators, cimd, authorize_prompt, authorize_step_up, security_cimd, security_registration,
registration_dcr, security_par, org_claims, security_csrf, and the anvil-web lib test `ui::consent`.

## E2E evidence (tests/e2e/specs/consent-agent.spec.ts)

The spec creates an agent client through the admin API (`client_kind: 'agent'`, consent `required`). It then:
1. requests two scopes and checks the badge, the provenance (static), and that everything is listed as new;
2. requests a third scope and checks that only `email` appears under `#consent-new-scopes`, with the other two in the
   collapsed `#consent-granted-scopes`;
3. denies, checks for `access_denied`, and checks that the first two scopes still return a code without the screen;
4. allows, after which all three scopes are covered.

The spec answers the redirect URI with its own small `node:http` server, so the browser actually lands on it. The
same journey also runs in a browser context with JavaScript disabled. The file is not named `nojs*`, so it runs in
the chromium project, and the no-JS run happens inside the spec.

**Ran locally:** debug `anvilid` started from a scratch copy on SQLite with the run.sh flags (no Mailpit needed).
`--project=chromium` gave 2 of 2 passed (JS and no-JS). All processes were stopped and the scratch dir deleted. A
Postgres e2e run is left to CI.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 - Blocking] Boxed `ConsentPage` in `ConsentStart::Started`**
- Found during: Task 1 (clippy `large_enum_variant` after adding the view).
- Fix: `page: Box<ConsentPage>`. The only consumer is ui/consent.rs, which is unaffected because the box derefs.
- Commit: e2d8494

**2. [Rule 1 - Test robustness] E2E redirect handling**
- A `page.route` stub and a `waitForRequest` approach both raced Chromium's error page when the next navigation
  started. Replaced with a small callback server started by the spec.
- Commit: 2231f24

No files outside `files_modified` were touched.

## Checks

- `rustfmt --edition 2024 --check` on all touched Rust files: clean.
- `cargo clippy -p anvil-core --all-targets -D warnings`: clean.
- `cargo clippy -p anvil-web --all-targets -D warnings`: **blocked by other plans' in-progress files**
  (`api_flows/native.rs` result_large_err, `ui/flow_driver.rs` dead code, `admin/branding.rs:1312` constant
  assertion). These are not in this plan's files. My anvil-web code compiles without warnings.
- `scripts/check-release-graph.sh`: OK. `scripts/check-deps.sh`: OK.
- `just doc`: the anvil-web step fails on another plan's private intra-doc link (`native` links to
  `FlowBinding::Token`). anvil-core docs, which contain my new links, build cleanly with
  `-D broken_intra_doc_links -D private_intra_doc_links`.
- `npx tsc --noEmit -p .` in tests/e2e: clean.

## Problems seen in other plans' files (for the orchestrator)

- `crates/anvil-core/src/service/flow.rs`: briefly did not compile mid-wave (a call with 5 arguments where the method
  takes 4). This resolved on its own.
- `crates/anvil-web/src/api_flows/native.rs`: clippy `result_large_err`, and a rustdoc private link to
  `FlowBinding::Token` (breaks `just doc`).
- `crates/anvil-web/src/ui/flow_driver.rs`: `FlowBinding::Token` is never constructed and `start_native_login` is
  unused (dead-code warnings, which clippy turns into errors).
- `crates/anvil-web/src/admin/branding.rs:1312`: clippy `assertions_on_constants`.
- `tests/e2e/specs/consent.spec.ts`: not prettier-clean under default settings. The repo has no prettier config or
  CI step, so this is informational only.

## Self-Check: PASSED

Commits e2d8494, 46f96d9, 2231f24 and both created files verified present.
