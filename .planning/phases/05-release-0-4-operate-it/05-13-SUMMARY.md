---
phase: 05-release-0-4-operate-it
plan: 13
subsystem: consent
tags: [consent, rfc8707, resource-indicators, cimd, mcp, i18n]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-12: AuthorizationParams.resource, ConsentPage.resources, consent 'Access to' list"
  - phase: 05-release-0-4-operate-it
    provides: "05-01: ConsentGrant/NewConsent.resources, normalize_resources, Client.registration_source; 05-02: upsert_consent merges resources, upsert_cimd; 05-06/05-07: both backends store and merge consent resources"
provides:
  - "Remembered consent covers resources: Skip only when the grant covers every requested scope AND every requested resource"
  - "Allow stores the requested resources in the same upsert_consent as the scopes (normalized, merged as a sorted set by the backend)"
  - "flow::consent::{ConsentCoverage, missing_resources}; PendingConsent.resources (serde default, omitted when empty)"
  - "ConsentService::decide takes the requested resources; ConsentPage.cimd_host; service::consent::cimd_host"
  - "Consent screen for CIMD clients: host as identity, unverified name, initials avatar, no images"
affects: [05-15, 05-agt-01, 05-agt-02]

tech-stack:
  added: []
  patterns:
    - "Consent coverage is one pure check over scopes and resources (ConsentCoverage::covers); the service only loads the grant"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/flow/consent.rs
    - crates/anvil-core/src/service/consent.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/ui/consent.rs
    - themes/default/templates/consent.html
    - themes/default/locales/en/resource.ftl
    - themes/default/locales/de/resource.ftl
    - crates/anvil-web/tests/consent.rs

key-decisions:
  - "Resources are compared exactly (they were validated against allowed_resources at /authorize); no URL normalisation in the consent check"
  - "The requested resources travel in PendingConsent (what the screen showed), not re-read from the request at Allow; the field is serde(default) so in-flight 0.3 consent flows still deserialize"
  - "A 0.3 grant (empty resources) skips for resource-less requests and asks once for the first request with a resource"
  - "Re-grant after revocation holds only the new resources (the backend replaces a revoked row instead of merging), so revocation clears resources with the grant"
  - "CIMD identity: consent-client (the legend) is the client_id host (with a non-default port); client_name is shown separately with '(name not verified)' and a note; the avatar is up to two initials of the name (host fallback). The page has no <img> at all"
  - "Resources keep their full escaped URI in <bdi><code> (host and path, plus scheme): dropping the scheme would hide http vs https, and the 04-12 assertion in resource_indicators.rs (not owned here) checks the full value"

patterns-established:
  - "CIMD-originated text on user-facing pages is displayed as unverified and never fetched from the client's servers"

requirements-completed: [ORG-05, AGT-01, AGT-02]

duration: about 45min
completed: 2026-11-26
---

# Phase 5 Plan 13: Resource-aware Remembered Consent and CIMD Consent Display Summary

**Stored consent now covers RFC 8707 resources: a remembered grant skips the screen only when it covers every requested scope and resource, Allow merges the requested resources into the grant in the same upsert, and 0.3 grants ask once for the first resource. CIMD clients are named on the consent screen by their client_id host, with their self-asserted name labelled unverified and an initials avatar instead of a logo.**

Note: `requirements-completed` lists the plan's requirement ids; no checkbox in REQUIREMENTS.md was ticked (wave rule).

## Accomplishments
- `flow::consent`: `ConsentCoverage { scopes, resources }` with `covers()`, `missing_resources`, and `consent_decision(mode, Option<ConsentCoverage>, ConsentCoverage, prompt)`. `PendingConsent.resources` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`).
- `service::consent`: `decide(..., requested, resources, prompt)` compares against `grant.resources`. `start` puts `request.params.resource` into the pending state and sets `ConsentPage.cimd_host` for `ClientSource::Cimd`. `approve` sends `normalize_resources(&pending.resources)` in `NewConsent`. The module docs and the `ConsentPage::resources` doc no longer describe a Phase 5 gap. No fields were added to `ConsentService`.
- `ui/consent.rs`: passes `cimd_host` and `client_initials` to the template. `initials()` is unit-tested.
- `consent.html`: a CIMD block (`consent-cimd`, `consent-avatar`, `consent-client-name`, `consent-cimd-unverified`, `consent-cimd-note`), and the legend's `consent-client` is the host for CIMD clients. Static and dynamic clients render exactly as before.
- Catalogs: `consent.cimd_unverified` and `consent.cimd_note` in en and de (`resource.ftl`).

## Task Commits
1. **Task 1: resource-aware remembered consent (core)** in `82059e5` (feat). It also contains the core part of Task 2 (`ConsentPage.cimd_host`, `cimd_host()`) and the one-call change in `service/authorize.rs`.
2. **Task 2: consent screen for CIMD clients plus the Task 1 integration tests** in `2cba25f` (feat).

TDD note: the core unit tests and the implementation went into one commit, so there was no separate RED commit. The new integration tests check the stored `resources` and the re-prompt, which the old code (it always stored `resources: Vec::new()`) fails.

## Verification (main tree, SQLite)
- `cargo test -p anvil-core --lib`: 755 passed. New tests: `a_grant_covering_scopes_and_resources_skips`, `a_new_resource_requires_consent` (including prompt=none giving consent_required, exact comparison, and skip_first_party), `a_grant_without_resources_asks_once_for_a_resource`, `pending_resources_are_omitted_when_empty_and_default_when_absent`, `cimd_host_is_the_client_id_host_with_a_non_default_port`.
- `cargo test -p anvil-web --test consent`: 19 passed (6 new):
  - `remembered_consent_covers_resources_and_a_new_resource_asks_again`: grant {openid, profile} + MCP is remembered. A new resource re-prompts and the screen lists it. prompt=none gives consent_required. Allow then stores [MCP, OTHER] sorted. A new scope with a granted resource still prompts.
  - `deny_does_not_add_the_resource`
  - `a_grant_without_resources_asks_once_for_a_resource` (a 0.3 grant written through upsert_consent)
  - `revoking_consent_revokes_families_and_clears_resources`
  - `a_cimd_client_is_named_by_its_host_with_an_unverified_name_and_no_remote_logo` (host, the escaped name `Acme &lt;Bank&gt;`, the en and de unverified label, AB initials, no `<img`, resources listed)
  - `a_static_client_has_no_cimd_block`
- `cargo test -p anvil-web` with `--test resource_indicators` (15), `--test i18n_catalogs` (4), `--test security_csp` (1), `--test i18n` (18), `--test account_apps` (4), `--test authorize_prompt` (18), and `--lib` (167): all green.
- `cargo clippy -p anvil-core -p anvil-web --lib --test consent -- -D warnings`: clean for this plan's files. Two lints in other wave-4 plans' in-progress files (`service/role.rs` unfulfilled expectation, `ui/account_attributes.rs` type_complexity) had to be allowed on the command line to get past them.
- Snapshots: no insta snapshot covers the consent page, so none needed review.

## Not run
- `ANVILID_TEST_DB=postgres` for consent and resource_indicators (Docker unavailable). CI will verify them. The Postgres merge of consent resources is covered by 05-07's contract tests.
- Playwright e2e (needs Docker).
- The full `cargo test -p anvil-web` suite (targeted binaries only, per the disk rule).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] One-call change in service/authorize.rs (owned by 05-15 this wave)**
- **Found during:** Task 1
- **Issue:** `ConsentService::decide` only received the requested scopes. The plan said to keep the change internal, but the resources can only reach `decide` from its caller, `AuthorizeService::consent_needed`.
- **Fix:** added a `resources` parameter to `decide`. `consent_needed` now passes `&params.resource`. This was the only change in authorize.rs, committed in `82059e5` while authorize.rs had no other uncommitted edits, so none of 05-15's work went into that commit. The hunk is still present in the working tree.
- **Files modified:** crates/anvil-core/src/service/authorize.rs (forced extra)
- **Commit:** 82059e5

### Notes
- No CSS was added for `.anvil-avatar` / `.anvil-consent-cimd` because `themes/default/static/anvil.css` is not in this plan's files. Without CSS the initials render as plain text, which is still correct and safe. A follow-up can style them.
- Resources are shown with their full URI rather than as host and path only. The reason is in key-decisions.

## Next Phase Readiness
- MCP clients (AGT-01/02) are asked again whenever they request a new audience.
- 05-15's materialised CIMD clients get the host-first consent screen with no further changes.

## Self-Check: PASSED
- Files exist: every file under key-files.modified
- Commits in history: 82059e5, 2cba25f
