---
phase: 06-release-1-0-orgs-and-sso
plan: 18
subsystem: auth
tags: [saml, sso, organizations, jit, replay-guard, acs, org-03]

requires:
  - phase: 06-05
    provides: "saml::request (authn_request, relay_state, split_relay_state, sp_metadata), saml::validate (check, replay_key, replay_expiry, SamlReject codes)"
  - phase: 06-09
    provides: "SamlXmlAdapter (verify_response, encode_redirect) and the tests/saml_support test IdP"
  - phase: 06-14
    provides: "UpstreamService::complete_identity (shared completion; SAML gets upstream_verified = None)"
  - phase: 06-04
    provides: "saml_experimental flag, empty ui::saml routers, ReplayKind::SamlAssertionId, saml_login_* audit actions"
provides:
  - "SamlService { flows, accounts, client, saml_xml, enabled }: start, acs, continue_login, sp_metadata"
  - "LoginState.saml: SamlPending (flow/login.rs) with with_saml / take_saml and SAML_PENDING_TTL (10 min)"
  - "service::saml helpers: sp_entity_id, acs_url, metadata_url, continue_url, xml_reason, decode_response, redirect_url"
  - "Routes: POST /ui/login/saml/{slug}/start?flow=, POST /ui/login/saml/{slug}/acs, GET /ui/login/saml/{slug}/continue?state=, GET /saml/{slug}/metadata"
  - "admin::branding::SAML_ACS_BODY_LIMIT (256 KiB) and is_saml_acs in the one body-limit layer"
affects: [06-22 (home-realm discovery posts the SAML start), 06-26 (gate: security map entries)]

tech-stack:
  added: []
  patterns:
    - "ACS: cheap RelayState checks first, then pending request consumed by compare-and-swap, then XML verify, then core check, then the DB replay guard, then the sealed identity swapped back in"
    - "Continue: binding cookie proves the browser before the flow changes; binding_proved decides whether the cookie is cleared (as in the upstream callback)"

key-files:
  created:
    - crates/anvil-web/tests/saml_login.rs
    - themes/default/locales/en/saml.ftl
    - themes/default/locales/de/saml.ftl
  modified:
    - crates/anvil-core/src/service/saml.rs
    - crates/anvil-core/src/flow/login.rs
    - crates/anvil-web/src/ui/saml.rs
    - crates/anvil-web/src/admin/branding.rs
    - crates/anvil-web/src/ui/upstream.rs

key-decisions:
  - "SamlPending carries binding_hash and identity_sealed in addition to the planned fields; the RelayState hash is stored as relay_state_hash (hash of the whole RelayState)"
  - "The pending request is consumed by CAS once the RelayState hash matches, before any XML is parsed; a wrong nonce consumes nothing (an attacker without the nonce cannot burn a sign-in)"
  - "The ACS body limit is a branch of the existing body-limit middleware (admin/branding.rs), because the global 64 KiB RequestBodyLimitLayer cannot be raised by a route layer"
  - "Line breaks in SAMLResponse are dropped before strict standard base64 decoding (some IdPs wrap lines)"
  - "saml_login_succeeded is audited at the continue step once the binding is proved, right before the shared completion (which audits its own failures as upstream_login_failed)"
  - "Tenant (non-org) SAML connections take email_verified from trust_email_verified; org connections always get the verified-domain rule in complete_identity"

requirements-completed: []

duration: about 1h15m
completed: 2026-11-26
---

# Phase 6 Plan 18: SAML login (SP-initiated, ACS, replay guard, JIT) Summary

**SAML 2.0 SP sign-in now works end to end behind `saml_experimental`. The start sends an unsigned HTTP-Redirect AuthnRequest with a 59-byte RelayState and sets the Lax binding cookie. The ACS validates fully, records the assertion ID in the database replay guard and seals only the extracted identity into the flow. The continue step requires the binding cookie and hands off to the shared upstream completion: JIT user, link and org membership, the verified-domain email trust, the MFA policy and the session. Every flow-level refusal has a named test.**

ORG-03 is prepared, not ticked (wave rule; the gate ticks REQUIREMENTS.md).

## Task Commits

1. `7a8d871` feat(06-18): 256 KiB body limit for the SAML ACS only (admin/branding.rs, committed early because 06-17 shares the file)
2. `8eebbed` feat(06-18): SamlPending login flow state with take/with helpers (flow/login.rs, committed early because 06-22 shares the file)
3. `9442104` feat(06-18): SamlService start, ACS, continue and SP metadata (Task 1)
4. `7d61cfc` feat(06-18): SAML start, ACS, continue and metadata routes with flow-level tests (Task 2)

TDD: I wrote the tests with each task and ran them before committing, with no separate RED commit, because peers build the same tree (same practice as 06-05 and 06-09).

## Routes

| Route | Layer | Behaviour |
|---|---|---|
| `POST /ui/login/saml/{slug}/start?flow=` | CSRF | `csrf_token` + flow cookie. Answers 303 to the IdP SSO URL (its own query kept, then `SAMLRequest`, `RelayState`) and sets the binding cookie. `ForceAuthn="true"` when the authorization request has `prompt=login`. |
| `POST /ui/login/saml/{slug}/acs` | outside CSRF | `SAMLResponse`, `RelayState`. Reads and sets no cookie. Body limit 256 KiB, 413 above. Answers 303 to continue, or the generic 400 page. |
| `GET /ui/login/saml/{slug}/continue?state=` | CSRF | Binding cookie required. Renders through `ui::upstream::outcome_page` (signed in / RP redirect, second factor, enrolment, link confirmation). |
| `GET /saml/{slug}/metadata` | CSRF (GET) | Unsigned SP metadata, `application/samlmetadata+xml`, only for enabled SAML connections. |

SP identifiers: entity ID `{issuer}/saml/{slug}`, ACS `{issuer}/ui/login/saml/{slug}/acs`. With the flag off, every route answers 404 and every `SamlService` method returns `FeatureDisabled("saml")`.

## Reason codes (`saml_login_failed`, reason only)

- Flow: `relay_state` (missing, malformed, unknown flow, or hash mismatch, which also covers unsolicited / IdP-initiated responses), `no_pending_request` (none, already used, CAS lost), `expired` (more than 10 minutes), `connection_mismatch`, `connection_disabled`, `binding` (continue: no or foreign cookie), `state_invalid` (sealed identity does not open), `replay` (assertion ID already in replay_guard).
- Decoding: `encoding`, `size`.
- XML (`SamlXmlReject`): `size`, `parse`, `dtd`, `structure`, `duplicate_id`, `encrypted`, `signature_profile`, `algorithm`, `signature`, `untrusted_key`, `unavailable`.
- Assertion (`SamlReject`): the 21 codes from 06-05 (for example `audience_mismatch`, `transient_name_id`, `in_response_to_mismatch`).

## Tests (`cargo test -p anvil-web --test saml_login`: 19 passed)

Happy paths:
- `saml_login_happy_path_jit_creates_user_link_membership` covers the start shape and the ACS (no cookie set, no session yet). The continue step then returns the RP a code, and the ID token `amr` is `["fed"]`. The JIT user has the mapped names and a trusted email (verified org domain), plus one link with the NameID subject and the org membership. Audit: `saml_login_succeeded` and `org_member_added`.
- `saml_existing_linked_user_signs_in`
- `saml_tenant_mfa_policy_applies` (tenant `Required` puts the user on the enrolment form, with no session)
- `saml_sp_metadata_served`
- `saml_force_authn_on_prompt_login`

Negative tests:
- `saml_unsolicited_response_is_refused`
- `saml_acs_for_other_connection_is_refused` (`connection_mismatch`; A's pending request is consumed)
- `saml_acs_without_binding_cookie_at_continue_is_refused`
- `saml_continue_with_foreign_binding_cookie_is_refused`
- `saml_replayed_response_is_refused`
- `saml_replayed_response_is_refused_across_instances`: a second router (`AppState::new`) on the same storage and KEK. The re-POST is refused. With the pending request put back into the flow, it is still refused with `replay` from the database `replay_guard`.
- `saml_response_for_other_flow_is_refused`
- `saml_pending_request_expires`
- `saml_wrong_audience_is_refused_with_generic_page`
- `saml_transient_name_id_is_refused`
- `saml_unsigned_or_foreign_signed_response_is_refused`
- `saml_foreign_domain_email_is_untrusted`
- `saml_acs_body_over_256_kib_is_413` (a 100 KiB body is still read at the ACS; `/ui/login` keeps 413 for the same body)
- `saml_routes_404_when_flag_off` (all four routes, plus the service methods directly)

Unit tests:
- core `service::saml` (6): identifiers, redirect URL query, strict/capped decoding, XML reason codes, identity mapping, sealed identity bound to its flow and tenant.
- core `flow::login` (3): identify-step-only storage, single take and JSON round trip, 10-minute expiry.
- web `admin::branding::saml_acs_paths`.

Mutation check: I temporarily disabled the replay check and the binding check. `saml_replayed_response_is_refused_across_instances` and both binding tests failed. I then restored the file (no diff).

## Files Created/Modified (beyond files_modified)

- `crates/anvil-web/src/admin/branding.rs` (06-17's file): `SAML_ACS_BODY_LIMIT` and `is_saml_acs` plus one branch in `body_limit`, with a unit test. The global 64 KiB `RequestBodyLimitLayer` sits in this one middleware, so a route-level `DefaultBodyLimit` could not raise it. It was committed on its own right away (`7a8d871`).
- `crates/anvil-web/src/ui/upstream.rs`: `outcome_page` is now `pub(super)`, so the SAML continue step renders `UpstreamOutcome` through the one existing implementation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The ACS body limit could not live on the route.** See above. It is a branch of the existing body-limit middleware instead of `DefaultBodyLimit` on the route.

**2. [Rule 2 - Missing critical] `SamlPending` needs the binding hash and the sealed identity.** The planned fields (`connection_id, request_id, relay_nonce_hash, created_at`) cannot support the continue step. I added `binding_hash` and `identity_sealed`, and named the RelayState hash `relay_state_hash`.

### Interpretations

- Unknown flow and nonce mismatch both report `relay_state`. A response whose `InResponseTo` names another flow's request reaches core validation and reports `in_response_to_mismatch`.
- After a completed sign-in the flow is gone, so a later replay reports `relay_state`, not `no_pending_request`. The test pins this.
- The plan says "two TestApps on one database file". The harness's SQLite is in-memory, so the second instance is a second `AppState`/router on the same `Arc<dyn Storage>`. That is the same database, and it also works on the Postgres backend.
- Extra tests beyond the plan list: `saml_transient_name_id_is_refused` (requested by the orchestrator) and `saml_unsigned_or_foreign_signed_response_is_refused`.

## Verification (main tree, SQLite)

- `cargo test -p anvil-core --lib`: 987 passed (`service::saml` + `flow::login`: 44)
- `cargo test -p anvil-web --test saml_login --test i18n_catalogs --test security_body_limit --test security_saml --test upstream_login --test enterprise_oidc --test upstream_buttons`: 19 + 4 + 5 + 67 + 15 + 7 + 7, all passed
- `cargo test -p anvil-web --lib admin::branding`: 2 passed
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean for this plan's files. The only error was in 06-17's in-progress `service/connection.rs` (type_complexity).
- `cargo clippy -p anvil-web --lib --test saml_login -- -D warnings`: clean. `--all-targets` failed only in 06-17's in-progress `tests/admin_org_sso.rs`.
- `scripts/check-release-graph.sh`: OK. `scripts/check-deps.sh`: OK. `scripts/check-security-tests.sh`: OK (632 pairs; Phase 6 SAML entries belong to the gate).
- `rustfmt --edition 2024` on every touched Rust file.

## Not run

- `ANVILID_TEST_DB=postgres` for `saml_login` (Docker is not used under the wave rules; left for CI). No SQL was added; `record_jti` with `SamlAssertionId` is covered on Postgres by the 06-04/06-08 contract test `record_jti_saml_assertion_id_replay`.
- e2e/Playwright (`specs/saml.spec.ts` is not in this plan) and conformance.

## Next Phase Readiness

- 06-22 can post `POST /ui/login/saml/{slug}/start?flow=` with the page's CSRF token when a routed domain's connection is SAML.
- 06-26 security map candidates: `saml_login::saml_unsolicited_response_is_refused`, `saml_replayed_response_is_refused_across_instances`, `saml_acs_for_other_connection_is_refused`, `saml_acs_without_binding_cookie_at_continue_is_refused`, `saml_continue_with_foreign_binding_cookie_is_refused`, `saml_transient_name_id_is_refused`, `saml_routes_404_when_flag_off`.

## Self-Check: PASSED

- FOUND: crates/anvil-core/src/service/saml.rs (`pub struct SamlService`, `verify_response`, `complete_identity`, `SamlAssertionId`), crates/anvil-web/src/ui/saml.rs (`/acs`), crates/anvil-web/tests/saml_login.rs (`saml_replayed_response_is_refused_across_instances`), themes/default/locales/{en,de}/saml.ftl
- FOUND commits: 7a8d871, 8eebbed, 9442104, 7d61cfc
