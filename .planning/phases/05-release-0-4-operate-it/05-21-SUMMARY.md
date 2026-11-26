---
phase: 05-release-0-4-operate-it
plan: 21
subsystem: oauth, protocol
tags: [rfc7591, rfc7592, dcr, initial-access-token, registration-access-token, discovery, ratelimit, oidc-17]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 DcrSettings/ClientSource/RegistrationRepo/ClientRepo RAT methods; 05-02 pre-declared modules; 05-05 limiter; 05-09 oauth::registration::validate; 05-15 client source handling
provides:
  - "RegistrationService { storage, clock, redirect_validator }: register / read / update / delete (RFC 7591/7592) and issue_iat / list_iats / revoke_iat"
  - "service::registration::{effective_settings, DEFAULT_DCR_SCOPES, client_metadata, client_information, registration_client_uri, IatRequest, IssuedIat, Registration}"
  - "ClientService::{create_dynamic, update_dynamic, delete_dynamic} (one insertion path; DCR audit actions)"
  - "POST /register, GET/PUT/DELETE /register/{client_id}; discovery registration_endpoint per policy; /register* in the Auth rate class"
affects: [05-23, 05-24, 05-25, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Tenant policy read per request; disabled -> the fallback's 404 page before body or token is read"
    - "IAT verified without consuming before validation, consumed atomically after validation and the cap check"

key-files:
  created:
    - crates/anvil-web/tests/registration_dcr.rs
    - crates/anvil-web/tests/security_registration.rs
    - crates/anvil-web/tests/dcr_support/mod.rs
  modified:
    - crates/anvil-core/src/service/registration.rs
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-web/src/protocol/registration.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/src/protocol/userinfo.rs
    - crates/anvil-web/src/layers/ratelimit.rs
    - crates/anvil-web/tests/discovery.rs

key-decisions:
  - "Empty dcr.allowed_scopes resolves to DEFAULT_DCR_SCOPES (openid profile email address phone), shared with discovery scopes_supported, before oauth::registration::validate"
  - "logo_uri/client_uri/policy_uri/tos_uri are validated but neither stored nor echoed: the 201 and the RFC 7592 read must show the same registered metadata, and the client model has no columns for them"
  - "IAT checked (not consumed) before metadata validation so unauthenticated callers only see 401; consumed atomically after validation and the max_clients check, so a rejected request does not burn a single-use token"
  - "IATs always expire: default 24 h, 1 min..365 d; uses 1..100000 or unlimited; never issued for the system tenant"
  - "RFC 7592 endpoints also 404 when the policy is disabled; a wrong token, an unknown client and a static/CIMD client all answer 401"
  - "PUT must carry the matching client_id, must not carry registration_access_token/registration_client_uri/client_id_issued_at/client_secret_expires_at, an included client_secret must match; token_endpoint_auth_method and application_type are fixed; the redirect-host allow-list binds updates too"
  - "Request bodies must be application/json (blocks cross-site form registration without a CORS preflight)"
  - "/register and below are Auth class for any method (superset of the plan's POST), with the OAuth JSON 429"
  - "max_clients is a soft cap (count before insert)"

requirements-completed: []

duration: ~55min
completed: 2026-11-26
---

# Phase 5 Plan 21: Dynamic client registration (RFC 7591/7592) Summary

**Dynamic registration follows the tenant policy. `disabled` and the system tenant get a 404 and no discovery entry. `allow_listed` needs a hashed, expiring initial access token with an optional use count, consumed atomically, and enforces the redirect-host allow-list. `open` needs no token. All policies are rate limited in the Auth class and capped by `max_clients`. RFC 7592 read/replace/delete need a 256-bit registration access token that is stored hashed. 18 named refusal tests run over HTTP and 24 unit tests run in core.**

## Endpoint behaviour

| Request | Result |
| ------- | ------ |
| any `/register*` while the effective policy is `disabled` (always for `system`) | 404 page of a missing route; discovery has no `registration_endpoint` |
| `POST /register`, `allow_listed`, no / malformed / unknown / expired / revoked / used-up / other-tenant IAT | 401 `invalid_token`, `WWW-Authenticate: Bearer error="invalid_token"` (before the body is validated) |
| `POST /register`, bad metadata | 400 `invalid_redirect_uri` / `invalid_client_metadata` / `invalid_software_statement` |
| `POST /register`, not `application/json` or invalid JSON | 400 `invalid_client_metadata`; bodies over 64 KiB are 413 |
| `POST /register`, `max_clients` reached | 400 `invalid_client_metadata` ("this tenant has reached its limit of N dynamically registered clients") |
| `POST /register` OK | 201, `Cache-Control: no-store`: registered metadata (substituted values) + `client_id`, `client_id_issued_at`, `registration_client_uri` (`{issuer}/register/{client_id}`), `registration_access_token`, and `client_secret` + `client_secret_expires_at: 0` for secret-based auth methods |
| `GET /register/{id}` with the RAT | 200 client information (no secret or RAT) |
| `PUT /register/{id}` with the RAT | 200 after the full metadata is replaced. The constraints are listed under the decisions above |
| `DELETE /register/{id}` with the RAT | 204. `ClientRepo::delete` revokes the token families |
| GET/PUT/DELETE: missing or wrong RAT, unknown client, static or CIMD client | 401 `invalid_token` (a PUT gets this before its body is read) |

Dynamic clients are stored with `registration_source = dynamic`, `consent_mode = required` and PKCE required. Audit: `client_registered`, `client_registration_updated` and `client_registration_deleted` (actor: the client, target: the client_id), plus `initial_access_token_created` and `initial_access_token_revoked` (actor: the admin, target: the token id).

## Security tests (`crates/anvil-web/tests/security_registration.rs`)

`dcr_disabled_returns_404`, `dcr_system_tenant_always_disabled`, `dcr_allow_listed_requires_initial_access_token`, `dcr_initial_access_token_single_use`, `dcr_rejected_metadata_keeps_the_single_use_token`, `dcr_expired_initial_access_token_refused`, `dcr_revoked_initial_access_token_refused`, `dcr_initial_access_token_hashed_at_rest`, `dcr_redirect_host_allow_list_enforced`, `dcr_software_statement_rejected`, `dcr_admin_scope_never_registrable`, `dcr_metadata_and_request_shape_rejected`, `dcr_registration_access_token_required`, `dcr_wrong_registration_access_token_401`, `dcr_static_client_not_manageable`, `dcr_update_constraints_rejected`, `dcr_rate_limited`, `dcr_max_clients_enforced`.

Core unit tests (`service::registration`) use an in-memory fake for clients, registration and audit. They cover the same refusals, and in addition: IAT input validation, the max_clients refusal leaving the token unconsumed, RFC 7592 unavailable for static clients, tenant isolation of IATs and RATs, and `client_metadata` equal to the 05-09 validator's `metadata()`.

Functional tests (`registration_dcr.rs`):
- register, read, update, delete, with hashes at rest and audit rows;
- a public client gets no secret;
- informational URIs are not echoed;
- a registered client completes code + PKCE through consent;
- allow-listed registration with a two-use IAT;
- path tenant issuer.

The discovery tests check that `registration_endpoint` follows the policy on both well-known forms and is never published for the system tenant.

## Task Commits

1. `831d766` feat(05-21): RegistrationService for RFC 7591/7592 and initial access tokens
2. `79ace5d` feat(05-21): RFC 7591/7592 endpoints, discovery registration_endpoint, Auth rate class

## Verification run

- `cargo test -p anvil-core --lib service::registration`: 24 passed. `cargo test -p anvil-core --lib service::`: 293 passed, which includes the ClientService tests after the refactor.
- `cargo test -p anvil-web --test registration_dcr --test security_registration --test discovery --test security_ratelimit`: 6, 18, 12 and 13 passed. Unit tests `--lib ratelimit` (4) and `--lib discovery` (3) passed.
- Regression: `--test admin_api --test userinfo --test security_userinfo --test cimd --test security_cimd` all pass.
- `cargo clippy -p anvil-core --lib --tests` and `cargo clippy -p anvil-web --lib --tests`: no findings in this plan's files. `rustfmt --edition 2024` was run on every touched file.
- `grep -rn registration_endpoint crates/anvil-web/src` matches only discovery.rs.

## Not run

- Postgres backend runs (`ANVILID_TEST_DB=postgres`), e2e and conformance. Docker is not available here, so these are left for CI. The default `/.well-known` document is unchanged, because the DCR default is disabled.
- The full workspace suite. Only targeted runs were done, per the shared rules.

## Deviations from Plan

### Auto-fixed / forced

**1. [Rule 3 - Blocking] ClientService could not create dynamic clients** (forced extra file `crates/anvil-core/src/service/client.rs`)
- `ClientService::create` hardcoded `registration_source = Static`, had no RAT hash, and audited `client_created`. The plan says to create clients only through ClientService.
- Fix: one private `insert` path that `create` and the new `create_dynamic` both use. `update` and `delete` share bodies with the new `update_dynamic` and `delete_dynamic`, which record the DCR audit actions with the client as actor. Admin behaviour is unchanged. No other wave-5 plan owns client.rs.

**2. [Rule 2 - One implementation] Bearer header parsing** (forced extra `crates/anvil-web/src/protocol/userinfo.rs`)
- `bearer_from_header` was made `pub(crate)` and reused, so no third bearer parser was added. The change is one visibility word plus a doc line.

**3. Shared test helper** (forced extra `crates/anvil-web/tests/dcr_support/mod.rs`)
- Policy switches, IAT issuance, JSON requests and audit reads are shared by `registration_dcr.rs` and `security_registration.rs`, following the `cimd_support` precedent.

**4. Interpretation choices**
- Rate class: the plan says to classify POST `/register` and `/register/*` as Auth. This plan applies Auth to every method under `/register`, a superset. `/register` was also added to the protocol 429 surface (OAuth JSON).
- `application/json` is required on POST and PUT. RFC 7591 specifies it, and the requirement blocks cross-site HTML form registration.
- Informational URIs are neither stored nor echoed. The prompt asked for this decision, and the reasons are under key-decisions.
- The plan's test name `dcr_wrong_registration_access_token_401` is kept. The core-level equivalent is `dcr_wrong_registration_access_token_refused`.
- TDD: each task's tests were written alongside the implementation and committed together (no separate RED commit). Every refusal still has a named failing-input test.
- During Task 2 the build was briefly broken by 05-20's in-progress `service/config.rs` (duplicate `configured`). It resolved on its own within minutes, and no workaround was applied.

## Deferred items logged

Three entries were added to `deferred-items.md`:
- the docs facts for 05-25/05-27 (scopes default, informational URIs, IAT bounds, soft cap, rate class);
- the security test names for `scripts/check-security-tests.sh` (05-28);
- the IAT API for the 05-23 admin routes.

## Self-Check: PASSED
