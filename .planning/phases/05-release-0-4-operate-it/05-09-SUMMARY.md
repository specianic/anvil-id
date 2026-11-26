---
phase: 05-release-0-4-operate-it
plan: 09
subsystem: oauth
tags: [rfc7591, dcr, cimd, draft-ietf-oauth-client-id-metadata-document-03, validation, proptest, cargo-fuzz]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 DcrSettings / ClientSource / NewClient registration fields / CoreError DCR variants; 05-02 pre-declared oauth::{registration,cimd}
provides:
  - "oauth::registration::validate(&Value, &DcrSettings, DcrMode) -> Result<ValidatedRegistration, CoreError> (pure RFC 7591)"
  - "ValidatedRegistration { client: ClientInput, options: ClientOptions, client_name, response_types, logo_uri, client_uri, policy_uri, tos_uri } + metadata() for the 201 response"
  - "oauth::cimd::check_url(&str, allow_http_loopback) and oauth::cimd::validate(url, body, &ServerCaps, allow_http_loopback) -> Result<NewClientMetadata, CimdError> (pure draft-03)"
  - "NewClientMetadata::to_new_client(id, created_at, metadata_expires_at, allowed_resources) -> NewClient (source cimd, consent required, PKCE, no secret)"
  - "fuzz bins registration_parse and cimd_parse"
affects: [05-15, 05-21, 05-25, 05-27]

tech-stack:
  added: []
  patterns:
    - "Self-service registration validators build a ClientInput and call service::client::validate_client (and validate_client_phase4 for DCR), so the client rules have one implementation; only registration-specific rules live in oauth::{registration,cimd}"
    - "JSON null counts as an absent metadata member in both validators"
    - "CIMD errors are fixed text (third-party input is never echoed); the service maps CimdError to CoreError"

key-files:
  created:
    - fuzz/fuzz_targets/registration_parse.rs
    - fuzz/fuzz_targets/cimd_parse.rs
  modified:
    - crates/anvil-core/src/oauth/registration.rs
    - crates/anvil-core/src/oauth/cimd.rs
    - fuzz/Cargo.toml

key-decisions:
  - "DcrMode is {AllowListed, Open} (disabled never reaches validation); the redirect-host allow-list applies only in AllowListed when the list is non-empty, also to post_logout_redirect_uris; hostless (private-use scheme) URIs are refused under a non-empty allow-list"
  - "DCR output is ClientInput + ClientOptions (what ClientService::create takes) rather than NewClient, so 05-21 creates clients through ClientService only"
  - "DCR native clients: loopback http (incl. localhost) or private-use scheme only, https refused (OIDC Registration 1.0 §2, as the plan states); web clients: https only, loopback http refused"
  - "DCR defaults: auth client_secret_basic, grants [authorization_code], response_types [code], scope = allowed_scopes minus admin scopes, allowed_resources = all DCR-allowed resources (so MCP clients registering via DCR can request their resource); empty allowed_scopes allows no scope (callers resolve tenant defaults first)"
  - "DCR resource metadata name is allowed_resources (our client field; RFC 7591 defines none)"
  - "Informational logo_uri/client_uri/policy_uri/tos_uri are validated (https, <= 2048 bytes) and echoed in ValidatedRegistration but NewClient has no columns for them; 05-21 decides whether to persist or just echo"
  - "CIMD: ServerCaps::default() = grants [authorization_code, refresh_token], response [code], auth [none, private_key_jwt], default_scopes [openid]; unknown grant/response values are dropped by intersection, an empty result is rejected; shared-secret methods are rejected whatever the caps say"
  - "CIMD redirect URIs follow the shared validate_redirect_uri rules (loopback http allowed, as MCP desktop clients need); application_type defaults to web"
  - "CIMD check_url compares the scheme literally (HTTPS:// refused) and rejects %2e-encoded dot segments and backslashes, never normalises"

patterns-established:
  - "Every rejection rule has a named negative unit test; proptests prove no panics; fuzz targets assert policy invariants on accepted outputs"

requirements-completed: []

duration: ~45min
completed: 2026-11-26
---

# Phase 5 Plan 09: Pure DCR and CIMD validators Summary

**Pure RFC 7591 registration validation and draft-03 Client ID Metadata Document URL/document validation. Both reuse the existing client, redirect and resource rules. Every rejection rule has a negative test, proptests show neither validator panics, and two new fuzz targets build and ran 60 s each without a crash.**

## Performance

- **Duration:** about 45 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2 (each RED -> GREEN; no refactor commit was needed)
- **Files:** 5 (2 core modules, 2 fuzz targets, fuzz/Cargo.toml)

## Accomplishments

### Task 1: RFC 7591 (`oauth::registration`)
- `validate(request, settings, mode)` returns `ValidatedRegistration` with substituted values, or `InvalidSoftwareStatement` / `InvalidRedirectUri` / `InvalidClientMetadata`.
- It calls `service::client::validate_client` and `validate_client_phase4`, which use `oauth::redirect::validate_redirect_uri` and `oauth::resource::parse_resources`. A `Validation{field: "redirect_uris"}` error maps to `invalid_redirect_uri`; every other field maps to `invalid_client_metadata`.
- `metadata()` returns the RFC 7591 §3.2.1 registered metadata (without client_id or secrets).

### Task 2: CIMD (`oauth::cimd`)
- `check_url` and `validate` follow the plan. `validate` calls `check_url` with the same flag first.
- `NewClientMetadata::to_new_client` builds the `upsert_cimd` row.
- `CimdError { InvalidUrl(&'static str), InvalidDocument(String), TooLarge }`. All messages are fixed text.

## Negative tests (security map)

**DCR** (`crates/anvil-core/src/oauth/registration.rs`):
- `dcr_software_statement_rejected`
- `dcr_jwks_uri_rejected` (alone, with jwks, with a secret method)
- `dcr_private_key_jwt_requires_inline_jwks`
- `dcr_jwks_without_private_key_jwt_rejected`
- `dcr_redirect_uri_rules_rejected` (http non-loopback, fragment, empty/missing, relative, wildcard, userinfo, too many)
- `dcr_web_client_loopback_http_rejected`
- `dcr_native_client_redirect_rules_rejected`
- `dcr_redirect_host_allow_list_enforced`
- `dcr_post_logout_redirect_uri_rules_rejected`
- `dcr_unknown_application_type_rejected`
- `dcr_client_credentials_without_allow_rejected`
- `dcr_unsupported_grant_types_rejected`
- `dcr_refresh_token_without_authorization_code_rejected`
- `dcr_public_client_credentials_rejected`
- `dcr_response_types_rejected`
- `dcr_unsupported_auth_methods_rejected`
- `dcr_admin_scope_never_registrable` (including a misconfigured allow-list)
- `dcr_scope_outside_allowed_scopes_rejected`
- `dcr_malformed_scope_rejected`
- `dcr_resource_outside_allowed_resources_rejected`
- `dcr_backchannel_logout_uri_must_be_https`
- `dcr_client_name_rules_rejected`
- `dcr_informational_uris_must_be_capped_https`
- `dcr_non_object_request_rejected`
- `dcr_wrongly_typed_metadata_rejected`
- proptest `dcr_validate_never_panics`

**CIMD** (`crates/anvil-core/src/oauth/cimd.rs`):
- `cimd_http_rejected_in_production_including_loopback`
- `cimd_dev_mode_accepts_only_loopback_http` (rejects example.com, 10.0.0.5, 192.168.1.1, ::ffff:127.0.0.1, localhost.example.com, 0.0.0.0)
- `cimd_url_shape_rules_rejected_in_both_modes` (userinfo, `/` path, no path, fragment, query, `..`/`.` and `%2e`, backslash, empty host, whitespace, uppercase scheme, other schemes, too long)
- `cimd_url_checked_before_document`
- `cimd_document_over_5k_rejected` (5121 bytes)
- `cimd_non_json_or_non_object_rejected`
- `cimd_client_id_mismatch_rejected` (trailing slash, host case, path case, explicit :443, missing, non-string)
- `cimd_client_secret_rejected`
- `cimd_shared_secret_method_rejected`
- `cimd_unsupported_auth_method_rejected`
- `cimd_jwks_uri_rejected`
- `cimd_private_key_jwt_requires_inline_jwks`
- `cimd_missing_or_bad_redirect_uris_rejected`
- `cimd_empty_grant_intersection_rejected`
- `cimd_empty_response_type_intersection_rejected`
- `cimd_refresh_token_without_authorization_code_rejected`
- `cimd_admin_scope_rejected`
- `cimd_client_name_rules_rejected`
- `cimd_bad_application_type_or_post_logout_rejected`
- proptests:
  - `cimd_validate_never_panics_on_bytes`
  - `cimd_check_url_never_panics`
  - `cimd_accepted_url_is_https_or_dev_loopback`
  - `cimd_validate_never_panics_on_documents`

## Task Commits

1. `37fc195` test(05-09): failing tests for RFC 7591 registration validation
2. `f99db03` feat(05-09): RFC 7591 registration validation + registration_parse fuzz target
3. `b480036` test(05-09): failing tests for CIMD URL and document rules
4. `0b36653` feat(05-09): CIMD URL and document validation + cimd_parse fuzz target

## Verification run

- `cargo test -p anvil-core --lib oauth::registration`: 36 passed
- `cargo test -p anvil-core --lib oauth::cimd`: 32 passed
- `cargo test -p anvil-core --lib oauth::`: 194 passed
- `cargo check --manifest-path fuzz/Cargo.toml --locked --bins`: OK. fuzz/Cargo.lock did not change.
- `scripts/fuzz.sh run registration_parse 60`: about 4.3M runs, no crash. `scripts/fuzz.sh run cimd_parse 60`: about 1.8M runs, no crash. Generated corpora deleted afterwards.
- `cargo clippy -p anvil-core --lib --tests`: no findings in these files. The two remaining warnings, unused `pkcs8` and `msg`, come from other wave-3 plans' in-progress files.
- `rustfmt --check --edition 2024` on all four files: OK.

## Not run

- The full workspace test suite (targeted runs only, per the shared rules). Nothing in this plan needs Docker or Postgres.

## Deviations from Plan

None in scope or files. Interpretation notes for downstream plans:
- **DcrMode** was not specified by the plan. It is `{AllowListed, Open}`, because a disabled policy never reaches validation.
- **jwks_uri:** research Pattern 3 accepts `jwks_uri` for CIMD `private_key_jwt`. The plan and 05-CONTEXT reject it in 0.4, and the code follows the plan. The 0.4 limitation still needs documenting (05-25 MCP.md, 05-27 UPGRADING).
- **CimdError -> CoreError:** no mapping was added. error.rs is not owned by this plan, so 05-15 maps the error at the service boundary, as planned.
- **Empty `allowed_scopes`:** DcrSettings says an empty list means "tenant defaults". `validate` cannot know those defaults, so it fails closed. 05-21 must fill `allowed_scopes` before calling `validate`.
- **Proptest regression seeds:** the RED runs (`todo!()` bodies) left seed files. They were deleted and not committed.

## Self-Check: PASSED
- FOUND: crates/anvil-core/src/oauth/registration.rs (1189 lines), crates/anvil-core/src/oauth/cimd.rs (906 lines), fuzz/fuzz_targets/registration_parse.rs, fuzz/fuzz_targets/cimd_parse.rs
- FOUND commits: 37fc195, f99db03, b480036, 0b36653
