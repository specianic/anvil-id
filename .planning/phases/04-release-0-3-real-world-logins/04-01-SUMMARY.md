---
phase: 04-release-0-3-real-world-logins
plan: 01
subsystem: core
tags: [domain-model, storage-ports, contract-tests, jose, pem, email-otp, backchannel-logout, fluent, moka]

requires:
  - phase: 03-release-0-2-secure-by-default
    provides: intent-method storage ports, TRANSITIONAL pending.rs pattern, AuditAction/AuditDetails, Kek::derive_key, single base64 (anvil_jose::encoding)
provides:
  - Every Phase 4 domain type (connections, identity links, branding, RP sessions, logout deliveries, MfaPolicy, resource indicators, FlowKind::Logout, SelfServiceKind::EmailChange, 3 EmailKinds, 15 AuditActions, AMR_FED)
  - ConnectionRepo, BrandingRepo, LogoutRepo, SessionRepo::upgrade_auth, UserRepo::complete_email_change, UpstreamClient port
  - CoreError::InvalidTarget and CoreError::UnmetAuthenticationRequirements in the single mapping
  - anvil_jose::email_code (generate/normalize/hash) and anvil_jose::pem (the single PEM parser, SigningKey::from_pkcs8_pem)
  - Pre-declared empty core modules for 04-07, 04-08, 04-09, 04-11, 04-13, 04-18, 04-21, 04-24
  - Shared contract suite for every new method (32 tests) and TRANSITIONAL(04-04)/(04-05) backend shims
  - fluent-bundle, fluent-langneg, unic-langid, moka declared for anvil-web
affects: [04-04, 04-05, 04-07, 04-08, 04-09, 04-11, 04-13, 04-15, 04-18, 04-21, 04-24]

tech-stack:
  added: [fluent-bundle 0.16.0, fluent-langneg 0.14.2, unic-langid 0.9.6, moka (anvil-web)]
  patterns:
    - "Back-channel logout deliveries are enqueued by the revoking storage intents in the same transaction (no service-layer fan-out)"
    - "Backends refuse Phase 4 values they cannot store yet (client fields, resource, logout flows, email_change tokens) with StorageError::Unsupported instead of dropping them"
    - "Kinds without an email template contract are an explicit error in the checker and the renderer (has_contract)"

key-files:
  created:
    - crates/anvil-core/src/model/connection.rs
    - crates/anvil-core/src/model/branding.rs
    - crates/anvil-core/src/model/logout.rs
    - crates/anvil-jose/src/email_code.rs
    - crates/anvil-jose/src/pem.rs
    - crates/anvil-storage/src/contract/connections.rs
    - crates/anvil-storage/src/contract/branding.rs
    - crates/anvil-storage/src/contract/logout.rs
    - crates/anvil-storage-sqlite/src/pending.rs
    - crates/anvil-storage-postgres/src/pending.rs
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/error.rs
    - crates/anvil-core/src/model/{client,tenant,grant,audit,flow,session,mail_settings,ids,mod}.rs
    - crates/anvil-storage/src/contract/{mod,fixtures,sessions,users,grants,access_tokens,clients,flows}.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/src/errors.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - Cargo.toml, Cargo.lock, crates/anvil-web/Cargo.toml

key-decisions:
  - "Backends refuse non-default Phase 4 client fields and non-empty resource vectors with Unsupported until 04-04/04-05 (Phase 3 precedent) rather than silently mapping them to defaults"
  - "SQLite/Postgres refuse FlowKind::Logout flows and EmailChange self-service tokens with Unsupported until their migrations land, so new contract tests fail only with Unsupported (not a raw CHECK error)"
  - "THE PEM helper is anvil_jose::pem: pkcs8_pem (encoder) moved there from keys.rs so `BEGIN PRIVATE KEY` appears only in pem.rs"
  - "anvil-mail keeps `variables(kind) -> &[&str]` (anvil-web depends on it) and adds has_contract(kind); checker and renderer return 'no template contract for kind … yet' for the three new kinds (TRANSITIONAL(04-15))"
  - "TenantSettingsPatch::merge keeps current values of the Phase 4 settings not yet on the wire (..current.clone()); NewTenantSettings uses Phase 4 defaults"
  - "LOGOUT_DELIVERY_TTL = 24 h lives in model::logout; GiveUp also increments attempts"

patterns-established:
  - "Revoking intents enqueue one logout_delivery per (revoked session x rp_session whose client has backchannel_logout_uri): uri copied, sub = user id, sid = session id, next_attempt_at = now, give_up_at = now + 24h, attempts 0; nothing when nothing was revoked"

requirements-completed: [OIDC-12, OIDC-16, AUTH-06, AUTH-07, AUTH-08, AUTH-11, AUTH-13, UI-03, SEC-03]

duration: 31min
completed: 2026-11-25
---

# Phase 4 Plan 01: Core Foundation Summary

**The whole Phase 4 contract in one place: domain model, three new repositories plus upgrade_auth/complete_email_change, the UpstreamClient port, flow-bound email OTP hashing, the single strict PKCS#8 PEM parser, and a 32-test storage contract suite. Both backends compile against it through explicit `Unsupported` shims.**

Note: `requirements-completed` lists the requirement IDs this foundation contributes to. None of them is delivered yet, and no requirement checkbox was ticked.

## Performance

- **Duration:** about 31 min
- **Started:** 2026-11-25T14:42:43Z
- **Completed:** 2026-11-25T15:13Z
- **Tasks:** 3
- **Files modified:** 97 (70 + 10 + 17 across the three commits)

## Accomplishments

### New types (anvil-core::model)
- ids: `ConnectionId`, `IdentityLinkId`, `LogoutDeliveryId`
- connection: `ConnectionKind` (+ `default_email_trust`), `SocialProvider`, `EndpointOverrides`, `AppleConfig`, `SocialConfig`, `OidcConfig` (PKCE default on), `ClaimMapping`, `OAuth2Config`, `ConnectionConfig` (tagged `type`, `kind()`, `client_id()`), `Connection` (Debug redacts `secret_enc`), `NewConnection`, `ConnectionUpdate`, `IdentityLink`, `NewIdentityLink`, `CONNECTION_SECRET_PURPOSE = "anvilid/connection-secret/v1"`, `connection_aad(tenant, id)`
- logout: `RpSession`, `LogoutDelivery`, `DeliveryResult { Delivered, Retry, GiveUp }`, `LOGOUT_DELIVERY_TTL`
- branding: `BrandingScope` (`scope_key`/`from_key`), `ThemeColors`, `ThemeTokens`, `Logo` (Debug hides bytes), `Branding`, `LogoChange`, `BrandingUpdate`, `BrandingDraft`
- client: `post_logout_redirect_uris`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `allowed_resources`, `mfa_policy` on Client/NewClient/ClientUpdate
- tenant: `MfaPolicy { Off, Optional, Required }` (Ord: strictest is greatest); `TenantSettings` gains `mfa_policy`, `email_otp`, `magic_link`, `auto_link` (default true), `upstream_registration`, `default_locale` ("en"). Settings JSON written by 0.2 still parses (test).
- grant: `resource: Vec<String>` on AuthorizationParams (serde default), codes, families and access tokens; `SelfServiceKind::EmailChange`
- `FlowKind::Logout`, `AMR_FED`, `EmailKind::{LoginCode, EmailChange, EmailChanged}`
- audit: 15 new actions (41 -> 56) and typed details `link`, `connection`, `logout`, `delivery`
- error: `CoreError::InvalidTarget` (invalid_target, 400), `CoreError::UnmetAuthenticationRequirements` (400, delivered like login_required); anvil-web error page maps InvalidTarget to the invalid_request key

### Port methods (anvil-core::ports)
- `Storage::{connections, branding, logout}`
- `ConnectionRepo`: create, get, get_by_slug, list, update, set_secret, delete, find_link, create_link, links_for_user, touch_link, delete_link, create_user_with_link
- `BrandingRepo`: get, put, delete, logo, put_draft, draft_by_preview
- `LogoutRepo`: rp_sessions, claim_due_deliveries, complete_delivery, deliveries_for_client
- `SessionRepo::upgrade_auth`, `UserRepo::complete_email_change`
- `UpstreamClient`: metadata, jwks, exchange_code, get_json, plus the `ProviderMetadata`, `TokenEndpointAuth`, `CodeExchange`, `TokenSet`, `ApiProfile` and `UpstreamError` DTOs (Display is fixed text)

### Enqueue-on-revoke semantics (documented in the ports module docs and on each method)
`SessionRepo::revoke`, `revoke_with_families`, `revoke_all_for_user`, `UserRepo::complete_recovery` and `UserRepo::delete` insert, in the same transaction, one `logout_delivery` per (session revoked by that call x `rp_session` of that session whose client has a `backchannel_logout_uri`). Each delivery copies `uri` from the client, uses `sub` = user id, `sid` = session id, `next_attempt_at = now`, `give_up_at = now + 24h` and `attempts = 0`. A call that changes nothing enqueues nothing. `GrantRepo::create_code` upserts `rp_session (tenant, session_id, client_id)` in its transaction.

### anvil-jose
- `email_code`: `EMAIL_OTP_PEPPER_INFO`, `generate_email_code` (rejection sampling over u32), `normalize_email_code`, `email_code_hash(kek, flow_id, code)` = HMAC-SHA256 over `flow_id || 0x00 || code`
- `pem`: `pkcs8_der_from_pem` (at most 16 KiB, exactly one PRIVATE KEY block, LF/CRLF, rejects other labels, headers, second blocks, junk before or after, blank or whitespace lines, non-canonical base64, empty body), `SigningKey::from_pkcs8_pem`. Negative tests cover every case, including RS256 PEM loaded as ES256.

### Contract tests (32 new, registered in `storage_contract_tests!`)
client_phase4_fields_round_trip, code_and_family_resource_round_trip, access_token_resource_round_trip, flow_logout_kind_round_trip, session_upgrade_auth, email_change_completes_and_notifies_old_address, email_change_rejects_invalid_tokens, email_change_conflict_keeps_token, email_change_concurrent_single_winner (N=8), connection_create_get_list_update, connection_slug_conflict_per_tenant, connection_set_secret_round_trip, connection_delete_cascades_links, identity_link_create_find_and_conflict, identity_link_delete_only_own, create_user_with_link_is_atomic, connections_isolated_by_tenant, branding_put_get_scopes, branding_logo_keep_clear_set, branding_draft_replace_and_preview, branding_delete, branding_isolated_by_tenant, create_code_records_rp_session_once, revoke_enqueues_backchannel_delivery, revoke_with_families_enqueues_backchannel_delivery, revoke_all_for_user_enqueues_backchannel_delivery, complete_recovery_enqueues_backchannel_delivery, user_delete_enqueues_backchannel_delivery, revoke_noop_enqueues_nothing, delivery_claim_leases_due_rows, delivery_claim_concurrent_each_row_once (8 claimers), delivery_complete_semantics.

SQLite run: 228 existing tests pass and 64 fail (32 new tests x file/memory). Every one of the 64 fails with `StorageError::Unsupported` from a TRANSITIONAL shim or write guard. Postgres contract compiles (`--no-run`). Its runtime run needs Docker and is left to CI.

## Task Commits

1. **Task 1: Dependencies, anvil-jose email code + PEM, domain model, pre-declared modules**: `755d7c0` (feat)
2. **Task 2: Storage ports, UpstreamClient port, TRANSITIONAL backend shims**: `81e4c13` (feat)
3. **Task 3: Contract suite for every new port method**: `e32bf9c` (test)

## deny.toml exceptions

None. `cargo deny check` passes as is. fluent-bundle 0.16.0 pulls fluent-langneg 0.13.1 next to the declared 0.14.2, and icu/writeable/tinystr/litemap gain second versions. These only produce duplicate-version warnings; bans pass.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] keys.rs edited so the PEM armor exists only in pem.rs**
- **Found during:** Task 1
- **Issue:** keys.rs had its own `pkcs8_pem` encoder containing `BEGIN PRIVATE KEY`, which broke the plan's grep gate ("only in pem.rs").
- **Fix:** Moved the encoder to `pem::pkcs8_pem` (now on `encoding::b64std`) and removed keys.rs's direct base64 use.
- **Files:** crates/anvil-jose/src/keys.rs, crates/anvil-jose/src/pem.rs
- **Commit:** 755d7c0

**2. [Rule 2 - Correctness] Backends refuse Phase 4 values instead of dropping them**
- **Found during:** Tasks 1 and 3
- **Issue:** Mapping the new fields to defaults on write would silently lose data, which is a success-returning stub. SQLite and Postgres CHECK constraints rejected `logout` flows and `email_change` tokens with raw backend errors.
- **Fix:** Added `pending.rs` write guards (`refuse_phase4_client`, `refuse_phase4_client_update`, `refuse_resource`, `refuse_phase4_flow_kind`, `refuse_phase4_token_kind`). They are called from insert_client, client update, insert_family, create_code, create_access_token, flow create, issue_self_service_token and UserRepo::create, and return `Unsupported`. Read converters default the new fields and are marked TRANSITIONAL.
- **Files:** anvil-storage-{sqlite,postgres}/src/{pending,clients,grants,flows,users}.rs
- **Commits:** 755d7c0, e32bf9c

**3. [Rule 3 - Blocking] Extra files the build forced**
- anvil-storage-{sqlite,postgres}/src/{sessions,users}.rs: the trait impls need `upgrade_auth` / `complete_email_change`. Both delegate to pending.rs.
- anvil-core/src/service/session.rs: the test-only `Fake` implements the new Storage accessors (unreachable) and `upgrade_auth` (Unsupported).
- anvil-storage-{sqlite,postgres}/src/flows.rs: the logout-flow guard (item 2).
- crates/anvil-web/tests/ui_helpers/mod.rs needed no change because it uses `..`.

**4. [Rule 1 - Bug prevention] Tenant settings PATCH keeps the Phase 4 settings**
- `TenantSettingsPatch::merge` now ends with `..current.clone()`. Without it, patching `registration` would reset `mfa_policy`, `auto_link` and the other new settings to their defaults.
- **File:** crates/anvil-web/src/admin/dto.rs (755d7c0)

**5. anvil-mail contract shape**
- `variables(kind)` keeps its signature because anvil-web/src/admin/email.rs, which this plan does not own, uses it. It returns `&[]` for the new kinds, and the new `has_contract(kind)` makes both `TemplateChecker::check` and `EmailRenderer::render_with` return explicit errors. A unit test covers this.

### Notes
- During Task 1, one `cargo fmt --all` in the main tree may have reformatted 04-02's in-progress anvil-web/anvilid files. The change is formatting only and none of those files is in my commits.
- Cargo warns `unused dependency` for fluent-bundle and fluent-langneg in anvil-web until the i18n plan uses them. This is a cargo lint, so `clippy -D warnings` is unaffected and clean.
- Expected TRANSITIONAL(04-15) failures (04-VALIDATION.md): `anvil-mail --test templates` (every_kind…) and the email-template list assertion in `anvil-web --test admin_api_v02`.
- Verification ran in a separate worktree (target/wt-04-01, own CARGO_TARGET_DIR) because 04-02's uncommitted anvil-web edits temporarily broke the main-tree build.

## Issues Encountered
None blocking.

## Next Phase Readiness
- 04-04 (SQLite) and 04-05 (Postgres) implement the shims against the 32 contract tests and delete pending.rs.
- 04-15 adds template contracts and defaults for login_code / email_change / email_changed and removes the has_contract guard.
- Later plans fill the pre-declared modules and never edit model/, ports.rs, error.rs, lib.rs, the mod.rs files or the Cargo manifests.

## Self-Check: PASSED

- Every key file listed above exists. Commits 755d7c0, 81e4c13 and e32bf9c are in the history.
- At e32bf9c, in a clean worktree, these all pass: `cargo build --workspace --all-targets --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --all --check`, `cargo test -p anvil-core --lib` (339), `cargo test -p anvil-jose --lib -- email_code pem` (9), `anvil-web --test openapi_drift` and `--test shell`, `anvil-mail --lib`, `npm run check:api`, `cargo deny check` and `scripts/check-deps.sh`.
- The `BEGIN PRIVATE KEY` grep matches only crates/anvil-jose/src/pem.rs.
