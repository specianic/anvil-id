---
phase: 05-release-0-4-operate-it
plan: 02
subsystem: foundation
tags: [ports, storage-contract, transitional-shims, module-skeletons, rbac, webhooks, dcr, cimd, attributes]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 domain model (role, attribute, webhook, registration), CoreError variants, NewAuditEvent.webhook
provides:
  - Every Phase 5 storage port (RoleRepo, AttributeRepo, WebhookRepo, RegistrationRepo, ClientRepo CIMD/DCR methods) and the non-storage ports AttributeSchemaCheck and ClientMetadataFetcher, so no later plan edits ports.rs
  - Documented atomicity: webhook enqueue inside AuditRepo::append, administrator role in SetupRepo::install / complete_setup, consent resource merge
  - TRANSITIONAL(05-06)/(05-07) backend shims returning StorageError::Unsupported
  - Pre-added Option service fields (attribute_check, metadata_fetcher) set at every construction site through AppState::attribute_check()/cimd_fetcher()
  - Pre-declared modules and empty route modules for every later Phase 5 plan
  - 36 new storage contract tests per backend (incl. 8-way webhook claim and 8-way IAT consume)
affects: [05-06, 05-07, 05-09, 05-10, 05-12, 05-14, 05-15, 05-17, 05-19, 05-20, 05-21, 05-23]

tech-stack:
  added: []
  patterns:
    - "One shared `XxxPending` unit struct per backend implements every not-yet-built repo with Unsupported; Storage accessors point at it"
    - "AppState accessors for later adapters live in the adapter's own file (impl AppState block) returning None with a TRANSITIONAL marker, so the owner changes one body in one file"
    - "Empty route modules return OpenApiRouter::new() / Router::new(): no route served, so the path stays 404"

key-files:
  created:
    - crates/anvil-storage-sqlite/src/pending.rs
    - crates/anvil-storage-postgres/src/pending.rs
    - crates/anvil-storage/src/contract/roles.rs
    - crates/anvil-storage/src/contract/attributes.rs
    - crates/anvil-storage/src/contract/webhooks.rs
    - crates/anvil-storage/src/contract/registration.rs
    - crates/anvil-web/src/adapters/{attribute_schema,cimd,webhook}.rs
    - crates/anvil-web/src/admin/{roles,attributes,webhooks,registration,config}.rs
    - crates/anvil-web/src/protocol/registration.rs
    - crates/anvil-web/src/ui/account_attributes.rs
    - crates/anvil-core/src/policy/{claims_mapping,webhook_event}.rs
    - crates/anvil-core/src/oauth/{registration,cimd}.rs
    - crates/anvil-core/src/service/{role,attribute,webhook,registration,client_resolver,config,admin_recovery}.rs
  modified:
    - crates/anvil-core/src/ports.rs
    - crates/anvil-core/src/service/{token,userinfo,authorize,client_auth,session,mod}.rs
    - crates/anvil-core/src/{policy.rs,oauth/mod.rs}
    - crates/anvil-storage-{sqlite,postgres}/src/{lib,clients}.rs
    - crates/anvil-web/src/protocol/{mod,token,userinfo,authorize,introspect}.rs
    - crates/anvil-web/src/{admin/mod.rs,ui/mod.rs,adapters/mod.rs}
    - crates/anvil-web/tests/security_setup.rs
    - crates/anvil-storage/src/contract/{mod,fixtures,clients,consent,audit,setup}.rs
    - docs/openapi/admin-v1.json

key-decisions:
  - "WebhookRepo::claim_due returns Vec<ClaimedWebhookDelivery { delivery, endpoint }> (endpoint as of the claim) so the 05-14 worker does not need a second lookup; claiming does not count an attempt, complete() increments attempts on every variant"
  - "WebhookRepo::complete only changes Pending rows (false otherwise); DisableEndpoint fails the delivery with last_error \"gone\" and disables the endpoint with disabled_reason \"gone\" in one transaction"
  - "List/paging shapes: users_with_role and deliveries take PageRequest and return Page; deliveries are newest first (page.after = exclusive upper id bound); roles, endpoints and IATs are plain Vecs (name / id order)"
  - "enqueue_test and redeliver return Option<WebhookDelivery> (None = unknown endpoint/delivery in this tenant); append-enqueued deliveries use created_at = next_attempt_at = event.at"
  - "RoleRepo::assign returns bool (false = role or user not in this tenant, nothing stored); holders_of_permission counts distinct UserStatus::Active users"
  - "AttributeRepo::upsert takes `now`; set_user_values replaces the whole object and bumps the user's updated_at"
  - "upsert_cimd forces registration_source = Cimd and metadata_expires_at from its argument, keeps row id/created_at on replace, Conflict over Static/Dynamic; get_by_registration_token matches Dynamic clients only"
  - "SchemaIssue is a { message } struct mirroring TemplateIssue; MetadataFetchError Display is fixed text (tested)"
  - "New ClientRepo shim methods live in each backend's clients.rs (the trait impl block is there), marked TRANSITIONAL(05-06)/(05-07)"

patterns-established:
  - "Phase 5 contract tests unwrap normally and so fail with an Unsupported panic until 05-06/05-07; assertions on expected errors print the actual result so the failure names Unsupported"

requirements-completed: []

duration: ~75min
completed: 2026-11-26
---

# Phase 5 Plan 02: Foundation B (ports, shims, skeletons, contract suite) Summary

**All Phase 5 storage and non-storage ports, Unsupported shims on both backends, the pre-added service fields and AppState accessors, pre-declared modules and route tables, and 36 new contract tests per backend that fail only with Unsupported until 05-06/05-07.**

## Performance

- **Duration:** about 75 min
- **Completed:** 2026-11-26
- **Tasks:** 2/2
- **Files:** 46 in the ports/skeleton commit, 10 in the contract commit

## Accomplishments

### Task 1: ports, shims, skeletons (commit b0232ab)

**Storage accessors:** `roles()`, `attributes()`, `webhooks()`, `registration()`.

**RoleRepo:** create (Conflict on a duplicate tenant-level name), get, get_by_name, list (name order), update (Conflict on rename), delete (cascades assignments), assign (idempotent, returns false for a role or user outside the tenant), unassign, roles_for_user, users_with_role(t, role, PageRequest) -> Page<User>, holders_of_permission (distinct active users).

**AttributeRepo:** list (position, then name), get, upsert(t, def, now), delete (user values untouched), user_values -> Option<Map>, set_user_values(t, user, &Map, now) -> bool.

**WebhookRepo:** create_endpoint, get_endpoint, list_endpoints, update_endpoint (re-enabling clears disabled_reason), rotate_secret(t, id, new_enc, previous_expires_at, now), disable_endpoint(t, id, reason, now), delete_endpoint (cascades deliveries), claim_due(owner_lease_until, now, limit) -> Vec<ClaimedWebhookDelivery> (installation-wide, enabled endpoints only, FOR UPDATE SKIP LOCKED on Postgres), complete(id, &WebhookResult, now), deliveries(t, endpoint, PageRequest), redeliver(t, delivery_id, now), enqueue_test(t, endpoint, &WebhookEvent, now).

**AuditRepo::append** docs, plus a new "Webhook enqueueing" section in the module docs: with `webhook: Some`, the same transaction inserts one Pending delivery per enabled, subscribed endpoint of that tenant. Nothing is enqueued without a payload.

**RegistrationRepo:** create_iat, list_iats, revoke_iat, consume_iat (a single conditional UPDATE that decrements), count_clients_by_source.

**ClientRepo additions:** upsert_cimd, get_by_registration_token, set_registration_token.

**Doc changes to existing intents:**
- `SetupRepo::install` creates the system tenant's `administrator` role with `[admin:write]`.
- `complete_setup` assigns that role in its transaction. It is the intent behind both the first-admin URL and `admin setup-url`.
- `GrantRepo::upsert_consent` merges resources the same way it merges scopes.

**Non-storage ports:**
- `AttributeSchemaCheck { check_definition(&Value) -> Result<(), SchemaIssue>; validate(&Value, &Value) -> Result<(), Vec<String>> }`
- `ClientMetadataFetcher { async fetch(&str) -> Result<FetchedMetadata, MetadataFetchError>; fn allow_http_loopback(&self) -> bool }`
- `MetadataFetchError { Blocked, Network, Timeout, Status(u16), TooLarge, InvalidResponse(&'static str) }`, with fixed Display text.
- The dyn-compatibility test now includes all new traits.

**Backends:** `pending.rs` holds `SqlitePending` (TRANSITIONAL(05-06)) and `PostgresPending` (TRANSITIONAL(05-07)). Each implements the four new repos with `Err(Unsupported(..))`, and the accessors in lib.rs point at it. The three new ClientRepo methods return Unsupported from clients.rs.

**Service fields (no behaviour change):**
- `TokenService.attribute_check` and `UserInfoService.attribute_check`: `Option<Arc<dyn AttributeSchemaCheck>>`.
- `metadata_fetcher` (`Option<Arc<dyn ClientMetadataFetcher>>`) on AuthorizeService, ClientAuthenticator and TokenService. TokenService passes its own field into the ClientAuthenticator it builds.
- protocol/{token,userinfo,authorize,introspect}.rs set them from `state.attribute_check()` and `state.cimd_fetcher()`. These accessors are defined in adapters/attribute_schema.rs and adapters/cimd.rs and return `None // TRANSITIONAL(05-10)` and `None // TRANSITIONAL(05-15)`.

**Core test fake:** the Fake Storage in service/session.rs implements the four repos, returning Unsupported.

**Skeleton owners (module doc names the owner, no items):**

| Module | Owner |
|---|---|
| core policy::claims_mapping, policy::webhook_event | 05-10 |
| core oauth::registration, oauth::cimd | 05-09 |
| core service::role | 05-12 |
| core service::attribute | 05-19 |
| core service::webhook | 05-14 |
| core service::registration | 05-21 |
| core service::client_resolver | 05-15 |
| core service::config | 05-10 / 05-20 |
| core service::admin_recovery | 05-17 |
| web adapters::webhook | 05-14 |
| web adapters::cimd (+ `AppState::cimd_fetcher`) | 05-15 |
| web adapters::attribute_schema (+ `AppState::attribute_check`) | 05-10 |
| web admin::roles (`routes() -> OpenApiRouter`, merged in api_router) | 05-12 |
| web admin::attributes, admin::webhooks, admin::registration | 05-23 |
| web admin::config | 05-20 |
| web protocol::registration (`Router::new()`, merged in protocol::routes) | 05-21 |
| web ui::account_attributes (`Router::new()`, merged inside the CSRF layer) | 05-19 |

**OpenAPI:** `base_document()` gains the tags roles, attributes, webhooks, registration and config. `docs/openapi/admin-v1.json` was regenerated (tags only). `npm run gen:api` left `schema.d.ts` unchanged because tags do not affect the types.

### Task 2: contract suite (commit 3f4a328)

There are 36 new tests, registered in `storage_contract_tests!` so both backends run them.

| File | Tests |
|---|---|
| roles.rs | role_create_get_update_delete, role_list_in_name_order, role_name_conflict_per_tenant, role_assign_idempotent_and_unassign, role_assign_refuses_foreign_tenant, role_delete_cascades_assignments, role_users_with_role_paginates, role_holders_of_permission_counts_active_users, roles_isolated_by_tenant |
| attributes.rs | attribute_upsert_list_get_delete, attribute_user_values_round_trip, attribute_delete_keeps_user_values, attributes_isolated_by_tenant |
| webhooks.rs | webhook_endpoint_crud_and_name_conflict, webhook_rotate_secret_keeps_previous_with_expiry, webhook_disable_and_reenable_endpoint, webhook_append_enqueues_subscribed_endpoints, webhook_claim_leases_due_rows, **webhook_claim_concurrent_each_row_once** (8 claimers, 12 rows), webhook_complete_semantics, webhook_deliveries_listing_newest_first, webhook_redeliver_and_enqueue_test, webhook_delete_endpoint_cascades_deliveries, webhooks_isolated_by_tenant |
| audit.rs | audit_append_without_webhook_enqueues_nothing |
| registration.rs | iat_create_list_revoke, iat_consume_decrements_and_stops_at_zero, iat_expired_or_revoked_not_consumed, **iat_single_use_concurrent_single_winner** (8 consumers), count_clients_by_source |
| clients.rs | client_upsert_cimd_inserts_then_replaces, client_upsert_cimd_never_overwrites_registered_clients, client_registration_token_lookup_and_rotation |
| consent.rs | consent_resources_round_trip_and_merge |
| setup.rs | install_creates_system_administrator_role, complete_setup_assigns_administrator_role (first admin, a second setup token, and no assignment on an invalid token) |

- New fixtures: new_role, expected_role, seed_role, new_attribute, new_endpoint, expected_endpoint, seed_endpoint, webhook_event, new_iat, expected_iat, new_cimd_client.
- **Test count (SQLite memory + file):** 380 total, 308 passing (all pre-existing tests) and 72 failing (36 new tests x 2). Every one of the 72 fails with `StorageError::Unsupported` (checked in the panic messages).
- No new test was needed in tenants.rs: 05-01 already extended `tenant_update_settings_round_trip` with non-default dcr/cimd/claims.

## Task Commits

1. **Task 1: ports, shims, service fields, skeletons, OpenAPI tags:** `b0232ab` (feat)
2. **Task 2: contract suite:** `3f4a328` (test)

## Verification run

- `cargo build --workspace --all-targets --locked`: OK. The only warning was 05-05's in-progress unused config fields in anvilid.
- `cargo test -p anvil-core --lib`: 612 passed.
- `cargo test -p anvil-web --test shell --test openapi_drift`: 12 + 3 passed. `cd admin-ui && npm run check:api`: up to date.
- `cargo test -p anvil-web --test security_setup --test authorize`: 13 + 7 passed (construction sites behave as before).
- `cargo test -p anvil-storage-sqlite --test contract --no-run`: OK. `-- tenants outbox logout connections`: 14 passed.
- Full SQLite contract run: 308 passed. The 72 failures are all Unsupported (the expected state until 05-06).
- `cargo test -p anvil-storage-postgres --test contract --no-run`: compiles.
- `cargo clippy -p anvil-core -p anvil-storage --features contract -p anvil-storage-sqlite -p anvil-storage-postgres -p anvil-web --all-targets --locked -- -D warnings`: OK.
  - The first anvil-core attempt failed on 05-11's in-progress flow/login.rs. The re-run after their fix was clean.
- `rustfmt --edition 2024 --check` on every touched file: OK.
- `grep -rn "TRANSITIONAL(05-0[67])" crates/anvil-storage-*`: only pending.rs, the lib.rs module/field comments, and the 05-01 refusal and converter sites in clients/consent/audit.

## Not run

- The Postgres contract suite (needs Docker). It compiles. The shims mirror SQLite.
- `cargo check` of the fuzz crate. No fuzz target constructs the changed service structs or implements Storage (grep), so it is unaffected.
- The full workspace test suite (per the shared rules; the gate starts after wave 3).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] ClientRepo shims live in each backend's clients.rs**
- **Issue:** the plan puts the new ClientRepo methods in pending.rs, but a trait impl cannot span files. `impl ClientRepo for SqliteClients/PgClients` is in clients.rs.
- **Fix:** the three methods return Unsupported from clients.rs with TRANSITIONAL(05-06)/(05-07) markers.
- **Forced extra files:** `crates/anvil-storage-sqlite/src/clients.rs` and `crates/anvil-storage-postgres/src/clients.rs`. No other wave-2 plan owns them.
- **Commit:** b0232ab

**2. [Rule 3 - Blocking] security_setup.rs has no AppState**
- **Issue:** the test builds `TokenService` from an `OwnApp` harness without an AppState, and the accessors are `pub(crate)`.
- **Fix:** the test sets both new fields to `None` with a comment. It is a test fixture and `client_credentials` uses neither port.
- **Commit:** b0232ab

### Notes
- Files listed in frontmatter that needed no change: `crates/anvil-core/src/lib.rs` (policy/oauth/service modules already exist), `crates/anvil-storage/src/contract/tenants.rs` (covered by 05-01), `admin-ui/src/api/schema.d.ts` (regenerated, byte-identical).
- Shared registries edited additively: admin/mod.rs, protocol/mod.rs, ui/mod.rs, adapters/mod.rs, core service/mod.rs, oauth/mod.rs and policy.rs. anvil-web lib.rs and state.rs (owned by 05-05) were not touched.

## Self-Check: PASSED
- Created files exist (pending.rs x2, contract roles/attributes/webhooks/registration, adapters, route modules, core skeletons). Commits b0232ab and 3f4a328 are present in `git log`.
