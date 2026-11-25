---
phase: 03-release-0-2-secure-by-default
plan: 21
subsystem: management, audit, bootstrap
tags: [admin-audit, client-options, signing-algs, captcha, console-client, admin-scopes]
requires:
  - phase: 03-02
    provides: AuditService, AuditAction admin variants, TenantSettings.signing_algs/captcha, Client 0.2 fields
  - phase: 03-08
    provides: request_context::AuditContext extractor
  - phase: 03-10
    provides: KeyRotationService::ensure_tenant
provides:
  - "service::client: ClientOptions, ClientOptionsPatch, validate_client_options(input, options, &TenantSettings)"
  - "ClientService::create(&Tenant, ClientInput, ClientOptions, AuditActor, &RequestContext); update(&Tenant, client_id, ClientPatch, ClientOptionsPatch, actor, ctx); rotate_secret(TenantId, client_id, actor, ctx); delete(TenantId, client_id, actor, ctx)"
  - "service::tenant: SUPPORTED_SIGNING_ALGS, normalize_signing_algs, CaptchaInput, CaptchaChange::{Set, Clear}, seal_captcha_secret, plan_settings"
  - "TenantService::create(NewTenantInput, actor, ctx); update(slug, TenantPatch, Option<CaptchaChange>, actor, ctx); delete(slug, actor, ctx)"
  - "UserService::create(&Tenant, issuer, UserInput, actor, ctx); update(TenantId, UserId, UserPatch, actor, ctx); delete(TenantId, UserId, actor, ctx)"
  - "admin_scope::Resource::{Sessions, Audit, Settings}; ALL_ADMIN_SCOPES has 14 entries"
  - "bootstrap: CONSOLE_CLIENT_ID, CONSOLE_CALLBACK_PATH, console_redirect_uri, build_console_client, console_client_drift, BootstrapService::ensure_console_client(&PublicUrl)"
  - "BootstrapService::complete_setup(token, email, password, &RequestContext); SetupResult.audit_error"
  - "AdminAuth::actor() (Admin, id = token sub)"
affects: [03-23, 03-24, 03-25]
tech-stack:
  added: []
  patterns:
    - "0.2 options live beside the 0.1 input structs (ClientOptions, CaptchaChange) so dto.rs and test literals keep compiling until 03-23 adds wire fields"
    - "Pure planners (validate_client_options, normalize_signing_algs, plan_settings, console_client_drift) unit-tested in core; storage behaviour tested in anvil-web integration tests"
key-files:
  created:
    - crates/anvil-web/tests/admin_audit.rs
    - crates/anvil-web/tests/console_client.rs
  modified:
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-core/src/service/user.rs
    - crates/anvil-core/src/service/bootstrap.rs
    - crates/anvil-core/src/service/admin_scope.rs
    - crates/anvil-web/src/admin/auth.rs
    - crates/anvil-web/src/admin/clients.rs
    - crates/anvil-web/src/admin/users.rs
    - crates/anvil-web/src/admin/tenants.rs
    - crates/anvil-web/src/ui/setup.rs
    - docs/openapi/admin-v1.json
key-decisions:
  - "Tenant events (tenant_created/updated/deleted) are recorded in the system tenant with target = tenant id (a deleted tenant's own log goes with it); client and user events in the owning tenant"
  - "Admin actor = AuditActor::admin(token sub): client id for client-credentials tokens, user id for console tokens (AuditDetails has no client-id constructor and model/audit.rs is not in this plan)"
  - "OQ5: system-tenant users are administrators; the console is the public client anvil-console of the system tenant, reconciled at every start with no off switch in 0.2; system registration forced to disabled"
  - "A sealed CAPTCHA value in TenantPatch.settings is refused unless it equals the current one; None keeps the current CAPTCHA (secrets enter only as plaintext via CaptchaChange)"
  - "Merged client options are re-validated on every update: if a tenant disables an algorithm a client uses, the next update of that client must change its alg"
  - "admin_setup_completed audit failure does not fail setup (the secret is shown once); it is returned in SetupResult.audit_error and logged by the page"
duration: 50min
completed: 2026-11-25
---

# Phase 3 Plan 21: Core management (admin audit, 0.2 settings, console client) Summary

**Every admin mutation of tenants, clients and users now records one typed audit event with the admin actor and caller IP. The services validate the new client options and tenant signing algorithms (enabling an algorithm creates its key at once) and store CAPTCHA secrets sealed. At startup the public `anvil-console` client of the system tenant is reconciled and system-tenant self-registration is forced off.**

## Performance

- **Duration:** about 50 min
- **Tasks:** 2
- **Files:** 13 (2 created, 11 modified)

## Accomplishments

- **Client options:** `ClientOptions { token_format, consent_mode, id_token_signed_response_alg, can_introspect }`. The default is the secure one: JWT, consent required, RS256, no introspection. `validate_client_options` rejects an ID-token alg the tenant has not enabled (`Validation { field: "id_token_signed_response_alg" }`, compared case-sensitively against `effective_signing_algs`). It also rejects `can_introspect` on a non-confidential client (`field: "can_introspect"`).
- **Tenant settings:**
  - `normalize_signing_algs` only accepts `RS256`, `ES256` and `Ed25519`. The result always starts with RS256 and has no duplicates.
  - `TenantService::create` and `update` call `KeyRotationService::ensure_tenant` after storing new settings, so an active ES256/Ed25519 key exists before the call returns.
  - `CaptchaChange::Set(CaptchaInput { provider, site_key, secret })` seals the secret as base64url `Kek::seal(CAPTCHA_SECRET_PURPOSE, tenant id bytes, ..)`. That is the form `adapters::captcha::open_secret` opens; a test checks the round trip. `Clear` removes it.
- **Admin audit:** each mutating Client/Tenant/User service method takes `(AuditActor, &RequestContext)` and records exactly one event after the change commits:
  - Clients: `client_created`, `client_updated`, `client_secret_rotated`, `client_deleted`.
  - Tenants: `tenant_created`, `tenant_updated`, `tenant_deleted`.
  - Users: `user_created` (with details `reason` = `invitation` | `password_set`), `user_updated`, `user_deleted`.
  - Update events list only the changed field names. Validation errors and not-found record nothing.
- **Scopes:** added `Resource::{Sessions, Audit, Settings}` and `admin:{sessions,audit,settings}:{read,write}`. `admin:read`/`admin:write` still satisfy every resource.
- **Console client:** `ensure_console_client(&PublicUrl)`:
  - Creates `anvil-console` in the system tenant: public, auth `none`, PKCE, Web, redirect `{public_url}/console/callback`, grants `authorization_code` + `refresh_token`, scopes `openid admin:read admin:write`, consent `skip_first_party`, JWT. This is audited as `client_created` by the System actor.
  - On later starts it reconciles any drift, e.g. a new public URL changes the redirect URI (audited as `client_updated` with the field names). When nothing changed it writes and audits nothing. A concurrent create (Conflict) is reconciled instead of failing.
  - It also switches system-tenant registration to `disabled` on installs where it is not, audited once as `tenant_updated` with fields `["settings.registration"]`. New installs were already disabled (`build_install_plan`).
- **Web call sites:** admin handlers take `AuditContext` after `AdminAuth` and pass `auth.actor()` and the context. `/setup` POST passes the context, so `admin_setup_completed` records the new admin as actor and the caller IP. The wire API is unchanged: admin_api, security_admin and security_setup pass without edits.

## Signatures for 03-23

```rust
ClientService::create(&self, tenant: &Tenant, input: ClientInput, options: ClientOptions, actor: AuditActor, ctx: &RequestContext) -> Result<CreatedClient, CoreError>
ClientService::update(&self, tenant: &Tenant, client_id: &str, patch: ClientPatch, options: ClientOptionsPatch, actor: AuditActor, ctx: &RequestContext) -> Result<Client, CoreError>
ClientService::rotate_secret(&self, tenant: TenantId, client_id: &str, actor: AuditActor, ctx: &RequestContext) -> Result<SecretString, CoreError>
ClientService::delete(&self, tenant: TenantId, client_id: &str, actor: AuditActor, ctx: &RequestContext) -> Result<(), CoreError>
TenantService::create(&self, input: NewTenantInput, actor: AuditActor, ctx: &RequestContext) -> Result<Tenant, CoreError>
TenantService::update(&self, slug: &str, patch: TenantPatch, captcha: Option<CaptchaChange>, actor: AuditActor, ctx: &RequestContext) -> Result<Tenant, CoreError>
TenantService::delete(&self, slug: &str, actor: AuditActor, ctx: &RequestContext) -> Result<(), CoreError>
UserService::create(&self, tenant: &Tenant, issuer: &str, input: UserInput, actor: AuditActor, ctx: &RequestContext) -> Result<User, CoreError>
UserService::update(&self, tenant: TenantId, id: UserId, patch: UserPatch, actor: AuditActor, ctx: &RequestContext) -> Result<User, CoreError>
UserService::delete(&self, tenant: TenantId, id: UserId, actor: AuditActor, ctx: &RequestContext) -> Result<(), CoreError>
BootstrapService::ensure_console_client(&self, public_url: &PublicUrl) -> Result<(), CoreError>
BootstrapService::complete_setup(&self, token: &str, email: &str, password: &SecretString, ctx: &RequestContext) -> Result<SetupResult, CoreError>
```

## Open Question 5 resolution

Users of the system tenant are the installation's administrators. The console signs in as the public client `anvil-console` of the system tenant. That client is product configuration, reconciled at every start; there is no disable flag in 0.2. Admin scopes exist only on system-tenant clients, and system registration is always `disabled`:
- `/t/system/ui/registration` shows `registration.disabled`.
- At the default tenant, `scope=admin:read` gives `invalid_scope`. Unregistered scopes are filtered and `openid` is required.
- `client_id=anvil-console` at the default tenant is `unknown_client`.

## Task Commits

1. **Task 1: Validation of new client/tenant settings, admin audit in services, scopes (+ admin handler call sites):** `9629aa3`
2. **Task 2: Console client reconciliation, system tenant lock-down, setup audit, tests:** `d64317e`

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] docs/openapi/admin-v1.json regenerated for the new scopes**
- **Found during:** Task 1
- **Issue:** The plan requires `ALL_ADMIN_SCOPES` to be extended and `openapi_drift` to pass. The OpenAPI security scheme is generated from `ALL_ADMIN_SCOPES`, so the committed document drifted. The plan also says not to edit the file.
- **Fix:** Regenerated it with `UPDATE_OPENAPI=1`. The only diff is the six new scope entries in `components.securitySchemes.oauth2`; no path, schema or DTO changed. No concurrent plan touches the file.
- **Commit:** 9629aa3

**2. [Rule 3 - Blocking] New options carried beside ClientInput/TenantPatch, not inside them**
- **Issue:** Adding fields to `ClientInput`, `ClientPatch` or `TenantPatch` would break `admin/dto.rs` (owned by 03-23) and six test files that build `ClientInput` literals.
- **Fix:** Added `ClientOptions`/`ClientOptionsPatch` and an `Option<CaptchaChange>` parameter. Signing algorithms still travel in `TenantPatch.settings.signing_algs`, as the plan specifies.

**3. [Rule 3 - Blocking] Admin handler call sites committed with Task 1**
- **Issue:** Changing the service signatures breaks the anvil-web build. Committing core alone would have left a commit that does not compile.
- **Fix:** The minimal handler changes (actor and context) went into the Task 1 commit. `ui/setup.rs` went with the bootstrap change in Task 2.

**4. [Rule 2 - Correctness] Setup audit failure does not hide the one-time secret**
- **Fix:** `SetupResult.audit_error` is returned and the page logs it at error level. Every other admin mutation returns the append error, as documented in `AuditService`.

**5. [Rule 2 - Security] Sealed CAPTCHA values cannot be injected through TenantPatch.settings**
- **Fix:** A value that differs from the current one gets `Validation { field: "captcha" }`. Create refuses any CAPTCHA value.

### Notes / follow-ups

- **03-23:**
  - Add wire fields for `ClientOptions`/`ClientOptionsPatch`, `CaptchaChange` and `signing_algs`.
  - `dto.rs` still maps a settings patch to `..CoreTenantSettings::default()`. A wire settings update therefore resets `signing_algs` to RS256, while CAPTCHA is now preserved by the service. Merge with the current settings.
  - The `admin:read` scope description in `admin/mod.rs` still says "Read tenants, clients and users".
- **03-24:** call `ensure_console_client(&config.public_url)` at startup after `ensure_installed`.
- Disabling an algorithm on a tenant does not check which clients use it. Their token requests then fail with server_error (03-10 no-fallback rule) until the client is updated.
- QUAL-01 security-test map (`scripts/check-security-tests.sh`) was not updated; it is outside files_modified. Candidates: `signing_algs_enable_keys_and_gate_client_id_token_alg`, `failed_admin_actions_record_nothing`, `default_tenant_clients_cannot_obtain_admin_scopes`.
- Verification ran in a separate worktree, because concurrent plans' in-progress files (flow/consent.rs) broke the shared tree's test build. anvil-core: 301 tests. anvil-web admin_audit, console_client, admin_api, security_admin, security_setup and openapi_drift passed on SQLite; all except openapi_drift (backend-independent) also passed on Postgres. Clippy is clean.
- TDD: each task's tests and implementation went into one commit.

## Self-Check: PASSED
