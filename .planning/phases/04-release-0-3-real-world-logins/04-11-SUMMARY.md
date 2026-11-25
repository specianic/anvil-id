---
phase: 04-release-0-3-real-world-logins
plan: 11
subsystem: admin-api
tags: [connections, upstream, sec-03, kek, admin-api, openapi, client-settings, tenant-settings, mfa-policy]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01 Connection model, ConnectionRepo, CONNECTION_SECRET_PURPOSE/connection_aad, SigningKey::from_pkcs8_pem, Phase 4 client/tenant fields; 04-04/04-05 storage; 04-07 upstream::providers::resolve; 04-02 module pre-registration"
provides:
  - "anvil_core::service::connection::ConnectionService { storage, clock, kek } with list/get/create/update/set_secret/delete and open_secret (the only place a connection secret is opened)"
  - "validate_connection_slug, validate_upstream_url, validate_config, validate_secret, seal_secret, plan_create, plan_update"
  - "ClientOptions/ClientOptionsPatch with post_logout_redirect_uris, backchannel_logout_uri, backchannel_logout_session_required, allowed_resources, mfa_policy; validate_client_phase4"
  - "validate_locale_tag, validate_phase4_settings; TenantPatch/NewTenantInput.installation_smtp; AppConfig.installation_smtp"
  - "/api/admin/v1/tenants/{slug}/connections routes (6 operations), new client and tenant fields on the wire, OpenAPI (37 operations) and console schema regenerated"
affects: [04-19, 04-21, 04-29]

tech-stack:
  added: []
  patterns:
    - "Connection secrets: validated, sealed with AAD tenant||connection before storage, write-only on the wire (secret_configured)"
    - "Settings that need an external dependency (SMTP) are checked only when they are turned on, so unrelated updates are not blocked when the dependency later goes away"

key-files:
  created:
    - crates/anvil-web/tests/admin_connections.rs
    - crates/anvil-web/tests/admin_api_v03.rs
    - crates/anvil-web/tests/security_admin_v03.rs
  modified:
    - crates/anvil-core/src/service/connection.rs
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-web/src/admin/connections.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/src/admin/mod.rs
    - crates/anvil-web/src/admin/tenants.rs
    - crates/anvil-web/src/config.rs
    - crates/anvilid/src/startup.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "Connections use the admin:settings:{read,write} scope family (the one SMTP and email templates use); writes to the system tenant's connections also need admin:write, like its clients. No new scope names."
  - "Trusting Microsoft-asserted email needs accept_email_trust_risk=true (nOAuth); the audit event carries reason email_trust_risk_accepted"
  - "The kind of a connection cannot change through PATCH; the slug is immutable"
  - "Generic OIDC is validated statically (issuer URL, client_id, scopes). Discovery-dependent checks stay at sign-in time because resolve() needs metadata."
  - "Upstream URLs must be https; plain http only to loopback hosts (localhost, 127/8, ::1)"
  - "email_otp/magic_link may be turned on only with SMTP: installation SMTP (AppConfig.installation_smtp = smtp_url configured) or the tenant's own SMTP row (checked by TenantService). Settings that are already on are not re-checked."
  - "default_locale is checked for BCP 47 tag syntax only (en, de-DE, pt-BR); render falls back to English if there is no catalog"
  - "PUT …/secret requires the secret field: an empty body is 422 and null clears the secret"

requirements-completed: []

duration: about 1h 40min of work, spread over three sessions (two interruptions)
completed: 2026-11-25
---

# Phase 4 Plan 11: Admin API for connections and 0.3 client/tenant fields Summary

**Admins can manage upstream connections (Google, Apple, Microsoft, GitHub, generic OIDC/OAuth2) per tenant. Each connection's secret is write-only and is sealed with the KEK under AAD tenant||connection before it reaches storage. Every 0.3 client and tenant setting is now in the management API. The OpenAPI document and console types are regenerated, and new negative tests cover scope, tenant isolation and secret disclosure.**

No requirement checkbox was ticked (shared rule). This plan contributes to SEC-03, AUTH-07, AUTH-08, AUTH-06, AUTH-11, OIDC-12 and OIDC-16.

## Routes (scope: `admin:settings:read|write`, or `admin:read|write`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/admin/v1/tenants/{slug}/connections` | `ConnectionList { items }`, slug order |
| POST | `/api/admin/v1/tenants/{slug}/connections` | 201 + Location; 409 if the slug is already used; 422 on validation |
| GET | `…/connections/{id}` | 404 for unknown, malformed or other-tenant ids |
| PATCH | `…/connections/{id}` | field-wise; `config` replaces the whole config but must keep the kind |
| DELETE | `…/connections/{id}` | 204; identity links are removed by cascade |
| PUT | `…/connections/{id}/secret` | `{"secret": "…"}` sets, `{"secret": null}` clears; the field is required |

Writes to the system tenant also need `admin:write`.

## DTO shapes
- `ConnectionView { id, slug, display_name, kind, enabled, config, trust_email_verified, secret_configured, redirect_uri, created_at, updated_at }`. `redirect_uri` = `{tenant issuer}/ui/login/upstream/{slug}/callback`.
- `ConnectionConfig` uses `type` as its tag: `social` (`provider, client_id, scopes, endpoints{issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, api_base_url}, microsoft_tenant, allowed_tenants, hosted_domains, apple{team_id,key_id}`), `oidc` (`issuer, client_id, scopes, use_pkce=true, fetch_userinfo`) and `oauth2` (`authorization_endpoint, token_endpoint, userinfo_endpoint, client_id, scopes, use_pkce=true, mapping{subject, email, email_verified, name}`). All of these reject unknown fields.
- `CreateConnection { slug, display_name, enabled=true, config, secret?, trust_email_verified?, accept_email_trust_risk=false }`.
- `UpdateConnection { display_name?, enabled?, config?, trust_email_verified?, accept_email_trust_risk }`.
- `PutConnectionSecret { secret: string|null }` (required).
- The Debug output of the secret-bearing DTOs is redacted.
- Clients: `post_logout_redirect_uris`, `backchannel_logout_uri` (`null` clears on PATCH), `backchannel_logout_session_required`, `allowed_resources`, `mfa_policy` (`off|optional|required|null`). These are on the view, on create and on PATCH.
- Tenant settings: `mfa_policy`, `email_otp`, `magic_link`, `auto_link`, `upstream_registration` (`null` follows registration), `default_locale`. These are on the view, on create and on PATCH, and PATCH merges field by field.

## ConnectionService::open_secret contract (for 04-21)
`fn open_secret(&self, conn: &Connection) -> Result<Option<SecretString>, CoreError>`
- `Ok(None)` when no secret is configured.
- Otherwise it opens `secret_enc` with `CONNECTION_SECRET_PURPOSE` and `connection_aad(conn.tenant_id, conn.id)`. For Apple the result is the `.p8` PEM, already checked as an ES256 PKCS#8 key when it was stored.
- A secret moved to another tenant or connection, or one that is not UTF-8, fails with `CoreError::Internal("connection secret could not be decrypted")`, and the message never contains the value.
- This is the only function that opens connection secrets. Callers must not log, store or return the result.

## Validation (all of it is `Validation` on a named field)
- Slug: `^[a-z0-9][a-z0-9-]{0,62}$`.
- display_name: same rules as tenants.
- client_id: 1-512 characters, no whitespace.
- Scopes: valid tokens, at most 50.
- URLs: absolute https; http only to loopback; no userinfo, fragment or whitespace; an OIDC issuer may not have a query.
- Provider-only options are refused on the wrong provider (Microsoft tenant/allowed_tenants, Google hosted_domains, GitHub api_base_url, Apple apple config).
- OAuth2 mapping values must be JSON pointers.
- `resolve()` runs for social and oauth2 configs.
- Secrets: Apple needs an ES256 PKCS#8 PEM, checked through `SigningKey::from_pkcs8_pem`. Other kinds need 1-1024 bytes with no control characters.
- Clients: post-logout URIs follow the redirect URI rules of the application type. The back-channel URI follows the web redirect rules (absolute, no fragment, https or loopback http). allowed_resources follows `parse_resources` (RFC 8707), at most 50.

## Task Commits
1. **Task 1 (core):** `16ed048` feat(04-11): ConnectionService and 0.3 client/tenant validation
2. **Forced extra:** `d6e8ee2` feat(04-11): AppConfig.installation_smtp from smtp_url
3. **Task 2 (web, OpenAPI, schema, tests):** `976a8fb` feat(04-11): admin API for upstream connections and 0.3 client/tenant fields
4. `a8dc41a` docs(04-11): log pre-existing console typecheck failures (deferred-items.md)

## Verification (main tree at 976a8fb plus other plans' uncommitted work; SQLite)
- `cargo test -p anvil-core --lib service::` passed. It includes 10 connection tests and the new client and tenant tests.
- `cargo test -p anvil-web --test admin_connections --test admin_api_v03 --test security_admin_v03 --test openapi_drift` passed (4 + 4 + 5 + 3).
- `cargo test -p anvil-web --test admin_api --test admin_api_v02 --test admin_audit --test security_admin --test security_admin_v02 --test console` passed (all green; 04-15 had already fixed the expected email-template reds).
- `cargo clippy -p anvil-core -p anvil-web -p anvilid --all-targets -- -D warnings` is clean, and rustfmt `--check` is clean on every file touched.
- `npm run check:api` reports the schema up to date.

## Not run
- **Postgres** (Docker is down). This plan adds no SQL; the connection repositories are 04-05's.
- **`npm run typecheck` / `npm run build`** fail on pre-existing console errors in `src/lib/email.ts` and `src/routes/audit/index.tsx`. The Phase 4 enum values came into schema.d.ts with 04-01; logged in deferred-items.md and left for the console plan. None of the errors involve the types this plan added.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Forced extra files**
- `crates/anvil-web/src/config.rs` and `crates/anvilid/src/startup.rs`: AppState had no way to know whether the installation SMTP is configured. The plan says "derive from existing AppState", but nothing in AppState carried it. Added `AppConfig.installation_smtp`, set from `smtp_url` (commit d6e8ee2).
- `crates/anvil-web/tests/openapi_drift.rs`: the operation count assertion went from 31 to 37 (6 new operations).
- `crates/anvil-web/src/admin/dto.rs` got minimal compile fixes inside the Task 1 commit, so anvil-web kept building between the two task commits. The full DTO work landed in Task 2.

**2. [Design] SMTP availability passed as `installation_smtp` in TenantPatch/NewTenantInput**
- The plan offered a `smtp_available: bool` from the caller. A parameter on `TenantService::update` would have broken admin_audit.rs, which another plan owns. Instead the patch and input carry `installation_smtp` (Default false), and the service checks the tenant's own SMTP row itself. `plan_settings` gained an explicit `smtp_available` argument.

**3. [Rule 2 - Security] System tenant connections need admin:write**
- Connections decide who can sign in to the system tenant (the console), so writes to them follow the clients rule rather than plain `admin:settings:write`.

**4. TDD commit shape**
- Task 1 tests and implementation landed in one commit instead of separate RED/GREEN commits.
- ConnectionService I/O paths (duplicate slug -> Conflict, audit rows) are covered by the anvil-web integration tests on SQLite. The core unit tests cover the pure plan/validation functions, following the mail_settings precedent, because core has no in-memory Storage.

### Notes
- An earlier session's `cargo fmt -p anvil-core` may have reformatted other plans' in-progress anvil-core files (formatting only; none of them are in my commits). After that I used per-file `rustfmt`.
- The orchestrator's object-repair (45182ec dropped) left my Task 2 work uncommitted in the main tree. I recovered it intact and committed it as 976a8fb.
- Building a worktree in the shared `target/wt-shared` produced a stale anvil-web, because cargo fingerprints recorded another worktree's source paths and its OpenAPI drift test passed without my routes. I verified in the main tree instead (allowed by the DISK RULE) and removed `target/wt-04-11`. Other plans that rely on wt-shared for workspace crates may hit the same staleness.

## Self-Check: PASSED
- Files exist: crates/anvil-core/src/service/connection.rs, crates/anvil-web/src/admin/connections.rs, crates/anvil-web/tests/{admin_connections,admin_api_v03,security_admin_v03}.rs.
- Commits 16ed048, d6e8ee2, 976a8fb and a8dc41a are in the history.
- `CONNECTION_SECRET_PURPOSE` is used in service/connection.rs, and `connections` appears in docs/openapi/admin-v1.json.
