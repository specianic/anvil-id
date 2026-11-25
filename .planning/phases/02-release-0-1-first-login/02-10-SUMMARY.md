---
phase: 02-release-0-1-first-login
plan: 10
subsystem: core-management-services
tags: [anvil-core, admin, bootstrap, setup, clients, tenants, users, scopes]
requires: [02-01, 02-02]
provides:
  - "service::admin_scope: ALL_ADMIN_SCOPES, ADMIN_READ/ADMIN_WRITE, Resource/Access, scope_satisfies, resource_scope, is_admin_scope"
  - "service::client: validate_client, RedirectValidator, ClientInput/ClientPatch/CreatedClient, ClientService, new_client_secret, uses_secret"
  - "service::tenant: seal_new_key (single key-creation helper), validate_slug/validate_new_slug, admin_page, TenantService"
  - "service::user: UserInput/UserPatch, build_user_plan, build_invitation, UserService"
  - "service::bootstrap: build_install_plan, build_mgmt_client, build_setup_token, setup_url, BootstrapService, InstallResult, SetupResult"
affects: [02-15, 02-16, 02-18]
tech-stack:
  added: []
  patterns:
    - "Pure plan builders (build_install_plan, build_mgmt_client, build_user_plan) unit-tested; async services are thin port orchestration"
    - "Redirect validation injected as a fn pointer (RedirectValidator) to avoid a wave-2 dependency on 02-07"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/admin_scope.rs
    - crates/anvil-core/src/service/client.rs
    - crates/anvil-core/src/service/tenant.rs
    - crates/anvil-core/src/service/user.rs
    - crates/anvil-core/src/service/bootstrap.rs
key-decisions:
  - "Admin page normalisation (limit 0 -> 50, else clamp 1..=200) lives once in service::tenant::admin_page and is used by all three services"
  - "Tenant slugs are immutable for every tenant (TenantPatch has no slug field; issuers derive from slugs)"
  - "Confidential clients may not use auth method none; jwks is only allowed with private_key_jwt"
  - "Client type, application type and auth method are fixed at creation; ClientService::update re-validates the merged registration"
  - "complete_setup peeks the token before Argon2 hashing so invalid tokens cost no hash; the atomic SetupRepo::complete_setup stays authoritative"
  - "new_setup_url on an uninstalled database returns Conflict"
requirements-completed: []
requirements-addressed: [ADM-01, ADM-03, OIDC-01, OIDC-02, OIDC-04]  # core logic; delivered end-to-end with 02-15/02-16/02-18
duration: 20min
completed: 2026-11-25
---

# Phase 2 Plan 10: Management services and bootstrap Summary

**This plan adds the core logic behind the admin API and first start.** It defines the admin scopes once, validates client registrations (including the C1 PKCE rule), adds tenant, client and user services, provides a single helper that generates and KEK-seals RS256 keys, and adds BootstrapService. On first start BootstrapService installs both tenants with their keys and a 1-hour setup token in one transaction. Setup completion then creates the first admin and the management client, whose secret is returned once.

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Admin scopes, client validation, ClientService, TenantService (with key sealing) | 7eeef44 |
| 2 | UserService and BootstrapService | e97d466 |

## What was built

- **admin_scope**: `admin:read` grants read on everything. `admin:write` grants everything. `admin:{tenants|clients|users}:write` grants read and write on that resource. `admin:{res}:read` grants read on that resource only.
- **validate_client** returns a `Validation` error naming the field in each of these cases:
  - `jwks_uri` is set (not supported in this release).
  - No grant types are given.
  - `refresh_token` is requested without `authorization_code`.
  - A public client uses an auth method other than `none`, sets `require_pkce=false`, or requests `client_credentials`.
  - A confidential client uses auth method `none`.
  - `private_key_jwt` comes without a valid public inline JWKS. `Jwks::parse` rejects private members.
  - A JWKS is given with any auth method other than `private_key_jwt`.
  - `authorization_code` comes with no redirect URIs, or with more than 50.
  - The injected validator rejects a redirect URI. Its error is re-labelled as field `redirect_uris`.
  - A scope entry is not a single valid token.

  A confidential client with `require_pkce=false` and `authorization_code` passes (C1).
- **ClientService**: secrets are 256-bit `random_token()` values. Only their SHA-256 is stored, and the plaintext is returned once as a `SecretString`. `client_id` is `random_token()[..22]`, retried once on a conflict. `rotate_secret` only works for secret-based methods.
- **TenantService**: `create` generates the key first, then creates the tenant and inserts the key. If the key insert fails, it deletes the tenant and returns `Internal`; the reasoning is documented in the code. `delete` of `system` or `default` returns Forbidden. Slugs are checked against `^[a-z0-9][a-z0-9-]{1,62}$`, the reserved slugs are rejected on create, and hosts are validated.
- **UserService**: an admin supplies either a password or `invite: true`, never both and never neither. Password users are checked against the policy and hashed through the port. Invited users get an Invitation token and an `invitation` email (payload keys `tenant_name`, `email`, `link`, `expires_in`; link `{issuer}/ui/recovery?token=…`; 7 days), stored in the same user-create transaction. Updates normalise the email and support block and unblock through `status`.
- **BootstrapService**:
  - `ensure_installed` returns `AlreadyInstalled` early if an installation exists. Otherwise it makes one `SetupRepo::install` call (system tenant with registration Disabled, default tenant with registration Open, one active key per tenant, a 1-hour token) and returns `{public_url}/setup?token=…`.
  - `complete_setup` validates the email and password policy, peeks at the token, hashes the password, then calls `SetupRepo::complete_setup`. The admin has `email_verified` set to true. The management client is `mgmt-<16>`, uses `client_secret_basic` and `client_credentials`, and has scopes `admin:read admin:write`.
  - An invalid, used or expired token always gives `Forbidden`.
  - Nothing is logged.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 2 - Correctness] More client consistency rules**
- Confidential clients with auth method `none` and a JWKS on clients that do not use `private_key_jwt` are both rejected. Otherwise a confidential client could have no authentication at all, or carry unused keys.
- Commit: 7eeef44

**2. [Rule 2 - Security] Token peek before the password hash in complete_setup**
- Without the peek, an invalid token would cost an Argon2 hash each time, which is a cheap DoS lever. The atomic consume is unchanged.
- Commit: e97d466

### Notes

- anvil-core has no async runtime among its dev-dependencies, and its Cargo.toml is outside this plan's files, so the async service methods are not unit-tested here. All the rules sit in pure functions that are tested. The async paths will be covered by the admin API and setup integration tests (02-15, 02-16) against real storage.
- In `seal_new_key`, the `tenant` parameter is kept because the interface specifies it. The envelope is bound to the key row id.
- Task 2 was verified in a detached worktree at HEAD, because another wave-2 plan's in-progress `flow/*` files temporarily broke the shared crate build. Result: 36 `service::` tests passed and clippy was clean.

## Verification

- `cargo test -p anvil-core --lib -- service::admin_scope service::client service::tenant`: 27 passed
- `cargo test -p anvil-core --lib -- service::` (worktree at HEAD with Task 2): 36 passed
- `cargo clippy -p anvil-core --all-targets -- -D warnings`: clean

## Self-Check: PASSED
