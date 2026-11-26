---
phase: 06-release-1-0-orgs-and-sso
plan: 11
subsystem: admin-api
tags: [keys, admin-api, openapi, console-types, ADM-02]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: 06-04 empty admin::keys router and the `keys` OpenAPI tag
provides:
  - GET /api/admin/v1/tenants/{slug}/keys (listKeys)
  - POST /api/admin/v1/tenants/{slug}/keys/rotate (rotateKey)
  - DTOs KeyView, KeyList, KeyState, SigningAlg, RotateKeyRequest, RotateKeyResponse
  - regenerated docs/openapi/admin-v1.json and admin-ui/src/api/schema.d.ts
affects: [06-16]

tech-stack:
  added: []
  patterns:
    - "Admin rotation reuses KeyRotationService::rotate_now (single implementation shared with the CLI)"

key-files:
  created:
    - crates/anvil-web/tests/admin_keys.rs
  modified:
    - crates/anvil-web/src/admin/keys.rs
    - crates/anvil-web/src/admin/dto.rs
    - crates/anvil-web/tests/openapi_drift.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts

key-decisions:
  - "Keys API uses the settings scope family; rotating the system tenant's keys also needs admin:write (they sign console/admin tokens)"
  - "KeyView is an allow-list (kid, alg, state, 4 timestamps); the JWK and sealed key have no field, public keys stay on /jwks"
  - "rotate answers 200 {kid}; the web layer passes RotationPolicy::default() because rotate_now never reads the policy"

requirements-completed: [ADM-02]

duration: ~55min (most of it waiting for peers' in-progress files to compile)
completed: 2026-11-26
---

# Phase 6 Plan 11: Signing keys admin API Summary

**Signing keys can now be managed through the admin API. You can list a tenant's keys (kid, alg, state, created/activated/retired/expires, newest first) and rotate one through `KeyRotationService::rotate_now` with the admin actor, which is the same call `anvilid keys rotate` makes. The routes have scope checks, tenant isolation and audit, and they never return private material.**

## Routes

| Method | Path | operationId | Scope |
|---|---|---|---|
| GET | `/api/admin/v1/tenants/{slug}/keys` | listKeys | admin:settings:read / write, admin:read / write |
| POST | `/api/admin/v1/tenants/{slug}/keys/rotate` | rotateKey | admin:settings:write, admin:write (system tenant: admin:write only) |

- The body is `{"alg": "RS256"|"ES256"|"Ed25519", "immediate": false}`, with `deny_unknown_fields`. The response is `200 {"kid": "..."}`.
- A disabled algorithm gives 422 (field `alg`, from rotate_now's Validation error). A concurrent active-key change gives 409. An unknown tenant gives 404.
- Audit: `key_rotation_requested`, then key_generated/activated/retired, written by the service with actor `admin:<client_id>`.

## DTOs (dto.rs)

`KeyState` (wire enum: next/active/retired), `SigningAlg`, `KeyView`, `KeyList`, `RotateKeyRequest`, `RotateKeyResponse`.

## Tests (crates/anvil-web/tests/admin_keys.rs, 6 passing)

- `keys_list_shows_active_and_published_keys`
- `keys_list_never_contains_private_material`: checks every object for no `private_key_enc`, `public_jwk`, d/p/q/dp/dq/qi/k. It also checks the exact member allow-list and that no sealed-key base64 appears anywhere.
- `keys_rotate_returns_new_kid_and_audits`: covers prepublish (next key, in /jwks), the idempotent repeat, and immediate rotation (new key active, old key retired and gone from /jwks). It also checks 3 audit rows with the admin actor.
- `keys_rotate_disabled_alg_is_422`: ES256/Ed25519 give 422; HS256, unknown members and an empty body give 4xx; no key is generated.
- `keys_routes_require_scopes`: no token or a garbage token gives 401; unrelated scopes give 403; read scopes can list but get 403 on rotate; admin:settings:write gets 403 on the system tenant (keys unchanged) and works on default; admin:write can rotate the system tenant.
- `keys_routes_isolate_tenants`: a default-tenant token (own issuer, or claiming the system issuer) gives 401 on both routes for both slugs; each list holds only its own tenant's keys; rotating one tenant leaves the other untouched; an unknown slug gives 404; the `/t/default/api/admin/v1/...` base gives 404.

Mutation check: removing the `require` or the `require_full_admin` call makes `keys_routes_require_scopes` fail.

## Task Commits

1. Task 1, keys list and rotate routes with tests, OpenAPI and console types: `58be85f` (feat)

## Verification

- `cargo test -p anvil-web --test admin_keys --test openapi_drift`: green (6 + 3)
- `cd admin-ui && npm run check:api && npm run typecheck`: green
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: green
- `scripts/check-release-graph.sh`: OK
- Not run: the Postgres backend (`ANVILID_TEST_DB=postgres`, needs Docker) and the full anvil-web suite. Both are left for CI.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] openapi_drift operation count**
- **Found during:** Task 1 (OpenAPI regeneration)
- **Issue:** `spec_is_openapi_3_1_with_oauth2_admin_scopes` pins the operation count at 81, and the two new operations make it 83.
- **Fix:** Changed the expected count to 83. `crates/anvil-web/tests/openapi_drift.rs` is a forced extra file outside files_modified.
- **Commit:** 58be85f

**2. TDD order.** The implementation and tests were written in one pass, and the build was blocked for a while by peers' in-progress files. Mutation checks on the security assertions stand in for a separate RED commit.

## Self-Check: PASSED
