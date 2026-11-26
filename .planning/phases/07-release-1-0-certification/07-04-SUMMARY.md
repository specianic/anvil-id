---
phase: 07-release-1-0-certification
plan: 04
subsystem: foundation-skeletons
tags: [skeleton, routing, rate-limit, cli, OIDC-18, UI-05, ADM-08, ADM-09]
requires: []
provides:
  - "core module skeletons: service::{par, user_import, user_export, hash_profile}, oauth::par"
  - "web skeletons: protocol::par, api_flows (top-level, merged outside ui's Fetch-Metadata layer), admin::{user_import, user_export, password_profiles}"
  - "CLI: anvilid users import|export with the final flags and explicit TRANSITIONAL errors"
  - "rate-limit classes: /par -> Token (protocol surface), POST /api/flows -> Auth (JSON 429)"
affects: [07-10, 07-13, 07-14, 07-15, 07-17, 07-18]
tech-stack:
  added: []
  patterns: [pre-declared empty routers, TRANSITIONAL(<plan>) CLI errors, one skeleton test file per owning plan]
key-files:
  created:
    - crates/anvil-core/src/service/par.rs
    - crates/anvil-core/src/service/user_import.rs
    - crates/anvil-core/src/service/user_export.rs
    - crates/anvil-core/src/service/hash_profile.rs
    - crates/anvil-core/src/oauth/par.rs
    - crates/anvil-web/src/protocol/par.rs
    - crates/anvil-web/src/api_flows/mod.rs
    - crates/anvil-web/src/admin/user_import.rs
    - crates/anvil-web/src/admin/user_export.rs
    - crates/anvil-web/src/admin/password_profiles.rs
    - crates/anvil-web/tests/skeleton_v10.rs
    - crates/anvilid/src/users_import.rs
    - crates/anvilid/src/users_export.rs
    - crates/anvilid/tests/users_import_skeleton.rs
    - crates/anvilid/tests/users_export_skeleton.rs
  modified:
    - crates/anvil-core/src/service/mod.rs
    - crates/anvil-core/src/oauth/mod.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/src/protocol/mod.rs
    - crates/anvil-web/src/admin/mod.rs
    - crates/anvil-web/src/layers/ratelimit.rs
    - crates/anvilid/src/main.rs
decisions:
  - "api_flows answers a JSON 404 problem (application/problem+json) for every path below /api/flows/v1 via a catch-all route, instead of being an empty router; without a route the Fetch-Metadata placement test could not detect a wrong merge"
  - "users_import::run / users_export::run take (&Config, &Args) already, dispatched from main.rs through #[tokio::main] wrappers, so 07-14/07-15 never edit main.rs"
  - "users export: --gdpr requires --user; --include-password-hashes conflicts with --gdpr (decision Q4)"
metrics:
  duration: ~70 min (about 25 min of it waiting for other wave-1 plans' in-progress files to compile)
  completed: 2026-11-26
requirements: [OIDC-18, UI-05, ADM-08, ADM-09 (not ticked; the gate 07-23 ticks them)]
---

# Phase 7 Plan 04: Phase 7 module, route and CLI skeletons Summary

Every Phase 7 module, route mount and CLI subcommand is pre-declared, so later plans fill their own files only.
The skeletons never return success: new HTTP paths answer 404 and the CLI commands exit non-zero with
`not available yet (TRANSITIONAL(07-14))` / `(TRANSITIONAL(07-15))`. The rate limiter classifies `/par` and
`/api/flows` POSTs.

## Module and route map (owning plans)

| Item | Kind | Owner | Current behaviour |
| ---- | ---- | ----- | ----------------- |
| `anvil_core::service::par` | doc-only module | 07-13 | none |
| `anvil_core::oauth::par` | doc-only module | 07-13 | none |
| `anvil_core::service::user_import` | doc-only module | 07-14 | none |
| `anvil_core::service::hash_profile` | doc-only module | 07-14 | none |
| `anvil_core::service::user_export` | doc-only module | 07-15 | none |
| `anvil_web::protocol::par` (`POST /par`) | empty `Router`, merged in `protocol::routes()` | 07-13 | HTML 404 (fallback) |
| `anvil_web::api_flows` (`/api/flows/v1/*`) | `pub fn routes()`, merged in `lib.rs` next to `ui::routes()`, outside the Fetch-Metadata layer and `public_cors()` | 07-10 / 07-18 | JSON 404 problem (catch-all) |
| `anvil_web::admin::user_import` | empty `OpenApiRouter` | 07-17 | admin problem 404 |
| `anvil_web::admin::user_export` | empty `OpenApiRouter` | 07-17 | admin problem 404 |
| `anvil_web::admin::password_profiles` | empty `OpenApiRouter` | 07-17 | admin problem 404 |

The empty admin routers add no OpenAPI paths, so they leave `docs/openapi/admin-v1.json` unchanged.

## CLI (`anvilid users`)

- `users import <FILE> [--tenant <SLUG>=default] [--dry-run] [--update] [--source <LABEL>]` plus the shared
  config overrides. Implemented in `crates/anvilid/src/users_import.rs` (07-14).
- `users export [--tenant <SLUG>=default] [--user <UUID>] [--gdpr] [--include-password-hashes] [--out <PATH>]`
  plus the shared config overrides. `--gdpr` requires `--user`. `--include-password-hashes` conflicts with
  `--gdpr`. Its help says "CLI only; audited; never part of the GDPR export (decision Q4)". Implemented in
  `crates/anvilid/src/users_export.rs` (07-15).
- Each `run(cfg, args)` currently fails with the TRANSITIONAL marker. It opens no storage and creates no data
  directory.

## Rate-limit classes

| Request | Class | 429 surface |
| ------- | ----- | ----------- |
| `/par` (any method) | `Token` | Protocol (OAuth JSON) |
| `POST /api/flows` and below | `Auth` | Admin-style problem JSON (everything below `/api`) |
| `GET /api/flows/...` | `Default` | problem JSON |

The tests are `layers::ratelimit::tests::par_is_token_class` and `flows_post_is_auth_class`.

## Tasks

| Task | Commit | Result |
| ---- | ------ | ------ |
| 1: module and route skeletons, rate-limit classes | 5c85a41 | done |
| 2: CLI `users import|export` skeleton | 3dc9753 | done |

## Verification

- `cargo test -p anvil-web --lib layers::ratelimit`: 6 passed.
- `cargo test -p anvil-web --test skeleton_v10`: 4 passed (par, flows, admin export 404s;
  `api_flows_not_behind_ui_fetch_metadata`).
- Mutation check: wrapping the `api_flows::routes()` merge in `fetch_metadata_layer()` made
  `api_flows_not_behind_ui_fetch_metadata` fail (403). Reverted afterwards.
- `cargo test -p anvilid --test users_import_skeleton --test users_export_skeleton --test cli`: 3 + 3 + 18 passed.
- `cargo clippy -p anvil-core --all-targets --locked -- -D warnings`: clean.
- `scripts/check-release-graph.sh`: OK.
- `cargo test -p anvil-web --test openapi_drift`: `committed_spec_matches_generated` FAILS in the shared tree
  because of another wave-1 plan's uncommitted `admin/dto.rs` change (new audit action variants such as
  `UsersImported`). This plan adds no OpenAPI paths. The plan that owns that change (07-03 owns admin-v1.json)
  needs to refresh the spec.
- `cargo clippy -p anvil-web` fails only on `ui/flow_driver.rs` (`large_enum_variant`), which is another
  plan's in-progress file. None of this plan's files produce warnings.
- `cargo test --workspace --locked` was not run: the shared tree held other plans' in-progress code, and the
  rules ask for targeted test commands. Postgres runs are left for CI.

## Deviations from Plan

**1. [Rule 2 - Correctness of the test] api_flows has a JSON 404 catch-all instead of an empty router**
- **Found during:** Task 1 (mutation check)
- **Issue:** an empty router contributes no routes, so `.layer(fetch_metadata_layer())` would never run for
  `/api/flows` paths. The placement test could not fail, so the required mutation check could not be met.
- **Fix:** `api_flows::routes()` serves `/api/flows/v1` and `/api/flows/v1/{*rest}` with an explicit 404
  problem JSON (never success). 07-10 adds its static routes next to the catch-all (static routes win in
  matchit).
- **Commit:** 5c85a41

**2. [Shared tree] admin/mod.rs committed hunk-wise**
- Another plan had an uncommitted hunk in `admin/mod.rs` (the `admin:users:export` scope description). Only this
  plan's two hunks were staged (index blob built from HEAD), and the other hunk stays in the working tree.

## Self-Check: PASSED
