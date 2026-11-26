---
phase: 07-release-1-0-certification
plan: 17
subsystem: admin-api-import-export
tags: [admin-api, user-import, user-export, gdpr, hash-profiles, body-limit, openapi, ADM-08, ADM-09]
requires:
  - "07-04 admin::{user_import, user_export, password_profiles} empty routers"
  - "07-14 UserImportService, IMPORT_BATCH_MAX, HashProfileService (HashProfileSummary without key)"
  - "07-15 UserExportService (export_user, gdpr_bundle, bulk_without_hashes, BulkExport page iterator)"
  - "07-03 admin:users:export scope (export_scope_satisfied)"
provides:
  - "POST /api/admin/v1/tenants/{slug}/users/import (NDJSON, report JSON)"
  - "GET/POST /api/admin/v1/tenants/{slug}/password-hash-profiles, DELETE .../{id}"
  - "GET /api/admin/v1/tenants/{slug}/users/{user_id}/export[?profile=gdpr], GET .../users/export (streamed NDJSON)"
  - "admin::branding::{is_user_import, IMPORT_BODY_LIMIT} body-limit branch"
  - "OpenAPI schemas ImportReportView, ImportCountsView, ImportRecordView, CreateHashProfile (signer_key writeOnly), HashProfileView, HashProfileList, UserExportDocument"
affects: [07-20 (console import/profiles/export pages use these routes and schema.d.ts), 07-22 (docs site links IMPORT-EXPORT), 07-23 (gate ticks ADM-08/ADM-09; security-test map)]
tech-stack:
  added: ["futures-util (direct dep of anvil-web; already in the graph through axum)"]
  patterns:
    - "Streamed admin body: futures_util::stream::unfold over the core page iterator, Body::from_stream"
    - "Audit-on-drop guard so an interrupted stream is still audited (failure + count so far)"
    - "Query structs with deny_unknown_fields as the refusal mechanism for forbidden options"
key-files:
  created:
    - crates/anvil-web/tests/admin_user_import.rs
    - crates/anvil-web/tests/admin_user_export.rs
    - crates/anvil-web/tests/security_import.rs
    - crates/anvil-web/tests/security_export.rs
  modified:
    - crates/anvil-web/src/admin/user_import.rs
    - crates/anvil-web/src/admin/user_export.rs
    - crates/anvil-web/src/admin/password_profiles.rs
    - crates/anvil-web/src/admin/branding.rs
    - docs/openapi/admin-v1.json
    - admin-ui/src/api/schema.d.ts
    - docs/IMPORT-EXPORT.md
    - docs/OPERATIONS.md
    - Cargo.toml, Cargo.lock, crates/anvil-web/Cargo.toml (forced extra, futures-util)
    - crates/anvil-web/tests/openapi_drift.rs (forced extra, operation count 123 -> 129)
  deleted:
    - crates/anvil-web/tests/skeleton_v10.rs
key-decisions:
  - "Over IMPORT_BATCH_MAX records is a 413 problem (not the service's 422), checked before the service runs; nothing imported, nothing audited"
  - "Import requires Content-Type application/x-ndjson (400 otherwise); non-UTF-8 lines become empty records the service rejects as invalid_record (never decoded lossily)"
  - "Hash-password options over HTTP are refused, not ignored: both export queries are deny_unknown_fields, so include_password_hashes in any spelling is a 422"
  - "Bulk export failure mid-stream writes a trailing {\"error\":\"export_failed\"} line (documented); a dropped response body audits the export as failure with the count so far"
  - "Profiles and import/export use the existing `users` OpenAPI tag (adding a tag would edit admin/mod.rs, not owned)"
  - "Export scope check lives in user_export.rs (require_system_admin + export_scope_satisfied); auth.rs not edited"
metrics:
  duration: ~110min (about 15 min waiting for 07-18's in-progress api_flows files to compile)
  completed: 2026-11-26
requirements: [ADM-08, ADM-09 (not ticked; the gate 07-23 ticks them)]
---

# Phase 7 Plan 17: Admin API for import, export and hash profiles Summary

The management API can now import users with legacy hashes (NDJSON, batch-capped, under a 1 MiB
body limit that applies to this one path only), manage Firebase hash profiles with a write-only
signer key, and export users individually, as a GDPR bundle or in bulk as streamed NDJSON. Export
needs `admin:users:export` or `admin:write`, every export is audited, and no HTTP path can export
password hashes.

## Routes and scopes

| Route | Scope | Notes |
| --- | --- | --- |
| `POST /tenants/{slug}/users/import?dry_run&update&source` | `admin:users:write` / `admin:write` | NDJSON body, report JSON, `no-store`; >1000 records 413; non-NDJSON 400; unknown query 422 |
| `GET /tenants/{slug}/password-hash-profiles` | `admin:settings:read` (+ write, admin:read, admin:write) | `{items: [HashProfileView]}` |
| `POST /tenants/{slug}/password-hash-profiles` | `admin:settings:write` / `admin:write` | 201 + Location; base64 signer_key/salt_separator; 409 duplicate name; 422 bad base64/kind/params |
| `DELETE /tenants/{slug}/password-hash-profiles/{id}` | `admin:settings:write` / `admin:write` | 204; 409 while referenced; 404 unknown/non-UUID |
| `GET /tenants/{slug}/users/{user_id}/export[?profile=gdpr]` | `admin:users:export` / `admin:write` | JSON record or GDPR bundle; 404 cross-tenant/unknown; other `profile` 422 |
| `GET /tenants/{slug}/users/export` | `admin:users:export` / `admin:write` | `application/x-ndjson`, `no-store`, id order, pages of 100 |

## Limits

- `IMPORT_BODY_LIMIT` = 1 MiB through `is_user_import(method, path)` (exact `POST
  /api/admin/v1/tenants/{slug}/users/import`), a branch of the single `body_limit` middleware.
  Every other route keeps `BODY_LIMIT` (unit test `user_import_paths`; integration test
  `import_body_limit_only_on_import_path`).
- Record cap `IMPORT_BATCH_MAX` (1000 non-blank lines) gives a 413 problem.

## Tests

- `cargo test -p anvil-web --lib admin::` 9 passed (incl. `branding::tests::user_import_paths`,
  `user_import::tests::{split_keeps_line_numbers_and_refuses_bad_utf8, ndjson_media_type}`,
  `password_profiles::tests::create_debug_redacts_the_signer_key`).
- `admin_user_import` (3): `import_over_http_then_login_with_old_passwords` (profile created via
  the API, dry run writes nothing, real run, unchanged rerun, UI login with Openwall bcrypt and
  the published Firebase vector, conflict after the rehash, 4 `users_imported` events with the
  source), `import_reports_bad_lines_by_number_without_echoing_them`,
  `import_requires_ndjson_content_type_and_a_valid_query`.
- `security_import` (6): `import_requires_users_write_scope`, `import_body_limit_only_on_import_path`,
  `import_record_cap_enforced`, `import_report_contains_no_hash`, `profile_signer_key_never_returned`
  (create/list/conflict/422 responses, OpenAPI response schemas, writeOnly flag, scope refusals),
  `profile_delete_referenced_conflict`.
- `admin_user_export` (3): `single_user_export_has_the_documented_fields`,
  `gdpr_bundle_has_every_inventory_category`, `bulk_export_streams_ndjson_over_several_pages`
  (130 users, line count = user count, id order, content type, empty tenant = empty body).
- `security_export` (5): `export_requires_export_scope` (admin:read, admin:users:read,
  admin:users:write refused on all three routes; export scope grants nothing else),
  `export_cross_tenant_refused`, `export_no_hash_via_http` (nine spellings of the hash option on
  all three routes are 422; no `$argon2`/`$2a$`/`password_hash` in any export; OpenAPI has no such
  parameter), `gdpr_export_redacts_admin_identity`, `export_is_audited`.
- `security_body_limit` 5 passed, `openapi_drift` 3 passed.
- `cargo test -p anvil-web --locked --no-fail-fast` (shared tree): 129 test binaries passed; the only
  failure is `openapi_flows_drift::committed_flows_spec_matches_generated`, flows-v1.json owned by
  07-18 and in progress in the tree.
- console: `npm run gen:api`, `npm run check:api` (up to date), `npm run typecheck` clean (with the
  existing node_modules; `npm ci` not re-run).

## Mutation results

| Mutation | Result |
| --- | --- |
| Import handler without `auth.require(Users, Write)` | `import_requires_users_write_scope` FAILED (admin:read imported a user, 200); reverted |
| Export check also accepts `admin:users:write` | `export_requires_export_scope` FAILED (200 instead of 403); reverted |

## Task Commits

1. `64429c2` feat(07-17): admin user import and password hash profile routes
2. `fce093e` feat(07-17): admin user export routes, regenerated contracts, import/export docs

## Deviations from Plan

1. **[Rule 3 - Blocking] futures-util dependency (forced extra: Cargo.toml, crates/anvil-web/Cargo.toml, Cargo.lock).**
   anvil-web had no Stream crate, and `Body::from_stream` needs one; 07-15 asked for
   `futures::stream::unfold`. futures-util 0.3.34 was already in anvil-web's normal graph through
   axum, so no new crate enters the build; `scripts/check-deps.sh` OK. No wave-4 plan owns these
   manifests.
2. **[Rule 3 - Blocking] openapi_drift.rs operation count 123 -> 129 (forced extra).** The drift test
   pins the number of operations; this plan adds six.
3. **Record cap answer is 413** (the must-have allows 413/400); the service's own 422 is not reached
   over HTTP.
4. **Import report rerun after sign-in reports `conflict`** (07-14 behaviour: the rehash changes the
   stored hash); the test asserts the unchanged rerun before the first sign-in and the conflict after.
5. **Announced oversize bodies get the limit layer's plain-text 413** (existing behaviour for every
   route, as in security_body_limit); streamed oversize bodies get the problem JSON from the handler.
6. **Interrupted bulk export audit** (beyond the plan): a `Drop` guard records `failure` with the count.

## Not run

- Postgres-backed runs (no Docker; CI). All new tests use `TestApp` (`ANVILID_TEST_DB`).
- `just doc` over the workspace fails only on 07-18's in-progress `api_flows/native.rs`
  (private intra-doc link); this plan adds no public rustdoc links.
- `cargo clippy -p anvil-web -D warnings` fails only on 07-18's `api_flows/native.rs`
  (`result_large_err`); with that lint allowed, `--all-targets` is clean.

## Notes for later plans

- 07-23: the named negatives above are not yet in `scripts/check-security-tests.sh` (not owned here).
- 07-20: profiles' `signer_key`/`salt_separator` are standard base64 strings; import response is
  `ImportReportView`; export responses are typed as `UserExportDocument` (Object) in schema.d.ts.

## Self-Check: PASSED
