---
phase: 07-release-1-0-certification
plan: 21
subsystem: api-compatibility
tags: [openapi, compatibility, versioning, upgrade, docs, QUAL-03]
requires:
  - "07-17: final admin API surface (import/export, admin:users:export)"
  - "07-18: final flows API surface (native mode)"
  - "07-08 / 07-11: upgrade tests 0.4 -> 1.0 and 1.0.0-beta.1 -> 1.0 on both backends"
provides:
  - "docs/COMPATIBILITY.md (published compatibility and deprecation policy)"
  - "1.0 OpenAPI baselines docs/openapi/{admin,flows}-v1.baseline-1.0.json"
  - "crates/anvil-web/tests/api_compat.rs breaking-change check"
  - "config_doc version tests"
  - "UPGRADING.md: Phase 7 changes, Limitations in 1.0, 1.0.0-beta.1 to 1.0"
affects: [07-22 (docs/SUMMARY.md needs a COMPATIBILITY.md entry), 07-23 (gate re-runs api_compat)]
tech-stack:
  added: []
  patterns:
    - "OpenAPI comparison as fact sets: kept (baseline subset of current), limited (current subset of baseline), response types (only for fields present in the baseline)"
key-files:
  created:
    - docs/COMPATIBILITY.md
    - docs/openapi/admin-v1.baseline-1.0.json
    - docs/openapi/flows-v1.baseline-1.0.json
    - crates/anvil-web/tests/api_compat.rs
  modified:
    - crates/anvil-core/src/model/config_doc.rs
    - docs/UPGRADING.md
key-decisions:
  - "api_compat compares the documents generated from the handlers (anvil_web::admin::openapi / api_flows::openapi), not the committed admin-v1.json/flows-v1.json, so it holds before the drift tests are refreshed"
  - "Required-field tracking follows the required chain only (a required field inside a new optional object is additive); oneOf/anyOf variant requirements are not tracked"
  - "Response type widening (e.g. adding null) is breaking only for fields that exist in the baseline"
  - "No deprecation helper in code (nothing deprecated in 1.0); COMPATIBILITY.md says it arrives with the first deprecation"
metrics:
  duration: "~40 min"
  completed: 2026-11-26
---

# Phase 7 Plan 21: API compatibility policy and 1.0 baselines Summary

In-repo OpenAPI breaking-change test against committed 1.0 baselines of the management and
headless flow APIs, pinned tenant-config version tests, the published compatibility/deprecation
policy (docs/COMPATIBILITY.md), and the final 1.0 upgrade guide.

## Comparator rules (api_compat.rs, ~500 lines incl. self-tests)

Each document becomes three fact sets ($ref resolved into components, cycles stopped; allOf
merged; oneOf/anyOf walked with no required chain; `items` -> `[]`, object `additionalProperties`
-> `{}`; path-level and operation-level parameters merged):

- **kept** (a baseline fact missing from current = breaking): operations (method + path),
  response status codes and content types, response field paths and enum/const values, request
  content types, request field paths, parameters (in:name), request enum values, request type
  members, security alternatives per operation (`(none)` for unauthenticated operations), declared
  security schemes and scopes.
- **limited** (a current fact missing from baseline = breaking): required request parameters,
  required request bodies, required request fields along the required chain.
- **response types**: a new type member (e.g. `null`) on a response field that exists in the
  baseline is breaking; new fields carry no constraint.

## Baselines

Byte copies of `docs/openapi/admin-v1.json` and `flows-v1.json` at 0ab478f (drift tests green,
so committed == generated):

- `admin-v1.baseline-1.0.json` sha256 `277552b05d07a0b2d7d4b4b326089fbd9b61940a32fba2d91b48d531f11e487e` (76 paths)
- `flows-v1.baseline-1.0.json` sha256 `573a3eee8b06c9a10c55a93ce3d33be1294933d976d1cf668fb6c1a196bb1e58` (8 paths)

## Tests

- `cargo test -p anvil-web --test api_compat`: 8 passed:
  `api_compat_admin_has_no_breaking_change`, `api_compat_flows_has_no_breaking_change`,
  `api_compat_baseline_is_compatible_with_itself_and_has_facts`,
  `api_compat_detects_removed_operation` (both docs), `api_compat_detects_removed_response_field`
  (also removed enum value and response field widened to null),
  `api_compat_detects_new_required_request_field` (also optional->required and type narrowing),
  `api_compat_detects_removed_scope` (security alternative and declared scope),
  `api_compat_allows_added_optional_field` (optional request/response fields, enum value, new
  operation, widened request type, extra security alternative).
- `--test openapi_drift` 3 passed, `--test openapi_flows_drift` 2 passed; both `cmp` checks OK.
- `cargo test -p anvil-core --lib model::config_doc`: 8 passed incl. `config_doc_version_1_accepted`
  and `config_doc_unknown_version_refused` (versions 0/2/99 -> `CoreError::Validation{field:"version"}`
  "unsupported document version N"; missing version -> serde "missing field `version`"; -1 refused).
- Mutation check: adding a fake operation `GET /api/admin/v1/gone` to the admin baseline (i.e. the
  current doc lacks an operation the baseline has) made `api_compat_admin_has_no_breaking_change`
  fail with "removed or narrowed: operation GET /api/admin/v1/gone"; baseline restored, `cmp` OK.
- rustfmt --check on touched files, clippy -D warnings (anvil-web api_compat test, anvil-core lib +
  tests), scripts/check-release-graph.sh, scripts/check-deps.sh: all OK.

## Commits

- 86e6f12 test(07-21): 1.0 OpenAPI baselines, breaking-change check, config version tests
- 98cf137 docs(07-21): compatibility policy and the 1.0 upgrade guide

## Deviations from Plan

- [Rule 1 - Bug] First comparator version flagged the types of newly added response fields as
  breaking (`api_compat_allows_added_optional_field` failed); response types moved to their own set
  checked only for baseline fields. Fixed before commit.
- Comparator is ~500 lines with self-tests (plan estimated ~200 for the comparator alone; the
  comparator part is ~250).

## Notes for other plans

- docs/SUMMARY.md (not owned here) needs a `COMPATIBILITY.md` entry (07-22 docs pass).
- No CHANGELOG file exists; COMPATIBILITY.md refers to "the release notes (CHANGELOG)" without a link.
- mdbook is not installed locally; the in-page anchors `#04-to-10`, `#new-in-the-final-10`,
  `#limitations-in-10` follow mdBook's id scheme but were not built here.
- docs/ARCHITECTURE.md L1440/L1463 and OPERATIONS.md "Limitations in 1.0" still say
  tenant-restricted admins are "deferred to Phase 7"; should say 1.x with the Q8 justification (07-22).

## Self-Check: PASSED
