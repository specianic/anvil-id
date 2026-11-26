---
phase: 05-release-0-4-operate-it
plan: 03
subsystem: ci, web, load-testing
tags: [fuzz, ci, body-limit, 413, k6, haproxy, ha, perf, compose]
requires:
  - phase: 04-36
    provides: security_body_limit test and the 400/413 finding for streamed bodies
  - phase: 04-18
    provides: per-request body limit middleware (64 KiB, 400 KiB logo uploads)
provides:
  - "ci.yml fuzz-build job + `just fuzz-check` (cargo check fuzz/Cargo.toml --locked --bins); fuzz.yml smoke on push to main"
  - "ui::login::rejection_is_too_large (crate-wide via ui::rejection_is_too_large): the one body-limit rejection check"
  - "ui::login::rejected_form / rejection_status: 413 or 400 for every FormRejection; AdminError::PayloadTooLarge -> 413 problem"
  - "tests/load/{token.js, ha.js, lib.sh, run-perf.sh, run-ha.sh, README.md}"
  - "deploy/compose/ha/{compose.yml, haproxy.cfg}"
  - ".github/workflows/load.yml (workflow_dispatch only)"
affects: [05-05, 05-16, 05-18, 05-26, 05-gate]
tech-stack:
  added: ["k6 2.4.0 (CI tool, pinned)", "HAProxy 3.2, Valkey 8 (compose images, pinned by digest)"]
  patterns:
    - "Every `Result<Form<_>, FormRejection>` handler answers `Err(e)` through `rejected_form` (pages) or `rejection_status` (JSON form endpoints)"
    - "Load scripts provision through the real setup page and admin API (no test hooks in the server)"
key-files:
  created:
    - tests/load/token.js
    - tests/load/ha.js
    - tests/load/lib.sh
    - tests/load/run-perf.sh
    - tests/load/run-ha.sh
    - tests/load/README.md
    - deploy/compose/ha/compose.yml
    - deploy/compose/ha/haproxy.cfg
    - .github/workflows/load.yml
  modified:
    - .github/workflows/ci.yml
    - .github/workflows/fuzz.yml
    - justfile
    - crates/anvil-web/src/admin/auth.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/mod.rs
    - crates/anvil-web/src/ui/{verification,account_apps,logout,mfa,registration,account_sessions,consent,account_linked,email_code,account_profile,account_security,select_account,recovery,setup,upstream}.rs
    - crates/anvil-web/tests/security_body_limit.rs
key-decisions:
  - "Body-limit detection matches http_body_util::LengthLimitError by its Display text along the source chain: http-body-util is only a dev-dependency of anvil-web and Cargo manifests are owned by 05-01; the integration test breaks if an upgrade changes the text"
  - "bad_form keeps its 3-argument form for invalid-but-parsed input (missing flow id, bad decision value); extractor rejections go through the new rejected_form(state, Option<tenant>, loc, &rejection), because several bad_form call sites have no rejection to pass and setup.rs has no tenant"
  - "Push to main runs the fuzz smoke job (10k iterations per target), not the 4 x 5 min nightly matrix"
  - "k6 summaries are written by handleSummary (not --summary-export) so the JSON file does not depend on k6 CLI flags; the median-of-3 verdict reads the per-metric threshold results from it"
  - "run-perf.sh generates its single-node compose file in a private temp dir and takes the Postgres image (digest) from deploy/compose/ha/compose.yml, so there is one pin"
metrics:
  duration: ~80min
  completed: 2026-11-26
---

# Phase 5 Plan 03: Fuzz build on push, unified 413, load/HA harness skeleton Summary

**The fuzz crate is type-checked on every push and PR, and every route family now answers exactly 413 for an oversized body, whether it is declared or streamed. A k6 + HAProxy harness for the PRD throughput target and the three-node restart test is in place, run only on demand until 05-26 makes it gating.**

## 413 unification

- One check: `ui::login::rejection_is_too_large(&dyn Error)` walks the rejection's source chain for the body-limit error. It is re-exported as `crate::ui::rejection_is_too_large` for the admin API.
- Pages: `rejected_form(state, tenant, loc, &rejection)` renders the themed error page with 413 or 400. All 29 page handlers that take `Result<Form<_>, FormRejection>` use it, including `setup.rs` (which has no tenant).
- JSON form endpoints: `/ui/login/passkey/options` uses `rejection_status(&rejection)`. The account passkey options endpoint takes the CSRF token from the form or a header, and it now returns 413 for an oversized body instead of ignoring the rejection.
- Admin API: when `AdminJson` hits the limit, it returns `AdminError::PayloadTooLarge`, a 413 `application/problem+json` (`type urn:anvilid:problem:invalid_request`, `status 413`).
- `grep -rn "StatusCode::BAD_REQUEST" crates/anvil-web/src/ui | grep -i reject`: empty.

### Tests for the security map (`crates/anvil-web/tests/security_body_limit.rs`, 4 tests)

- `protocol_and_page_routes_answer_413_above_64_kib`: `POST /token`, `POST /logout`, `POST /ui/login?flow=…`, `POST /ui/login/passkey/options?flow=…`. Each gets exactly 413 with `Content-Length` and exactly 413 when streamed.
- `admin_json_routes_answer_413_above_64_kib`: `POST /api/admin/v1/tenants`, `PATCH …/tenants/default`, `PUT …/tenants/default/branding`. Each gets exactly 413 in both modes, and the problem body has `status: 413`.
- `logo_uploads_accept_up_to_400_kib_and_no_more`: both logo routes give 413 in both modes for 400 KiB + 1, and 200 for a 100 KiB PNG.
- `other_body_rejections_stay_400` (new, negative): a form page posted as JSON and malformed admin JSON both still get 400.

## Fuzz on push

- `just fuzz-check` (`cargo check --manifest-path fuzz/Cargo.toml --locked --bins`) is added to `just ci`. The `ci.yml` job `fuzz-build` runs it on the stable toolchain, with rust-cache on `fuzz -> target`.
- `fuzz.yml` now also triggers on push to main for `fuzz/**`, `crates/anvil-core/src/oauth/**` and `crates/anvil-jose/src/**`, and runs the smoke job there. The nightly matrix runs only on schedule or dispatch.

## Harness usage

```sh
just docker-image
tests/load/run-perf.sh   # RATE=1000 TRIALS=3; median trial by p99 decides; results in target/load/
tests/load/run-ha.sh     # RATE=300 RESTART_SPACING=20; 3 nodes behind HAProxy, restarts under load
```

The setup and provisioning steps (setup URL from the logs, setup completion, system admin client, benchmark client in `default`) are in `lib.sh`, together with the k6 runner (the binary, or the pinned `grafana/k6` image) and the job summary writer. `load.yml` is `workflow_dispatch` only (`which` = both | perf | ha). It builds the image with `just docker-image`, installs k6 2.4.0 and uploads `target/load/`. The README documents the runner size (Q2: a public 4 vCPU runner shared by k6, Postgres and AnvilID), the median-of-3 rule, and that nothing here gates until 05-26.

Pinned images: `postgres:18-alpine@sha256:0115267a…`, `valkey/valkey:8-alpine@sha256:9971099a…`, `haproxy:3.2-alpine@sha256:7816a980…`, `grafana/k6:2.4.0@sha256:d41bb79c…`. The digests were read from Docker Hub on 2026-11-26.

## Verification

- `cargo test -p anvil-web --test security_body_limit`: RED first (3 failures, streamed bodies got 400), then 4 passed.
- `cargo test -p anvil-web --lib`: 136 passed.
- `cargo test -p anvil-web --test security_csrf --test security_setup --test flow_login --test flow_registration --test account_security --test account_profile --test logout --test admin_api --test render --test flow_mfa --test consent --test flow_passkey`: all green.
- `cargo clippy -p anvil-web --lib --test security_body_limit --locked -- -D warnings`: clean. Clippy with `--all-targets` could not run, because `backchannel_wake.rs` does not compile against 05-01's in-progress `NewClient` fields.
- Plan Task 2 verify (`bash -n` on the three scripts, the greps, YAML parse of load.yml and compose.yml): OK. `node --check` on token.js and ha.js: OK.
- `lib.sh` provisioning run end to end against a locally built `anvilid serve` (SQLite, scratch data dir, removed afterwards): setup completion, management token, system admin client, benchmark client and a client_credentials token all worked. `ANVILID_REDIS_URL`, `ANVILID_SHUTDOWN_DRAIN` and `ANVILID_DATABASE_MAX_CONNECTIONS` were set and ignored, with no startup error.
- The median-of-3 verdict script was run against synthetic summaries: it picks the median trial by p99 and exits 1 when that trial misses a threshold.

**Not run (CI only):** docker compose (Docker CLI unavailable here, so `docker compose config` did not run either), k6 itself (no k6 binary locally, `k6 inspect` not run), shellcheck (not installed), and the `load.yml` dispatch. The orchestrator should dispatch `load.yml` once after pushing. That first run will probably fail the 1000 req/s threshold until the 05-18 perf work lands, and the HA run may fail on concurrent first start and on drain (05-05/05-16/05-26 own those). It is not gating.

**`cargo check --manifest-path fuzz/Cargo.toml --locked --bins` fails right now.** `fuzz/fuzz_targets/authorize_parse.rs:40` builds a `Client` literal without 05-01's new fields (`metadata_expires_at`, `registration_access_token_hash`, `registration_source`). The new `fuzz-build` job is catching exactly the regression it was added for. The fix belongs to 05-01 (it owns the model change; `fuzz/` is not in 05-03's files). The `--locked` resolution itself succeeded.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing] JSON-answering form endpoints also map the limit to 413**
- Found during: Task 1 (the per-file `FormRejection` count did not match the `rejected_form` count).
- Issue: `/ui/login/passkey/options` answered every rejection with a 400 JSON error. The account passkey options endpoint dropped the rejection and continued with the header CSRF token.
- Fix: `rejection_status()` is shared with `rejected_form`. Both endpoints return 413 for an oversized body. A test covers the login one.
- Files: `ui/login.rs`, `ui/account_security.rs`, `tests/security_body_limit.rs`. Commit a32dcf0.

**2. [Rule 3 - Blocking] `bad_form` signature**
- The plan said to change `bad_form` to take the rejection. 9 of its call sites are not extractor rejections (missing flow id or token, an invalid decision value, a bad Location header), and `setup.rs` has no tenant. So `bad_form` stays as the 400 "invalid input" page, and a new `rejected_form(state, Option<&ResolvedTenant>, loc, &FormRejection)` handles every rejection site.

**3. [Rule 3 - Blocking] Detection by message instead of downcast**
- `http_body_util::LengthLimitError` cannot be downcast without a normal dependency on http-body-util, and the Cargo manifests are owned by 05-01. axum's composite rejections also skip the axum `LengthLimitError` wrapper in their source chain. The check therefore matches the leaf error's text, `length limit exceeded`. The integration tests pin that text.

**4. [Rule 3 - Blocking] k6 summary via handleSummary**
- The plan says `--summary-export`. The scripts write the JSON summary from `handleSummary` instead, so the file does not depend on the k6 CLI flags. The k6 binary could not be downloaded here to confirm the 2.x flag set.

### Forced extras

- `crates/anvil-web/src/ui/mod.rs`: one additive line, `pub(crate) use login::rejection_is_too_large;`. `ui::login` is a private module, and the admin API needs the shared check.

## Deferred Issues

- `fuzz/fuzz_targets/authorize_parse.rs` needs 05-01's new `Client` fields (see Verification). Not fixed here, because it is outside this plan's files.

## Commits

- fd62689 feat(05-03): fuzz targets type-checked on push, 413 for every oversized body
- a32dcf0 fix(05-03): 413 for oversized bodies on the passkey JSON form endpoints
- de91121 feat(05-03): k6 load and HA harness skeleton, dispatch-only load workflow

## Self-Check: PASSED
