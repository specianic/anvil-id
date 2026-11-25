---
phase: 01-foundations-and-spikes
plan: 04
subsystem: api
tags: [rust, axum, oidc-discovery, rust-embed, aws-lc-rs, mimalloc, clap, tracing]

requires:
  - phase: 01-01
    provides: Workspace manifests and Cargo.lock with axum, rust-embed, aws-lc-rs, mimalloc, clap, tracing
provides:
  - "anvil_web::WebConfig { issuer: url::Url } and anvil_web::router(cfg) -> axum::Router"
  - "GET /.well-known/openid-configuration derived from the issuer (path-preserving, trailing slash trimmed)"
  - "GET /healthz -> ok"
  - "Explicit 501 JSON errors for GET /authorize, POST /token, GET /jwks"
  - "GET /assets/{*path}: embedded themes/default/static with aws-lc-rs SHA-256 ETag, 304 on If-None-Match"
  - "`anvilid serve --listen <SocketAddr> --issuer <URL>` (ANVILID_LISTEN / ANVILID_ISSUER), mimalloc, graceful SIGINT/SIGTERM"
affects: [01-06, 01-07, phase-02]

tech-stack:
  added: []
  patterns:
    - "Discovery document serialised once at router build time and shared as Bytes state"
    - "Advertised-but-unbuilt endpoints answer 501 with {error: not_implemented, error_description}"
    - "Asset paths validated (no empty/./.. segments, no backslash) before rust-embed lookup"
    - "Tokio runtime started inside the serve subcommand; CLI parsing and tracing init stay synchronous"

key-files:
  created:
    - themes/default/static/anvil.css
    - crates/anvil-web/src/discovery.rs
    - crates/anvil-web/src/assets.rs
    - crates/anvil-web/src/not_implemented.rs
    - crates/anvil-web/tests/router.rs
  modified:
    - crates/anvil-web/src/lib.rs
    - crates/anvilid/src/main.rs

key-decisions:
  - "If-None-Match uses weak comparison (W/ prefix, comma lists, *) per RFC 9110; 304 also carries ETag and Cache-Control"
  - "anvilid rejects issuers with a query, fragment or non-http(s) scheme before binding"
  - "#[tokio::main] is applied to the serve fn rather than main so future subcommands need not start a runtime"

requirements-completed: []  # FND-04/FND-05 groundwork only; delivered by plans 07 and 06

duration: 5min
completed: 2026-11-25
---

# Phase 1 Plan 04: anvil-web router and `anvilid serve` Summary

**axum router with an issuer-derived OIDC discovery document, explicit 501s for /authorize, /token and /jwks, and rust-embed theme assets with an aws-lc-rs SHA-256 ETag, served by an `anvilid serve` binary using mimalloc with graceful SIGTERM shutdown**

## Performance

- **Duration:** about 5 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- Discovery metadata built from `WebConfig.issuer`: trailing slash trimmed, issuer path kept (`https://example.test/t/acme/token`), and only M1-targeted values advertised (code, public, ES256, S256, authorization_code, client_secret_basic, openid)
- Unimplemented endpoints fail explicitly with 501 and a JSON error. Tests check they never return success
- Embedded `anvil.css` is served with `text/css`, a quoted lowercase hex SHA-256 ETag, `Cache-Control: public, max-age=3600` and 304 on a matching If-None-Match. Missing assets and traversal attempts (raw and percent-encoded) return 404
- `anvilid serve` passes the plan's smoke test: healthz, discovery issuer, 501 on POST /token, a byte-identical asset, exit 0 on SIGTERM, and a non-zero exit when no issuer is given

## Task Commits

1. **Task 1 (RED): failing router tests + stylesheet** - `fda1471` (test)
2. **Task 1 (GREEN): anvil-web router** - `5e773ec` (feat)
3. **Task 2: anvilid serve binary** - `dfe09bf` (feat)

## Files Created/Modified
- `themes/default/static/anvil.css` - Self-contained default stylesheet: system font stack, CSS variables, dark mode, no external URLs
- `crates/anvil-web/src/lib.rs` - `WebConfig`, `router()`, `/healthz`
- `crates/anvil-web/src/discovery.rs` - `ProviderMetadata` plus a document serialised once
- `crates/anvil-web/src/not_implemented.rs` - Shared 501 JSON handler
- `crates/anvil-web/src/assets.rs` - rust-embed handler, ETag, path checks, unit tests for hex, path checks and If-None-Match
- `crates/anvil-web/tests/router.rs` - 10 in-process router tests
- `crates/anvilid/src/main.rs` - clap CLI, mimalloc, tracing (JSON when `ANVILID_LOG_FORMAT=json`), graceful shutdown, issuer validation tests

## Decisions Made
See key-decisions in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Asset path check in addition to rust-embed confinement**
- **Found during:** Task 1
- **Issue:** In debug builds rust-embed reads from disk. Relying only on its own confinement for traversal protection was not enough.
- **Fix:** `is_safe_path` rejects empty, `.` and `..` segments and backslashes before the lookup. Unit and integration tests cover it, including percent-encoded traversal.
- **Files modified:** crates/anvil-web/src/assets.rs
- **Commit:** 5e773ec

**2. [Rule 2 - Missing critical] Issuer scheme check**
- **Found during:** Task 2
- **Issue:** The plan only asked to reject a query or fragment. A non-http(s) issuer would produce an invalid discovery document.
- **Fix:** `validate_issuer` also requires the http or https scheme. This is unit tested.
- **Files modified:** crates/anvilid/src/main.rs
- **Commit:** dfe09bf

---

**Total deviations:** 2 auto-fixed (both Rule 2)
**Impact on plan:** Small hardening changes. The planned behaviour and interfaces are unchanged.

## Issues Encountered
None.

## User Setup Required
None.

## Next Phase Readiness
- Plan 06 (conformance) and plan 07 (static build and storage wiring) can use `anvil_web::router(WebConfig { issuer })` and the `serve` CLI. Plan 07 adds `--database-url`.

## Self-Check: PASSED
