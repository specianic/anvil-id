---
phase: 03-release-0-2-secure-by-default
plan: 33
subsystem: web
tags: [refactor, etag, audit, captcha, release, gap-closure]
requires:
  - phase: 03-10
    provides: reuse-detection audit events
  - phase: 03-18
    provides: embedded console with ETag/304
  - phase: 03-22
    provides: account security/sessions pages
provides:
  - one strong-ETag / If-None-Match implementation (crate-private http_cache module)
  - one iso/human timestamp formatter module for the account pages
  - reuse audit events with real request context
  - async test runtime available to anvil-core tests
affects: [03-29]
tech-stack:
  added: ["tokio (anvil-core dev-dependency only, rt + macros)"]
  patterns:
    - "Cacheable handlers use http_cache::{strong_etag, etag_from_digest, if_none_match}"
    - "TokenRequest.context carries the AuditContext into TokenService"
key-files:
  created:
    - crates/anvil-web/src/http_cache.rs
    - crates/anvil-web/src/ui/format.rs
  modified:
    - crates/anvil-web/src/assets.rs
    - crates/anvil-web/src/console.rs
    - crates/anvil-web/src/protocol/jwks.rs
    - crates/anvil-web/src/ui/account_security.rs
    - crates/anvil-web/src/ui/account_sessions.rs
    - crates/anvil-web/src/protocol/token.rs
    - crates/anvil-core/src/service/token.rs
    - crates/anvil-core/Cargo.toml
    - themes/default/templates/captcha.html
    - .github/workflows/release.yml
    - crates/anvil-web/tests/security_introspect_revoke.rs
    - crates/anvil-web/tests/security_setup.rs
key-decisions:
  - "if_none_match evaluates all If-None-Match header lines (the JWKS variant), a strict superset of the single-line behaviour assets/console had"
  - "strong_etag hashes with aws-lc-rs directly in anvil-web; console keeps rust-embed's precomputed digest via etag_from_digest"
  - "Account timestamps always convert to UTC (the sessions variant); account_security previously assumed UTC input"
  - "hCaptcha left unchanged: it has no flexible size; only Turnstile gets data-size=flexible"
requirements-completed: []
duration: 25min
completed: 2026-11-25
---

# Phase 3 Plan 33: Web/misc follow-ups Summary

**Single ETag/If-None-Match and date-formatter implementations, client IP and user agent recorded on reuse-detection audit events, tokio test runtime in anvil-core, a flexible-width Turnstile widget and the release attestation permission**

## Accomplishments
- `http_cache.rs` (pub(crate)): `strong_etag`, `etag_from_digest`, `if_none_match` (RFC 9110 weak compare across all header lines), with the combined unit tests from all three callers. `assets.rs`, `console.rs` and `protocol/jwks.rs` now call it, and `grep 'fn if_none_match'` matches only one function.
- `ui/format.rs`: `iso`/`human` UTC formatters, used by both account pages (the duplicate tests are merged into one, plus a non-UTC-offset case).
- `TokenRequest.context: RequestContext`: the `/token` handler extracts `AuditContext` and `audit_reuse` records it, so `code_reuse_detected` and `refresh_reuse_detected` now carry the client IP and user agent. The `refresh_and_code_reuse_are_audited` test asserts the peer IP on both events.
- anvil-core dev-dependency `tokio` (rt, macros). Cargo.lock gains one line, and check-deps still passes.
- captcha.html: Turnstile `data-size="flexible"`.
- release.yml image job: `artifact-metadata: write`.

## Task Commits
1. **Task 1: Deduplicate HTTP cache and date helpers**: `7ab3760` (refactor), plus `c0e5dba` (style: rustfmt blank lines; committed separately because Task 1 was committed before fmt and amending is not allowed)
2. **Task 2: Reuse audit context, core test runtime, CAPTCHA width, release permission**: `4f7c631` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] security_setup.rs builds a TokenRequest literal**
- **Found during:** Task 2
- **Issue:** The new `context` field broke the struct literal in `crates/anvil-web/tests/security_setup.rs`, which is not in files_modified.
- **Fix:** Added `context: RequestContext::system()` and the import.
- **Commit:** 4f7c631

**2. [Rule 2 - Test placement] Reuse-context test went into security_introspect_revoke.rs**
- **Found during:** Task 2
- **Issue:** The existing reuse-audit test (`refresh_and_code_reuse_are_audited`) lives in `security_introspect_revoke.rs`, which is not in files_modified.
- **Fix:** Added `ctx.ip == DEFAULT_PEER.ip()` assertions for both reuse events there. This file needed no new test scaffolding.
- **Commit:** 4f7c631

**3. Formatting follow-up commit**: `c0e5dba` removes the blank lines the Task 1 dedupe left behind.

## Verification
- `cargo test -p anvil-web --lib` (104) and the console/jwks_rotation/discovery/account_security/sessions suites pass. Clippy is clean with `-D warnings`.
- `cargo test -p anvil-core` (330) and the security_code/security_refresh/security_introspect_revoke/security_setup/captcha/render/security_bruteforce suites pass.
- `cargo test --workspace` passes with no failures (run while 03-32 had uncommitted storage changes in the tree).
- `scripts/check-deps.sh` passes. release.yml parses as YAML. The grep checks pass.

## Next Phase Readiness
Web/misc follow-ups are closed before the Phase 3 gate (03-29).

## Self-Check: PASSED
