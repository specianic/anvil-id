---
phase: 03-release-0-2-secure-by-default
plan: 31
subsystem: oauth
tags: [oidc, response_mode, form_post, request-object, conformance, gap-closure]
requires:
  - phase: 03-11
    provides: single AuthorizationResponse builder, form_post delivery
  - phase: 03-28
    provides: Form Post conformance plan and the failing module report
provides:
  - request_not_supported delivered via the outer response_mode, else the request object's (unverified, error delivery only)
affects: [03-29]
tech-stack:
  added: []
  patterns:
    - "Unverified request object peeked (8 KiB cap, strict base64url JSON payload) only to choose error delivery and echo state"
key-files:
  created: []
  modified:
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-web/tests/response_mode.rs
key-decisions:
  - "request_not_supported: outer response_mode/state win; else the request object's response_mode (exactly form_post, anything else query) and string state; malformed or > 8 KiB objects fall back to outer params"
  - "request_uri is never fetched; request_uri_not_supported uses only the outer response_mode"
requirements-completed: []
duration: 15min
completed: 2026-11-25
---

# Phase 3 Plan 31: request_not_supported via the requested response mode Summary

**/authorize now delivers `request_not_supported` with the response mode the client asked for. It uses the outer `response_mode` when one is sent. Otherwise it reads `response_mode` and `state` from the unsigned request object, without trusting it, and uses them only to deliver the error.**

## Performance

- **Duration:** about 15 min
- **Completed:** 2026-11-25
- **Tasks:** 1 (TDD: RED and GREEN commits)
- **Files modified:** 2

## Accomplishments

- `peek_request_object` in `authorize_request.rs` does the following:
  - It refuses objects over 8 KiB and anything that is not exactly three dot-separated segments.
  - It decodes the payload as strict base64url JSON and requires a JSON object.
  - It reads `response_mode`, which counts only when it is exactly `form_post`; any other value means `query`.
  - It reads `state`, which counts only when it is a non-empty string.
  - It never panics and never verifies a signature.
  - Its result is used only in the `request` rejection branch. That branch runs after the client, the redirect URI, `response_mode`, duplicates and `response_type` have been checked, so an untrusted redirect URI still gets the error page.
- Unit tests cover:
  - the object's form_post and state
  - the outer mode and state winning in both directions
  - fallback to query for unknown, wrong-case, `.jwt`, array, number and missing modes
  - a non-string state that is not echoed
  - nine malformed or oversized objects
  - the error page for a mismatched or missing redirect URI and for an unknown client
  - `request_uri`, which takes only the outer mode
- HTTP tests (both SQLite and Postgres):
  - An `alg: none` request object with form_post and state, sent by GET and by POST, gets a 200 form_post page. The page posts `error=request_not_supported`, `error_description`, `state` and `iss` and has the per-response CSP.
  - When the request also sends `response_mode=query`, the outer mode wins and the response is a query redirect.
  - Fragment, malformed and oversized objects fall back to a query redirect.
  - An invalid redirect URI gets the error page, with no form and nothing reflected.

## Task Commits

1. **Task 1 RED: failing unit tests** - `572fd9a` (test)
2. **Task 1 GREEN: implementation and HTTP tests** - `2097942` (feat)

## Decisions Made

- Outer parameters always win over the object. Object values are used only when the outer parameter is absent.
- The PKCE/nonce rule (02-19 amendment) is unchanged. Nothing from the object reaches authorization.

## Deviations from Plan

None. The plan was executed as written.

## Issues Encountered

- `tests/conformance/run.sh formpost` was not run locally. Docker on WSL2 drops TLS handshakes in this environment, which is not a product problem. The module `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` will be confirmed by CI in 03-29.

## Next Phase Readiness

- 03-29 can re-run the Form Post plan in CI. No product-code failure is known to remain. Optionally, add the new negative tests to the QUAL-01 security-test map (`scripts/check-security-tests.sh`).

## Self-Check: PASSED

- FOUND: crates/anvil-core/src/oauth/authorize_request.rs
- FOUND: crates/anvil-web/tests/response_mode.rs
- FOUND: 572fd9a
- FOUND: 2097942
