---
phase: 03-release-0-2-secure-by-default
plan: 28
subsystem: conformance
tags: [openid-conformance, form-post, basic-op, config-op, rate-limit, consent, ci]
requires:
  - phase: 03-11
    provides: response_mode=form_post page and per-response CSP
  - phase: 03-13
    provides: rate limiting on by default (Auth class 10/min, burst 5 per IP)
  - phase: 03-23
    provides: setup.sh static clients with consent_mode skip_first_party
provides:
  - "tests/conformance/run.sh [basic|config|formpost|all]; formpost = oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  - "Conformance instance login quota ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=600 (CONFORMANCE_AUTH_PER_MINUTE); other limits at defaults"
  - "CI conformance job runs all three plans against one suite and one anvilid"
affects: [03-29]
tech-stack:
  added: []
  patterns:
    - "Raise one limiter quota for the conformance instance through ANVILID_RATE_LIMIT_* instead of turning limiting off"
key-files:
  created: []
  modified:
    - tests/conformance/run.sh
    - tests/conformance/setup.sh
    - tests/conformance/config.template.json
    - tests/conformance/expected-skips.json
    - tests/conformance/README.md
    - .github/workflows/conformance.yml
key-decisions:
  - "03-28: Conformance runs raise only the Auth-class quota (600/min, burst 300). The default 10/min answered 429 to the suite's scripted logins, all from one Docker gateway IP. This was the cause of CI run 45574616586 (Basic OP aborted on scope-profile/email/address)"
  - "03-28: The existing reviewed skip (variant *) covers the Form Post plan too; no new skips; expected-failures stays []"
  - "03-28: run.sh config uses a generated empty skip list, because run-test-plan.py fails on unused skip entries"
requirements-completed: []
duration: 50min
completed: 2026-11-25
---

# Phase 3 Plan 28: Form Post OP conformance plan, Basic/Config re-run Summary

**The harness and CI now run the Basic OP, Config OP and Form Post OP plans. The login quota is raised for the conformance instance (the cause of the red main CI run). One real Form Post failure is still open, and it needs a product decision outside this plan's files: `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[response_mode=form_post]`.**

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Harness: plan selection, formpost plan, login quota, token_format, README | a3613b4 |
| 2 | CI workflow runs basic, config and formpost | f1a1ca3 |

## CI failure on main (run 45574616586): root cause

The suite log shows `Clicked: login-submit` followed by `Response Code: 429` for oidcc-scope-profile. That is the per-IP Auth class limit (10 POSTs a minute, burst 5). Every scripted login comes from the one Docker gateway address. Consent is not involved: the static clients carry `consent_mode: skip_first_party`, and locally scope-profile/email/address/phone/all passed in both plans without a consent stop. With `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=600` there were 0 responses with status 429 in three local runs (suite.log `Response Code: 429` count 0).

## Local results (Docker Desktop on WSL2)

- `run.sh all`:
  - Config OP: PASSED.
  - Basic OP: 33 of 35 modules completed with PASSED, REVIEW or the expected SKIPPED result. Two were interrupted by "Remote host terminated the handshake" (userinfo-post-header at /token, userinfo-post-body at discovery).
  - Form Post OP: 30 of 35 modules completed. Interrupted: prompt-login, max-age-1, codereuse-30seconds and ensure-registered-redirect-uri, by handshake drops or browser loads that ended on about:blank. The fifth module, unsigned-request-object, is the real failure described below.
- `run.sh formpost`, two more runs:
  - Run 1 aborted after 3 consecutive handshake-interrupted modules.
  - Run 2 completed 36 modules. The interrupted modules were different ones: oidcc-server, response-type-missing, codereuse-30seconds, ensure-registered-redirect-uri. The same real failure appeared again.
- anvilid logged nothing at the moments of the drops, only rustls `UserCanceled` warnings. This matches the Docker Desktop/WSL2 issue from 02-19/02-21, which never showed on GitHub Linux runners. No retries were added and no expected failures were listed.
- form_post works end to end. The suite's HtmlUnit browser runs JavaScript, so `form_post.js` submits the form and no `<noscript>` Continue task is needed. Across the runs, every form_post module except unsigned-request-object passed in at least one run, except codereuse-30seconds and ensure-registered-redirect-uri, which were interrupted by the environment both times. Their Basic counterparts pass. CI has to confirm them.

## Open conformance failure (product code, outside this plan's files)

- **Module:** `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported[client_auth_type=client_secret_basic][response_mode=form_post][response_type=code]`
- **What happens:**
  - The suite sends `/authorize?client_id&redirect_uri&response_type=code&scope=openid&request=<alg none JWT>`. `response_mode=form_post` (and state/nonce) is only inside the request object.
  - anvilid ignores the object and answers `request_not_supported` as a 303 to the callback **query**.
- **Failed conditions:** CheckCallbackHttpMethodIsPost (expected POST, got GET), CheckCallbackContentTypeIsFormUrlEncoded, RejectErrorInUrlQuery and ValidateIssIfPresentInAuthorizationResponse. CheckDiscEndpointRequestParameterSupported produced a warning (`request_parameter_supported: false`).
- **Why Basic passes:** in the query variant, the same answer lets the module call `fireTestSkipped`, which the reviewed skip covers.
- **Suite logic (release-v5.3.5, AbstractOIDCCServerTest.skipTestIfNoneUnsupported):** the module is skipped at configure time when discovery has `request_object_signing_alg_values_supported` and it does not contain `none`. anvilid publishes no such field, so the module runs.
- **Options for the orchestrator or user** (files: `crates/anvil-web/src/protocol/discovery.rs` or `crates/anvil-core/src/oauth/authorize_request.rs`):
  - (a) Publish `request_object_signing_alg_values_supported` without `none`. To be checked: whether a list is truthful while request objects are unsupported, and whether Config OP accepts it.
  - (b) When rejecting `request`, read `response_mode` from an unsigned object only to choose how the error is delivered. The redirect URI is already validated, so only the delivery mode changes.
  - (c) Support request objects (later phase).
  - Listing an expected failure is not allowed without an explicit reviewed decision.

## form_post CSP `form-action` check

HtmlUnit does not enforce CSP, so the suite cannot observe the problem. The suite's callback answers the POST directly (200) without a cross-origin redirect, so the conformance result is not affected either way. For real RPs the 03-11 concern still holds: Chromium applies `form-action` to redirects after the form submission, so an RP callback that answers the POST with a redirect to another origin is blocked. The README documents this.

## Deviations from Plan

- **[Rule 3 - Blocking] Empty skip list for `run.sh config`.** run-test-plan.py fails on unused skip entries, and the reviewed skip belongs to the Basic and Form Post plans. A Config-only run checks against a generated `[]` in the temporary directory.
- **Workflow PR paths.** The existing `crates/**` trigger is kept. It is a superset of the paths the plan lists.
- **Done criterion not met locally.** "Basic, Config and Form Post pass locally" is blocked by the open product failure above and by environmental handshake drops. CI confirmation is in 03-29.

## Deferred Issues

- The open Form Post failure above (needs a decision; outside files_modified).
- Docker Desktop/WSL2 TLS handshake drops make local full runs flaky (the 02-19 issue; CI unaffected so far).

## Self-Check: PASSED

- FOUND: tests/conformance/run.sh (contains oidcc-formpost-basic-certification-test-plan), .github/workflows/conformance.yml (contains formpost), tests/conformance/setup.sh (skip_first_party)
- FOUND: a3613b4, f1a1ca3
