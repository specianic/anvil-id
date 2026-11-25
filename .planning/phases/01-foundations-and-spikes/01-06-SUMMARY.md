---
phase: 01-foundations-and-spikes
plan: 06
subsystem: testing
tags: [conformance, openid, docker-compose, github-actions, spike-c]

requires:
  - phase: 01-04
    provides: "`anvilid serve --listen --issuer`, discovery document, 501 on /authorize, /token, /jwks"
provides:
  - "tests/conformance/run.sh: one script that fetches suite release-v5.3.5, starts prebuilt images and a fresh anvilid, runs oidcc-config-certification-test-plan and tears down"
  - "tests/conformance/expected-failures-m0.json: exact M0 ratchet (7 failures, 1 warning), each commented"
  - ".github/workflows/conformance.yml: `just conformance` on main, workflow_dispatch and Phase-1-relevant PRs; always uploads conformance-results/"
affects: [01-07, 01-08, phase-02]

tech-stack:
  added: ["OpenID conformance suite release-v5.3.5 (prebuilt images, test-only)"]
  patterns:
    - "Suite git tag and image tag share one variable (CONFORMANCE_TAG); checkout tag recorded in suite/.anvil-conformance-tag"
    - "Binary invocation on a single marked ANVILID_ARGS=(...) line for plan 07 to extend"
    - "Cleanup trap saves suite logs and runs compose down -v; script exits with run-test-plan.py's code"

key-files:
  created:
    - tests/conformance/run.sh
    - tests/conformance/compose.override.yml
    - tests/conformance/config-m0.json
    - tests/conformance/expected-failures-m0.json
    - tests/conformance/README.md
    - .github/workflows/conformance.yml
  modified: []

key-decisions:
  - "Default ANVILID_BIN path is always incrementally rebuilt so a stale binary is never tested; a custom path must already exist"
  - "run.sh fails fast if ANVILID_PORT does not match the discoveryUrl in config-m0.json (the ratchet keys on the config filename, so no runtime config rewrite)"
  - "INTERRUPTED module (FetchServerKeys stops the module) counts as completed by run-test-plan.py, so the ratchet passes over plain http and no TLS fallback is needed for M0"

requirements-completed: [FND-05]

duration: 9min
completed: 2026-11-25
---

# Phase 1 Plan 06: OpenID conformance pipeline (Spike C) Summary

**`just conformance` runs OpenID conformance suite release-v5.3.5 (prebuilt images) against a freshly started anvilid using the Config OP plan and enforces an exact ratchet of expected failures. It completed locally end to end and exits 0 with the ratchet in place**

## Performance

- **Duration:** about 9 min (the first local run pulled about 1 GB of images; a warm run takes under 1 min)
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- One script runs the same steps locally and in CI: sparse clone of the suite at the pinned tag, `docker compose` up with a host-gateway override, fresh `anvilid` on 0.0.0.0:9090, the suite's own `run-test-plan.py` in a venv, then teardown with logs exported to `conformance-results/`
- **The local run completed** (Docker 29.1 on WSL2, host-gateway works). The module `oidcc-discovery-endpoint-verification` ends INTERRUPTED with result FAILED after `FetchServerKeys`. The runner treats this as completed
- The ratchet was bootstrapped from that run. A second run exited 0 and printed "All tests ran to completion", with every condition shown as expected. The containers were removed afterwards
- The CI workflow uses the same `just conformance` entry point, needs no secrets, and uploads the artifact on `if: always()`

## M0 failing conditions (the ratchet)

| Condition | Result | Cause | Removed in |
|-----------|--------|-------|------------|
| CheckDiscEndpointDiscoveryUrl | failure | http discovery URL | Phase 2 (https job) |
| CheckDiscEndpointIssuerIsValidUrl | failure | http issuer (RFC 8414) | Phase 2 |
| CheckDiscEndpointAuthorizationEndpoint | failure | http endpoint | Phase 2 |
| CheckDiscEndpointTokenEndpoint | failure | http endpoint | Phase 2 |
| CheckJwksUri | failure | http endpoint | Phase 2 |
| OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported | failure | only ES256 advertised; certification requires RS256 | Phase 2 |
| CheckDiscEndpointUserinfoEndpoint | warning | no userinfo_endpoint | Phase 2 |
| FetchServerKeys | failure | /jwks returns 501 (stops the module) | Phase 2 |

After /jwks serves keys, conditions later in the module will run for the first time. The ratchet will then flag any new failures. That is the intended behaviour.

## Task Commits

1. **Task 1: Conformance harness script and config** - `af42d25` (feat)
2. **Task 2: Local run, ratchet bootstrap, CI workflow** - `026b58d` (feat)

## Files Created/Modified
- `tests/conformance/run.sh` - Local and CI driver (env: CONFORMANCE_TAG, ANVILID_BIN, ANVILID_PORT, RESULTS_DIR, KEEP_SUITE)
- `tests/conformance/compose.override.yml` - `host.docker.internal:host-gateway` on the suite server
- `tests/conformance/config-m0.json` - Discovery URL and placeholder static client (not a secret)
- `tests/conformance/expected-failures-m0.json` - 8 commented entries
- `tests/conformance/README.md` - Usage, ratchet semantics, placeholder client note, http-issuer limitation and the TLS plan
- `.github/workflows/conformance.yml` - CI job (ubuntu-24.04, 30 min timeout)

## Decisions Made
See key-decisions in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Stale-binary and port-mismatch guards in run.sh**
- **Found during:** Task 1
- **Issue:** The plan builds only when the binary is missing. Locally this would silently test an outdated build. `ANVILID_PORT` could also drift from the port hardcoded in `config-m0.json`.
- **Fix:** The default binary path is always built incrementally (a no-op when up to date). A custom `ANVILID_BIN` must exist. The script exits early if the config does not reference `ANVILID_PORT`. It also checks that anvilid is still alive while waiting for discovery.
- **Files modified:** tests/conformance/run.sh
- **Commit:** af42d25

---

**Total deviations:** 1 auto-fixed (Rule 2)
**Impact on plan:** Small robustness changes. The interfaces and the CI contract are unchanged.

## Issues Encountered
- **Doc divergence to raise (CLAUDE.md):** ARCHITECTURE.md §(signing keys) makes RS256 the default algorithm, but the M0 discovery document from plan 04 advertises only `ES256`. The suite flags this as a certification failure. This plan does not change the binary. Phase 2 (M1 signing keys) must advertise RS256. The issue is recorded in the ratchet comment.
- `run-test-plan.py` prints a Python traceback for the INTERRUPTED module. This is normal upstream behaviour and does not affect the exit code.

## User Setup Required
None. CI needs no secrets.

## Next Phase Readiness
- Plan 07: append `--database-url "sqlite::memory:"` to the `ANVILID_ARGS=(...)` line in run.sh
- Plan 08: confirm the run is green on GitHub. The ratchet is already bootstrapped from a local run, so CI only needs to match it. If the CI environment behaves differently, update the file from the CI log
- Phase 2: https issuer for the conformance job (self-signed rustls listener with a temporary key), RS256, /jwks and userinfo

## Self-Check: PASSED
