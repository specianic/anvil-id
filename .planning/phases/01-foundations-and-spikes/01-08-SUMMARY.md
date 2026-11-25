---
phase: 01-foundations-and-spikes
plan: 08
subsystem: infra
tags: [phase-gate, ci, conformance, spikes, musl, arm64]
requires:
  - phase: 01-02
    provides: ci.yml, dependency rules, cargo-deny
  - phase: 01-05
    provides: Postgres backend + duplication cost (Spike A)
  - phase: 01-06
    provides: conformance pipeline + M0 ratchet (Spike C)
  - phase: 01-07
    provides: storage wiring, static musl build, release-build.yml (Spike B)
provides:
  - 01-SPIKE-RESULTS.md with §2.1 verdicts (conditions 1-3 met, stack confirmed)
  - Green ci, release-build (amd64 + arm64) and conformance runs on GitHub (commit 64270e5)
  - Portable conformance suite fetch (no sparse-checkout) and ephemeral mongo volume
affects: [phase-02]
tech-stack:
  added: []
  patterns:
    - "Fetch the suite with a blobless --no-checkout clone plus a path checkout (portable across git versions)"
    - "compose.override.yml replaces upstream bind mounts with named volumes so `down -v` leaves nothing on the host"
key-files:
  created:
    - .planning/phases/01-foundations-and-spikes/01-SPIKE-RESULTS.md
  modified:
    - tests/conformance/run.sh
    - tests/conformance/compose.override.yml
    - scripts/check-deps.sh
key-decisions:
  - "Phase 1 gate: §2.1 conditions 1-3 met, so the Rust stack is confirmed and not revisited before M1"
  - "Conformance ratchet unchanged: the CI outcome matched the local bootstrap (8 entries); no TLS fallback needed for M0"
  - "CI evidence comes from main (push authorized by the user), not from a phase-1-foundations branch/PR"
requirements-completed: [FND-01, FND-02, FND-03, FND-04, FND-05]
duration: 20min
completed: 2026-11-25
---

# Phase 1 Plan 08: Phase gate (local suite, CI on GitHub, spike verdicts) Summary

**All three workflows are green on GitHub at 64270e5 after a fix to how the conformance suite is fetched. The aarch64 static musl binary is 7.66 MiB and idles at about 19-21 MB RSS, and amd64 is 9.44 MiB and about 21 MB. All of ARCHITECTURE.md §2.1 conditions 1-3 are met, so the stack is confirmed.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-11-25
- **Tasks:** 2 (Task 2's push checkpoint was pre-resolved by the orchestrator)
- **Files modified:** 4

## Accomplishments

- Local gate green: `just ci` (fmt, clippy, deny, deps, SQLite + Postgres tests), `just deps-selftest`, `scripts/sqlx.sh check`, and `just conformance`. Conformance passed twice in a row from a fresh suite checkout.
- Found and fixed the reason conformance.yml had failed on every GitHub run so far: newer git on the runner rejects the non-cone pattern `/docker-compose-prebuilt.yml` in `sparse-checkout add`.
- CI on 64270e5:
  - ci: https://github.com/specianic/anvil-id/actions/runs/45524848960 (all 5 jobs green)
  - release-build: https://github.com/specianic/anvil-id/actions/runs/45524848917 (amd64 + arm64)
  - conformance: https://github.com/specianic/anvil-id/actions/runs/45524848884 (8 expected failures loaded, runner exit 0)
- arm64 measurements (the manual-only check in 01-VALIDATION.md): 8,029,632 B (7.66 MiB), VmRSS 18,632 kB at ce293ab and 20,688 kB at 64270e5. The binary is statically linked and the embedded-asset check passed.
- Wrote 01-SPIKE-RESULTS.md with the Spike A/B/C tables, the verdicts against §2.1, the CI evidence and the doc follow-ups (RS256 default, http issuer until Phase 2 TLS, no implicit default DB in M0).

## Task Commits

1. **Task 1: local gate** (found and fixed conformance/self-test issues): `64270e5` (fix)
2. **Task 2: push, CI green, spike results:** `a399506` (docs)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Conformance suite fetch failed on newer git (CI)**
- **Found during:** Task 1/2 (conformance.yml runs 45522654402 and 45524049040 failed)
- **Issue:** `git sparse-checkout add /docker-compose-prebuilt.yml` fails with "specify directories rather than patterns" when git defaults to cone mode. Local git 2.34 defaults to non-cone, which is why the local runs passed.
- **Fix:** a blobless `--no-checkout` clone followed by `git checkout HEAD -- scripts docker-compose-prebuilt.yml`. This works the same on both git versions.
- **Files modified:** tests/conformance/run.sh
- **Commit:** 64270e5

**2. [Rule 1 - Bug] Root-owned mongo data left in ./suite broke re-fetch and deps-selftest**
- **Found during:** Task 1 (local gate)
- **Issue:** the upstream compose file bind-mounts `./mongo/data`. Docker writes it as root, so `rm -rf suite` (tag change or re-fetch) and the tar copy in `check-deps.sh --self-test` both failed with permission errors.
- **Fix:** compose.override.yml mounts a named volume `mongo-data` on the same target. `compose down -v` deletes it, so every run starts with an empty database. The self-test copy now excludes the gitignored `./suite` and `./conformance-results`. The existing root-owned directory was removed once via a throwaway container.
- **Files modified:** tests/conformance/compose.override.yml, scripts/check-deps.sh
- **Commit:** 64270e5

### Plan adjustments

- The plan expected a `phase-1-foundations` branch and a PR. Following the orchestrator's instruction, work was pushed straight to `main`, as it was throughout the phase. The verify command's branch filter does not apply; the three green runs on `main` are the equivalent evidence.
- `expected-failures-m0.json` was not modified, because the CI outcome matched the local bootstrap.

## Issues Encountered

- The aarch64 binary is `statically linked` (non-PIE) while x86_64 is `static-pie`. Both are static, so §2.1 is met. PIE on aarch64 musl is a possible hardening item for later.
- Idle RSS varies by about 2 MB between runs of the same binary.

## Next Phase Readiness

- Phase 1 exit criteria are met: spikes succeeded and CI is green. Phase 2 must advertise and sign with RS256, serve /jwks, add the userinfo endpoint, and add an https conformance job that removes the http-related ratchet entries.

## Self-Check: PASSED
