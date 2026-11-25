---
phase: 01-foundations-and-spikes
plan: 02
subsystem: infra
tags: [ci, cargo-deny, github-actions, dependency-rules, supply-chain]

requires:
  - phase: 01-01
    provides: workspace skeleton, justfile recipe contract (fmt-check, lint, deny, deps, deps-selftest, test, sqlx-check)
provides:
  - deny.toml cargo-deny policy (advisories, licenses, bans, sources) with nine crate bans
  - scripts/check-deps.sh FND-02 crate dependency-rule checker with --self-test
  - .github/workflows/ci.yml running lint, deny, deps (+ self-test), test and sqlx-check on PRs and pushes to main
affects: [01-08 phase gate (CI proven green on GitHub), every later phase (rules gate all PRs)]

tech-stack:
  added: [cargo-deny 0.22.1 (dev tool), GitHub Actions]
  patterns:
    - "Dependency rules checked per package with cargo tree -p over normal+build edges on all targets; dev-dependencies ignored by construction"
    - "Negative self-test mutates a temp copy of the workspace with cargo add --offline and asserts RULE VIOLATION output"
    - "CI jobs delegate to just recipes"

key-files:
  created:
    - deny.toml
    - scripts/check-deps.sh
    - .github/workflows/ci.yml
  modified: []

key-decisions:
  - "cargo-deny >= 0.22 is required: 0.21 treats transitive unmaintained advisories (astral-tokio-tar via testcontainers, dev-only) as errors"
  - "Self-test failures only count when the checker prints RULE VIOLATION, so a cargo error cannot pass as a rejection"
  - "direct_of uses --target all (stronger than the plan's command) so target-specific deps cannot bypass the anvil-core allowlist"

patterns-established:
  - "Rules apply to normal (and build) dependencies only; backends and anvil-web may dev-depend on anything"

requirements-completed: [FND-01, FND-02]

duration: 15min
completed: 2026-11-25
---

# Phase 1 Plan 02: CI and architecture-rule enforcement Summary

**cargo-deny policy banning openssl/native-tls/ring/rsa/chrono/samael/xmlsec/oxide-auth, a per-package cargo-tree dependency-rule checker whose self-test proves forbidden normal deps are rejected and dev deps accepted, and a five-job GitHub Actions workflow that runs both on every PR.**

## Performance

- **Duration:** about 15 min
- **Completed:** 2026-11-25
- **Tasks:** 3
- **Files created:** 3

## Accomplishments
- `cargo deny --locked check`: advisories ok, bans ok, licenses ok, sources ok. No license had to be added beyond the research list.
- `scripts/check-deps.sh` passes on the clean tree. `--self-test` runs five cases on a temp copy: 0 (unmodified) passes; A (core+tokio), B (web normal dep on sqlite backend) and D (sqlite backend+web) are rejected with RULE VIOLATION; C (web dev dep on sqlite backend) passes. It takes about 7s.
- `.github/workflows/ci.yml`: lint, deny, deps, test, sqlx-check on `pull_request` and `push: main`. Permissions are read-only, PR runs cancel in progress, and the toolchain comes from rust-toolchain.toml.

## Task Commits

1. **Task 1: cargo-deny policy**: `e7412db` (chore)
2. **Task 2: Dependency-rule checker** (TDD): `ac586b4` (test, RED: harness with checker exiting 2, case C failed), `dc33757` (feat, GREEN)
3. **Task 3: GitHub Actions workflow**: `2060d16` (chore)

## Decisions Made
- Upgraded the local cargo-deny from 0.21.0 to 0.22.1 (`cargo install cargo-deny --locked`), as the plan instructs. With 0.21.0, advisories failed on RUSTSEC-2026-0440 (astral-tokio-tar unmaintained, pulled in only through the testcontainers dev-dependency). 0.22 limits unmaintained checks to workspace crates by default, which is what the research assumed. The bans were not loosened. cargo-deny-action@v2 uses a current cargo-deny.
- The self-test mutates the copy with `cargo add --offline`, which also updates the copied Cargo.lock, so the checker's `--locked` still works. The sed fallback was not needed. `cargo fetch --locked` runs first so the offline steps work on a cold CI runner.
- The sqlx-cli install also passes `--locked`, and its cache key includes the runner arch.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] The self-test only counts real rule violations, and there is a baseline case**
- **Found during:** Task 2
- **Issue:** Before this, any non-zero exit (for example a cargo resolution error, or the RED stub) counted as "rejected". Cases A, B and D could then pass for the wrong reason.
- **Fix:** An expected-fail case now needs `RULE VIOLATION:` in the output, otherwise it is reported as `error`. Added case 0: the unmodified copy must pass.
- **Files modified:** scripts/check-deps.sh
- **Commit:** dc33757

**2. [Rule 2 - Correctness] `direct_of` uses `--target all`**
- **Found during:** Task 2
- **Issue:** The plan's `direct_of` command only looks at host-target deps, so a `[target.'cfg(..)'.dependencies]` entry could get past the anvil-core allowlist.
- **Fix:** Added `--target all`, the same as `deps_of`.
- **Commit:** dc33757

---

**Total deviations:** 2 auto-fixed (both make the checker stricter)
**Impact on plan:** None on scope.

## Issues Encountered
- actionlint is not installed locally, and running it through Docker was not permitted in this session. Following the plan's fallback, the workflow was checked by parsing the YAML and asserting the job set. `actions/cache@v5` is not pinned in the research. Confirm it resolves when CI first runs on GitHub in plan 08.

## User Setup Required
None.

## Next Phase Readiness
- Plan 08 (phase gate) must push and confirm all five jobs are green on GitHub. `sqlx-check` depends on plan 03's `scripts/sqlx.sh`, which has now landed.

## Self-Check: PASSED
- FOUND: deny.toml, scripts/check-deps.sh, .github/workflows/ci.yml
- FOUND commits: e7412db, ac586b4, dc33757, 2060d16

---
*Phase: 01-foundations-and-spikes*
*Completed: 2026-11-25*
