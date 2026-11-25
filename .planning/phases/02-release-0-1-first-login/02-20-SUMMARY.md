---
phase: 02-release-0-1-first-login
plan: 20
subsystem: packaging-and-e2e
tags: [docker, distroless, qual04, playwright, mailpit, e2e, readme]
requires:
  - phase: 02-04
    provides: examples/node-rp, tests/e2e helpers
  - phase: 02-15
    provides: hosted UI pages and selectors
  - phase: 02-16
    provides: admin API (clients, users)
  - phase: 02-18
    provides: zero-config binary, Setup URL log line
provides:
  - "Dockerfile: distroless static-debian13:nonroot (digest-pinned), /data WORKDIR, ANVILID_LISTEN=0.0.0.0:8080"
  - "scripts/docker-image.sh: build-if-stale, < 50 MB size gate, nonroot check, zero-config smoke test"
  - "scripts/qual04.sh sqlite|postgres + deploy/compose/qual04-postgres.yml: timed zero-config -> sample-app login (<= 120 s)"
  - "tests/e2e/run.sh sqlite|postgres: Mailpit + real binary; registration, recovery and login specs"
  - "README quickstart"
affects: [02-21, CI e2e workflow]
tech-stack:
  added: ["gcr.io/distroless/static-debian13:nonroot (base image)", "axllent/mailpit v1.29.7 (test only)"]
  patterns:
    - "Script-driven Playwright in two tagged steps (@qual04-setup, @qual04-rp) around starting the RP"
    - "Specs share one installation: the first spec completes /setup and caches the management credential in E2E_STATE_FILE; the suite runs with --workers=1"
key-files:
  created:
    - Dockerfile
    - .dockerignore
    - scripts/docker-image.sh
    - scripts/qual04.sh
    - deploy/compose/qual04-postgres.yml
    - tests/e2e/run.sh
    - tests/e2e/specs/qual04.spec.ts
    - tests/e2e/specs/registration.spec.ts
    - tests/e2e/specs/recovery.spec.ts
    - tests/e2e/specs/login.spec.ts
  modified:
    - tests/e2e/lib/anvil.ts
    - examples/node-rp/README.md
    - examples/node-rp/server.js
    - README.md
    - .github/workflows/e2e.yml
key-decisions:
  - "Base image gcr.io/distroless/static-debian13:nonroot pinned by digest (debian13 exists; chosen over debian12)"
  - "/data is created by COPYing an empty target/docker/data dir with --chown=nonroot (distroless has no shell); docker-image.sh creates it"
  - "The default tenant's issuer is the root URL (http://localhost:8080); the RP uses that"
  - "Postgres compose: ANVILID_KEK defaults to empty so compose logs/down work without it; anvilid refuses to start on Postgres without a KEK"
  - "e2e runs the debug binary on port 18090 (E2E_PORT) so it does not collide with qual04 on 8080"
  - "CI qual04 job builds the image first (just docker-image); the e2e job runs on both backends"
requirements-completed: []
requirements-addressed: [OPS-01, QUAL-04, AUTH-02, AUTH-03, QUAL-02]
duration: 25min
completed: 2026-11-25
---

# Phase 2 Plan 20: Container image, QUAL-04 check, Mailpit e2e and README quickstart Summary

**The 19.1 MB distroless image runs as nonroot with no configuration and logs the setup URL. `scripts/qual04.sh` goes from `docker run` to a sample-app login with UserInfo and a rotated refresh in 5 s on SQLite and 8 s on Postgres, against a 120 s limit. Playwright tests registration with email verification, recovery and login over real SMTP (Mailpit) against the real binary, and pass on both backends.**

## Measurements

| Check | Result |
|-------|--------|
| Image size (`anvilid:ci`) | 19,134,822 bytes (18.2 MiB). The limit is 52,428,800. |
| Image user | `nonroot` |
| QUAL-04 sqlite | 4–5 s from `docker run` to the login and refresh, across three runs |
| QUAL-04 postgres | 8 s, across two runs |
| e2e sqlite | 3 specs passed (8 s) |
| e2e postgres | 3 specs passed (8 s) |

## Task Commits

1. **Task 1: Container image with size gate**: `84a6a79` (feat)
2. **Task 2: QUAL-04 timed check on SQLite and Postgres**: `808be46` (feat)
3. **Task 3: Self-service e2e over Mailpit, run script, README quickstart, workflow**: `aa50771` (feat)

## What the specs prove

- **qual04:**
  - Setup works from the URL in the logs.
  - A client_credentials token is issued for the management client.
  - A confidential client is created through the admin API.
  - The user starts at RP `/login`, lands on AnvilID's login page, follows `#link-registration` and registers. The browser then returns to RP `/me` with `sub` and an `email` that matches.
  - `/refresh` gives refresh-count 1 with the same sub, and `/me` still works.
- **registration:**
  - The verification email arrives in Mailpit.
  - Opening the link does not verify the address (admin API still shows `email_verified: false`). The confirm POST sets it to `true`.
  - A second confirm gets `verification.invalid_token`.
  - The new account can sign in.
- **recovery:**
  - The reset link arrives in Mailpit and the new password can be set (`recovery.done`).
  - The old password gets exactly the same `login.invalid_credentials` text as a random wrong password.
  - The new password signs in.
  - An unknown email gets the same `recovery.sent` page text.
- **login:**
  - A wrong password and an unknown account get the identical generic message.
  - The password is not echoed back.
  - The correct password signs in.
  - Every request the page makes goes to the AnvilID host.

## Verification

- `scripts/docker-image.sh` passes, followed by the size and user checks: OK
- `scripts/qual04.sh sqlite && scripts/qual04.sh postgres`: OK (5 s / 8 s)
- `tests/e2e/run.sh sqlite` and `tests/e2e/run.sh postgres`: OK
- `python3 -c "import yaml; …e2e.yml"`: OK
- `npx tsc --noEmit -p tests/e2e/tsconfig.json`: OK

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Compose interpolation blocked cleanup**
- **Found during:** Task 2
- **Issue:** `${ANVILID_KEK:?}` made `docker compose logs/down` fail after the script unset the KEK. The containers were left behind, and the next run reused an installed database, which prints no setup URL.
- **Fix:** Changed to `${ANVILID_KEK:-}`. anvilid itself refuses to start on Postgres without a KEK. `qual04.sh` also runs `compose down -v` before `up`.
- **Commit:** 808be46

**2. [Rule 3 - Blocking] The plan's `--smtp-url` flag does not exist**
- **Issue:** Per 02-18, smtp_url is env or file only, to keep it out of the process list.
- **Fix:** `run.sh` passes `ANVILID_SMTP_URL=smtp://127.0.0.1:1025` through the environment.

**3. [Rule 3 - Blocking] The CI qual04 job had no image**
- **Fix:** Added a `just docker-image` step before `just qual04` in e2e.yml. The e2e job is now a sqlite/postgres matrix and no longer runs the unused `npm ci` for node-rp.

**4. [Docs] node-rp ISSUER example**
- **Change:** The README and the server.js comment pointed at `/t/default`. Both work, but the default tenant's issuer is the root URL, so the docs now use `http://localhost:8080` and mention the qual04 script.

No product bugs were found. No product code was changed.

## Notes

- **HIBP lookup during QUAL-04:** the zero-config image keeps the default `breach_check = hibp`. The QUAL-04 sign-up therefore makes one outbound HIBP range request from the container. `run.sh` uses `--breach-check off`.
- **Docker state:** The Docker daemon has many leftover `postgres:18-alpine` testcontainers from other plans' runs. They did not affect this plan, and this plan leaves none behind. `just clean-test-containers` removes them.
- **Resource contention:** No contention-related failures occurred while 02-19 ran in parallel.

## Self-Check: PASSED
