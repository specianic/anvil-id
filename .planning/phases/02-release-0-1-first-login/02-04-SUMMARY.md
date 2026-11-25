---
phase: 02-release-0-1-first-login
plan: 04
subsystem: testing
tags: [e2e, playwright, openid-client, express, relying-party, mailpit]

requires: []
provides:
  - "examples/node-rp: standards-strict sample RP (code + PKCE S256 + state + nonce, UserInfo, rotated refresh)"
  - "tests/e2e: Playwright project skeleton (chromium) with helpers for setup, admin API, Mailpit and the sample RP"
affects: [02-15, 02-16, 02-18, 02-20]

tech-stack:
  added: ["openid-client 6.9.1", "express 5.3.0", "@playwright/test 1.65.1", "typescript 5.9.3", "@types/node 22.20.5"]
  patterns:
    - "All e2e endpoints from env (ANVIL_URL, MAILPIT_URL, RP_URL); credentials created at runtime by completeSetup()"
    - "Commits made with `git commit -- <paths>` so concurrent agents' staged changes are not swept in"

key-files:
  created:
    - examples/node-rp/server.js
    - examples/node-rp/package.json
    - examples/node-rp/package-lock.json
    - examples/node-rp/README.md
    - tests/e2e/package.json
    - tests/e2e/package-lock.json
    - tests/e2e/playwright.config.ts
    - tests/e2e/tsconfig.json
    - tests/e2e/lib/anvil.ts
    - tests/e2e/lib/mailpit.ts
    - tests/e2e/lib/rp.ts
  modified:
    - .gitignore

key-decisions:
  - "Sample RP authenticates with client.ClientSecretBasic (openid-client 6 defaults to client_secret_post when a bare secret string is passed)"
  - "Loopback-only insecure http: allowInsecureRequests is passed to discovery via execute and applied to the config only when the issuer host is localhost/127.0.0.1"
  - "Sample RP rejects a refresh response without a new refresh token (AnvilID rotates; a missing one is an OP bug the e2e should surface)"
  - "Session cookie is HMAC-signed with SESSION_SECRET (random per start when unset) over an in-memory map; no session library"
  - "TypeScript pinned to 5.9.3 rather than 7.x for Playwright/tsc compatibility"

patterns-established:
  - "e2e helpers throw descriptive errors on unexpected HTTP status instead of returning partial data"

requirements-completed: []  # QUAL-04 building blocks only; requirement completes in 02-20

duration: 8min
completed: 2026-11-25
---

# Phase 2 Plan 04: Sample RP and Playwright skeleton Summary

**Express 5 + openid-client 6.9.1 sample relying party (PKCE S256, state, nonce, UserInfo, rotated refresh) plus a Playwright 1.65 project with typed helpers for setup, admin API, Mailpit and the RP**

## Performance

- **Duration:** about 8 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 12

## Accomplishments
- `examples/node-rp/server.js` exposes `/`, `/login`, `/callback`, `/me` (`#sub`, `#email`, `#refresh-count`), `/refresh` and `/healthz`. All configuration comes from env. Tokens are never logged.
- Smoke-tested against a local fake discovery document. `/healthz` returns `ok`, and `/login` sets an HttpOnly SameSite=Lax cookie and redirects with `code_challenge_method=S256`, `state` and `nonce`.
- `tests/e2e` installs, type-checks and reports Playwright 1.65.1. There are no specs yet, as planned (02-20 writes them).
- Helpers: `completeSetup`, `parseSetupUrl`, `adminToken`, `createClient`, `createUser`, `login`, `register`, `randomEmail`, `randomPassword` (anvil.ts); `latestMessageTo`, `extractLink` (mailpit.ts); `rpLogin`, `rpMe`, `rpRefresh` (rp.ts).

## Task Commits

1. **Task 1: Sample relying party** - `8d2a527` (feat)
2. **Task 2: Playwright skeleton and helpers** - `c7a0776` (feat)

## Decisions Made
See key-decisions in frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Explicit client_secret_basic in discovery**
- **Found during:** Task 1
- **Issue:** The planned call `client.discovery(url, CLIENT_ID, CLIENT_SECRET)` would use client_secret_post. The admin API registers clients with `client_secret_basic`, so the token request would be rejected.
- **Fix:** Pass `undefined` metadata plus `client.ClientSecretBasic(CLIENT_SECRET)`. The `client.discovery` key link still holds.
- **Files modified:** examples/node-rp/server.js
- **Commit:** 8d2a527

**2. [Rule 3 - Blocking] Insecure-request allowance during discovery**
- **Found during:** Task 1
- **Issue:** Calling `allowInsecureRequests(config)` after discovery is too late, because discovery itself fetches over http on localhost.
- **Fix:** For loopback issuers only, also pass `{ execute: [client.allowInsecureRequests] }` to discovery.
- **Commit:** 8d2a527

Additions beyond the plan's helper list: `parseSetupUrl` (for the `Setup URL:` log line from 02-18), `randomPassword` and an optional `tenant` parameter on `createClient` and `createUser`.

## Issues Encountered
None.

## Next Phase Readiness
- 02-20 can write specs against these helpers. The helpers assume the DOM IDs and endpoints listed in the plan's `<interfaces>` block (02-14/15/16/18).

## Self-Check: PASSED
