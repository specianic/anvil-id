---
phase: 03-release-0-2-secure-by-default
plan: 29
subsystem: release-gate
tags: [gate, QUAL-01, ci, release, docs, migrations, console]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "03-01..03-33 (all Phase 3 plans)"
provides:
  - "QUAL-01 map covers every Phase 3 control (230 control/test pairs)"
  - "`just ci` runs migrations-check and console-check"
  - "release.yml and release-build.yml build the console once and fail if a binary does not embed it"
  - "0.2 migrations pinned (SQLite 0003/0004, Postgres 0003)"
  - "ARCHITECTURE/PRD/theme README in sync with release 0.2; docs/UPGRADING.md"
  - "anvilid 0.2.0 on main"
  - "Published AnvilID v0.2.0 (tag on 177b7f4): GitHub Release with 4 archives + 4 sha256, ghcr.io/specianic/anvil-id:0.2.0 and latest (linux/amd64, linux/arm64)"
affects: [Phase 3 verification, Phase 4 (release 0.3)]
tech-stack:
  added: []
  patterns:
    - "Release builds verify the embedded console by grepping the binary for the content-hashed entry script named by admin-ui/dist/index.html (catches stale cached targets too)"
key-files:
  created:
    - scripts/check-console-embedded.sh
    - docs/UPGRADING.md
  modified:
    - scripts/check-security-tests.sh
    - scripts/released-migrations.sha256
    - justfile
    - .github/workflows/release.yml
    - .github/workflows/release-build.yml
    - docs/ARCHITECTURE.md
    - docs/PRD.md
    - docs/RELEASING.md
    - themes/default/README.md
    - README.md
    - crates/anvilid/Cargo.toml
    - Cargo.lock
key-decisions:
  - "release.yml never built admin-ui, so release binaries would have shipped the console placeholder; added a shared console job + per-binary embed check to release.yml and release-build.yml"
  - "0.2 released from main (anvilid 0.2.0 set on main), not from a maintenance branch as 0.1 was"
  - "Released-migration immutability and browser-level behaviour stay outside the Rust QUAL-01 map (check-migrations.sh and Playwright specs); the map header says so"
  - "REQUIREMENTS.md checkboxes not ticked here (orchestrator: phase verification does it)"
  - "ghcr package stays private: anonymous pull is 403, authenticated pull works; making it public is the owner's one-time package setting (not worked around)"
requirements-completed: []
duration: ~65min
completed: 2026-11-25
---

# Phase 3 Plan 29: Phase 3 gate and v0.2.0 release Summary

**The security-test map covers all Phase 3 controls (230 pairs). `just ci` gained the migration and console checks. Release builds now must embed the admin console. The 0.2 migrations are pinned and the docs match the shipped code. Every workflow (ci, conformance Basic+Config+Form Post, e2e on SQLite and Postgres, release-build, fuzz) is green on 177b7f4, and v0.2.0 is published from that commit.**

## Tasks

| # | Task | Commit |
|---|------|--------|
| 1 | Security-test map, ci recipe, release console check | `664820f` |
| 2 | Docs sync (ARCHITECTURE, PRD, theme README) | `fb5c0f5` |
| 2b | Upgrade notes, RELEASING, README for 0.2 | `d432610` |
| 2c | Release commit: anvilid 0.2.0 + 0.2 migrations pinned | `00033d9` |
| 3a | Fix: fuzz `authorize_parse` built with the 0.2 Client fields (found by CI) | `177b7f4` |
| 3 | Push to main, CI green, v0.2.0 tag and release | see CI and Release |

## What changed

### QUAL-01 map (`scripts/check-security-tests.sh`)
- Added 123 pairs; the map now has 230. The Task 1 commit message says 129, which is a miscount; the right number is 123.
- New controls covered:
  - passkeys: challenge single use at login and at enrolment, clone/stale counter, counter CAS, credential id uniqueness, another user's or tenant's passkey, garbage responses, IP-literal RP ids;
  - TOTP: replay and the concurrent step;
  - second factor: binding token, password route, CSRF;
  - recovery codes: single use and concurrency;
  - account pages: CSRF/binding, owner and kind, re-auth, session required;
  - introspection: confidential only, request shape, `can_introspect` visibility, inactive cases, opaque tenant binding;
  - revocation: authentication, no oracle, hints, family effects, another client's token, `unsupported_token_type` for JWT client-credentials tokens, reuse audit;
  - consent: CSRF/binding, deny, `prompt=none`, double submit, session required, `id_token_hint` alg gate, app revocation without binding, storage revoke/isolation;
  - sessions: the two 03-19 candidate pairs, token revocation, idle/absolute limits;
  - rate limits: per IP, per class, per client, admin, path tenants, XFF spoofing, missing peer;
  - brute force: progressive lock, per identifier+IP, byte-identical answers, identifier tier, CAPTCHA before password, second-factor and passkey throttles;
  - CAPTCHA fail-closed: 7 cases;
  - trusted proxies: 8 cases including both proptests;
  - form_post: escaping, CSP, error page, unsupported mode; the three 03-31 request-object cases;
  - id-token alg gate; key rotation (alg gate, single promotion, immediate);
  - job leases;
  - destructive-migration guard on both backends and the binary message;
  - 03-32 composite FK test;
  - admin v0.2 routes (missing token, other tenant, scope, tenants-write, write-only secrets);
  - 03-21 and 03-23 admin audit candidates; console client scopes and registration;
  - console traversal; mail template sandbox; SMTP error hygiene.
- The header now lists what is deliberately not in the map: SSRF (nothing is fetched), SEC-06, released-migration immutability (check-migrations.sh) and browser-level behaviour (Playwright).
- `scripts/check-security-tests.sh`: "OK (230 control/test pairs, all present and registered)". `--self-test`: OK.

### `just ci`
- `ci: fmt-check lint deny deps migrations-check test test-pg release-graph security-tests console-check`.

### Release builds require the console
- New script `scripts/check-console-embedded.sh`:
  - with no argument, it checks that `admin-ui/dist/index.html` and its entry script exist;
  - given a binary, it also checks that the binary contains that content-hashed entry path.
- Locally: the release binary passes; the debug binary is rejected, because debug rust-embed reads files from disk. So the check has been seen to fail on a binary without the embedded console.
- `release-build.yml` and `release.yml` now have a `console` job (Node 22, `npm ci && npm run build`) that uploads `admin-ui-dist`. The linux musl and macOS jobs download it, check it before the build, and check the binary after the build. In release.yml, setup-node is pinned by SHA (v6.5.0).

### Migrations
- `scripts/released-migrations.sha256` gained these lines, added in the release commit:
  - SQLite `0003_release_0_2.sql`;
  - SQLite `0004_release_0_2_token_family.sql`;
  - Postgres `0003_release_0_2.sql`.
- `check-migrations.sh` and its `--self-test` are green.

### Docs
- **ARCHITECTURE:**
  - §2: totp-rs/RustCrypto exception, qrcodegen, governor+moka, release console check.
  - §6.1: credential/recovery_code/consent_grant/access_token/audit_event/email_template/smtp_settings/job_lease, new client/session columns, Postgres composite tenant FKs (authorization_code NOT VALID).
  - §6.2: SMTP/CAPTCHA secrets.
  - §7.1: accessors, new intent methods, **audit written after commit**.
  - §7.3: destructive guard, migration lint, SQLite lock note, upgrade tests.
  - §8.1: Ed25519 only, per-tenant algs, rotation policy and CLI.
  - §8.2: `aud`=client_id until RFC 8707, opaque hashed, introspection visibility, revocation semantics incl. **unsupported_token_type for JWT client-credentials tokens**, amr/acr.
  - §9: **consent as its own state machine**, MFA, settings flows.
  - §10.1–10.4: 0.2 endpoints/discovery, request_not_supported delivery, UI routes, admin routes and scopes, console client/serving.
  - §11: route classes/quotas/429 shapes, two-tier brute force, CAPTCHA + WCAG 3.3.8 caveat, trusted-proxy algorithm, CSP exceptions, SSRF note.
  - §13: 0.2 config keys, startup reconciliation, audit stdout, email templates.
  - §14: leases.
  - §17: CI.
- **PRD:** only the roadmap row "ES256/EdDSA" was changed, to "ES256/Ed25519", to match OIDC-11. No requirement wording changed.
- **themes/default/README.md:**
  - the script rule now allows self-hosted script files only, never inline scripts, with the CAPTCHA exception;
  - context tables for login (passkey/captcha), second_factor, captcha, consent, form_post, account_*, totp_enroll and recovery_codes;
  - the full 0.2 selector contract and the webauthn.js DOM contract;
  - the `too_many_requests` error sentence and the `login.too_many_attempts` sentence;
  - the stylesheet class table, including `data-label`;
  - the `recovery_code_used` email and template overrides.
- **docs/UPGRADING.md (new):** the 0.1 to 0.2 upgrade is automatic and non-destructive. It covers:
  - stop all 0.1 nodes before starting a 0.2 node (0.1 cannot write passwords to the 0.2 credential table);
  - SQLite has no cross-process migration lock (serve.lock protects the data directory);
  - existing clients default to `consent_mode = required`;
  - trusted proxies, key rotation and the audit stream.
- **docs/RELEASING.md:** pin migrations in the release commit, the console is embedded, ghcr package visibility.
- **README:** 0.2 status and features, `/console/`, account pages, 0.2.0 install commands, Node prerequisite.

## Open questions (research)
OQ1–OQ8 are resolved and recorded in ARCHITECTURE (§8.2 audience/introspection/revocation/amr, §10.3 console admins, §6.1 schema, §7.3 upgrade tests). OQ9 (whether a local conformance run is accepted for certification) is still open. It does not block 0.2 and carries over to Phase 7.

## CI

Pushed straight to `origin/main` (authorized). Two pushes were needed:

**00033d9** (first push). ci, conformance, e2e and release-build were all green. Fuzz, triggered by hand, failed: `fuzz_targets/authorize_parse.rs` built a `Client` without the four 0.2 fields (E0063). The fuzz workflow runs only nightly, on fuzz PR paths or by hand, which is why the earlier Phase 3 pushes never caught this. Fixed in `177b7f4`. That commit also refreshes the stale `fuzz/Cargo.lock`: it adds totp-rs and its dependencies at the main lock's versions.

**177b7f4** (tagged). Every workflow is green:

| Workflow | Run | Jobs |
|---|---|---|
| ci | 45583760917 | fmt+clippy, cargo deny, dependency rules, sqlx offline metadata, release dependency graph, tests (sqlite), tests (postgres), admin console (Node 22) |
| conformance | 45583761038 | OpenID conformance (Basic, Config and Form Post OP) |
| e2e | 45583760967 | Playwright e2e (sqlite), Playwright e2e (postgres), QUAL-04 sqlite/postgres, container image size gate |
| release-build | 45583760772 | admin console build, musl x86_64, musl aarch64 (each "embeds the console (entry assets/index-CfbcFzpQ.js)") |
| fuzz (manual) | 45583817466 | authorize_parse, client_assertion, jwt_decode, redirect_match |

Two failures from before this plan are now fixed:
- The admin console `npm ci` failure, fixed by the lockfile regeneration in 03-25.
- The conformance failure (CI run 45574616586): the login rate limit was fixed in 03-28 and the request-object delivery in 03-31.

No expected failures or skips were added.

## Release

- Tag `v0.2.0` ("AnvilID 0.2.0") is on `177b7f4`, the green main HEAD. Release run: https://github.com/specianic/anvil-id/actions/runs/45585671872
- **Attempt 1:** GitHub never gave the `macos aarch64-apple-darwin` job a runner. It was cancelled after 15 minutes with "The job was not acquired by Runner of type hosted even after multiple attempts" (macOS arm64 capacity). That skipped the `github release` job, so no Release existed yet. Every other job passed, including the image push.
- **Attempt 2:** `gh run rerun --failed` reran the macOS arm64 job and the release job, and both passed. The tag was not moved.
- `gh release view v0.2.0`: "AnvilID 0.2.0", not a prerelease, 4 archives (linux musl x86_64/aarch64, macOS aarch64/x86_64) and 4 `.sha256` files.
- Checks on the x86_64 Linux archive:
  - `sha256sum -c` OK;
  - `anvilid --version` prints `anvilid 0.2.0`;
  - `scripts/check-console-embedded.sh` confirms the downloaded binary embeds the console;
  - `gh attestation verify` exit 0.
- Image: ghcr has version `sha256:160dc7d9f2e6…` tagged `0.2.0` and `latest`. An authenticated registry token returns its OCI index with linux/amd64 and linux/arm64.
  - Anonymous pull fails with **403** because the package visibility is `private`. This is the same situation as 0.1 (02-23); it was reported, not worked around.
  - A local `docker pull` could not be run: Docker Desktop on this machine crashed during the session (the CLI segfaults). The authenticated manifest fetch stands in for the logged-in pull.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] release.yml shipped binaries without the admin console**
- **Found during:** Task 1
- **Issue:** The plan asked only release-build.yml to require `admin-ui/dist`. The tag-triggered release.yml never built the console, so v0.2.0 archives and the image would have served the placeholder at `/console/`.
- **Fix:** One console job per workflow. Every linux/macOS build downloads it, checks it before the build, and checks the embedded entry script in the binary after the build.
- **Files:** .github/workflows/release.yml, .github/workflows/release-build.yml, scripts/check-console-embedded.sh
- **Commit:** 664820f

**2. [Rule 1 - Bug] Fuzz target `authorize_parse` did not compile against the 0.2 `Client` model**
- **Found during:** Task 3 (fuzz run 45582351728 on 00033d9)
- **Issue:** The fixture `Client` literal lacked `token_format`, `consent_mode`, `id_token_signed_response_alg` and `can_introspect`. `fuzz/Cargo.lock` lacked totp-rs.
- **Fix:** Added the fields with their model defaults. The new lock entries were checked against the main `Cargo.lock` (16 packages, same versions).
- **Files:** fuzz/fuzz_targets/authorize_parse.rs, fuzz/Cargo.lock
- **Commit:** 177b7f4

### Orchestrator overrides of the plan
- REQUIREMENTS.md was not ticked. Phase verification does that, so the Task 2 automated check `grep -c ... | grep -qx 16` is intentionally not met.
- Task 3 pushed straight to `origin/main` (the user authorized it through the orchestrator) instead of opening a PR branch. After that, tag v0.2.0 was pushed and the release published.
- The migration pins went into the release commit (`00033d9`) instead of the Task 1 commit.

### Environment
- Local `just ci`: fmt-check, lint, deny, deps, migrations-check, test (the SQLite web/binary suites plus the Postgres storage contract and upgrade suites, through testcontainers), release-graph, security-tests and console-check all passed.
- `test-pg` stopped partway: the first binary passed 104/104, then Docker Desktop crashed (CLI segfault, socket gone, testcontainers `CreateContainer` 500 in `access_token_format`). This is an environment failure. The Postgres web suites ran in CI instead ("tests (postgres)" job).
- The dev database `anvil_dev` was not touched.



## Self-Check: PASSED

Files: scripts/check-console-embedded.sh, docs/UPGRADING.md, this SUMMARY present. Commits 664820f, fb5c0f5, d432610, 00033d9, 177b7f4 present; v0.2.0 tag on origin (annotated, peels to 177b7f4); GitHub Release v0.2.0 with 8 assets.
