---
phase: 04-release-0-3-real-world-logins
plan: 32
subsystem: release-gate
tags: [gate, QUAL-01, ci, release, migrations, fuzz, conformance]
requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01..04-31 and the gap-closure plans 04-34..04-37"
provides:
  - "QUAL-01 map covers every Phase 4 control (430 control/test pairs, up from 230)"
  - "anvilid 0.3.0 on main; 0.3 migrations pinned (SQLite 0005 + 0006, Postgres 0004 + 0005)"
  - "fuzz authorize_parse builds against the 0.3 API, with resource and prompt=create invariants"
  - "STATE.md parseable by `state advance-plan` again"
  - "Every workflow green on the release commit 9f88363 (run ids below)"
affects: [04-33 (manual provider checklist and v0.3.0 tag), Phase 4 verification]
tech-stack:
  added: []
  patterns: []
key-files:
  created: []
  modified:
    - scripts/check-security-tests.sh
    - scripts/released-migrations.sha256
    - crates/anvilid/Cargo.toml
    - Cargo.lock
    - fuzz/fuzz_targets/authorize_parse.rs
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md
    - .planning/phases/04-release-0-3-real-world-logins/deferred-items.md
key-decisions:
  - "AUTH-07 stays unticked: its automated evidence is green, but the requirement also needs the owner's manual real-provider checklist (04-33). The other 10 Phase 4 requirements are ticked, as this plan's must-haves say"
  - "Browser-only behaviour (upstream journeys, logout UI, email code pages, theme preview, i18n) stays in the 'not mapped' note: Playwright specs and conformance plans cover it"
  - "Fuzz runs only on schedule, dispatch and PRs, so it was dispatched by hand on the release commit; that is how the stale authorize_parse target was found"
  - "STATE.md Current Plan counts plans in execution order: 04-32 is the 36th of 37, so advance-plan moves to 37 (04-33) and 04-33's advance-plan reports the phase complete"
requirements-completed: [OIDC-12, OIDC-14, OIDC-16, AUTH-06, AUTH-08, AUTH-11, AUTH-13, UI-03, UI-04, SEC-03]
duration: ~55min
completed: 2026-11-26
---

# Phase 4 Plan 32: Phase 4 gate (release 0.3) Summary

**The security map now names a registered negative test for every Phase 4 control: 430 pairs, up from 230. anvilid is 0.3.0 and the four 0.3 migrations are pinned. A stale fuzz target that broke the nightly fuzz job is fixed. ci, e2e (SQLite and Postgres), conformance (all five plans), release-build and fuzz are green on the release commit 9f88363. Tagging v0.3.0 waits for the manual provider checklist (04-33).**

## Tasks

| # | Task | Commit |
|---|------|--------|
| 1 | Security map, version 0.3.0, 0.3 migration pins | `5786f08` |
| 2 | Push and drive CI to green; fuzz target fix | `9f88363` |

## Security map (scripts/check-security-tests.sh)

200 new pairs in these groups (each one is a `file::test_fn` that the owning test binary lists):

- **SSRF guard:** `security_ssrf.rs` (blocked IP literals, DNS to loopback, redirects, userinfo/non-https, size, timeout, no echo, proxy env, extra CA) plus `adapters/outbound.rs` unit tests (blocked v4/v6 nets, URL rules, allow-list), and the outbound policy applied to upstream discovery and back-channel destinations.
- **Upstream sign-in:** state, replay, binding cookie (required, cleared only on a state match: 04-37), nonce, RFC 9207 iss, ID token iss/alg (none, HS confusion, allow-list, signature)/aud/exp/check order (`upstream/claims.rs`), UserInfo subject, generic provider errors, CSRF on start, cross-site POST only on the callback, `require_verified_email` for upstream accounts (04-37).
- **Linking:** never auto-link on unverified emails (either side), confirmation for untrusted connections without enumeration, Microsoft never auto-links, one identity per user, owner + re-auth + binding for Connect. Also the unlink guard: web tests, the contract test `delete_link_keeps_a_sign_in_method`, the concurrency test `delete_link_concurrent_never_removes_the_last_method` and the unverified-email rule (04-34). Atomic JIT creation and tenant isolation are covered too.
- **Connection secrets:** sealed with tenant + connection AAD (core), sealed at rest (SQLite and Postgres `plaintext.rs`), write-only and never echoed (API, validation errors, Debug); https issuers and endpoints; Microsoft email trust needs the risk flag.
- **Admin scope:** connection routes (`security_admin_v03.rs`) and branding routes (`security_theme.rs`).
- **RP-Initiated Logout:** id_token_hint checks (alg none, foreign key, other tenant, tampered, not an ID token, unknown client), exact registered redirect URI, client_id/hint match, repeated parameters, confirmation needs the flow cookie and CSRF, and the CSRF/fetch-metadata exemption limited to the end_session POST.
- **Back-Channel Logout:** exact spec claims, the client's alg, `iss` per RP session (04-34, web + core + contract), response classification (400 gives up, 500 retries, removed URI), every revocation enqueues a delivery, a delivery is claimed once under concurrency, and every revocation path wakes the worker (04-36).
- **Resource indicators:** invalid_target at authorize and token, an error page for an untrusted redirect, downscoping only within the grant (code burned outside it), client_credentials only allowed resources, UserInfo refuses tokens for other audiences.
- **Email code / magic link:** enumeration-safe sends, single use (including concurrent submits), attempt cap and per-user lock, expiry, send limits, POST-only link, cross-browser link consumes nothing, CSRF, nothing stored in clear, never claims MFA. Also the per-toggle enforcement and the `login_code` template guard check (04-35).
- **MFA policy and step-up:** strictest policy wins, `required` enrols before the session (also after upstream sign-in), enrolment CSRF, step-up refused without the session, essential acr unmet is `unmet_authentication_requirements`, voluntary acr issues the lower acr, `prompt=none` never shows a step-up page.
- **Session switch:** signing in as another user revokes the previous session; the old session is never used for the answer; chooser binding and ownership; `login_hint` escaped.
- **Email change:** needs re-auth, confirmed by POST, single use (also concurrent), tampered/expired links refused, a conflict keeps the token.
- **Theme:** CSS validator (forbidden constructs, `url(` in any casing, control characters, context escape), logo sniffing and size, cross-tenant theme/logo/preview, frame-ancestors only on the preview page.
- **Cookies:** names unique per tenant even when two tenants are created in the same millisecond (04-37).
- **Body limit:** 413 per route family above 64 KiB, 400 KiB only for logo uploads (04-36).

The "SSRF guard: not mapped" paragraph is gone. The browser note now lists the 0.3 Playwright and conformance coverage, and the header describes release 0.3. `--self-test` passes.

## Local gate

Docker was down, so Postgres tests and e2e/conformance were left to CI.

- `scripts/check-security-tests.sh`: OK, 430 pairs. `--self-test`: OK.
- `scripts/check-migrations.sh` and `--self-test`: OK.
- `just fmt-check lint deny deps migrations-check`: pass.
- `just test`: SQLite and all non-Postgres crates pass: `cargo test --workspace --locked --exclude anvil-storage-postgres --no-fail-fast`, 2327 passed, 0 failed. `anvil-storage-postgres --lib` fails only with "docker must be running".
- `just release-graph security-tests console-check`: pass.
- `just fuzz authorize_parse 60` (nightly, after the fix): 426,941 runs, no crash.
- `test-pg`, `tests/e2e/run.sh` and `tests/conformance/run.sh all` were not run locally. CI runs all of them.

## CI

The commit the 04-37 agent pushed, 6322291, finished green before this plan pushed anything: ci 45728654541, e2e 45728654467, conformance 45728654459, release-build 45728654569.

5786f08 (Task 1): ci 45729687831, e2e 45729687772, conformance 45729687848 and release-build 45729687748 were all green. **Fuzz failed: 45729739115.** `fuzz_targets/authorize_parse.rs` no longer compiled: `validate` takes a `RegistrationMode` now, and `Client` has five new 0.3 fields. Fuzz only runs on schedule, dispatch and PRs, so pushes to main never caught it. The other three fuzz targets passed.

9f88363 (release commit, fuzz fix):

| Workflow | Run | Result |
|----------|-----|--------|
| ci (fmt + clippy, tests sqlite, tests postgres, sqlx offline, deny, dependency rules, release graph, console) | 45731215331 | success |
| e2e (Playwright sqlite + postgres, QUAL-04 sqlite + postgres, image size gate) | 45731215199 | success |
| conformance (Basic, Config, Form Post, RP-Initiated Logout, Back-Channel Logout) | 45731215313 | success |
| release-build (musl x86_64 + aarch64, console build) | 45731215350 | success |
| fuzz (4 targets x 300 s, dispatched) | 45731242861 | success |

Conformance (run 45731215313 on 9f88363; run 45729687848 on 5786f08 had the same totals). `expected-failures.json` is `[]`. Totals per plan:

| Plan | Modules | Successes | Failures | Warnings |
|------|---------|-----------|----------|----------|
| Basic | 36 | 1910 | 0 | 0 |
| Config | 2 | 35 | 0 | 0 |
| Form Post | 36 | 2066 | 0 | 0 |
| RP-Initiated Logout | 12 | 559 | 0 | 0 |
| Back-Channel Logout | 3 | 90 | 0 | 0 |

## Requirements evidence

- **OIDC-12:** `logout.rs`, `security_logout.rs`, `backchannel.rs`, `backchannel_wake.rs`, `anvilid/tests/backchannel_worker.rs`, contract `logout.rs`. e2e `logout.spec.ts` and `nojs-logout.spec.ts`. The conformance RP-Initiated Logout and Back-Channel Logout plans pass.
- **OIDC-14:** `authorize_prompt.rs` (none/login/consent/select_account/create, max_age), `authorize_step_up.rs` (acr_values, login_hint). e2e `prompt.spec.ts` and `mfa-policy.spec.ts`. Conformance Basic and Form Post (prompt/max_age modules) pass.
- **OIDC-16:** `resource_indicators.rs`, core `service/token.rs` and `service/userinfo.rs` unit tests, contract `code_and_family_resource_round_trip`. CI tests on sqlite and postgres.
- **AUTH-06:** `flow_email_code.rs`, `security_email_code.rs`, core `flow::email_code`, anvil-mail `templates.rs` login_code tests. e2e `email-code.spec.ts` and `nojs-email-code.spec.ts`.
- **AUTH-07 (not ticked):** `upstream_google.rs`, `upstream_microsoft.rs`, `upstream_apple.rs`, `upstream_github.rs`, `upstream_oauth2.rs`, `upstream_login.rs`, `upstream_adapter.rs`, core `upstream/{claims,providers}.rs`. e2e `social.spec.ts` and `mock-idp.spec.ts`. Still pending: the manual real-provider checklist `docs/social-login-checklist.md` (owner, 04-33).
- **AUTH-08:** `flow_mfa_policy.rs`, `authorize_step_up.rs`, core `policy/mfa.rs`, `upstream_login.rs` required-MFA tests. e2e `mfa-policy.spec.ts`. In-flow passkey enrolment under `required` moved to Phase 5 and is documented.
- **AUTH-11:** `security_linking.rs`, `account_linked.rs`, core `upstream/linking.rs`, the contract `delete_link_*` and `create_user_with_link_*` tests. e2e `linking.spec.ts` and `nojs-linking.spec.ts`.
- **AUTH-13:** `account_profile.rs`, `account_security.rs`, `account_linked.rs`, `account_apps.rs`, `sessions.rs`, contract `email_change_*`. e2e `account.spec.ts`, `sessions.spec.ts` and `keyboard.spec.ts`.
- **UI-03:** `security_theme.rs`, `admin_branding.rs`, `theme.rs`, core `policy/branding.rs`, contract `branding.rs`. e2e `theme.spec.ts`, `console.spec.ts` and `console-connections.spec.ts`.
- **UI-04:** `i18n.rs`, `i18n_catalogs.rs` (catalog parity), render snapshots. e2e `i18n.spec.ts`.
- **SEC-03:** `plaintext.rs` on both backends (`secrets_never_stored_plaintext`, connection secret tests), core `secret_is_sealed_with_tenant_and_connection_aad`. The CI postgres job runs the Postgres variant.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fuzz target out of date with the 0.3 API**
- **Found during:** Task 2 (fuzz dispatched on 5786f08, run 45729739115)
- **Issue:** `authorize_parse` did not compile: `validate` gained a `RegistrationMode` argument (prompt=create), and `Client` gained `post_logout_redirect_uris`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `allowed_resources` and `mfa_policy`.
- **Fix:** Added the fields and passed `Open` for the web client and `Disabled` for the native one. Two invariants were added while there: an accepted `resource` is always one of the client's allowed resources, and `prompt=create` is only accepted with open registration.
- **Files modified:** `fuzz/fuzz_targets/authorize_parse.rs`, which is not in the plan's files.
- **Commit:** `9f88363`

### Other

- `just ci` could not run as one command: Docker was down, so `test-pg` and the Postgres crate's `--lib` tests ran only in CI. The CI `tests (postgres)` job is green.
- REQUIREMENTS.md was edited after CI went green, in the docs commit rather than the Task 1 commit. AUTH-07 stays unticked: it waits for the manual provider checklist.
- Files edited outside the plan's list: STATE.md (Current Position repair, which the orchestrator asked for) and deferred-items.md (a gate check section giving every gate item its disposition).
- ROADMAP.md was stale from the parallel waves: it showed 22/33 and left 23 finished plans unticked, and `roadmap update-plan-progress` did not change it. Every 04 plan with a SUMMARY is now ticked and the row reads 36/37.

## Open items

- AUTH-07: the manual real-provider checklist and the v0.3.0 tag (04-33).
- Phase 5: remembered consent covering resources, and in-flow passkey enrolment under MFA `required`.
- Cosmetic: streamed oversized bodies get 400 on form pages and the admin API, 413 on /token and /logout.
- Pushes to main do not run fuzz, so a breaking API change shows up only in the nightly run. Consider adding `push` paths to `fuzz.yml`, or building the fuzz crate in ci.

## Self-Check: PASSED

Commits 5786f08 and 9f88363 exist. All modified files are present. Version is 0.3.0, four 0.3 migration pins exist, and the map references security_ssrf and security_linking.
