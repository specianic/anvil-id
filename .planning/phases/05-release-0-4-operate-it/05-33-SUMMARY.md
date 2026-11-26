---
phase: 05-release-0-4-operate-it
plan: 33
subsystem: account-ui, theme, admin-console
tags: [gap-closure, attributes, account-nav, cimd, consent, css, console, one-time-secret]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-13 CIMD consent block (consent-cimd, consent-avatar); 05-19 account attributes page and account_attributes_nav; 05-24 OneTimeSecret and the secret-in-component-state pattern"
provides:
  - "account_attributes::attributes_nav (one rule, is_user_field, shared with the page's field list) and attributes_nav_or_page for handlers"
  - "Attributes entry on every account page when the tenant has a user-editable attribute"
  - "CSS for .anvil-consent-cimd and the .anvil-avatar initials (theme variables, light and dark)"
  - "Console client create and secret rotation keep the secret only in component state, shown once in OneTimeSecret"
affects: [05-gate, e2e account navigation]

tech-stack:
  added: []
  patterns:
    - "A page flag that needs storage is computed in the async handler before a one-time change (TOTP confirm, recovery codes, email confirm), so a failure never loses the one-time result"

key-files:
  created: []
  modified:
    - crates/anvil-web/src/ui/account_attributes.rs
    - crates/anvil-web/src/ui/account_profile.rs
    - crates/anvil-web/src/ui/account_security.rs
    - crates/anvil-web/src/ui/account_sessions.rs
    - crates/anvil-web/src/ui/account_apps.rs
    - crates/anvil-web/src/ui/account_linked.rs
    - crates/anvil-web/tests/account_attributes.rs
    - tests/e2e/specs/attributes.spec.ts
    - themes/default/static/anvil.css
    - admin-ui/src/components/ClientForm.tsx
    - admin-ui/src/routes/t/$tenant/clients/new.tsx
    - admin-ui/src/routes/t/$tenant/clients/$clientId.tsx
    - tests/e2e/specs/console.spec.ts

key-decisions:
  - "attributes_nav returns Result; handlers render the tenant error page on failure (no silent false). attributes_nav_or_page wraps that for the account handlers"
  - "The email confirmation page (/ui/account/email/confirm) also carries the entry; render_confirm, render_enrolment and render_codes stay sync and take the flag, which the handler computes before the one-time change"
  - "After the created client secret is dismissed the page says so (created-client-secret-gone); a public client's status line says it has no secret; created-client-id is always outside the panel"
  - "The rotation mutation returns only { client_id }; the new secret is shown in OneTimeSecret testId rotated-client-secret"

requirements-completed: [AUTH-14, ORG-01, AGT-02]

duration: about 10 min wall clock
completed: 2026-11-26
---

# Phase 5 Plan 33: User-facing polish (Attributes nav, CIMD consent CSS, one-time client secrets) Summary

**The Attributes entry now appears on every account page (profile, email and its confirmation, password, security with TOTP enrolment and recovery codes, sessions, apps, linked, attributes) whenever the tenant has a user-editable attribute, decided by one rule shared with the attributes page. The CIMD consent block shows the client initials as a themed circle. Console client creation and secret rotation show the secret once and keep it out of the TanStack cache.**

No requirement checkbox in REQUIREMENTS.md was ticked (wave rule).

## Accomplishments

### Task 1 (commit 5d9cf58)
- `account_attributes.rs`: `fn is_user_field(d)` (the predicate `field_views` uses), `pub(crate) async fn attributes_nav(state, tenant) -> Result<bool, CoreError>`, and `attributes_nav_or_page(state, tenant, loc) -> Result<bool, Box<Response>>`.
- Every account context sets `account_attributes_nav`: profile, email, email confirm, password (account_profile.rs), the security overview, TOTP enrolment and recovery codes (account_security.rs), sessions, apps and linked. In `totp_begin`, `totp_confirm`, `recovery_codes` and `confirm_submit` the flag is computed before the service call, so if the lookup fails it fails before the one-time change happens.
- `anvil.css`: `.anvil-consent-cimd` is a bordered flex row with wrap. `.anvil-avatar` is a 2.5rem circle in `--anvil-primary` / `--anvil-primary-text` with centred bold initials, `flex: none` and `user-select: none`. The note (`> .anvil-muted`) takes its own line. Only theme variables are used, so dark mode follows automatically.
- Tests (`tests/account_attributes.rs`, 2 new, 11 total):
  - `attributes_nav_on_every_account_page`: the 9 GET pages plus the TOTP enrolment and recovery-codes pages (reached by a real enrolment with a computed TOTP code). Each has the entry and exactly one `aria-current` in the nav, and that mark is on the page's own entry.
  - `attributes_nav_hidden_without_editable_attributes`: no attributes, and then a non-editable attribute only. The entry is on none of those pages.
- e2e `attributes.spec.ts`: from the profile page the Attributes link is visible and opens the attributes page, which then has `aria-current`.

### Task 2 (commit 2a5b990)
- `clients/new.tsx`: `mutationFn` destructures `{ client_secret, ...client }`, calls `setSecret`, and returns `client`. `<p role="status">Client <code data-testid="created-client-id">` is always rendered. `OneTimeSecret testId="created-client-secret"` shows while the secret is set. After dismissal the page shows `created-client-secret-gone`. A file header comment was added.
- `clients/$clientId.tsx` DangerZone: the rotation follows the same pattern, with `OneTimeSecret testId="rotated-client-secret"`.
- `ClientForm.tsx`: `SecretOnce` was removed. `grep -rn SecretOnce admin-ui/src` finds nothing.
- `console.spec.ts`: after creating the client, `takeOneTimeSecret(page, 'created-client-secret', false)` (the existing helper from lib/console-v04.ts) checks that the value is gone from the HTML after dismissal and that `created-client-id` is still present. The client page then rotates the secret through the confirm dialog, checks the rotated panel with axe and dismisses it.

## Verification (main tree, SQLite)
- `cargo test -p anvil-web --test account_attributes --test account_profile --test account_apps --test account_linked --test sessions --test consent --test render --test theme`: all green (11, 15, 4, 14, 13, 19, 13, 6).
- `cargo test -p anvil-web --test account_security`: 11/12. The failure, `a_stale_session_must_sign_in_again_and_changes_nothing` (line 454), is not caused by this plan. The test stores a passkey and then signs in again with only a password. 05-30's uncommitted change in the working tree (`flow/login.rs`, `service/flow.rs`: passkey as a second factor) now sends that user to the second-factor step. The test passes the parts this plan touches: the overview, the enrolment and the codes pages.
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean.
- `admin-ui`: `npm run check:api` (schema.d.ts up to date), `npm run typecheck` and `npm run build` pass. `npm ci` was skipped because node_modules was already installed. The route tree is unchanged.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- **Local browser e2e without Docker.** A debug `anvilid` was copied to a scratch dir and run with a fresh data dir and the run.sh flags (`--public-url http://localhost:18133`, `--breach-check off`, auth budget 1200/min) under Playwright chromium:
  - `attributes.spec.ts`: **2 passed**, including the new profile-to-attributes step.
  - `console.spec.ts`: **every step passed** up to "SMTP settings and a test send delivered to Mailpit". That step failed only because Mailpit (Docker) was not running ("Connection refused"). The sign-in uses `createConsoleAdmin`. The new create/dismiss and rotate/dismiss steps passed, including their axe checks.
  - `console-tenants.spec.ts` (reads `created-client-id`): passed.
  - `mcp.spec.ts`: 2 passed. A temporary copy (deleted after the run) added axe checks on the CIMD consent page in light and dark modes, and both passed. The avatar is 40x40 with border-radius 50%: rgb(47,91,211) on white in light mode, rgb(109,142,240) on rgb(13,16,32) in dark mode. A screenshot confirmed the layout.
  - The scratch instance was stopped and its directory deleted.

## Not run
- Postgres variants and `tests/e2e/run.sh` as written (both need Docker). Left for CI.
- The Mailpit step of console.spec.ts.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] The flag is computed before one-time changes**
- **Found during:** Task 1
- **Issue:** If the flag were computed inside the render path after `confirm_totp`, `regenerate_recovery_codes` or `complete_email_change`, a failed lookup would show an error page after the change. The freshly generated recovery codes would then be lost.
- **Fix:** those handlers compute the flag first and pass it to the sync renderers. The email confirmation renderer stays sync and takes the flag as a parameter.
- **Files modified:** crates/anvil-web/src/ui/account_profile.rs, account_security.rs
- **Commit:** 5d9cf58

### Notes
- The email confirmation page was not in the plan's list, but it is an account page with the nav, so it gets the entry too.
- TDD: the tests and the implementation went into one commit. There was no separate RED commit, because a `git stash` is unsafe in the shared working tree. Before this change the profile page did not pass the flag, so the new test would have failed there.
- The TOTP code helper in the new tests is copied into the test file, like the other test files do. tests/ui_helpers is not in this plan's files.

## Self-Check: PASSED
- Files: all 13 modified files exist. `attributes_nav` is in account_attributes.rs, `.anvil-avatar` is in anvil.css, and `OneTimeSecret` and `setSecret` are in both client routes.
- Commits: 5d9cf58 and 2a5b990 are in `git log`.
