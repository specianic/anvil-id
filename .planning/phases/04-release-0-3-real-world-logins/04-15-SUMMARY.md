---
phase: 04-release-0-3-real-world-logins
plan: 15
subsystem: account
tags: [account, profile, email-change, password, email-templates, i18n]
requires:
  - phase: 04-01
    provides: EmailKind login_code/email_change/email_changed, EmailChange token kind
  - phase: 04-04
    provides: UserRepo::complete_email_change intent (SQLite)
  - phase: 04-05
    provides: Postgres complete_email_change and repositories
  - phase: 04-06
    provides: t() rendering, RequestLocale, per-area .ftl catalogs
provides:
  - Variable contracts and default templates for login_code, email_change, email_changed
  - AccountService::{profile, update_profile, request_email_change, complete_email_change, change_password}
  - /ui/account/profile, /ui/account/email, /ui/account/email/confirm, /ui/account/password
  - Unified account navigation in account_base.html
affects: [04-24, 04-25]
tech-stack:
  added: []
  patterns:
    - email-change confirmation link is GET-safe (renders a button); the token is consumed only on POST
    - the new address travels sealed in the link (KEK purpose anvilid/email-change-link/v1, AAD = tenant + token hash)
key-files:
  created:
    - crates/anvil-web/tests/account_profile.rs
    - themes/default/templates/account_profile.html
    - themes/default/templates/account_email.html
    - themes/default/templates/account_password.html
    - themes/default/locales/en/account.ftl
    - themes/default/emails/{login_code,email_change,email_changed}.{txt,html}
  modified:
    - crates/anvil-core/src/service/account.rs
    - crates/anvil-web/src/ui/account_profile.rs
    - themes/default/templates/account_base.html
    - crates/anvil-mail/src/check.rs
    - crates/anvil-mail/src/render.rs
    - crates/anvil-mail/tests/templates.rs
    - crates/anvil-web/tests/admin_api_v02.rs
key-decisions:
  - "Email change to an address already used by another user responds exactly like success but sends nothing (anti-enumeration); the attempt is audited as a failure with reason email_taken"
  - "A conflict at confirmation (address taken meanwhile) shows account.email_taken and leaves the token unconsumed, so it works once the address is free again"
  - "AUTH-13 is not ticked in REQUIREMENTS.md: requirements are marked only after phase verification (commit 9109b9a)"
duration: multi-session (interrupted twice)
completed: 2026-11-25
---

# Phase 4 Plan 15: Account Profile, Email and Password Pages Summary

You can now edit your profile, change your email (the new address must be re-verified) and change or set your password from the account page. The plan also adds default templates and variable contracts for the login_code, email_change and email_changed emails.

## Routes

| Route | Methods | Notes |
| --- | --- | --- |
| `/ui/account/profile` | GET, POST | name, given_name, family_name (each up to 200 chars), locale (`^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`); audited `profile_updated`; locale feeds the account page language |
| `/ui/account/email` | GET, POST | re-auth within 15 min (`account.reauth_required`); issues EmailChange token (24 h, 256-bit, SHA-256 at rest) + sealed email_change mail to the new address; audited `email_change_requested` |
| `/ui/account/email/confirm` | GET, POST | GET only renders a "Confirm new email" button; POST consumes the token, switches the email (verified), sends email_changed to the old address; audited `email_changed` |
| `/ui/account/password` | GET, POST | re-auth, password policy, breach check, optionally revokes other sessions (default on, back-channel deliveries enqueued), password_changed notice; social-only users can set a password |

Every route uses the settings flow (flow cookie + CSRF -> 403). A GET without a session redirects to sign-in and returns afterwards.

## Email contracts

- `login_code` {tenant_name, code, link, expires_minutes}
- `email_change` {tenant_name, link, new_email, expires_minutes}
- `email_changed` {tenant_name, new_email} (sent to the old address)

No `TRANSITIONAL(04-15)` remains. The two tests 04-01 left red (anvil-mail every-kind and admin_api_v02 kinds list) are now green.

## Navigation keys

In `account_base.html`, `account_nav` is one of profile, email, password, security, sessions, apps. The current entry gets `aria-current="page"`. The strings are `account_nav.{label,profile,email,password,security,sessions,apps}` in `locales/en/account.ftl`. The linked-identities entry is added in 04-25.

## Commits

- e42aad7 feat(04-15): login_code, email_change, email_changed templates and contracts
- d1ed871 feat(04-15): profile, email change and password change on the account page
- 0a9bed1 style(04-15): rustfmt the anvil-mail template tests

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test account_profile` (15), `account_security` (12), `sessions` (13), `admin_api_v02` (9), `security_admin_v02` (6): all pass
- `cargo test -p anvil-mail`: all pass
- `cargo clippy -p anvil-core -p anvil-web -p anvil-mail --all-targets`: no warnings
- rustfmt --check on the plan's files: clean

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Confirmation form hidden token lacked an id**
- **Found during:** Task 2
- **Issue:** The `token` hidden input in account_email.html had no `id`. That was out of line with the other forms, and the shared form helper could not find the field.
- **Fix:** Added `id="token"`.
- **Commit:** d1ed871

**2. [Rule 3 - Blocking] Test PasskeyCeremonies fake out of date with the port**
- **Found during:** Task 2
- **Issue:** The `NoPasskeys` test double did not match the current `PasskeyCeremonies` trait.
- **Fix:** Rewrote the fake (test code only) and removed the unused imports.
- **Commit:** d1ed871

## Deferred Issues

- `ANVILID_TEST_DB=postgres` run of account_profile not done: Docker is not available on this host (testcontainers panics with "docker must be running"). The Postgres `complete_email_change` intent was already covered by 04-05.

## Self-Check: PASSED
