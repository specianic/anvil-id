---
phase: 04-release-0-3-real-world-logins
plan: 25
subsystem: account
tags: [account, linked-identities, upstream, unlink, auth-11, auth-13]
requires:
  - phase: 04-15
    provides: account page patterns, account_base.html navigation
  - phase: 04-21
    provides: UpstreamService::start (settings flow -> UpstreamPurpose::Link), Link callback (identity_linked mode account)
  - phase: 04-01
    provides: ConnectionRepo::{links_for_user, delete_link, list}, AuditAction::IdentityUnlinked, AuditDetails::link
provides:
  - AccountService::{linked_identities, available_connections, check_link_start, unlink}
  - LinkedIdentityView, AvailableConnection; AccountFailure::{LastSignInMethod, LinkNotFound}
  - Routes GET /ui/account/linked, POST /ui/account/linked/connect/{slug}?flow=, POST /ui/account/linked/{id}/unlink?flow=
  - account_linked.html, locales/en/account_linked.ftl, "Linked accounts" nav entry (account_nav = "linked")
affects: [04-21 follow-up (link success page), phase 4 verification]
tech-stack:
  added: []
  patterns:
    - "Connect checks binding and re-auth on the account page first (check_link_start), so refusals render there instead of the upstream service's sign-in restart"
    - "Last-sign-in-method guard: password || passkeys > 0 || other links > 0 || tenant email_otp/magic_link"
key-files:
  created:
    - crates/anvil-web/tests/account_linked.rs
    - themes/default/templates/account_linked.html
    - themes/default/locales/en/account_linked.ftl
  modified:
    - crates/anvil-core/src/service/account.rs
    - crates/anvil-web/src/ui/account_linked.rs
    - themes/default/templates/account_base.html
key-decisions:
  - "Unlink of an unknown, malformed or another user's link id is account.link_not_found with status 404 (page re-rendered); the last-method refusal is 409"
  - "The guard counts passkeys as a sign-in method and the tenant's email_otp/magic_link as one, as the plan specifies; it does not check that the user's email is verified"
  - "Connect reuses the one upstream start implementation by building UpstreamService in the handler (fields are public); no second start route logic"
duration: about 35 min
completed: 2026-11-25
---

# Phase 4 Plan 25: Linked Accounts Page Summary

**`/ui/account/linked` lists the user's linked upstream identities (provider, email at link time, connected date, last used) and offers a Connect button for each enabled connection not linked yet. Connect starts the upstream flow with purpose Link from the page's settings flow. Disconnect needs CSRF, the settings binding and a sign-in within 15 minutes, and is refused when it would remove the last way to sign in.**

## Routes

| Route | Notes |
| --- | --- |
| `GET /ui/account/linked` | 303 to sign-in without a session; starts a settings flow; `no-store`; re-auth notice `account-reauth` when the sign-in is older than 15 min |
| `POST /ui/account/linked/connect/{slug}?flow=` | `check_link_start` (binding + re-auth, refusals shown on the page), then `UpstreamService::start` -> 303 to the provider with the binding cookie; unknown or disabled slug -> 404; `LinkFailed` keys (for example `upstream.already_linked` from the callback) are shown as page errors |
| `POST /ui/account/linked/{id}/unlink?flow=` | `AccountService::unlink`: binding (403 `csrf`), re-auth (400 `account.reauth_required`), guard (409 `account.last_sign_in_method`), unknown or foreign id (404 `account.link_not_found`); success: `linked.unlinked`, audited `identity_unlinked` {connection, mode: account} |

Template selectors: table `linked-list`, rows `linked-{id}`, forms `linked-unlink-{id}` and `linked-connect-{slug}`, submit buttons `{form id}-submit`, empty state `linked-none`. The table cells carry `data-label` so the table stacks on narrow screens like the sessions table. The page uses no script.

## Task Commits

1. **Task 1: linked identities page, connect, guarded unlink, tests:** `13b11d9`

## Verification (main tree, SQLite)

- `cargo test -p anvil-web --test account_linked` (12), `--test account_profile` (15), `--test account_security` (12): pass
- Regressions: `anvil-web --lib` (133), `i18n`, `render`, `theme`, `sessions`, `account_apps`, `security_theme`, `security_csp`, `upstream_login` (12), `security_linking` (16): pass
- `cargo test -p anvil-core --lib service::account` (8, including the new guard unit test): pass
- `rustfmt --edition 2024 --check` on the three Rust files: clean
- Clippy with `-D warnings` (anvil-core lib+tests, anvil-web lib + account_linked): clean (see Clippy)

## Not run

- `ANVILID_TEST_DB=postgres` for `account_linked`: Docker is not used (wave rule), so this is left for CI. The plan adds no SQL; it uses the existing `list`, `get`, `links_for_user` and `delete_link` intents.

## Deviations from Plan

### Notes

**1. Link success still shows the `upstream.linked` message page**
- After the provider returns, `crates/anvil-web/src/ui/upstream.rs` (`outcome_page`, `UpstreamOutcome::Linked`) renders the message page `upstream.linked`. It does not redirect to `/ui/account/linked`.
- That file is not in this plan's files_modified (wave 6 rule), so it was left unchanged. The new link does appear on `/ui/account/linked` (tested).
- **Follow-up:** answer `UpstreamOutcome::Linked` with a 303 to `tenant.ui_url("/ui/account/linked")`. This is a one-line change in upstream.rs and needs an update to the assertion in `upstream_login.rs::account_page_link_connects_the_signed_in_user`.

**2. [Rule 2] Added `AccountService::check_link_start`**
- Without it, an expired settings flow posted to connect would get the upstream service's sign-in restart page instead of the account page.
- It changes nothing; the upstream service still checks the binding itself.

**3. Two new AccountFailure variants**
- `LastSignInMethod` (`account.last_sign_in_method`) and `LinkNotFound` (`account.link_not_found`).
- Their strings are in `account_linked.ftl`, the plan's own catalog.

### Known limitation

- The guard is check-then-delete. Two concurrent unlinks of two different links from two settings flows could both pass and leave a user without a password, a passkey or a link. Recovery by email still works.
- A serialising storage intent (delete the link only if another sign-in method remains, in one transaction) would close this. Flagged for review; it was not added because it needs new SQL in both backends.

## Clippy

- The first clippy run failed in another wave-6 plan's uncommitted files (`flow/email_code.rs`, then `ui/login.rs` `FlowEnv`), not in this plan's files.
- Once that work settled, `cargo clippy -p anvil-core --lib --tests -D warnings` and `cargo clippy -p anvil-web --lib --test account_linked -D warnings` were clean.
- `account_linked` (12) was green again on that tree.

## Self-Check: PASSED

- Files exist: crates/anvil-web/src/ui/account_linked.rs, crates/anvil-web/tests/account_linked.rs, themes/default/templates/account_linked.html, themes/default/locales/en/account_linked.ftl
- Commit in history: 13b11d9
- key_links: `UpstreamPurpose::Link` is reached through `UpstreamService::start` with the settings flow (connect handler); `delete_link` in `AccountService::unlink`
