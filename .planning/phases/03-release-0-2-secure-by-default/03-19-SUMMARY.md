---
phase: 03-release-0-2-secure-by-default
plan: 19
subsystem: auth
tags: [sessions, idle-timeout, absolute-timeout, revocation, token-families, audit, account-pages]
requires:
  - phase: 03-02
    provides: SessionRepo get/list_for_user/list/revoke_with_families/revoke_all_for_user, AuditAction::{SessionRevoked, SessionsRevokedAll}
  - phase: 03-08
    provides: AuditContext extractor, empty ui::account_sessions module, account_base.html
  - phase: 03-12
    provides: sessions store client IP and user agent
  - phase: 03-14
    provides: settings flows (AccountService::start), SettingsBinding/AccountError
provides:
  - Throttled session activity writes (TOUCH_INTERVAL 60 s) in SessionService::current
  - SessionService list/revoke for users and admin functions for the management API (03-23)
  - /ui/account/sessions page (list, sign out one, sign out the others, sign out this browser)
affects: [03-23, 03-26]
tech-stack:
  added: []
  patterns:
    - "Core service unit tests on in-memory port fakes driven by a noop-waker block_on (anvil-core has no async runtime dev-dependency)"
    - "Multi-browser web tests: a per-test Browser with its own cookie jar that always sets a Cookie header"
key-files:
  created:
    - themes/default/templates/account_sessions.html
    - crates/anvil-web/tests/sessions.rs
  modified:
    - crates/anvil-core/src/service/session.rs
    - crates/anvil-web/src/ui/account_sessions.rs
key-decisions:
  - "03-19: Touch throttle is needs_touch(now, last_seen_at) = now - last_seen_at >= 60 s. The stored idle deadline lags activity by under a minute; get_active still enforces both deadlines"
  - "03-19: Signing out sessions requires a settings-flow binding (cookie + CSRF + owner) but no recent sign-in. SessionService::check_settings_binding mirrors AccountService's binding checks without the 15-minute re-auth step"
  - "03-19: revoke_mine/admin_revoke answer NotFound for unknown, another user's, revoked or expired sessions; revoke_others and admin_revoke_all audit sessions_revoked_all with details {sessions: n} (also when n = 0)"
  - "03-19: Revoking the current session from the page clears the session and flow cookies and answers 303 to the sign-in page"
  - "03-19: The sessions page needs no JavaScript and keeps the default CSP; it sets Cache-Control: no-store"
requirements-completed: []
metrics:
  duration: 75min
  completed: 2026-11-25
---

# Phase 3 Plan 19: Sessions (idle/absolute timeouts, list/revoke) Summary

**Sessions now record activity at most once a minute. Users can list their active sessions at `/ui/account/sessions` and sign out one session, every other session, or the current browser. Each revocation also revokes the token families issued under the session and is audited. `SessionService` provides admin list and revoke functions for the 03-23 management API.**

## Performance

- Duration: about 75 min
- Tasks: 2/2
- Files: 4

## Service API (`anvil_core::service::session`)

- `TOUCH_INTERVAL = 60 s` and `needs_touch(now, last_seen_at)`. `current()` writes `touch` only when `needs_touch` is true. `idle_expires_at = next_idle_expiry(now, expires_at)`.
- `is_active(&BrowserSession, now)`
- `SessionInfo { id, user_id, created_at, last_seen_at, auth_time, expires_at, idle_expires_at, acr, amr, ip, user_agent, current }`. It never carries the token hash.
- `check_settings_binding(tenant, &session, &SettingsBinding) -> Result<(), AccountError>`
  - `Failure(FlowExpired)` when the flow is missing or expired.
  - `Core(Forbidden)` for a wrong kind, cookie, CSRF token or owner.
- `list_for_user(tenant, user, current: Option<SessionId>) -> Vec<SessionInfo>`: active sessions only, newest first.
- `revoke_mine(tenant, user, id, ctx) -> Result<(), CoreError>`: NotFound unless the session is an active session of `user`. Uses `revoke_with_families`. Audits `session_revoked` with a User actor and target = session id.
- `revoke_others(tenant, user, current, ctx) -> u64`: `revoke_all_for_user(except current)`. Audits `sessions_revoked_all` with a User actor, target = user id and details `{sessions: n}`.
- Admin API for 03-23:
  - `admin_list_user(tenant, user) -> Vec<SessionInfo>`: NotFound for an unknown user.
  - `admin_list_tenant(tenant, PageRequest) -> Page<SessionInfo>`: follows the `admin_page` rules (0 means 50, otherwise clamped to 1..=200), in id order.
  - `admin_revoke(tenant, id, admin: &str, ctx)`: NotFound for an unknown or inactive session. Audits `session_revoked` with an Admin actor.
  - `admin_revoke_all(tenant, user, admin: &str, ctx) -> u64`: NotFound for an unknown user. Audits `sessions_revoked_all` with an Admin actor.
- Page message keys and texts (`message_text`): `sessions.revoked`, `sessions.revoked_others`, `sessions.not_found`.

## Web routes

| Method | Path | Behaviour |
| --- | --- | --- |
| GET | `/ui/account/sessions` | 303 to `/ui/login` without a session. Otherwise starts a settings flow (flow cookie) and renders the list. |
| POST | `/ui/account/sessions/{id}/revoke?flow=` | Another session: 200 with `sessions.revoked`. The current session: cookies cleared and 303 to `/ui/login`. Unknown or foreign session: 400 with `sessions.not_found`. |
| POST | `/ui/account/sessions/revoke-others?flow=` | 200 with `sessions.revoked_others` |

- A missing or wrong CSRF token, a missing flow, another user's flow, or a cross-site request returns the `csrf` page (403).
- An expired flow returns 400 with `account.flow_expired` and a fresh flow.

## Selectors for e2e (03-26)

- Table `#session-list` with a `<caption>`.
- Each row is `#session-{id}`. This browser's row has the `data-current` attribute and contains `#session-current-marker` ("(this device)").
- Cells `.anvil-session-device` (user agent, escaped, truncated to 80 characters ending in …, or "Unknown device") and `.anvil-session-ip`.
- Per-row form `#session-revoke-{id}`, button `#session-revoke-{id}-submit` with `aria-label="Sign out {device}[ (this device)]"`.
- `#sessions-revoke-others` / `#sessions-revoke-others-submit`. Only shown when other sessions exist.
- Messages `#account-messages [data-message-key]`. Navigation `#account-nav-sessions` has `aria-current="page"`.

## Task Commits

1. Task 1, service timeouts, throttling, list/revoke and admin functions: `25e2ad0`
2. Task 2, sessions page, template and integration tests: `e9c02aa`

## Verification

- `cargo test -p anvil-core`: 306 passed. This includes 9 session tests on in-memory fakes: throttle (30 s no write, 61 s one write), idle, absolute, revoked, list order and current marker, refusal of another user's session, revoke_others, admin revoke actor, and paging.
- `cargo test -p anvil-web --test sessions`: 13 passed on SQLite and 13 on Postgres. `--test authorize --test flow_login --test flow_login_factors` pass on SQLite, and `authorize` and `flow_login` also pass on Postgres.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -D warnings` is clean.
- All of these ran in an isolated worktree, because other plans' in-progress `admin/clients.rs` changes did not compile in the main tree at the time.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Settings-flow binding check for the sessions page lives in SessionService**
- **Issue:** `AccountService::open` is private, is not in this plan's files, and also requires a sign-in within the last 15 minutes. Signing out sessions should not need that.
- **Fix:** `SessionService::check_settings_binding` reuses the shared `check_binding` and `SettingsState`, and runs the same kind, binding and owner checks without the re-auth step. Flows are still created by `AccountService::start`.
- **Commit:** 25e2ad0

**2. [Rule 3 - Blocking] Core unit tests without an async runtime**
- **Issue:** anvil-core has no tokio dev-dependency, and `Cargo.toml` is not in this plan's files.
- **Fix:** The test module includes a small `block_on` built on `Waker::noop()`. This works because the fakes never wait.
- **Commit:** 25e2ad0

**3. Admin functions also tested over real backends**
- `admin_list_user` and `admin_revoke_all` check that the user exists through `UserRepo`. The in-memory fake does not implement `UserRepo`, so those two are covered in `tests/sessions.rs` on both backends instead of in the unit tests.

## Notes for later plans

- 03-23: map `SessionInfo` to the DTO. Pass the admin client id as `admin`. NotFound maps to 404.
- Small formatting helpers (`iso`, `human`) are duplicated from `ui/account_security.rs`, which was outside this plan's files. They could move to a shared account-UI helper later.
- `scripts/check-security-tests.sh` (QUAL-01 map) was not in this plan's files. Candidate pairs: session revoke refuses another user's session (`another_users_or_unknown_session_cannot_be_revoked`) and sessions CSRF (`posts_without_csrf_with_a_wrong_binding_or_cross_site_are_rejected`).

## Self-Check: PASSED
