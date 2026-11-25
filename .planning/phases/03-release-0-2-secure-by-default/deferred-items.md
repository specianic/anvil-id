# Phase 3 deferred items

Out-of-scope discoveries logged by executors (not fixed by the plan that found them).

## From 03-08

- At commit b0c9f1b (clean worktree, without any uncommitted 03-08 change) every anvil-web test
  that creates a user fails with 500 (registration, admin user create, login, token, userinfo,
  refresh, cookies, CSRF, CSP, enumeration, setup: 14 test binaries). With the 03-08 changes the
  failure set is identical. Coincides with the 0.2 schema migrations landing (03-05/03-06) while
  the matching repository code is still in progress; expected to clear when those plans finish.
- `crates/anvil-web/tests/ui_helpers/mod.rs` has its own router harness (`oneshot` without
  `TestApp::send`), so its requests carry no `ConnectInfo`. Once a UI route uses `ClientIp` or
  `AuditContext`, those tests get 500 unless that harness inserts a peer address too (as
  `support::TestApp::send` now does with `DEFAULT_PEER`). The plan that first adds `ClientIp` to a
  route exercised by ui_helpers should add it.

## From 03-11 (form_post)

- `themes/default/README.md` does not yet document the new `form_post.html` template contract
  (context `page`, `action`, `fields`; ids `form-post`, `form-post-continue`; script `form_post.js`).
  Not in 03-11's files_modified; pick up with the theme docs.
- The form_post page's CSP `form-action` allows only the redirect URI's origin (as planned). Chromium
  applies `form-action` to redirects that follow the POST, so an RP callback that immediately redirects
  to a *different* origin would be blocked. Same-origin callback redirects are unaffected. Revisit if
  the 03-28 Form Post conformance run or RP reports show problems.

## From 03-13 (rate limiting on by default)

The route-class rate-limit layer now runs on every request, so two pre-existing test harness gaps
fail 9 anvil-web tests. Both fixes are in files outside 03-13's files_modified:

- `tests/ui_helpers/mod.rs` `OwnApp::send` inserts no `ConnectInfo`. The rate-limit layer resolves
  the client IP for every classified request and answers the generic 500 of `MissingPeerAddress`
  when the peer is missing (it never invents an address). Failing: `security_csp`
  (`every_ui_page_has_the_strict_headers_and_no_external_references`), `security_enumeration`
  (both tests), `security_setup` (5 of 7: `fresh_install_has_no_users_and_no_default_credentials`,
  `concurrent_submissions_complete_setup_exactly_once`,
  `valid_token_shows_the_form_invalid_token_is_403_without_a_form`, `expired_token_is_refused`,
  `setup_creates_the_admin_and_a_working_management_client_once`). Fix: in `OwnApp::send`, insert
  `ConnectInfo(support::DEFAULT_PEER)` unless one is set (same as `support::TestApp::send`).
- `tests/flow_recovery.rs` `recovery_resets_the_password_revokes_sessions_and_is_single_use` makes
  6 auth-class POSTs (registration, login, recovery, reset, login with the old password, login with
  the new one) from one peer with no clock movement. The 6th exceeds the default auth burst of 5 and
  gets 429 (as SEC-05 requires). Fix: `app.clock().advance(Duration::from_secs(60))` before the
  final logins, or send them with `send_from` from another peer.

## From 03-12

- `password_changed` notice cannot move into the recovery transaction (`RecoveryNotice`) while
  its template contract requires `email` (03-15 `check::variables`, default templates, render
  test): the address is only known after the token is consumed. Decide: mail worker supplies
  `email` from the recipient, or drop `email` from the password_changed contract; then switch
  FlowService `CompleteRecovery` to `complete_recovery(.., Some(&notice))`.
- 03-14's `tests/account_security.rs` asserts an empty audit log after signing in; sign-in now
  records `user_registered`/`login_succeeded` (03-12), so those assertions must filter to the
  account actions.
