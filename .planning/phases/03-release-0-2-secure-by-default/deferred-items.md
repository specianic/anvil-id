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
