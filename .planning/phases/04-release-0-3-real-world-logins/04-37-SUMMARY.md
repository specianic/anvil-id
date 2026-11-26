---
phase: 04-release-0-3-real-world-logins
plan: 37
subsystem: auth
tags: [upstream, require-verified-email, binding-cookie, account-linking, userinfo, cookies, docs, auth-07, auth-11, auth-13, oidc-12, auth-06]

requires:
  - phase: 04-34
    provides: "create_user_with_link(.., token, email) storing the verification token + email atomically"
  - phase: 04-35
    provides: "independent email_otp / magic_link (doc facts); service/flow.rs as changed there"
  - phase: 04-36
    provides: "AppState::wake_logout_worker (documented here)"
provides:
  - "UpstreamService::callback -> CallbackResult { outcome, binding_proved }"
  - "Upstream JIT accounts with an unverified email get a verification email in the same transaction; require_verified_email refuses upstream sign-in to unverified accounts (reason email_not_verified)"
  - "FlowService::restart_login_with_message (pub(crate)); self_service_email is pub(crate)"
  - "Account-page linking answers 303 to /ui/account/linked (upstream-linked catalog key removed)"
  - "Generic OIDC UserInfo fallback when the ID token has no email (sub must match)"
  - "Tenant cookie suffix = first 16 hex of SHA-256(tenant UUID bytes)"
  - "Docs: ARCHITECTURE, UPGRADING and theme README describe the closed gaps and the Phase 5 limitations"
affects: [04-32, 04-33, 04-gate]

tech-stack:
  added: []
  patterns:
    - "The binding cookie is cleared only by a callback that proved the binding (state + cookie matched)"
    - "Upstream sign-in applies require_verified_email at the same point for every Login decision (SignIn, AutoLink, JitCreate)"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/service/upstream.rs
    - crates/anvil-core/src/service/flow.rs
    - crates/anvil-web/src/ui/upstream.rs
    - crates/anvil-web/src/cookies.rs
    - crates/anvil-web/tests/security_linking.rs
    - crates/anvil-web/tests/upstream_login.rs
    - crates/anvil-web/tests/account_linked.rs
    - themes/default/locales/en/upstream.ftl
    - themes/default/locales/de/upstream.ftl
    - tests/e2e/specs/linking.spec.ts
    - tests/e2e/specs/nojs-linking.spec.ts
    - docs/ARCHITECTURE.md
    - docs/UPGRADING.md
    - themes/default/README.md

key-decisions:
  - "Cookie rename: no transition read of the old names. After the upgrade everyone signs in again (documented in UPGRADING). Reading old names would have touched every cookie lookup for a one-off benefit"
  - "Cookie suffix: first 16 hex chars (64 bits) of SHA-256 over the tenant UUID's 16 bytes, pinned in a unit test"
  - "UserInfo fallback applies to generic OIDC only. Without fetch_userinfo it takes only email + email_verified (the ID token's email_verified is dropped so the pair comes from one source). A failed fallback call is not fatal, so existing links still sign in. A sub mismatch always rejects (userinfo_subject)"
  - "A just-created unverified upstream account shows registration.check_email (info) on a fresh sign-in form; an existing unverified account shows login.email_not_verified (error, 400)"
  - "upstream-linked catalog entry removed from en and de (nothing else used it)"
  - "StartResult::Done pages never clear the binding cookie (nothing was proved)"

requirements-completed: [AUTH-07, AUTH-11, AUTH-13, OIDC-12, AUTH-06]

duration: ~45min
completed: 2026-11-26
---

# Phase 4 Plan 37: Upstream gap closure and 0.3 docs pass Summary

**Upstream sign-up no longer gets around `require_verified_email`. A forged callback can no longer clear the binding cookie, so it cannot cancel a pending sign-in. Connect on the account page returns to `/ui/account/linked`. Generic OIDC reads `email` from UserInfo when the ID token has none. Tenant cookie names come from the whole tenant id. The 0.3 docs no longer carry the closed "open items".**

Note: no requirement checkbox was ticked (wave rule). `requirements-completed` records scope only.

## Performance

- **Duration:** ~45 min
- **Tasks:** 3 (Task 1, Task 2, plus the extra deferred-items task)
- **Files modified:** 14

## Task Commits

1. **Task 1: verified email for upstream accounts, binding-cookie rule, link redirect.** Includes the UserInfo fallback, which lives in the same files: `9d6a7a9`
2. **Extra task: tenant cookie names from the whole id:** `e041004`
3. **Task 2: docs for the closed gaps:** `45d73d2`

## Behaviour

- **JIT verification:** `JitCreate` with `email_verified = false` builds the verification token + sealed email with `self_service_email` and passes them to `create_user_with_link` (one transaction). This happens whatever `require_verified_email` says, as in local registration.
- **require_verified_email:** after the Login decision (SignIn, AutoLink, JitCreate) and before `upstream_primary`, an unverified user gets the following: `upstream_login_failed` is audited with reason `email_not_verified` and connection details, and the login restarts as `UpstreamOutcome::Continue` (fresh flow, no session). The form shows `registration.check_email` for a just-created account and `login.email_not_verified` otherwise. The Link purpose is not affected. Other ways in were already gated (password and passkey check `require_verified_email`; email code needs a verified address).
- **Binding cookie:** `callback` returns `CallbackResult { outcome, binding_proved }`. `binding_proved` is set right after `check_callback` passes. `outcome_page(.., clear_binding)` adds `clear_upstream_binding` only then. The start's `Done` pages pass `false`, and `form_post` still never touches the cookie.
- **Link redirect:** `UpstreamOutcome::Linked` answers `303` with `Location: {issuer}/ui/account/linked` (`ui_locales` carried) and `Cache-Control: no-store`.
- **UserInfo fallback:** this applies to a generic OIDC connection that has a `userinfo_endpoint` and whose ID token has no `email`. UserInfo is called through the `UpstreamClient` port, which is the guarded outbound client. Its `sub` must equal the ID token's, otherwise the sign-in fails with `userinfo_subject`.
- **Cookie names:** `{prefix}anvil_{session|flow|upstream}_{hex16(sha256(uuid bytes))}`. Example: tenant `0192f0c4-7a1b-7c3d-8e9f-0123456789ab` gives suffix `18f890a451dcc086`.

## Tests (for 04-32's security map)

`security_linking.rs` (negative):
- Binding-cookie rule:
  - `forged_callback_does_not_cancel_pending_sign_in`. The forged callbacks are a garbage state, an unknown flow, a tampered random part, another started flow's state, the right state without the binding cookie, and the right state with another cookie. Each answers 400 without `Max-Age=0` for the binding cookie, the jar keeps it, and no code is exchanged. The genuine callback then signs in and clears the cookie.
  - `matching_callback_clears_the_binding_cookie_even_when_it_fails_later` (provider_error with the right state + cookie).
- Unverified upstream accounts:
  - `untrusted_jit_account_must_verify_before_sign_in`. The user and link are created, exactly one verification email is sent, there is no session or session cookie, the page shows `registration.check_email`, and the audit has `user_registered` plus `email_not_verified`. A second attempt gets `login.email_not_verified` and no new email. After the verification link, the sign-in works.
  - `linked_unverified_account_is_refused_under_require_verified_email`.
- UserInfo: `userinfo_fallback_rejects_another_subject`.

`upstream_login.rs` (positive):
- `trusted_verified_jit_signs_in_at_once` (require on, no email)
- `untrusted_jit_without_requirement_signs_in_and_gets_verification_email`
- `email_only_in_userinfo_is_used_when_the_id_token_has_none` (names stay the ID token's; UserInfo is not called when the ID token has an email)
- `account_page_link_connects_the_signed_in_user` (303 to `/ui/account/linked`; the page lists `linked-{id}`)

`cookies.rs` unit: `tenants_created_in_the_same_millisecond_get_distinct_cookie_names`, plus pinned names in the existing tests.

JIT conflict (email taken concurrently): no web-level test, because the race cannot be produced through HTTP. Atomicity rests on 04-34's storage contract tests `create_user_with_link_is_atomic` and `create_user_with_link_stores_verification_atomically`.

## Verification

- `cargo test -p anvil-web --test security_linking --test upstream_login` (SQLite): 21 + 15 passed.
- `cargo test -p anvil-web --test account_linked --test upstream_google --test upstream_microsoft --test upstream_apple --test upstream_github --test upstream_oauth2 --test flow_registration --test i18n_catalogs --test i18n --test security_cookies --test security_csrf --test sessions --test upstream_buttons --test render`: all green.
- `cargo test -p anvil-web --lib cookies`: 5 passed. `cargo test -p anvil-core --lib service::upstream`: 3 passed.
- `cargo clippy -p anvil-core -p anvil-web --all-targets -- -D warnings`: clean.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- **Local e2e without Docker** (debug anvilid copied to a scratch dir, fresh data dir, run.sh flags, no SMTP): `social`, `linking` and `nojs-linking` passed 7/7. The social spec's generic OIDC test was also run once with `fetch_userinfo: false` (temporary local edit, reverted): it passed, so the UserInfo fallback works against AnvilID as a real upstream. Scratch dir deleted.
- `scripts/check-security-tests.sh`: OK. The Task 2 doc greps pass.

**Not run here (left for CI):** `ANVILID_TEST_DB=postgres` for `security_linking` and `upstream_login` (no Docker); the release-build e2e and the full e2e suite.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extra files**
- `crates/anvil-web/tests/account_linked.rs`: two tests asserted the old 200 page after Connect and now expect the 303.
- `themes/default/locales/{en,de}/upstream.ftl`: the unused `upstream-linked` entry was removed. The plan allowed this.
- `crates/anvil-web/src/cookies.rs`: the extra cookie-name task.

**2. [Scope] Extra task from deferred-items.md (added by the orchestrator)**
- The UserInfo email fallback and the tenant cookie-name collision. Both are done, tested and documented (ARCHITECTURE §9.2 and §11 cookies row; UPGRADING behaviour changes).

**3. [Scope] No core unit test for the verified-email gate**
- The gate sits inside the async service, between storage calls. It is covered end to end by the web tests above.

## Self-Check: PASSED
