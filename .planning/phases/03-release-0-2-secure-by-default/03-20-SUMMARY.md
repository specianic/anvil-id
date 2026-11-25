---
phase: 03-release-0-2-secure-by-default
plan: 20
subsystem: auth
tags: [login, passkeys, webauthn, totp, recovery-codes, mfa, brute-force, captcha, rate-limit, ui]
requires:
  - phase: 03-04
    provides: accessible template conventions, snapshot procedure
  - phase: 03-09
    provides: webauthn.js DOM contract, WebauthnPasskeys, relying_party
  - phase: 03-12
    provides: FlowService passkey_options / submit with SubmitResult { outcome, attempt }
  - phase: 03-13
    provides: guard_attempt / record_attempt / attempt_keys, CaptchaVerifier, captcha.html, captcha_csp
  - phase: 03-14
    provides: ACCOUNT_CSP (script/connect 'self'), recovery-code helpers
provides:
  - "Login page passkey button (usernameless, webauthn.js) with POST /ui/login/passkey/options and POST /ui/login/passkey"
  - "second_factor.html and POST /ui/login/second-factor (TOTP or recovery code), GET redirects to /ui/login"
  - "Brute-force wiring: password (identifier+IP, identifier), passkey (IP), second factor (user) through the one limiter"
  - "CAPTCHA escalation verified server-side before the password; AppConfig.captcha_endpoints (injectable)"
affects: [03-23, 03-26, 03-27]
tech-stack:
  added: []
  patterns:
    - "Pages answered before the flow runs (lock, CAPTCHA) rebuild the identify form from engine::FlowState::initial + bind_form, so known and unknown identifiers get the same bytes"
    - "KEK-sealed factor token (purpose anvilid/second-factor-user/v1, AAD tenant||flow) names the per-user limiter key without handlers reading flow state"
key-files:
  created:
    - themes/default/templates/second_factor.html
    - crates/anvil-web/tests/flow_mfa.rs
    - crates/anvil-web/tests/flow_passkey.rs
    - crates/anvil-web/tests/security_bruteforce.rs
  modified:
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/src/ui/mfa.rs
    - themes/default/templates/login.html
    - crates/anvil-web/tests/snapshots/render__login.snap
    - crates/anvil-web/src/config.rs
    - crates/anvil-web/src/adapters/captcha.rs
    - crates/anvil-web/tests/security_csp.rs
key-decisions:
  - "03-20: The second-factor page is rendered directly as the answer to the password POST (200), not via a 303 to GET /ui/login/second-factor: the flow stores only the CSRF token hash, so a GET cannot render a usable form without a core change (flow.rs belongs to 03-30). GET /ui/login/second-factor redirects to /ui/login"
  - "03-20: Per-user second-factor throttling needs the user before the code is checked; handlers cannot read flow state, so the password step adds a KEK-sealed factor_token (user id, AAD tenant id || flow id). It only names the limiter key; the flow service still decides from the flow state. Missing/tampered token restarts the sign-in (400, flow.expired)"
  - "03-20: /ui/login POST now maps only email+password; a code posted there is flow.invalid_input (no throttle bypass)"
  - "03-20: A lock answers 429 + Retry-After + Cache-Control no-store with the form and an in-page message login.too_many_attempts ('Too many attempts. Try again in N second(s).'). The failure that causes the lock already answers 429. The second-factor pre-check lock uses the generic too_many_requests error page (its form cannot be rebuilt without flow state)"
  - "03-20: Passkey failures are keyed by client IP (LimitKey::Ip) for both guard tiers; an assertion posted without a challenge is not an attempt (core renders it without verification), so throttling applies to verified assertions"
  - "03-20: CAPTCHA: a submitted response that fails (rejected, unavailable, config error) is audited captcha_failed; a missing response is not. Messages login.captcha_required / login.captcha_failed. The page with the widget sends captcha_csp(provider); other login pages send LOGIN_CSP (= ACCOUNT_CSP)"
  - "03-20: CaptchaVerifier is built per verification from AppConfig.captcha_endpoints (only when a CAPTCHA response must be checked)"
requirements-completed: []
metrics:
  duration: 95min
  completed: 2026-11-25
  tasks: 2
  files: 11
---

# Phase 3 Plan 20: Login pages (passkey, second factor, brute force, CAPTCHA) Summary

**The sign-in page now offers a usernameless "Sign in with a passkey" button (webauthn.js, hidden without JavaScript) next to the unchanged password form, users with an authenticator app get a second-factor page (TOTP or recovery code) before any session exists, and every password, passkey and second-factor attempt goes through the single limiter: progressive per-(identifier, IP) locks with 429/Retry-After and "try again in N seconds", enumeration-safe answers, reset on success, per-user second-factor locks, and a server-side CAPTCHA check before the password when the identifier tier trips on a tenant with CAPTCHA configured.**

## Routes

| Method | Path | Notes |
|---|---|---|
| GET | `/ui/login[?request=]` | password form, passkey form (when the issuer can be a WebAuthn RP), `LOGIN_CSP` |
| POST | `/ui/login?flow=` | email + password, behind the brute-force gate |
| POST | `/ui/login/passkey/options?flow=` | JSON options (no allowCredentials), `csrf_token` field; errors JSON `{"error": "csrf"|"login.passkey_failed"|...}`; `no-store` |
| POST | `/ui/login/passkey?flow=` | `response` (assertion JSON); failures: login form with `login.passkey_failed` (400) |
| POST | `/ui/login/second-factor?flow=` | `code` or `recovery_code`, plus `factor_token` and `csrf_token` |
| GET | `/ui/login/second-factor` | 303 to `/ui/login` |

Order of a password POST: binding fields present → `guard_attempt(strict, loose, tenant has CAPTCHA)` → Deny: 429 page; RequireCaptcha: verify the widget response (fail closed) or re-render with the widget (400) → `FlowService::submit` → `record_attempt` (failure counts, success forgets) → if now locked: 429 page; if now RequireCaptcha: the failure page already shows the widget.

## Selectors (for e2e, 03-26)

- Login page: password form `#login` (`#identifier`, `#password`, `#login-submit`) unchanged and first; passkey form `#login-passkey` (`data-webauthn="authenticate"`, `data-options-url`), button `#login-passkey-submit` (`hidden` until webauthn.js reveals it), status `#login-passkey-status` (aria-live); script `/assets/webauthn.js` (or `/t/{slug}/assets/webauthn.js`).
- CAPTCHA (only when required): `#captcha-widget` inside `#login`, `#captcha-noscript`; messages `login.captcha_required`, `login.captcha_failed`.
- Lock: message key `login.too_many_attempts` in `#login-msg-1` / `#second-factor-msg-1`, header `Retry-After`.
- Second-factor page: form `#second-factor`, hidden `#factor_token`, `#code` (`inputmode="numeric"`, `autocomplete="one-time-code"`, hint `#code-hint`), disclosure `#recovery-code-toggle` (`<details>`) with `#recovery_code` (hint `#recovery-code-hint`), button `#second-factor-submit`, link `#link-login` ("Start over"); error `login.second_factor_invalid`.

## Task Commits

1. **Task 1: Passkey button and second-factor pages** (with the brute-force/CAPTCHA wiring in the same handlers): `f1ef6bb`
2. **Task 2: Brute-force protection and CAPTCHA escalation tests**: `1c103fa`

The limiter integration lives in the same handler functions as the Task 1 routes (login.rs, mfa.rs), and partial staging is not available, so the implementation of both tasks is in `f1ef6bb`; `1c103fa` adds the AUTH-09 HTTP tests. Tests and implementation were written together (no separate RED commits).

## Verification

- `cargo test -p anvil-web` (SQLite): all binaries pass, including the new `flow_mfa` (7), `flow_passkey` (4), `security_bruteforce` (8) and the `ui::mfa` unit test; existing `flow_login`, `render`, `security_csp`, `security_csrf`, `security_ratelimit`, `security_enumeration`, `flow_login_factors`, `account_security` unchanged and green.
- `ANVILID_TEST_DB=postgres cargo test -p anvil-web --test security_bruteforce --test flow_mfa --test flow_passkey --test flow_login --test security_csp`: all pass.
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
- The main tree did not build (03-21 in progress), so verification ran in the worktree `target/wt-03-20` (HEAD 540bc4d + this plan's files, private CARGO_TARGET_DIR); both removed afterwards.
- The axe/Playwright specs are not part of this plan (03-26); templates follow the 03-04 conventions (one h1, labelled inputs, error messages `role="alert"` linked via `aria-describedby`, `aria-invalid`, no-JS disclosure for the recovery code).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `CaptchaVerifier::verify` future was not `Send`** (`adapters/captcha.rs`, 03-13)
- **Found during:** Task 1 (the login handler would not compile as an axum handler)
- **Issue:** `url::form_urlencoded::Serializer` was held across the request `.await`.
- **Fix:** the body is finished in a block before the request is sent. No behaviour change; `tests/captcha.rs` still passes.
- **Commit:** f1ef6bb

**2. [Rule 3 - Blocking] `AppConfig.captcha_endpoints`** (`config.rs`)
- **Issue:** the plan requires siteverify mocked "through the injectable endpoint", but nothing in AppConfig/AppState carried the endpoints.
- **Fix:** `pub captcha_endpoints: CaptchaEndpoints` (default: the providers' public endpoints) on AppConfig.
- **Commit:** f1ef6bb

**3. [Rule 3 - Blocking] `security_csp.rs` forbade any `<script`**
- **Issue:** the plan requires `<script src="/assets/webauthn.js" defer>` on the login page.
- **Fix:** the test now allows only `<script src="/…/assets/…" defer></script>` (same-origin file, no inline code); CSP checks unchanged.
- **Commit:** f1ef6bb

**4. [Design] Second-factor page rendered directly, not via 303** (see key decisions): a GET cannot show the flow's CSRF token (only its hash is stored). Tests assert "correct password → second-factor page, no session cookie".

**5. [Rule 2 - Security] Factor token for the per-user limiter key** (see key decisions), and the `/ui/login` POST no longer maps `code`/`recovery_code` (would have bypassed the second-factor throttle). Tests: `a_second_factor_post_without_a_valid_binding_token_restarts_the_sign_in`, `a_code_posted_to_the_password_route_is_not_a_second_factor`, unit test `factor_token_round_trips_only_for_its_tenant_and_flow`.

**6. [Test design] Counting hasher replaced by a timing-free counter:** TestApp does not expose its hasher; the CAPTCHA test proves the password is never verified by posting a wrong password without/with a rejected CAPTCHA and asserting the `login_failed` audit count is unchanged (and that the right password without a CAPTCHA does not sign in).

**7. [Test design]** The tests raise the per-IP auth route-class quota (`rate_limits.auth`) so it does not mask the brute-force limits; brute-force limits stay at their defaults except `loose_threshold_per_hour` (5 or 1) in the identifier-tier tests.

## Not done / follow-ups (files outside this plan; recorded in deferred-items.md)

- `anvil.css`: no rules for `.anvil-qr` (QR scales to full width; constrain it), `.anvil-table`, `.anvil-recovery-codes`, `.anvil-secret` (from 03-14), nor the new `.anvil-passkey`, `.anvil-secondary`, `.anvil-disclosure`, `.anvil-captcha`.
- `error.html`: no sentence for `too_many_requests` (from 03-13).
- `themes/default/README.md`: ground rule "No `<script>`" is outdated; add `second_factor.html`, the login extras and the new selectors to the contract.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/ui/login.rs, crates/anvil-web/src/ui/mfa.rs, themes/default/templates/login.html, themes/default/templates/second_factor.html, crates/anvil-web/tests/flow_mfa.rs, crates/anvil-web/tests/flow_passkey.rs, crates/anvil-web/tests/security_bruteforce.rs
- FOUND: f1ef6bb, 1c103fa
