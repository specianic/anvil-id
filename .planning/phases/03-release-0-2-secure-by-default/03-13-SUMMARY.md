---
phase: 03-release-0-2-secure-by-default
plan: 13
subsystem: web
tags: [rate-limit, 429, retry-after, brute-force, captcha, turnstile, hcaptcha, csp]
requires:
  - phase: 03-07
    provides: anvil_cache::limiter (RateLimiter, InProcessLimiter, LimiterConfig, RouteClass, LimitKey, Decision)
  - phase: 03-08
    provides: ClientIp extractor, AppConfig.trusted_proxies, harness send_from
  - phase: 03-02
    provides: CaptchaSettings / CAPTCHA_SECRET_PURPOSE, AuditAction::RateLimitLockout, AuditService
provides:
  - AppConfig.rate_limits (LimiterConfig::default, on) and AppState::limiter()
  - anvil_web::layers::ratelimit (classify, Surface, too_many_requests, layer, guard_attempt, record_attempt, attempt_keys, identifier_hash)
  - per-client token limit at /token (claimed client_id)
  - anvil_web::adapters::captcha (CaptchaVerifier, CaptchaEndpoints, CaptchaError, open_secret, response_field, captcha_csp/CaptchaCsp)
  - themes/default/templates/captcha.html widget partial
affects: [03-20, 03-24, 03-27]
tech-stack:
  added: []
  patterns:
    - "One 429 builder (too_many_requests) chooses the shape per surface: protocol, admin, browser"
    - "Rate-limit layer sits inside the tenant-routed service, so classification uses tenant-relative paths"
    - "Outbound verification client: endpoint as constructor argument, https-or-loopback check, no redirects, timeout, body cap"
key-files:
  created:
    - crates/anvil-web/src/layers/ratelimit.rs
    - crates/anvil-web/src/adapters/captcha.rs
    - themes/default/templates/captcha.html
    - crates/anvil-web/tests/security_ratelimit.rs
    - crates/anvil-web/tests/captcha.rs
  modified:
    - crates/anvil-web/src/config.rs
    - crates/anvil-web/src/state.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/src/layers/mod.rs
    - crates/anvil-web/src/protocol/token.rs
    - crates/anvil-web/src/adapters/mod.rs
key-decisions:
  - "03-13: classify returns Option<RouteClass>; None = never limited (/health/*, /healthz, /assets/*)"
  - "03-13: a classified request without ConnectInfo gets the generic MissingPeerAddress 500; the layer never invents an address or waves the request through"
  - "03-13: 429 bodies: protocol {\"error\":\"invalid_request\",\"error_description\":\"too many requests\"} + no-store/no-cache; admin problem JSON type urn:anvilid:problem:too_many_requests; browser error page key too_many_requests with a detail sentence; Retry-After is whole seconds rounded up (min 1)"
  - "03-13: per-client token limit keys on the claimed client_id (Basic user name, else client_id parameter), skipped for ids over 256 chars and for private_key_jwt without client_id; bounded by the per-IP check that runs first"
  - "03-13: record_attempt takes tenant and RequestContext (needed for the audit event) and audits rate_limit_lockout only on the unlocked to locked transition, with key kind and locked_seconds, never the identifier"
  - "03-13: CaptchaVerifier is a standalone adapter (not in AppState); 03-20 builds it with CaptchaVerifier::with_defaults() or wires it into state"
requirements-completed: []
metrics:
  duration: 50min
  completed: 2026-11-25
  tasks: 2
  files: 11
---

# Phase 3 Plan 13: Limiter wiring and CAPTCHA Summary

**Rate limiting is now on by default. One layer keys every classified request by trusted-proxy client IP and answers 429 with Retry-After in the right shape for each surface. /token also has a per-client limit. UI handlers get a two-function brute-force API. Turnstile/hCaptcha verification runs server-side and fails closed, and the widget partial sends a per-page CSP.**

## Route classification (`layers::ratelimit::classify`, tenant-relative path)

| Request | Class |
| ------- | ----- |
| `/health/*`, `/healthz`, `/assets/*` (any method) | never limited (`None`) |
| `/token`, `/introspect`, `/revoke` and below (any method) | `Token` (per IP 50/s burst 50) |
| `/api/admin` and below (any method) | `Admin` (20/s burst 20) |
| `POST` to `/ui/login`, `/ui/registration`, `/ui/recovery`, `/setup` and below (e.g. `/ui/login/mfa`, `/ui/recovery/reset`) | `Auth` (10/min burst 5) |
| everything else, including `GET` of those pages | `Default` (50/s burst 50) |

Prefixes match on whole segments, so `/ui/loginx` and `/tokens` are `Default`. The layer runs after `tenant::resolve`, so `/t/acme/ui/login` is classified as `/ui/login`. When `rate_limits.enabled = false` the layer does nothing at all.

## 429 shapes (`too_many_requests`, the only 429 builder)

Every 429 carries `Retry-After` (whole seconds, rounded up, at least 1) and `Cache-Control: no-store`. The surface comes from the path (`Surface::of`):

| Surface | Paths | Body |
| ------- | ----- | ---- |
| Protocol | `/token`, `/introspect`, `/revoke`, `/userinfo`, `/jwks`, `/.well-known/*` | `{"error":"invalid_request","error_description":"too many requests"}` plus `Pragma: no-cache`. OAuth has no rate-limit error code, so `invalid_request` is the documented choice. |
| Admin | `/api/*` | `application/problem+json`: `type urn:anvilid:problem:too_many_requests`, `title "Too Many Requests"`, `status 429`, `detail "too many requests"`, `errors []` |
| Browser | everything else | themed `error.html`, `error_key = too_many_requests`, detail "Too many requests. Please wait a moment and try again." |

## Per-client token limit

`protocol/token.rs` parses the request and then calls `check(Token, Client{tenant, claimed client_id})` before `TokenService` runs. The claimed id is the HTTP Basic user name (via core `parse_basic`), or else the `client_id` parameter. Ids longer than 256 characters, and `private_key_jwt` requests with no `client_id`, get only the per-IP limit. The trade-off is documented in code: a caller can spend another client's per-client quota by naming it. That spending is still capped by the caller's own per-IP token limit, and keying on the authenticated client would let unauthenticated floods reach client authentication.

## Brute-force helper API (for 03-20)

```rust
pub fn attempt_keys(tenant: TenantId, identifier: &str, ip: IpAddr) -> (LimitKey /*strict*/, LimitKey /*loose*/);
pub fn identifier_hash(identifier: &str) -> [u8; 32]; // SHA-256 of trim+lowercase
pub async fn guard_attempt(state: &AppState, strict: &LimitKey, loose: &LimitKey, captcha_available: bool) -> Decision;
pub async fn record_attempt(state: &AppState, tenant: TenantId, ctx: &RequestContext, keys: &[LimitKey], success: bool);
pub fn too_many_requests(state: &AppState, tenant: Option<&ResolvedTenant>, surface: Surface, retry_after: Duration) -> Response;
```

On success, `record_attempt` forgets every key. On failure, it counts each key. When a key goes from unlocked to locked, it appends one `rate_limit_lockout` audit event (actor `system`, outcome `failure`, `details.reason` = key kind such as `identifier_ip`, `details.locked_seconds`, no target, never the identifier). If the audit append fails, the error is logged and the request carries on.

## CAPTCHA

- `CaptchaVerifier::new(CaptchaEndpoints, timeout)` / `with_defaults()`. The defaults are `https://challenges.cloudflare.com/turnstile/v0/siteverify` and `https://api.hcaptcha.com/siteverify`, with a 5 s timeout (request and connect).
- Endpoint guard: an endpoint must be https, or http to a loopback host only (that is how the wiremock tests reach it). Redirects are never followed and the response body is capped at 16 KiB. Request data cannot choose the destination.
- `verify(&CaptchaSettings, &SecretString, token, Option<IpAddr>)` sends a form-encoded POST with `secret`, `response` and `remoteip`. Only `success: true` returns Ok. An empty or whitespace token returns `MissingToken` without any network call. HTTP errors, timeouts, malformed or oversized JSON, and redirects all return `Unavailable`. `success:false` returns `Rejected`.
- `open_secret(kek, tenant, settings)` decodes `secret_sealed` from base64url and opens it with `CAPTCHA_SECRET_PURPOSE` and the tenant id bytes as AAD. `response_field(provider)` gives the form field name: `cf-turnstile-response` or `h-captcha-response`.
- `captcha.html` uses `captcha.provider` and `captcha.site_key`. It renders `div.cf-turnstile` or `div.h-captcha#captcha-widget[data-sitekey]`, the provider's script tag, and a `<noscript>` explanation (`#captcha-noscript`). With no `captcha` value it renders nothing.

### CSP origins (`captcha_csp(provider)`, only for pages that render the widget)

| Provider | script-src | frame-src | connect-src | style-src |
| -------- | ---------- | --------- | ----------- | --------- |
| Turnstile | `https://challenges.cloudflare.com` | same | same | none extra |
| hCaptcha | `https://hcaptcha.com https://*.hcaptcha.com` | same | same | same |

`CaptchaCsp::header_value()` returns the full policy: `default-src 'none'`, `'self'` added to script/style/connect, the provider origins, and `frame-ancestors 'none'; base-uri 'none'`. The handler sets it on the response, and the security-headers layer keeps any CSP a handler already set. All other pages keep the strict default `CSP`.

**Operator notes:** Turning CAPTCHA on loads a third-party script for that tenant, which is the operator's choice and gives up "no external assets" for that tenant. Interactive challenges conflict with WCAG 3.3.8 (accessible authentication), so we recommend Turnstile in managed/non-interactive mode.

## Task Commits

1. **Task 1: Limiter in AppState, route-class layer, per-client token check** - `34cc019` (feat), `0ae2774` (clippy style fix in the test)
2. **Task 2: CAPTCHA verifier, widget partial, CSP relaxation** - `a98a529` (feat)

Each task's tests and implementation went into one commit, not separate RED/GREEN commits. The tests were written against the plan's listed behaviours and run before committing.

## Verification

- `cargo test -p anvil-web --test security_ratelimit`: 13 passed on SQLite, and 13 passed on Postgres (`ANVILID_TEST_DB=postgres`).
- `cargo test -p anvil-web --test captcha`: 12 passed. `cargo test -p anvil-web --lib`: 84 passed (this includes `layers::ratelimit` and `adapters::captcha`).
- `cargo test -p anvil-web --test token --test security_client_auth`: pass.
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean.
- Because parallel plans had uncommitted, non-compiling changes in the main tree (anvil-core flow/session, anvil-web account_security), these checks ran in the worktree `target/wt-03-13` at HEAD plus the 03-13 files. The worktree has since been removed.

## Deviations from Plan

### Design clarifications (within scope)

**1. `classify` returns `Option<RouteClass>`.** The plan's signature returns `RouteClass`, but exempt paths (health, assets) need a "never limited" value, so the return is `None` for those.

**2. `record_attempt` signature.** It also takes `tenant: TenantId` and `ctx: &RequestContext`. The plan requires a `rate_limit_lockout` audit event with the RequestContext, and an IP key carries no tenant. `guard_attempt` takes its keys by reference.

**3. Error page key.** `error.html` has no sentence for `too_many_requests`. The page shows the generic sentence, the detail line "Too many requests. Please wait a moment and try again." and "Error 429". Adding a dedicated sentence to the theme contract is left to the theme owner, because `error.html` is not in this plan's files.

**4. No `CoreError` variant for 429.** anvil-core is outside this plan's files, so the 429 bodies are built in `too_many_requests`. It is the single 429 builder and mirrors the `oauth_json` and `problem_json` shapes.

**5. CAPTCHA request body.** The body is built with `url::form_urlencoded`, not `RequestBuilder::form`. reqwest 0.13's `form` is behind a feature that the workspace does not enable.

## Deferred Issues (in files outside files_modified; see deferred-items.md)

9 anvil-web tests now fail, and all 9 come from harness gaps exposed by limiting on every request:
- `tests/ui_helpers/mod.rs` `OwnApp::send` sets no `ConnectInfo`, so the layer answers 500. Failing tests: `security_csp` (1), `security_enumeration` (2) and `security_setup` (5 of 7). Fix: insert `ConnectInfo(support::DEFAULT_PEER)` in `OwnApp::send`.
- `tests/flow_recovery.rs` `recovery_resets_the_password_revokes_sessions_and_is_single_use` makes a 6th auth POST from one peer and correctly gets 429. Fix: advance the test clock 60 s before the final logins, or use a different peer.

## Self-Check: PASSED
