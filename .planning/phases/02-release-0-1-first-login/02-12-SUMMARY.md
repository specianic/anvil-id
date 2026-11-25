---
phase: 02-release-0-1-first-login
plan: 12
subsystem: web-shell
tags: [axum, tenant-resolution, csp, csrf, fetch-metadata, cookies, minijinja, argon2, hibp, test-harness]
requires:
  - phase: 02-01
    provides: anvil-jose (Kek, generate_rs256, encoding helpers), Phase 2 dependencies
  - phase: 02-02
    provides: domain model, ports, CoreError mapping, FormDescription
  - phase: 02-03
    provides: default theme templates and selector contract
provides:
  - "anvil_web::app(AppConfig, AppDeps) -> Router: the tenant layer runs before routing; protocol/ui/admin plug in via routes()"
  - "AppState accessors: storage/clock/hasher/breach/kek (+ *_arc), config, renderer, cookies"
  - "ResolvedTenant extractor (FromRequestParts + OptionalFromRequestParts), base_path(), ui_url()"
  - "errors.rs: oauth_json, problem_json, error_page, core_error_page (the only CoreError -> HTTP mapping)"
  - "Renderer + PageContext/PageLinks + page_context()"
  - "CookiePolicy (session/flow cookies, __Host- in prod, tenant short id in the name)"
  - "layers: security headers (strict CSP, HSTS on https), fetch_metadata_layer() (ui only), public_cors()"
  - "adapters: Argon2Pool (PasswordHasher), HibpChecker / breach_checker(BreachCheckMode) (BreachChecker)"
  - "tests/support TestApp harness on SQLite and Postgres (ANVILID_TEST_DB)"
affects: [02-13, 02-14, 02-15, 02-16, 02-17, 02-18]
tech-stack:
  added: []
  patterns:
    - "Outer Router whose fallback_service is ServiceBuilder.layer(tenant middleware).service(inner router), so path rewriting happens before routing"
    - "The tenant layer inserts AppState, AllowedOrigins and ResolvedTenant as request extensions; the CSRF layer reads them"
    - "Security headers are added only when absent, so handlers can override them (e.g. the public Cache-Control on assets)"
key-files:
  created:
    - crates/anvil-web/src/config.rs
    - crates/anvil-web/src/state.rs
    - crates/anvil-web/src/tenant.rs
    - crates/anvil-web/src/errors.rs
    - crates/anvil-web/src/render.rs
    - crates/anvil-web/src/cookies.rs
    - crates/anvil-web/src/health.rs
    - crates/anvil-web/src/layers/{mod,security_headers,csrf,cors}.rs
    - crates/anvil-web/src/adapters/{mod,argon2,hibp}.rs
    - crates/anvil-web/src/protocol/{mod,discovery,jwks,authorize,token,userinfo}.rs
    - crates/anvil-web/src/ui/{mod,login,registration,verification,recovery,setup}.rs
    - crates/anvil-web/src/admin/mod.rs
    - crates/anvil-web/tests/support/mod.rs
    - crates/anvil-web/tests/shell.rs
    - crates/anvil-web/tests/render.rs
    - crates/anvil-web/tests/snapshots/render__*.snap (9)
  modified:
    - crates/anvil-web/src/lib.rs
key-decisions:
  - "fetch_metadata_layer() takes no argument. Allowed origins come from the AllowedOrigins extension that the tenant layer sets: the public origin, plus the tenant host origin for host-based tenants. If the extension is missing, any Origin is rejected (fail closed)"
  - "A 403 from the CSRF layer renders the themed error page with error_key csrf. It finds AppState through the request extension that the tenant layer sets"
  - "Security headers apply to every response, not only UI responses. X-Frame-Options: DENY is added as well. HSTS is max-age=31536000 without includeSubDomains"
  - "Root and path tenant lookups that fail with a storage error return a 500 error page. /health/live, /health/ready and /healthz skip tenant resolution entirely"
  - "Host tenants are looked up by the exact Host header value (lowercased, trailing dot removed). A Host header equal to the public host_port skips the lookup"
  - "The public URL path prefix is not stripped from requests (as in Phase 1). Deployments under a sub-path need a proxy that strips it"
  - "minijinja escapes '/' as &#x2f;. That is valid HTML and browsers decode it. Test assertions compare decoded text (TestResponse::html())"
metrics:
  duration: 14min
  completed: 2026-11-25
  tasks: 3
  files: 40
requirements-completed: [SEC-04, UI-01, AUTH-01, QUAL-02]
---

# Phase 2 Plan 12: Web shell, adapters and test harness Summary

**This plan adds the HTTP shell for the wave-3 plans:**
- `anvil_web::app()` resolves the tenant before routing: custom host, then `/t/{slug}`, then the RFC 8414 inserted path, then `default`.
- There is one mapping from `CoreError` to HTTP responses.
- Every response gets a strict CSP and the other security headers.
- A Fetch-Metadata CSRF layer and a `__Host-` cookie policy are in place.
- Templates render from embedded files and can be overridden by a theme directory.
- `Argon2Pool` and `HibpChecker` implement the password-hashing and breach-check ports.
- A `TestApp` harness runs green on both SQLite and Postgres.

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Config, state, tenant resolution, errors, security headers, CSRF, CORS, cookies, health, module skeleton | f1789a8 |
| 2 | Render snapshots, Argon2Pool, HibpChecker | 8659ef2 |
| 3 | Integration-test harness for both backends + shell smoke tests | 48f372b |

## What wave-3 plans use

- **Add routes:** fill your own `protocol/*.rs` / `ui/*.rs` `pub(super) fn routes() -> Router<AppState>`. 02-16 replaces `admin/mod.rs`. Do not edit `lib.rs`. Apply `layers::cors::public_cors()` inside your own `routes()`. Only discovery, jwks, token and userinfo get CORS.
- **Handlers:** take `State<AppState>` and `ResolvedTenant`. A missing tenant automatically gets the `not_found` page. Use `Option<ResolvedTenant>` for installation-level pages such as `/setup`.
- **Errors:** protocol endpoints use `errors::oauth_json(&err)`. The admin API uses `errors::problem_json(&err)`. Pages use `errors::error_page(state, tenant, status, key, detail)` or `errors::core_error_page`.
- **Rendering:** `state.renderer().page("login.html", context!{ page => PageContext::for_tenant(..).into_value(), form => Value::from(Serde(&form)) })`. To set links, change `PageContext.links` before calling `into_value()`.
- **Cookies:** `state.cookies().session_cookie(&tenant, v)`, `flow_cookie`, `clear_flow`, `clear_session`. Add them to the response with `axum_extra::extract::cookie::CookieJar`.
- **Harness:** add `mod support;` in a new test file. The API: `TestApp::new()`, `::dev()`, `::with(|cfg| ..)`, `::uninstalled()`; `app.get`, `post_form` (sends `Sec-Fetch-Site: same-origin` and a Content-Length), `send`, `follow`; `location`, `json`, `csrf_from`; and `app.system` / `app.default` (tenant, key id, kid), `storage()`, `clock().advance(..)`, `kek()`, `issuer(slug)`.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 - Blocking] render.rs landed in Task 1**
- **Found during:** Task 1
- **Issue:** `AppState` owns the `Renderer`, and `error_page` needs `PageContext`. The Task 1 shell could not compile without them.
- **Fix:** `Renderer`, `PageContext` and `page_context` were committed in Task 1. Task 2 added the snapshot, override and escaping tests (`tests/render.rs`) as planned.
- **Commit:** f1789a8

**2. [Rule 2 - Correctness] The CSRF layer signature has no argument**
- **Issue:** `ui::routes()` receives no configuration, so it had no value to pass as `fetch_metadata_layer(allowed_origin)`. A single fixed origin would also reject legitimate POSTs on host-based tenants.
- **Fix:** `fetch_metadata_layer()` reads the `AllowedOrigins` extension that the tenant layer sets. Without that extension, any request carrying an Origin is rejected (fail closed). This is unit-tested.
- **Commit:** f1789a8

**3. [Rule 3 - Blocking] Verified in a scratch worktree while the backends were mid-edit**
- The parallel 02-05/02-06 work left the backends uncompilable in the shared tree (`SQLX_OFFLINE` cache misses), and they are dev-dependencies of anvil-web. Tasks 1 and 2 were verified in a scratch git worktree at the committed HEAD, with the anvil-web files synced in. No backend files were edited. The worktree has since been removed.

**4. No `#[ignore]` markers remain**
- The storage-backed shell tests (tenant resolution, installation, readiness) were first written with `#[ignore = "needs 02-05/02-06"]`. Both backends landed during this plan (fbca624, 7f5c892, and the shims are gone). The tests then passed on SQLite and on Postgres (testcontainers), so the markers were removed before committing. **02-13 has no ignores to remove.**

## Verification

- `cargo test -p anvil-web`: lib 44, render 13, router 10 (Phase 1, unchanged), shell 12. All green in the main tree.
- `ANVILID_TEST_DB=postgres cargo test -p anvil-web --test shell`: 12 passed.
- `INSTA_UPDATE=no cargo test -p anvil-web --test render`: green, with 9 snapshots committed.
- `cargo clippy -p anvil-web --all-targets -- -D warnings`: clean. The only remaining output is the existing manifest notice about the unused `utoipa-axum` dependency, which 02-16 will use.

## Self-Check: PASSED
