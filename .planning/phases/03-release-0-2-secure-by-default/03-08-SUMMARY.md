---
phase: 03-release-0-2-secure-by-default
plan: 08
subsystem: web
tags: [client-ip, trusted-proxies, x-forwarded-for, forwarded, connect-info, audit, harness]
requires:
  - phase: 03-02
    provides: anvil_core::model::RequestContext
  - phase: 02-12
    provides: web shell, module routes() pattern, TestApp harness
  - phase: 02-18
    provides: anvilid plain and TLS listeners
provides:
  - anvil_web::client_ip (TrustedProxies, ForwardedHeader, client_ip, ClientIp, MissingPeerAddress)
  - anvil_web::request_context (AuditContext extractor, request_context helper)
  - AppConfig.trusted_proxies (loopback in dev mode, none otherwise)
  - empty, registered route modules for every Phase 3 UI/protocol endpoint
  - themes/default/templates/account_base.html
  - TestApp::storage_arc, kek_arc, DEFAULT_PEER, send_from
  - ConnectInfo<SocketAddr> on plain and TLS listeners of anvilid
affects: [03-14, 03-17, 03-18, 03-19, 03-20, 03-24, every plan emitting audit events]
tech-stack:
  added: []
  patterns:
    - "Client IP only via ClientIp/AuditContext extractors (one implementation, OPS-06)"
    - "Feature plans own pre-registered module files; mod.rs need not change"
key-files:
  created:
    - crates/anvil-web/src/client_ip.rs
    - crates/anvil-web/src/request_context.rs
    - crates/anvil-web/tests/client_ip.rs
    - crates/anvil-web/src/ui/{mfa,consent,account_security,account_sessions,account_apps}.rs
    - crates/anvil-web/src/protocol/{introspect,revoke}.rs
    - themes/default/templates/account_base.html
  modified:
    - crates/anvil-web/src/config.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/src/ui/mod.rs
    - crates/anvil-web/src/protocol/mod.rs
    - crates/anvil-web/tests/support/mod.rs
    - crates/anvilid/src/server.rs
    - crates/anvilid/src/startup.rs
key-decisions:
  - "03-08: Audit extractor is anvil_web::request_context::AuditContext(RequestContext) (orphan rule forbids implementing FromRequestParts on the core type); missing ConnectInfo rejects with MissingPeerAddress (generic 500)"
  - "03-08: Forwarding entries accept bare IPs, IPv4:port and [IPv6](:port); at most 32 hops are walked; a non-ASCII header line counts as one unparsable entry"
  - "03-08: anvilid startup builds AppConfig with AppConfig::new + field assignment so new AppConfig fields keep their defaults; trusted-proxy operator config is still mapped in 03-24"
requirements-completed: []
metrics:
  duration: 45min
  completed: 2026-11-25
---

# Phase 3 Plan 08: Web foundation (client IP, RequestContext, route skeletons) Summary

**One trusted-proxy client-IP implementation (X-Forwarded-For or Forwarded walked right to left past trusted CIDRs), an `AuditContext` extractor, `ConnectInfo` on both anvilid listeners, pre-registered empty Phase 3 route modules, an account base template and harness peer support.**

## Performance

- Duration: about 45 min
- Completed: 2026-11-25
- Tasks: 2/2
- Files: 20

## Accomplishments

- `client_ip(peer, headers, cfg)`: the peer is the answer unless it is in a trusted CIDR. If it is, the configured header (one only, never mixed) is walked from the right, skipping trusted hops. Unparsable entries (`unknown`, `_obf`, garbage, a `Forwarded` element without `for=`) stop the walk at the last trusted hop. IPv4-mapped IPv6 is normalised. Quoted `Forwarded` values with brackets and ports parse, and keys are case-insensitive.
- `ClientIp` extractor reads `ConnectInfo<SocketAddr>`. When it is missing the request gets a generic 500 (`MissingPeerAddress`), never an invented address. `AuditContext` returns a core `RequestContext` with the client IP, the User-Agent (truncated by core) and `x-request-id` (capped at 128 chars).
- `AppConfig::new` trusts loopback (127.0.0.0/8, ::1/128) when the public URL is in dev mode. In production it trusts nobody, so forwarding headers are ignored.
- Tests (`tests/client_ip.rs`, 12): a spoofed XFF from an untrusted peer, right-to-left walking that never picks the leftmost entry, joining multiple header lines, Forwarded with IPv6 and IPv4, unparsable entries stopping the walk, mapped IPv6, no mixing of header modes, and issuer/HSTS/`__Host-` Secure cookies unchanged by `X-Forwarded-Proto`/`X-Forwarded-Host`/`Forwarded`. Two proptests check that the result never comes from an attacker-controlled prefix (XFF, and Forwarded split across lines). Lib unit tests cover node parsing, quote-aware splitting, the hop cap and the extractor without ConnectInfo.

### Skeleton modules (empty `routes()`: no endpoint exists until the owner lands)

| Module | Owner plan |
| --- | --- |
| `ui::mfa` | 03-20 |
| `ui::account_security` | 03-14 |
| `ui::account_sessions` | 03-19 |
| `ui::account_apps` | 03-17 |
| `ui::consent` | 03-17 |
| `protocol::introspect` | 03-18 |
| `protocol::revoke` | 03-18 |

The UI modules are merged behind `fetch_metadata_layer()` and the protocol modules into `protocol::routes()`.

### Account base template

`account_base.html` extends `base.html` and adds a `<nav aria-label="Account">` with Security, Sessions and Connected apps links (ids `account-nav-*`), followed by `{% block account %}`. Variables: `account_base` is the tenant base path prefixed to the links and `account_nav` (`security` | `sessions` | `apps`) sets `aria-current="page"`. A unit test in `ui::tests` covers it.

### Harness API (`tests/support/mod.rs`)

- `TestApp::storage_arc() -> Arc<dyn Storage>`, `TestApp::kek_arc() -> Arc<Kek>`
- `DEFAULT_PEER` = `203.0.113.10:40000`. `send` inserts it as `ConnectInfo` unless one is already set.
- `TestApp::send_from(peer: SocketAddr, req)` overrides the peer.

### anvilid

- The plain listener uses `into_make_service_with_connect_info::<SocketAddr>()`.
- Each TLS connection wraps the router in `WithPeer`, a small tower `Service` that inserts `ConnectInfo(peer)` into every request.
- New unit tests: `plain_listener_provides_the_peer_address` (real listener plus reqwest) and `tls_connection_service_inserts_the_peer_address`.

## Task Commits

1. **Task 1: Trusted-proxy client IP extractor and RequestContext** - `7fe9c32` (feat)
2. **Task 2: Skeleton route modules, account base template, harness additions, ConnectInfo** - `ba610dd` (feat)

Tests and implementation for Task 1 went into one commit. There is no separate RED commit, because the extractor and its tests were written together against the plan's listed behaviours.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] anvilid built AppConfig with a struct literal**
- **Found during:** Task 2 verification
- **Issue:** The new `AppConfig.trusted_proxies` field broke `crates/anvilid/src/startup.rs`, which built `AppConfig { .. }` directly instead of using `AppConfig::new` as the interface notes assumed.
- **Fix:** Build it with `AppConfig::new(public_url)` and assign the operator fields. Future fields now keep their defaults.
- **Files modified:** crates/anvilid/src/startup.rs (not in files_modified, but needed for the build)
- **Commit:** ba610dd

**2. [Rule 1 - Lint] Rejection type instead of `Response`**
- Clippy `result_large_err` rejected `Result<_, Response>`, so the extractors reject with a `MissingPeerAddress` unit type (`IntoResponse`, generic 500, logged).

## Deferred Issues

Logged in `deferred-items.md`:
- Commit b0c9f1b already has 14 failing anvil-web test binaries without this plan's changes: every test that creates a user returns 500. This was checked in a clean worktree, and the failure set is identical with 03-08 applied. It started when the 0.2 migrations landed (03-05/03-06) while their repository code is still in progress.
- `tests/ui_helpers/mod.rs` has a second router harness that does not insert `ConnectInfo`. The first plan that puts `ClientIp`/`AuditContext` on a route used by those tests must add a peer there.

## Verification

- `cargo test -p anvil-web --test client_ip`: 12 passed. `cargo test -p anvil-web --lib`: 71 passed.
- `cargo test -p anvilid`: all passed (25 unit, 10 cli, 6 serve, 1 zero_config).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean at ba610dd (in the worktree target/wt-03-08, since removed).
- `cargo test -p anvil-web` overall: only the pre-existing failures above.

## Self-Check: PASSED
