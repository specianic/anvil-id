---
phase: 04-release-0-3-real-world-logins
plan: 02
subsystem: outbound-http
tags: [ssrf, outbound, reqwest, captcha, hibp, config, module-skeletons]
requires: []
provides:
  - "anvil_web::adapters::outbound: OutboundPolicy { allow_cidrs, extra_ca_pem, allow_http } + loopback_dev(), allows(ip), allow_listed(ip); is_blocked, embedded_v4, BLOCKED_V4/BLOCKED_V6"
  - "OutboundClient::new(&OutboundPolicy) -> Result<_, WebError>; check_url(&Url); get/post/request(method, url) -> Result<OutboundRequest, OutboundError>"
  - "OutboundRequest: header(HeaderName, HeaderValue), form_body(String), json(&T), basic_auth, bearer_auth, timeout(Duration), send() (non-2xx incl. 3xx -> Status), send_any_status(), fetch(limit) -> Vec<u8>"
  - "read_capped(resp, limit) -> Result<Vec<u8>, OutboundError>; LIMIT_DOCUMENT = 1 MiB, LIMIT_TOKEN = 64 KiB; CONNECT_TIMEOUT 5 s, TOTAL_TIMEOUT 10 s"
  - "OutboundError { Blocked, Network, Timeout, Status(u16), TooLarge, InvalidUrl } (Display never echoes URL/IP/body); validate_ca_pem(&[u8])"
  - "AppConfig.outbound; AppState::outbound() / outbound_arc() / upstream() -> &UpstreamHttp / logout_wake() -> Arc<Notify>"
  - "adapters::upstream::UpstreamHttp { new(Arc<OutboundClient>), outbound() }"
  - "CaptchaVerifier::new(Arc<OutboundClient>, endpoints, timeout), with_defaults(outbound); HibpChecker::new(outbound, base_url, timeout); breach_checker_with(mode, outbound)"
  - "anvilid keys outbound_allow_cidrs (ANVILID_OUTBOUND_ALLOW_CIDRS, --outbound-allow-cidrs) and outbound_ca_file (ANVILID_OUTBOUND_CA_FILE, --outbound-ca-file)"
  - "Pre-registered empty modules for every Phase 4 web plan (see ownership table)"
affects: [04-06, 04-11, 04-13, 04-14, 04-15, 04-17, 04-18, 04-20, 04-21, 04-24, 04-25]
tech-stack:
  added: []
  patterns:
    - "Two inner reqwest clients per OutboundClient: https (resolver keeps any allowed answer) and, only when allow_http, http (resolver keeps allow-listed answers only)"
    - "Resolver error is a private DestinationBlocked type found by walking the reqwest error source chain -> OutboundError::Blocked"
    - "Proxy-env test re-executes the test binary as a child with *_PROXY set (no unsafe set_var), with a default reqwest client as a positive control"
    - "TLS/CA tests generate a throwaway CA + 127.0.0.1 leaf with openssl per run and serve with openssl s_server; skipped (with a message) if openssl is missing, like the 03 TLS listener test"
key-files:
  created:
    - crates/anvil-web/src/adapters/outbound.rs
    - crates/anvil-web/src/adapters/upstream/mod.rs
    - crates/anvil-web/src/adapters/backchannel.rs
    - crates/anvil-web/src/i18n.rs
    - crates/anvil-web/src/theme.rs
    - crates/anvil-web/src/protocol/logout.rs
    - crates/anvil-web/src/ui/{upstream,email_code,logout,account_profile,account_linked,preview,select_account}.rs
    - crates/anvil-web/src/admin/{connections,branding}.rs
    - crates/anvil-web/tests/security_ssrf.rs
    - crates/anvilid/tests/config_phase4.rs
  modified:
    - crates/anvil-web/src/adapters/{mod,captcha,hibp}.rs
    - crates/anvil-web/src/config.rs
    - crates/anvil-web/src/state.rs
    - crates/anvil-web/src/lib.rs
    - crates/anvil-web/src/{ui,protocol,admin}/mod.rs
    - crates/anvil-web/src/ui/login.rs
    - crates/anvil-web/tests/captcha.rs
    - crates/anvil-web/tests/security_bruteforce.rs
    - crates/anvilid/src/config.rs
    - crates/anvilid/src/startup.rs
decisions:
  - "Blocked table extends research Pattern 1 with 192.88.99/24, ::/96 (IPv4-compatible), 64:ff9b:1::/48, 100::/64, 2001::/32 (Teredo), 2001:2::/48, 2001:10::/28, 3fff::/20, fec0::/10; embedded IPv4 (mapped, NAT64, 6to4) is blocked if the IPv4 is blocked; allow-list matches the address or the IPv4 an IPv4-mapped address connects to (not NAT64/6to4)"
  - "Non-https / userinfo / unparsable URL -> InvalidUrl; disallowed destination -> Blocked; plain http needs allow_http AND an allow-listed destination (literal or every resolved answer)"
  - "read_capped returns Vec<u8> (anvil-web has no direct bytes dependency; manifests are owned by 04-01)"
  - "breach_checker(mode) keeps its signature (test support files use it with Off) and uses the production policy; the binary uses breach_checker_with(mode, operator client)"
  - "startup.rs sets outbound.allow_http = AppConfig::dev_mode() (loopback public URL or insecure_http); allow_cidrs dev default follows public_url.is_dev_mode() only (trusted-proxies precedent); an explicit outbound_allow_cidrs, even empty, replaces it"
  - "The binary builds a second OutboundClient instance (same builder, same policy) for HIBP because AppDeps.breach is built before AppState; still one implementation"
metrics:
  duration: 50min
  completed: 2026-11-25
---

# Phase 4 Plan 02: SSRF-guarded outbound client Summary

All outbound HTTP in anvil-web now goes through one SSRF-guarded reqwest client. It checks every IP literal before sending and every DNS answer as it resolves, so the address it connects to is the address it checked. It blocks private, loopback, link-local, reserved and embedded-IPv4 ranges, never follows redirects, ignores proxy environment variables, sends only https (plain http only to allow-listed destinations in dev mode), caps body size and times out. CAPTCHA and HIBP now use it. Operators can set `outbound_allow_cidrs` and `outbound_ca_file`. Every Phase 4 web module that later plans own is registered ahead of time.

## OutboundClient API (for 04-14, 04-17 and later)

```rust
let c: &OutboundClient = state.outbound();            // or state.upstream().outbound()
let body = c.get(&jwks_uri)?                          // check_url: scheme, userinfo, IP literal
    .timeout(Duration::from_secs(5))                  // optional, default total 10 s
    .fetch(outbound::LIMIT_DOCUMENT).await?;          // send (non-2xx -> Status) + read_capped
let resp = c.post(&token_endpoint)?.form_body(enc).basic_auth(id, secret)
    .send_any_status().await?;                        // token endpoint: read error bodies
let bytes = outbound::read_capped(resp, outbound::LIMIT_TOKEN).await?;
```

`impl From<OutboundError> for anvil_core::ports::UpstreamError` is still to be added, in 04-14.

## Config keys and defaults

| Key | Env / CLI | Default |
|-----|-----------|---------|
| `outbound_allow_cidrs` | `ANVILID_OUTBOUND_ALLOW_CIDRS` / `--outbound-allow-cidrs` (comma list or TOML array) | dev mode: `127.0.0.0/8, ::1/128`; otherwise none. An explicit value, even empty, replaces the default |
| `outbound_ca_file` | `ANVILID_OUTBOUND_CA_FILE` / `--outbound-ca-file` | unset; validated at load (unreadable, non-PEM or unusable -> error naming the key, never the content) |

Plain http is allowed only in development mode (loopback public URL, or `insecure_http`) and only to allow-listed destinations.

## Module ownership table

| File | Owner | Registration |
|------|-------|--------------|
| protocol/logout.rs | 04-13 | `routes()` merged in protocol::routes |
| ui/logout.rs | 04-13 | merged inside the Fetch-Metadata layer |
| ui/account_profile.rs | 04-15 | inside layer |
| ui/select_account.rs | 04-20 | inside layer |
| ui/account_linked.rs | 04-25 | inside layer |
| ui/email_code.rs | 04-24 | inside layer |
| ui/preview.rs | 04-18 | inside layer |
| ui/upstream.rs | 04-21 | `routes()` inside the layer; `callback_routes()` merged after `.layer(fetch_metadata_layer())` |
| theme.rs | 04-18 | `pub(crate) routes()` merged into the tenant-routed router in lib.rs |
| i18n.rs | 04-06 | `pub(crate) mod` in lib.rs, doc only |
| adapters/upstream/mod.rs | 04-14 | `UpstreamHttp` shell, held by AppState |
| adapters/backchannel.rs | 04-17 | doc only; worker wakes on `AppState::logout_wake()` |
| admin/connections.rs | 04-11 | doc only; the owning plan adds `routes!` in `api_router()` |
| admin/branding.rs | 04-18 | doc only; the owning plan adds `routes!` in `api_router()` |

## Tasks

| # | Task | Commit |
|---|------|--------|
| 1 | Guarded outbound client + SSRF negative tests (TDD: unit table + proptest + security_ssrf.rs) | 6f2544d |
| 2 | Move CAPTCHA/HIBP onto the guarded client, add operator config and AppState handles | b500def |
| 3 | Pre-register every Phase 4 web module | 88b70bf |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] ui/login.rs and tests/security_bruteforce.rs edited outside files_modified**
- **Found during:** Task 2
- **Issue:** `CaptchaVerifier::new` now takes the guarded client, and login.rs builds the verifier per request. The brute-force CAPTCHA tests run on a production-mode TestApp whose default policy (correctly) blocks the loopback wiremock.
- **Fix:** login.rs passes `state.outbound_arc()` (a 4-line change). The two CAPTCHA tests in security_bruteforce.rs set `c.outbound = OutboundPolicy::loopback_dev()`.
- **Commit:** b500def

**2. [Rule 3 - Blocking] adapters/upstream/mod.rs created in Task 2 instead of Task 3**
- AppState::upstream() needs the type, so the shell came with the state change.

**3. [Rule 2 - Hardening] Blocked ranges extended beyond the research list** (Teredo, IPv4-compatible, local-use NAT64, discard, deprecated site-local/ORCHID, 3fff::/20, 192.88.99/24). These are listed in decisions.

## Verification

- `cargo test -p anvil-web outbound` (9 unit tests incl. 2 proptests) and `--test security_ssrf` (9 tests + 1 child-only) green. The extra-CA test ran for real (openssl present), not skipped.
- `--test captcha` (13), `hibp` (8), `--test security_bruteforce` (8), `-p anvilid` (all suites incl. `config_phase4` 6, `serve`), `--test shell` (12), `--lib` (115) green.
- `cargo clippy -p anvil-web -p anvilid --all-targets -D warnings` clean; `cargo fmt --check` clean; `scripts/check-deps.sh` OK.
- `grep -rn "Client::builder" crates/anvil-web/src` matches only adapters/outbound.rs.
- Full `cargo test -p anvil-web --no-fail-fast`: everything green except 3 email-template tests (admin_api_v02 `email_templates_default_override_validation_and_reset`, security_admin_v02 `every_new_route_*`). They return 500 on GET email-templates and fail identically at 04-01's commit 755d7c0, before any 04-02 change to that path. 04-01 has that work in progress (anvil-mail render/check). Out of scope; logged in deferred-items.md.

## Self-Check: PASSED
