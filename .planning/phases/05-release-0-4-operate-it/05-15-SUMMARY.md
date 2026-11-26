---
phase: 05-release-0-4-operate-it
plan: 15
subsystem: oauth
tags: [cimd, draft-ietf-oauth-client-id-metadata-document-03, mcp, ssrf, rate-limit, discovery, client-resolution]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-02 ClientMetadataFetcher port + metadata_fetcher service fields + AppState::cimd_fetcher stub; 05-05 AppState::cimd_fetch_permits; 05-06/05-07 ClientRepo::upsert_cimd on both backends; 05-09 oauth::cimd::{check_url, validate}
provides:
  - "service::client_resolver::ClientResolver: the only client_id -> Client entry point at /authorize and in client authentication (token, revoke, introspect)"
  - "CimdError and MetadataFetchError mapped to CoreError at the service boundary (cimd_error, fetch_error)"
  - "adapters::cimd::OutboundMetadataFetcher on the single OutboundClient; AppState::cimd_fetcher returns it (TRANSITIONAL(05-15) removed)"
  - "Discovery client_id_metadata_document_supported per tenant policy"
  - "tests/cimd_support: loopback wiremock document server, policy helpers, scripted fetcher double"
affects: [05-22, 05-25, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Services build ClientResolver from their existing metadata_fetcher field (no new struct fields, no constructor edits)"
    - "Fetcher adapter holds an AppState clone to reach the outbound client, the one limiter and the fetch permits"

key-files:
  created:
    - crates/anvil-web/tests/cimd_support/mod.rs
    - crates/anvil-web/tests/cimd.rs
    - crates/anvil-web/tests/security_cimd.rs
  modified:
    - crates/anvil-core/src/service/client_resolver.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-core/src/service/client_auth.rs
    - crates/anvil-web/src/adapters/cimd.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/tests/discovery.rs

key-decisions:
  - "A URL client id is resolved only if a fetcher exists, the effective policy is not disabled, check_url passes with fetcher.allow_http_loopback() and (allow_listed) the host is listed; otherwise it is an ordinary id, and materialised CIMD rows are hidden (disabling the policy stops CIMD clients at once)"
  - "A static/dynamic client registered under a URL id always wins; nothing is fetched"
  - "Cache: fresh while metadata_expires_at > now; ttl = max-age clamped to [min_cache_secs, max_cache_secs], no header = min; hard expiry = metadata_expires_at + max_cache_secs"
  - "Transient = Network, Timeout, HTTP 429 or 5xx: serve the row until hard expiry, else ClientMetadataUnavailable (503); everything else (blocked, 3xx/4xx, too large, invalid document) is invalid_client; nothing is ever written on failure"
  - "Every upsert (first materialisation and refresh) is audited as cimd_client_refreshed (actor client, target client_id, details source=cimd)"
  - "CIMD clients get the tenant's dcr.allowed_resources (shared self-service resource list); CimdSettings has no resource field"
  - "Per-host fetch budget: LimitKey::Identifier { nil tenant, sha256(cimd-host:<host>) } under RouteClass::Auth in the one limiter; installation-wide because the port carries no tenant and the budget protects the third-party host; denial reported as Status(429) (transient)"
  - "Concurrency: cimd_fetch_permits (16); waiting longer than TOTAL_TIMEOUT for a permit is a Timeout"
  - "/authorize: refused document -> unknown_client error page (400); transient -> 503 error page via core_error_page; never a redirect. Token endpoint: refused -> the usual invalid_client (401), transient -> 503 temporarily_unavailable"

patterns-established:
  - "Resolver tests run on real storage with a scripted fetcher double; HTTP tests use a wiremock document server on loopback in development mode"

requirements-completed: [AGT-02, AGT-01]

duration: ~50min
completed: 2026-11-26
---

# Phase 5 Plan 15: CIMD resolver Summary

**URL client ids (draft-03 Client ID Metadata Documents) are now resolved at /authorize and in token-endpoint client authentication, under the tenant's admin policy. Documents are fetched only through the SSRF-guarded OutboundClient (5 KiB cap, no redirects, per-host budget, concurrency cap) and materialised as `cimd` client rows with clamped cache lifetimes. Errors are never cached. Discovery advertises the feature only when the tenant enables it.**

## Performance

- **Duration:** about 50 minutes
- **Completed:** 2026-11-26
- **Tasks:** 2
- **Files:** 9 (3 created, 6 modified)

## Accomplishments

- `ClientResolver::resolve(tenant, client_id, now)`. It checks policy, URL rules and the allow-list before any fetch, then the cache, then fetch, validate and upsert, then audits.
- `CimdError` and `MetadataFetchError` are mapped to `CoreError` at the service boundary (the item addressed to 05-15 in deferred-items).
- `OutboundMetadataFetcher` sends `Accept: application/json`, requires status 200, reads at most 5 KiB through `read_capped`, and parses `Cache-Control: max-age` (`no-store`/`no-cache` count as none). It maps `OutboundError` to `MetadataFetchError` and enforces the per-host limiter key and the fetch permits. `allow_http_loopback()` returns `AppConfig.outbound.allow_http`.
- The `AppState::cimd_fetcher` body now returns `Some(OutboundMetadataFetcher)`, so no TRANSITIONAL(05-15) marker remains.
- `AuthorizeService::authorize` and `ClientAuthenticator::authenticate` use the resolver. The other lookups (stored authorization requests, consent, select-account) keep `ClientRepo::get`, because the rows are already materialised.
- `/authorize` also accepts URL client ids longer than the 255-byte limit, up to `MAX_URL_LEN` (2048).
- Discovery adds `client_id_metadata_document_supported: true` when the effective policy is not disabled. The system tenant never gets it, and the default document is unchanged, so conformance stays warning-free.

## Cache semantics

| Situation | Result |
|---|---|
| Row fresh (`metadata_expires_at > now`) | Served, no fetch |
| Missing/expired, fetch OK, document valid | Upsert with `expires = now + clamp(max-age or min, min, max)`, audit `cimd_client_refreshed` |
| Fetch OK, document invalid / blocked / 3xx / 4xx / too large | `invalid_client`, nothing written |
| Transient failure (network, timeout, 429, 5xx, local budget) with row before `expires + max_cache_secs` | Stale row served, nothing written, next request fetches again |
| Transient failure otherwise | `ClientMetadataUnavailable` (503) |
| Policy disabled / host not allow-listed / http in production / no fetcher | Treated as an unknown client, no fetch, materialised CIMD rows hidden |

## Security tests (tests/security_cimd.rs)

`cimd_policy_checked_before_fetch`, `cimd_allow_list_checked_before_fetch`, `cimd_private_destination_blocked` (production: 127.0.0.1, 10.0.0.7, 169.254.169.254, ::1), `cimd_redirect_not_followed`, `cimd_document_over_5k_rejected`, `cimd_client_id_mismatch_rejected`, `cimd_shared_secret_method_rejected` (basic, post, client_secret_jwt), `cimd_jwks_uri_document_rejected`, `cimd_fetch_error_not_cached`, `cimd_failure_never_redirects` (invalid, 404, 502 with form_post), `cimd_fetch_rate_limited`, `cimd_http_client_id_rejected_in_production` (loopback reachable over https, but http is refused with 0 requests).

Other tests: tests/cimd.rs has 10 `resolver_*` tests, the code + PKCE + `resource=https://mcp.example/` flow (aud contains the resource, the row's source is cimd, one fetch), the token endpoint's 503 and `invalid_client`, and two discovery tests. tests/discovery.rs adds `cimd_flag_follows_the_tenant_policy`. There are also unit tests in client_resolver.rs (6) and adapters/cimd.rs (3).

## Task Commits

1. **Task 1: ClientResolver and fetcher adapter:** `f2ed57e`
2. **Task 2: wiring, discovery flag, security tests:** `5df060c`
3. Deferred items: `1d329c4`

## Verification run

- `cargo test -p anvil-core --lib service::`: 267 passed (includes 6 client_resolver tests). The core lib test target was later broken by another plan's in-progress files (`test_tenant`, `User.attributes`), which are not 05-15's.
- `cargo test -p anvil-web --lib -- adapters::cimd protocol::discovery`: 5 passed.
- `cargo test -p anvil-web --test cimd --test security_cimd --test authorize --test token --test security_client_auth --test resource_indicators --test security_private_key_jwt --test security_introspect_revoke --test consent`: 14 + 12 + 13 + 8 + 9 + 15 + 16 + 16 + 19 passed.
- `cargo test -p anvil-web --test discovery`: 10 passed.
- `cargo clippy -p anvil-web --lib --tests` and `cargo clippy -p anvil-core --lib`: no warnings.
- `grep -rn "TRANSITIONAL(05-15)" crates/`: no matches.

**Not run:** the Postgres variant (`ANVILID_TEST_DB=postgres`; Docker not used, left for CI), the e2e and conformance suites, and the full workspace run.

## Deviations from Plan

### Auto-fixed / design adjustments

**1. [Rule 3 - Blocking] The limiter key cannot carry a tenant**
- **Found during:** Task 1
- **Issue:** The plan's key is `LimitKey::Identifier { tenant, ident: sha256(host) }`, but `ClientMetadataFetcher::fetch(url)` has no tenant, and ports.rs is not owned by this plan.
- **Fix:** The budget is per host across the installation, with the nil tenant id and `sha256("cimd-host:<host>")`. This also protects the third-party host whichever tenant triggers the fetch. A denial is reported as `Status(429)`, which counts as transient.
- **Files:** crates/anvil-web/src/adapters/cimd.rs

**2. [Rule 3 - Blocking] The adapter holds an AppState clone**
- **Issue:** AppState exposes the limiter only as `&dyn RateLimiter`, with no Arc accessor, and state.rs is not owned by this plan.
- **Fix:** `OutboundMetadataFetcher { state: AppState }`, which is cheap because AppState is Arc-backed. It is built per service construction.

**3. [Rule 2 - Missing critical] Resources for CIMD clients**
- **Issue:** `to_new_client` needs `allowed_resources`, and `CimdSettings` has no such field. Without one, the plan's MCP resource flow cannot work.
- **Fix:** CIMD clients use the tenant's `dcr.allowed_resources`. This is recorded in deferred-items for docs, or for a dedicated setting.

**4. Materialised CIMD rows are hidden when the policy forbids them**
- An admin who disables CIMD stops existing CIMD clients at /authorize and at the token endpoint right away. The plan only required that disabled means no fetch.

**5. No protocol/authorize.rs change was needed**
- The transient case already renders the 503 error page through `core_error_page`, and the refused case is an `ErrorPage` outcome. The file is unchanged.

**6. TDD commit granularity**
- Tests and implementation were committed together per task, with no separate RED commits, to limit builds in the shared main tree. Every test was run green before committing.

## Issues Encountered

- 05-13 had an uncommitted hunk in service/authorize.rs (the `decide` signature). This plan waited until 05-13 had committed it, so 05-15's commit contains only 05-15's hunks.
- Other plans' in-progress files broke the anvil-core lib *test* build for a while (role.rs, then model test helpers). The lib build and the anvil-web suites were unaffected.

## Next Phase Readiness

- 05-22 (MCP e2e/docs) can use URL client ids end to end. Document the 0.4 limits: no `jwks_uri`, resources come from `dcr.allowed_resources`, and the per-host budget.
- 05-28: add the security_cimd names to scripts/check-security-tests.sh, and drop the `dead_code` allow on `cimd_fetch_permits` in state.rs.

## Self-Check: PASSED
