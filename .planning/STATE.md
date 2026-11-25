---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: verifying
stopped_at: Completed 02-19-PLAN.md
last_updated: "2026-11-25T03:55:16.554Z"
last_activity: "2026-11-25 — Completed 01-08 (phase gate: CI green on GitHub, spike verdicts, stack confirmed)"
progress:
  total_phases: 7
  completed_phases: 1
  total_plans: 59
  completed_plans: 29
  percent: 53
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-11-25)

**Core value:** A standards-correct, secure OIDC provider that anyone can run in two minutes.
**Current focus:** Phase 1: Foundations and Spikes (M0)

## Current Position

Phase: 1 of 7 (Foundations and Spikes (M0))
Plan: 8 of 8 in current phase (phase complete; all plans 01-01 through 01-08 done)
Status: Phase complete — ready for verification
Last activity: 2026-11-25 — Completed 01-08 (phase gate: CI green on GitHub, spike verdicts, stack confirmed)

Progress: [█████░░░░░] 53%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
| Phase 01 P01 | 15min | 3 tasks | 28 files |
| Phase 01 P04 | 5min | 2 tasks | 7 files |
| Phase 01 P03 | 4min | 3 tasks | 13 files |
| Phase 01 P02 | 15min | 3 tasks | 3 files |
| Phase 01 P06 | 9min | 2 tasks | 6 files |
| Phase 01 P05 | 4min | 2 tasks | 10 files |
| Phase 01 P07 | 10min | 3 tasks | 9 files |
| Phase 01 P08 | 20min | 2 tasks | 4 files |
| Phase 02 P03 | 10min | 2 tasks | 21 files |
| Phase 02 P04 | 8min | 2 tasks | 12 files |
| Phase 02 P01 | 16min | 3 tasks | 29 files |
| Phase 02 P02 | 31min | 3 tasks | 50 files |
| Phase 02 P11 | 25min | 2 tasks | 6 files |
| Phase 02 P07 | 20min | 2 tasks | 5 files |
| Phase 02 P10 | 20min | 2 tasks | 5 files |
| Phase 02 P08 | 30min | 2 tasks | 5 files |
| Phase 02 P09 | 25min | 2 tasks | 8 files |
| Phase 02 P05 | 30min | 3 tasks | 16 files |
| Phase 02 P06 | 50min | 3 tasks | 16 files |
| Phase 02 P12 | 14min | 3 tasks | 40 files |
| Phase 02 P22 | 25min | 2 tasks | 9 files |
| Phase 02 P14 | 35min | 2 tasks | 11 files |
| Phase 02 P13 | 35min | 2 tasks | 10 files |
| Phase 02 P17 | 30min | 2 tasks | 9 files |
| Phase 02 P16 | 25min | 2 tasks | 11 files |
| Phase 02 P15 | 16min | 2 tasks | 16 files |
| Phase 02 P18 | 45min | 3 tasks | 18 files |
| Phase 02 P20 | 25min | 3 tasks | 15 files |
| Phase 02 P19 | 90min | 2 tasks | 13 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: One phase per ARCHITECTURE.md §18 milestone; M5 (1.0) split into Phase 6 (organizations and SSO) and Phase 7 (certification and release)
- [Roadmap]: Cross-cutting requirements mapped to the phase where they are first fully delivered (e.g. ORG-01 and ADM-07 to Phase 5, ADM-02 to Phase 6), even though parts land earlier
- [Roadmap]: QUAL-01 (negative test per security control) is mapped to Phase 2 but remains a gate for every later phase
- [Phase 01]: Storage ports live in anvil_core::ports; backends normal-depend on anvil-core only, anvil-storage (contract suite) is a dev-dependency
- [Phase 01]: ConsumeOutcome::Consumed holds AuthorizationCode unboxed (documented clippy expect)
- [Phase 01]: If-None-Match uses RFC 9110 weak comparison; anvilid rejects issuers with query, fragment or non-http(s) scheme
- [Phase 01]: Discovery document serialised once at router build; advertised-but-unbuilt endpoints return 501 JSON
- [Phase 01]: SQLite storage passes the contract (incl. 32-way consume) with the production single-writer config; no multi-connection writer
- [Phase 01]: sqlx metadata prepared per crate via scripts/sqlx.sh (skips crates without sqlx.toml); dev Postgres bound to 127.0.0.1
- [Phase 01]: cargo-deny >= 0.22 required (0.21 fails on transitive dev-only unmaintained advisories); bans not loosened
- [Phase 01]: Dependency rules apply to normal+build edges only (cargo tree -p, --target all); self-test counts only RULE VIOLATION output as rejection
- [Phase 01]: Conformance: INTERRUPTED module counts as complete in run-test-plan.py, so the M0 ratchet passes over plain http (no TLS fallback needed for M0)
- [Phase 01]: M0 discovery advertises only ES256 but ARCHITECTURE makes RS256 default and certification requires it: Phase 2 must advertise RS256 (raised as doc/code divergence)
- [Phase 01]: Postgres backend passes the shared contract (incl. 32-way consume) with one PgPool and zero query overrides; two sqlx backends judged manageable (§2.1 condition 3 met)
- [Phase 01]: anvilid serve requires --database-url (no implicit default DB); unknown schemes rejected without echoing the URL; Postgres pool 10
- [Phase 01]: Spike B local x86_64 static-pie musl: 9.44 MiB, 18.3 MB idle RSS (vs probe 3.5 MB/9.1 MB, now with sqlx SQLite+Postgres + aws-lc-rs linked); arm64 proven in CI (plan 08)
- [Phase 01]: Phase 1 gate: §2.1 conditions 1-3 met (conformance green in CI, static musl amd64+arm64, two sqlx backends manageable); Rust stack confirmed
- [Phase 01]: Conformance suite fetched via blobless --no-checkout clone (sparse-checkout not portable across git versions); mongo on a named volume removed by down -v
- [Phase 02]: Theme selector/text contract (input id=name, {form.id}-submit, mgmt-client-*, error_key sentences) documented in themes/default/README.md; forms use novalidate so errors come from FormDescription
- [Phase 02]: Sample RP (examples/node-rp) uses client.ClientSecretBasic explicitly; openid-client 6 defaults to client_secret_post for a bare secret
- [Phase 02]: Sample RP allows insecure http only for localhost/127.0.0.1 issuers and fails on a refresh response without a rotated refresh token
- [Phase 02]: e2e helpers take all endpoints from ANVIL_URL/MAILPIT_URL/RP_URL; credentials are created at runtime via /setup
- [Phase 02]: anvil-jose signs/verifies via jsonwebtoken::crypto::{sign,verify} (public in 12.0); headers, JWKs and thumbprints are built in-crate; RSA PKCS#8 loaded as PRIVATE KEY PEM
- [Phase 02]: All Phase 2 deps declared up front (tower-http 0.6.x to match reqwest 0.13); deny.toml allows 0BSD for quoted_printable (lettre); ring absent
- [Phase 02]: Client assertions: aud exactly the issuer (string or 1-element array), iss==sub==client_id, exp within 5 min, jti required (<=256 chars); future nbf/iat rejected; jti replay left to GrantRepo::record_jti
- [Phase 02]: Storage ports use intent methods (create_code+family, rotate_refresh, record_jti, complete_recovery, complete_setup, install) instead of begin()/Tx; ARCHITECTURE §7.1 updated
- [Phase 02]: CoreError single mapping: Validation->invalid_request/422, NotFound/Conflict/Forbidden->not_found/conflict/forbidden (404/409/403), Overloaded->temporarily_unavailable/503, Internal/Storage->server_error/500 with generic description
- [Phase 02]: purge_expired keeps consumed-but-unexpired codes/refresh tokens so reuse detection survives purges; Page.next_cursor is Some iff more items follow
- [Phase 02]: Backends run on TRANSITIONAL pending.rs (StorageError::Unsupported) until 02-05/02-06; contract suite (67 tests) compiles and fails with Unsupported until then
- [Phase 02]: Mail: subject is the first .txt line (optional 'Subject:' prefix stripped); strict undefined so a missing payload key fails the row
- [Phase 02]: Mail: OutboxWorker depends on narrow OutboxAccess (StorageOutbox wraps Arc<dyn Storage>); backoff min(30s*2^(n-1),1h), parked at expires_at after 8 attempts, 2 min lease
- [Phase 02]: Mail: SmtpTransport::from_url needs a Tokio runtime (lettre pool) and never echoes the URL
- [Phase 02]: redirect_uri defaults to the single registered URI only for error reporting; OpenID requests must send it explicitly, so codes never bind an implicit redirect URI
- [Phase 02]: max_age is satisfied by a login during the request (auth_time >= request created_at), so max_age=0 acts like prompt=login without a resume loop
- [Phase 02]: id_token_hint sub is compared with session user_id.to_string(); ID tokens must use the user id as sub
- [Phase 02]: Admin page normalisation (limit 0 -> 50, clamp 1..=200) lives once in service::tenant::admin_page
- [Phase 02]: Tenant slugs immutable for every tenant; system/default protected from delete; confidential clients may not use auth none; jwks only with private_key_jwt
- [Phase 02]: complete_setup peeks the setup token before Argon2 hashing; SetupRepo::complete_setup stays authoritative; bad token -> Forbidden
- [Phase 02]: KeyService has a clock field; published_jwks(storage, clock, tenant) is the single JWKS path shared with AccessTokenVerifier (no KEK needed)
- [Phase 02]: All client-credential failures share one invalid_client description (CoreError::description returns the reason); grant/token failures likewise one description per class
- [Phase 02]: validate_refresh passes a consumed token from the right client to rotate_refresh (reuse detection) regardless of scope; wrong client rejected before consume
- [Phase 02]: Code exchange/refresh require an existing Active user; codes without challenge refused for public or require_pkce clients
- [Phase 02]: Flow engine style: transition(state,input,FlowEnv) plans effects; FlowService runs them; first Failure -> on_failure(state, pending) renders a form (no further I/O)
- [Phase 02]: FlowOutcome::Restarted(StartedFlow) for expired/unknown flows (new flow cookie + flow.expired)
- [Phase 02]: password_changed notice enqueued via OutboxRepo::enqueue after complete_recovery (recipient unknown until token consumed); port refinement raised
- [Phase 02]: require_verified_email honoured: unverified login -> login.email_not_verified after correct password; registration -> registration.check_email
- [Phase 02]: SQLite 0002 replaces Phase 1 authorization codes (not carried over; lack NOT NULL auth context); unit test proves 0002 applies on a populated Phase 1 DB
- [Phase 02]: SQLite: token families have no FK to user/session/client; codes, credentials, sessions, self-service tokens cascade from user via composite (tenant_id,user_id) FKs
- [Phase 02]: UserRepo::delete/ClientRepo::delete stamp family revocation with storage clock (ports take no now)
- [Phase 02]: Outbox payloads may hold plaintext token links (02-08 to decide: build link at send time or document)
- [Phase 02]: 02-06: Postgres token families/codes/refresh tokens reference only tenant (+family); user/client delete revokes families instead of cascading
- [Phase 02]: 02-12: fetch_metadata_layer() takes allowed origins from the tenant layer's AllowedOrigins extension (public origin + host-tenant origin), fail closed without it
- [Phase 02]: 02-12: security headers on every response (insert-if-absent); tenant layer skips /health/*; minijinja escapes '/' as &#x2f; (tests compare decoded HTML)
- [Phase 02]: Outbox payloads sealed with KEK (purpose anvilid/outbox-payload/v1, tenant AAD); FlowService/UserService/OutboxWorker take kek: Arc<Kek> and must share one KEK
- [Phase 02]: 02-14: /userinfo answers client-credentials ATs with 403 insufficient_scope (never carry openid); query access_token -> 401; header+body -> invalid_request
- [Phase 02]: 02-14: /token form-only, repeated parameter -> invalid_request, empty values treated as omitted; no-store + Pragma no-cache on all token/userinfo responses
- [Phase 02]: 02-17: Fuzz targets assert security invariants (RFC 7523 model for client assertions, redirects only to registered URIs, PKCE for public clients); fuzz/ has its own workspace and Cargo.lock seeded from the main lock
- [Phase 02]: 02-17: Release-graph gate forbids test crates and anvil-storage on anvilid normal/build edges; source check skips #[cfg(test)] mod blocks by rustfmt indentation; http-body-util allowed (axum dep)
- [Phase 02]: 02-16: Admin API rejects ATs of deleted system clients (live client check) and requires admin:write for system-tenant client writes (no escalation from admin:clients:write)
- [Phase 02]: 02-16: one api_router() feeds admin::routes() and admin::openapi(); docs/openapi/admin-v1.json drift-checked (just openapi-update)
- [Phase 02]: 02-15: UI POSTs without a parseable ?flow= id or csrf_token get the csrf 403 page; login with ?request= answers 303 to {issuer}/authorize/continue?request=…, without it the login.signed_in message page
- [Phase 02]: Binary logs go to stderr; stdout carries command output; json mode also prints the plain Setup URL line on stdout
- [Phase 02]: kek and smtp_url are env/file only (no CLI flags); config show redacts them and database passwords
- [Phase 02]: serve.lock is taken before KEK generation; Postgres never generates a KEK or creates a data dir
- [Phase 02]: Container image: distroless static-debian13:nonroot pinned by digest; 19.1 MB; /data via COPY --chown of an empty dir
- [Phase 02]: QUAL-04 measured at 5 s (sqlite) / 8 s (postgres) vs 120 s limit; e2e suite runs with one worker sharing one setup via E2E_STATE_FILE
- [Phase 02]: C1 amended by user: confidential clients with require_pkce=false may omit nonce (OIDC Core / Basic OP); PKCE default, public-client PKCE, S256-only and downgrade defense unchanged
- [Phase 02]: Conformance harness runs anvilid on 9443 (suite nginx owns 8443/8444); one reviewed skip; expected failures []

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 6]: Decision D4 (pure-Rust SAML XML-DSig vs alternatives) must be resolved before M5; SAML stays experimental until it passes a signature-wrapping attack corpus
- [Phase 4]: Social login exit criterion requires testing against real providers in a staging environment (provider app registrations needed)

## Session Continuity

Last session: 2026-11-25T03:55:16.552Z
Stopped at: Completed 02-19-PLAN.md
Resume file: None
