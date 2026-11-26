# Phase 5: Release 0.4 "Operate it" - Research

**Researched:** 2026-11-26
**Domain:** Running AnvilID in production with several nodes and tenants, and letting integrators automate it. This covers the multi-tenant console, RBAC and custom attributes in tokens, signed webhooks, declarative tenant YAML, RFC 7591/7592 dynamic registration, Client ID Metadata Documents for MCP clients, a shared Redis-backed limiter, HA on Postgres, observability (metrics, OTLP traces, JSON logs), Helm and Compose, the CLI's backup/restore and admin recovery, and the token-endpoint performance gate. All of it builds on the 0.3 codebase.
**Confidence:** HIGH for the codebase (read at `42f6775`) and for the crate facts, which come from the Cargo manifests of the current releases. HIGH/MEDIUM for the specs: RFC 7591/7592, CIMD draft-03, MCP 2026-07-28 and Standard Webhooks were all read at the source today. MEDIUM for the performance and HA tuning claims. They are reasoned from the code and still need a measurement.

## Summary

Phase 5 adds fourteen requirements to a codebase whose patterns are already set. Most of the phase reuses existing parts:

- the `RateLimiter` trait in `anvil-cache`;
- the single `OutboundClient`;
- the leased delivery-row worker in `adapters/backchannel.rs`;
- the `AuditService` choke point;
- the OpenAPI-driven console;
- the storage contract suite;
- the CLI pattern of `keys rotate` / `admin setup-url`, which run next to a live server.

Some current facts force specific designs. The planner must account for each:

1. **The limiter is already a trait (`anvil_cache::limiter::RateLimiter`, async), and `InProcessLimiter` is its only implementation.** Shared limiting is therefore a second backend behind the same trait, the way storage has two backends behind one port. It is not a second limiter. It needs a **limiter contract suite** run against both backends with the fake clock: pass `now` from the core `Clock` into the Redis script and never use Redis `TIME`. The brute-force backoff store (moka) is also per node today. Behind a load balancer, an attacker who spreads attempts across nodes gets N× the free attempts. The Redis backend must implement the whole trait (GCRA + backoff + loose tier), not just GCRA.
2. **The default quotas make the PRD throughput test impossible from one load generator.** The `token` class allows 50 req/s per IP and 100 req/s per client id (`LimiterConfig::default`). A 1,000 req/s test from one IP gets mostly 429s. The perf and HA configurations must raise these through the existing config keys (`rate_limit_token_per_second`, `rate_limit_token_client_per_second`). The shared-limit property needs a separate, deliberately over-quota assertion.
3. **Every token request re-opens and re-parses the signing key.** `KeyService::signer_for` reads the active key row, opens it with the KEK (HKDF + AES-GCM) and builds a `jsonwebtoken::EncodingKey`. On top of that, jsonwebtoken 12's aws-lc backend calls `RsaKeyPair::from_der` **on every signature** (`src/crypto/aws_lc/rsa.rs::try_sign_rsa`, read from the registry source). A safe optimisation is a process-local cache of the parsed signer keyed by `(tenant, kid, sha256(sealed bytes))`. The active-key row is still read from the DB on each request, so rotation and `--immediate` take effect at once with no staleness. If profiling shows the per-sign DER parse matters, `anvil-jose` can hold an aws-lc `RsaKeyPair` and sign directly. **Do not cache clients or tenants across nodes.** The existing rule is that a deleted client's tokens stop working immediately, and a TTL cache would break it. Postgres has a hardcoded pool of 10 (`POSTGRES_MAX_CONNECTIONS`). Expose it as `database_max_connections`.
4. **The console hardcodes one tenant.** `admin-ui/src/api/client.ts` exports `CONSOLE_TENANT = "default"`, and 99 references in 20 files use it. The multi-tenant console is a route-level refactor (`/console/t/$tenant/...` with TanStack Router plus a tenant switcher and list/create pages). The admin API already supports every tenant (`/api/admin/v1/tenants/{slug}/...`), so the server side needs little change.
5. **One event path already exists.** `AuditService::record` runs right after every state change commits and calls `AuditRepo::append`. ARCHITECTURE §19 says "audit and webhooks are subscribers". Turn `append` into a storage intent that also inserts `webhook_delivery` rows for the tenant's enabled, subscribed endpoints **in the same transaction**. This copies the 0.3 logout precedent, where revoking intents enqueue deliveries. A cloned `LogoutDeliveryWorker` then delivers them through `OutboundClient`, so there is no second queue mechanism, no second HTTP client and no second event bus.
6. **CIMD client ids must work everywhere a `client_id` is looked up (19 call sites).** The cheapest correct design materialises a fetched metadata document as a `client` row (`registration_source = cimd`, `metadata_expires_at`). Only `/authorize` and `/token` trigger a fetch or refresh. Consent, token families, logout and the console then keep working unchanged, and an admin can see and block CIMD clients. No table has a foreign key to `client`; this was checked in both migration sets. The CIMD draft is now **-03 (2026-11-02)**. It recommends a **5 KB** document cap, forbids shared-secret auth methods and requires the `client_id` to equal the fetched URL.
7. **MCP 2026-07-28 deprecates DCR** in favour of CIMD. DCR stays MAY. CIMD carries AGT-02 and the MCP success criterion. DCR (OIDC-17) is still required by the PRD, so build it, behind policy, default disabled. RFC 7591 says plainly that "use of an initial access token is required when the authorization server limits the parties that can register a client". That points the "allow-listed" policy at initial access tokens (owner question Q1).
8. **SQLite online backup cannot use the C backup API.** sqlx 0.9 does not expose it, and the workspace denies `unsafe_code`. `VACUUM INTO '<path>'` makes a transactionally consistent online copy through plain SQL. Use it.
9. **The container image is distroless (no shell).** Compose health checks and Kubernetes `preStop` hooks cannot `curl` or `sleep`. Provide `anvilid healthcheck` (local probe) and an in-process drain delay on SIGTERM (readiness turns 503, wait, then graceful shutdown). Without the drain delay, the HA test sees connection errors on every restart.

**Primary recommendation:**
- Start with three foundation plans:
  - core model + ports + contract suite + every new workspace dependency;
  - installation config + observability plumbing in `anvilid` (metrics recorder, `/metrics` listener, OTLP layer, request log/span layer with redaction, drain on SIGTERM, pool size);
  - CI and deploy scaffolding (HA/perf compose + k6, Helm chart, fuzz build on push, 413 unification).
- Then run both storage backends, the Redis limiter backend, the console tenant refactor and the pure-core pieces in parallel. The pure-core pieces are DCR/CIMD validation, webhook signing, the config diff and claim mapping.
- Then run the feature tracks.
- Serialise OpenAPI regeneration: at most one admin-API plan per wave.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- All CLAUDE.md rules apply: no stubs, one implementation per concern (one rate limiter, one outbound HTTP client, one job
  runner pattern, one audit path), a negative test for every security check, storage only through the storage traits,
  public-repo hygiene (no secrets, hostnames, personal data, unverified claims about other products).
- **Shared rate limiting:** Redis-backed (ARCHITECTURE M4) as an optional backend of the ONE existing limiter (governor-based
  in-memory stays the default for single-node). No second limiter implementation path in handlers. Failure mode when Redis
  is unreachable must be explicit and documented (fail closed for auth endpoints unless configured otherwise) and tested.
- **Nodes are stateless:** everything shared lives in Postgres (and Redis for limiter counters only). Background jobs
  (outbox, back-channel, webhooks, purge) stay leased/SKIP LOCKED so N nodes never double-deliver.
- **Webhooks:** delivered through the existing outbox/lease pattern (no second queue), signed (HMAC-SHA256 over id,
  timestamp and body, following the widely used "Standard Webhooks" header layout), retried with backoff, per-tenant
  endpoints, secrets sealed with the KEK, SSRF-guarded via the single outbound client, delivery log visible in the console.
- **Declarative config:** YAML export/apply per tenant through the admin API and the CLI; apply is idempotent (re-applying
  is a no-op) and produces a plan/diff before changes; secrets are never exported in clear (references or sealed blobs).
- **CLI operations:** online backup/restore (SQLite via its online backup API; Postgres documented pg_dump path plus an
  AnvilID-consistent export), key rotation, admin access recovery (local, requires shell access to the host — never a
  network backdoor).
- **DCR (RFC 7591) and MCP:** dynamic registration policy per tenant: disabled (default) / allow-listed / open; Client ID
  Metadata Documents fetched only through the SSRF-guarded client with size/time limits and caching; resource indicators
  (RFC 8707, shipped in 0.3) bind tokens to the MCP server.
- **RBAC:** tenant-scoped roles, permissions and custom user attributes, mapped into tokens via an explicit claim mapping
  (no arbitrary expression language in 0.4). Org-scoped roles arrive in Phase 6; keep the schema ready for an org scope.
  Permissions engine choice (D5) stays deferred to 3.0 — 0.4 is plain role → permission sets.
- **Multi-tenant console:** an operator (system tenant admin) can create, list, switch between and manage isolated tenants;
  each tenant keeps its own issuer.
- **Observability:** `/healthz` (liveness) and `/readyz` (readiness, checks DB), Prometheus metrics endpoint (opt-in bind
  or same port behind config), OpenTelemetry traces via OTLP (off unless configured), JSON logs option. No PII or secrets in
  metrics labels, spans or logs (test it).
- **Deployment:** in-repo Helm chart and Docker Compose examples; CI validates them (helm lint/template, and an actual
  deploy smoke test in kind or compose).
- **HA + performance tests run in CI** (Docker is available on CI runners; locally Docker is often down — executors leave
  those runs to CI and say so). Performance results are measured on the documented runner size; the CI job fails if the
  targets are missed, and records the numbers.
- **Phase 4 carry-overs (must be planned here):**
  - Remembered consent covering resources (consent_grant schema, consent screen, revocation) — fits with the RBAC/permission
    work.
  - In-flow passkey enrolment as an MFA choice under `required`.
  - Fuzz targets are not built on push to main (a stale target slipped through in 0.3): build the fuzz crate in `ci` or add
    push paths to fuzz.yml.
  - Cosmetic: streamed oversized bodies get 400 on form pages/admin API vs 413 on /token and /logout — unify to 413.

### Claude's Discretion
- Plan decomposition and waves (maximize parallel plans with disjoint files; shared files in an early foundation plan).
- Redis client crate choice (must pass cargo deny; prefer a maintained async client on tokio; keep it optional via a
  feature or runtime config — not in the default dependency graph if the binary-size gate is at risk).
- Load-test tool (k6, oha, or a Rust harness) and HA orchestration (compose in CI).
- Exact YAML schema, provided it is documented, versioned and validated.

### Deferred Ideas (OUT OF SCOPE)
- Organizations, org-scoped roles, per-org SSO, SAML (Phase 6)
- Fine-grained authorization engine (D5, 3.0)
- Localized email templates (noted in 0.3)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ORG-01 | Operator runs multiple isolated tenants, each with its own issuer (path default, host optional) [0.4 UI] | §Multi-tenant console: `CONSOLE_TENANT` refactor, tenant list/create/switch, issuer display; the existing tenants admin API and `tenant.host` |
| ORG-05 | Roles and permissions at tenant (and later org) level, emitted as token claims | §RBAC: `role`/`role_assignment` with nullable `org_id`, claim mapping, RFC 9068 §2.2.3.1 `roles`/`entitlements` naming, the claims pipeline in `service/claims.rs` |
| ADM-05 | Signed, retried webhooks for user and session lifecycle events | §Webhooks: Standard Webhooks v1 header layout, enqueue inside `AuditRepo::append`, a worker cloned from `adapters/backchannel.rs`, the retry schedule, 410 handling, delivery log |
| ADM-06 | Export and idempotently apply a tenant's configuration as YAML | §Declarative config: serde-saphyr in the CLI, a JSON document in the admin API, pure diff in core, apply through existing services, secret references, `--prune` |
| ADM-07 | CLI: serve, migrate, backup/restore, import/export, rotate keys, recover admin access | §CLI: `VACUUM INTO`, offline restore, Postgres guidance, `keys rotate` (exists), `admin recover`, `tenant export/plan/apply`, `healthcheck` |
| OIDC-17 | Dynamic registration (RFC 7591/7592) under policy disabled / allow-listed / open | §DCR: endpoint, metadata validation, registration access token, RFC 7592 GET/PUT/DELETE, initial access tokens, rate class, system tenant forced off |
| AGT-01 | MCP clients get audience-bound tokens (RFC 8414 + RFC 8707), with docs for publishing RFC 9728 metadata | §MCP: discovery order verified (RFC 8414 path insertion is already served), `resource` already shipped, e2e with a mock MCP client/RS, RFC 9728 docs + example |
| AGT-02 | Client ID Metadata Documents under admin policy | §CIMD: draft-03 rules, fetch via `OutboundClient` with a 5 KiB cap, cache semantics, materialisation as client rows, policy tri-state, discovery flag |
| AUTH-14 | Custom user attributes per tenant with JSON Schema: validation, editability, claims | §Custom attributes: per-attribute definitions with JSON Schema fragments, the `jsonschema` crate behind a core port (offline, `regex` engine), account-page editing, claim release |
| OPS-03 | Multiple stateless instances on one Postgres without extra coordination services | §HA: what is still node-local (limiter, backoff), concurrent first start, drain on SIGTERM, HAProxy health checks, the HA compose test |
| OPS-07 | Online backup and restore (SQLite snapshot; Postgres guidance) | §CLI backup: `VACUUM INTO`, integrity/version checks, atomic replace, the KEK warning, pg_dump docs |
| OPS-08 | Health endpoints, Prometheus metrics, OTel traces, JSON logs | §Observability: metrics 0.24 + metrics-exporter-prometheus 0.18 (no listener feature), opentelemetry 0.33 + tracing-opentelemetry 0.34 (http-proto, blocking client), redaction tests |
| OPS-09 | In-repo Helm chart and Docker Compose examples | §Deployment: chart layout, values, ct 3.15 + kind-action 1.15 in CI, compose examples, smoke tests |
| QUAL-05 | Idle memory < 100 MB; token endpoint ≥ 1,000 req/s at p99 < 50 ms on 4 vCPU with Postgres | §Performance: k6 `constant-arrival-rate` + thresholds, quotas, signer cache, pool size, the runner-size question (Q2), a gate on idle memory in `measure-idle.sh` |
</phase_requirements>

## Standard Stack

### Core (already present, reused)
| Library | Version | Purpose in this phase |
|---------|---------|------------------------|
| governor | 0.10.4 | Stays the in-process GCRA backend of `RateLimiter` |
| moka | 0.12.16 | In-process backoff store; the CIMD jwks cache reuses `adapters/upstream/jwks.rs` |
| reqwest | 0.13.5 (rustls → aws-lc-rs) | Under `OutboundClient` (webhooks, CIMD fetch). The OTLP exporter needs the `blocking` feature added to the workspace entry |
| utoipa / utoipa-axum | 6.0.0 / 0.3.0 | New admin routes; the drift test `tests/openapi_drift.rs` |
| tracing / tracing-subscriber | 0.1.44 / 0.3 (json) | JSON logs exist (`log_format`); add the request span/log layer and the OTel layer |
| testcontainers-modules | 0.15 | Already used for Postgres; enable the `redis` (or `valkey`) feature for limiter contract tests (feature confirmed in the 0.15.0 manifest) |
| aws-lc-rs | 1.19 | HMAC-SHA256 for webhook signatures (through `anvil-jose`) |
| sqlx | 0.9.1 | `VACUUM INTO` for SQLite backup. New migrations: **SQLite `0007`, Postgres `0006`** |

### New dependencies (versions verified on crates.io 2026-11-26)
| Library | Version | Crate | Purpose | Notes |
|---------|---------|-------|---------|-------|
| redis | 1.8.3 (updated 2026-11-23) | anvil-cache | Shared limiter backend | `default-features = false, features = ["tokio-comp", "connection-manager", "script"]` + optional `"tokio-rustls-comp"` for `rediss://`. License BSD-3-Clause. Its rustls/tokio-rustls deps are `default-features = false` and it builds TLS with `rustls::ClientConfig::builder()`, so it uses the single aws-lc-rs provider already in the graph. **No ring.** `tls-rustls` always pulls `rustls-native-certs 0.8`. Always-on deps: arcstr, combine, itoa, percent-encoding, ryu, url, xxhash-rust (BSL-1.0, already allowed). `base64` only comes with `entra-id` (never enable it: check-deps.sh rejects base64 anyway). `ConnectionManagerConfig::set_response_timeout` / `set_connection_timeout` exist |
| metrics | 0.24.6 | anvil-web, anvilid | Counters/histograms (ARCHITECTURE §2 choice) | |
| metrics-exporter-prometheus | 0.18.3 | anvilid | Render `/metrics` | **`default-features = false`**: the defaults (`http-listener`, `push-gateway`) pull hyper-rustls and their own listener. Serve `PrometheusHandle::render()` from our own axum route. License "MIT AND Apache-2.0" (both allowed) |
| opentelemetry / opentelemetry_sdk | 0.33.1 | anvilid | Trace provider | `default-features = false, features = ["trace"]` (+ `testing` in dev-deps for `InMemorySpanExporter`) |
| opentelemetry-otlp | 0.33.1 | anvilid | OTLP/HTTP exporter | `default-features = false, features = ["http-proto", "reqwest-blocking-client", "trace"]`. The docs say the default thread-based `BatchSpanProcessor` must use the **blocking** client; the async clients are explicitly warned against with it. Never `grpc-tonic` / `tls-ring` |
| tracing-opentelemetry | 0.34.0 | anvilid | tracing → OTel bridge | Depends on opentelemetry 0.33; `default-features = false` (drops tracing-log and metrics) |
| serde-saphyr | 2.2.0 | anvilid | Tenant YAML parse/emit in the CLI | MIT OR Apache-2.0; "panic-free parsing". `serde_yaml` is deprecated and `serde_yml` carries **RUSTSEC-2025-0068 (unsound, unmaintained)**, so do not use either. The `serialize` feature pulls base64 transitively (allowed; check-deps only rejects direct deps) |
| jsonschema | 0.63.1 | anvil-web (adapter) | AUTH-14 attribute validation | **`default-features = false`** (the defaults include `resolve-http` = reqwest + rustls). Build validators with `.offline()` / `draft202012`, `PatternOptions::regex()` (linear-time, no ReDoS), `should_validate_formats(true)`; meta-validate admin schemas with `jsonschema::meta::validate`. MIT |

**Installation sketch** (workspace `Cargo.toml`, one plan, 05-01):
```toml
# Phase 5 (release 0.4). Every crate Phase 5 needs is declared here once.
redis = { version = "1.8.3", default-features = false, features = ["tokio-comp", "connection-manager", "script", "tokio-rustls-comp"] }
metrics = "0.24.6"
metrics-exporter-prometheus = { version = "0.18.3", default-features = false }
opentelemetry = { version = "0.33.1", default-features = false, features = ["trace"] }
opentelemetry_sdk = { version = "0.33.1", default-features = false, features = ["trace"] }
opentelemetry-otlp = { version = "0.33.1", default-features = false, features = ["http-proto", "reqwest-blocking-client", "trace"] }
tracing-opentelemetry = { version = "0.34.0", default-features = false }
serde-saphyr = "2.2.0"
jsonschema = { version = "0.63.1", default-features = false }
# reqwest gains "blocking" (OTLP exporter thread)
testcontainers-modules = { version = "0.15", default-features = false, features = ["postgres", "redis"] }
```
Run `cargo deny --locked check` and `scripts/check-deps.sh` right after. Expect `multiple-versions` warnings only. The deny policy treats them as warnings, not errors.

**Binary-size headroom:** the image was 18–19 MiB at 0.2 (03 SUMMARY) against the 50 MiB gate. Redis, metrics and OTel add an estimated few MiB. Recommendation: **compile everything into the one binary and enable it with runtime config** (`redis_url`, `otel_endpoint`, `metrics_listen`), with no cargo features. Then the released binary is the one that was tested. ARCHITECTURE §2 says "OpenTelemetry behind the `otel` feature". Either update the doc, or make `otel` a default feature that release builds keep. Release binaries must include OTel, because success criterion 5 requires traces from the shipped artifact.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| redis 1.8 | fred 10.1.0 | Last release 2025-02-27 (stale); larger API. redis-rs is maintained (release 3 days ago) |
| metrics + exporter | prometheus-client 0.26 | No global recorder (easier test isolation), but ARCHITECTURE §2 names `metrics`; stay with the documented choice |
| jsonschema | boon 0.6.1 | Smaller, but last release 2025-01; jsonschema has the offline / regex-engine controls we need |
| k6 | oha 1.17 (MIT, Rust) | oha has `-q` rate and JSON output but no built-in pass/fail thresholds; k6's `constant-arrival-rate` + `thresholds` encode "≥1000 req/s at p99 < 50 ms, 0 errors" directly and fail the job with a non-zero exit |
| k6 | goose 0.19 (Rust) | A Rust harness in the workspace adds compile time and deps for a CI-only tool |
| HAProxy in the HA test | nginx | Open-source nginx has no active health checks, so a draining node keeps getting traffic. HAProxy `option httpchk` on `/health/ready` removes it before shutdown |

## Architecture Patterns

### Recommended module layout (new files; keeps parallel plans disjoint)
```
crates/anvil-core/src/
├── model/{role.rs, attribute.rs, webhook.rs, registration.rs, config_doc.rs}
├── oauth/{registration.rs (RFC 7591 metadata validation, pure), cimd.rs (URL + document rules, pure)}
├── policy/{claims_mapping.rs (roles/permissions/attributes → claims, pure), webhook_event.rs (AuditAction → event type + thin payload)}
├── service/{role.rs, attribute.rs, webhook.rs, registration.rs, client_resolver.rs, config.rs (export, plan, apply)}
└── ports.rs  (+ RoleRepo, WebhookRepo, RegistrationRepo/ClientRepo additions, AttributeSchemaCheck, ClientMetadataFetcher)
crates/anvil-cache/src/limiter/{redis.rs, scripts/*.lua, contract.rs (feature "contract")}
crates/anvil-web/src/
├── adapters/{webhook.rs (worker, cloned from backchannel.rs), cimd.rs (fetcher on OutboundClient), attribute_schema.rs (jsonschema)}
├── protocol/registration.rs  (POST /register, GET/PUT/DELETE /register/{client_id})
├── admin/{roles.rs, attributes.rs, webhooks.rs, config.rs, registration_policy.rs (or tenant settings), initial_access_tokens.rs}
├── observability.rs (request span + log layer, route-class labels, metrics names)
└── ui/{account_attributes.rs, login passkey-enrol additions}
crates/anvilid/src/{backup.rs, recover.rs, tenant_config.rs (YAML <-> JSON), healthcheck.rs, telemetry.rs (OTel + metrics install), limiter.rs (backend selection)}
admin-ui/src/routes/t/$tenant/...  (moved from routes/*), routes/tenants/{index,new}.tsx, routes/t/$tenant/{roles,attributes,webhooks,config}/...
deploy/helm/anvilid/{Chart.yaml, values.yaml, values.schema.json, templates/*, ci/*-values.yaml}
deploy/compose/{postgres/, ha/, observability/}/compose.yml
tests/load/{token.js, ha.js, run-perf.sh, run-ha.sh}   (k6 scripts + orchestration)
tests/mcp/  (mock MCP client + resource server for e2e, Node, zero deps, like tests/e2e/lib/mock-idp.ts)
docs/{OPERATIONS.md (backup/restore, HA, Redis, metrics, OTel), MCP.md (RFC 9728 publishing), CONFIG-YAML.md}
```

### Pattern 1: Second limiter backend behind the one trait
**What:** `RedisLimiter` implements `anvil_cache::limiter::RateLimiter`. `anvilid` selects the backend at startup: `redis_url` set means Redis, otherwise `InProcessLimiter`. `AppState` keeps holding `Arc<dyn RateLimiter>`. `layers/ratelimit.rs`, `guard_attempt` and `record_attempt` do not change at all.
**Semantics:** identical decisions to the in-process limiter under a fake clock, proven by one contract suite (`anvil-cache` feature `contract`, run against `InProcessLimiter` always and against Redis via testcontainers in `test-pg`-style CI).
**Atomicity:** one Lua script per operation (GCRA check, record_failure, record_success, brute_force_gate), invoked with `redis::Script` (EVALSHA with automatic EVAL fallback). `now` is passed in as microseconds from the core clock.
**Keys:** do not put raw IPs or client ids in Redis key names. Use `anvil:rl:{class}:{hex(hmac_sha256(kek_derived_key, canonical(LimitKey)))}`. The KEK derive (`Kek::derive_key("anvilid/ratelimit-key/v1")`) already exists for the recovery-code pepper. Identifiers are already SHA-256 in `LimitKey`.
**Failure mode (locked: explicit, documented, tested):**
- Every Redis call gets a short response timeout (e.g. 50 ms) and a connection timeout.
- Behind that sits a simple circuit breaker: after a failure, skip Redis for N seconds, so requests do not each wait out the timeout.
- When Redis is unavailable:
  - `Auth` class and brute-force gate → **deny** with 503 (`fail closed`), unless `rate_limit_redis_failure = local`;
  - `Token` / `Admin` / `Default` → see owner question Q8. The recommendation is to fall back to a node-local `InProcessLimiter`, the same implementation, not a new path.
- Each fallback increments `anvil_ratelimit_backend_errors_total` and logs once per state change.
**Example (GCRA script, single key; mirrors governor: emission interval T, burst b, tolerance τ = T·(b−1)):**
```lua
-- KEYS[1] = bucket key; ARGV = now_us, T_us, tau_us
local now, T, tau = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local allow_at = tat - tau
if now < allow_at then
  return {0, allow_at - now}            -- deny, retry_after_us
end
local new_tat = tat + T
redis.call('SET', KEYS[1], new_tat, 'PX', math.ceil((new_tat - now + tau) / 1000))
return {1, 0}                           -- allow
```
The off-by-one between this tolerance and governor's `allow_burst` must be pinned by the contract suite (burst N exactly allowed, N+1 denied, refill after T). Do not assume it matches.

### Pattern 2: Webhooks as an audit subscriber (one event path, one queue pattern)
**What:**
1. Core computes the webhook event from the audit event, a pure function in `policy/webhook_event.rs`: `AuditAction` + outcome → `Option<WebhookEvent { type, payload_json }>`. Lifecycle events only, success outcome only.
2. `NewAuditEvent` gains `webhook: Option<WebhookEvent>`. `AuditRepo::append` inserts the audit row and, in the **same transaction**, one `webhook_delivery` row per enabled endpoint of that tenant whose subscription list contains the type: `INSERT … SELECT … FROM webhook_endpoint WHERE tenant_id = ? AND enabled AND ? = ANY(events)`. SQLite uses `json_each` or a join table.
3. `WebhookDeliveryWorker`, a clone of `LogoutDeliveryWorker`, runs on every node. It claims due rows with a row lease (`FOR UPDATE SKIP LOCKED` on Postgres; SQLite is single-node), signs at send time, POSTs through `OutboundClient`, and classifies the result.
**Event types (recommended, `type` field, dot-delimited):**
- `user.created` (admin create, self-registration, JIT);
- `user.updated` (profile, admin patch);
- `user.deleted`;
- `user.email_verified`;
- `user.email_changed`;
- `user.password_changed`;
- `session.created` (login succeeded);
- `session.revoked` (single and all);
- `session.logged_out` (RP-initiated logout).
**Payload:** "thin", carrying ids only (owner question Q4):
```json
{"type":"user.created","timestamp":"2026-11-26T10:00:00Z",
 "data":{"tenant":"acme","user_id":"0193…","actor":{"kind":"admin","id":"0193…"}}}
```
**Delivery rules (Standard Webhooks, read at the source):**
- Headers `webhook-id` (stable across retries = delivery row id), `webhook-timestamp` (unix seconds), `webhook-signature: v1,<base64(HMAC-SHA256(secret, "{id}.{ts}.{body}"))>`.
- The secret is `whsec_` + base64 of 32 random bytes (the spec allows 24–64), sealed with the KEK (purpose `anvilid/webhook-secret/v1`, AAD tenant ‖ endpoint id). It is shown once on create/rotate. During rotation both signatures go out, space-separated, for 24 h.
- `2xx` = delivered. `3xx` = failure (redirects are never followed; `OutboundClient` already refuses them). `410` = disable the endpoint (audited). `429/502/503/504` = retry (honour `Retry-After` up to the schedule cap). Other `4xx`/`5xx`/network/timeout = retry.
- Request timeout 15 s (spec range 15–30 s; `OutboundRequest::timeout`). The claim lease must exceed batch time. Raise `CLAIM_LEASE` accordingly or deliver with bounded concurrency.
- Retry schedule: the spec's example (immediately, 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 14 h, 20 h, 24 h, about 3 days in total) with jitter. Then give up: audit `webhook_delivery_failed`, row kept for the delivery log until retention purges it.
- Delivery is at-least-once. Graceful shutdown waits for in-flight deliveries (the existing `JOBS_SHUTDOWN_TIMEOUT`). A hard kill mid-request can produce one duplicate with the same `webhook-id`. Document this, and tell receivers to dedupe on `webhook-id`.
- Payload ≤ 20 KB (spec guidance; thin payloads are far below).
**Delivery log:** endpoint → recent deliveries (status, attempts, last HTTP status, last error class, next attempt) via the admin API, plus a "send test event" and a "redeliver" action. Both are audited.

### Pattern 3: CIMD client resolution (materialise, refresh on demand)
**What:** `ClientResolver` (core service) is the only entry point that turns a `client_id` into a `Client` at `/authorize` and `/token` (and `/revoke`, `/introspect`, `/logout` hint checks):
1. If `client_id` parses as an https URL **and** the tenant's CIMD policy is not `disabled` **and** it passes the allow-list (checked **before** any fetch), load the row by `client_id`.
   - If missing or `metadata_expires_at <= now`, fetch through the `ClientMetadataFetcher` port (adapter on `OutboundClient`).
   - Validate with pure `oauth::cimd::validate(url, doc, server_caps)`.
   - Upsert the row (`registration_source = cimd`, `consent_mode = required` always, `client_type = public` unless `private_key_jwt` with `jwks`/`jwks_uri`).
2. Otherwise use the plain `ClientRepo::get`.
**Fetch rules (draft-03):**
- https only, no userinfo, path ≠ `/`, no `.`/`..` segments, no fragment, query discouraged (reject); string comparison, never normalise.
- `GET` with `Accept: application/json`, no redirects (already enforced), body cap **5 KiB** (`read_capped(resp, 5 * 1024)`), the existing 5 s connect / 10 s total timeouts.
- Require status 200, valid JSON, `client_id` == URL, `redirect_uris` present. Reject `client_secret`/`client_secret_expires_at`, both `jwks` and `jwks_uri`, and any shared-secret auth method. Missing auth method → `none` (never the RFC 7591 default `client_secret_basic`). `private_key_jwt` needs `jwks` or `jwks_uri`, else `invalid_client`. Intersect `grant_types`/`response_types` with ours; empty → `invalid_client`.
- Cache: honour `Cache-Control: max-age` within `[min, max]` (e.g. 5 min to 24 h). Never cache errors. A transient fetch failure keeps the previous valid row until a hard expiry.
- On failure at `/authorize`: error page, **never redirect**. At `/token`: `invalid_client`, or 503 on a transient failure.
- Loopback/private destinations: blocked by `OutboundPolicy` except in development mode with allow-listed CIDRs. This matches the draft's "only in development or testing, when the server is also on loopback" and needs no new code path.
**Abuse control:** an unauthenticated `/authorize` can trigger a fetch. Add a limiter key for CIMD fetches per IP (a new `LimitKey`/class in the one limiter) and cap concurrent fetches.
**Discovery:** add `client_id_metadata_document_supported: true` per tenant when the policy is not `disabled` (discovery is already built per request from the resolved tenant).
**Consent screen:** show the `client_id` host prominently (draft §10.6). `client_name`/`logo_uri` are untrusted. Do not fetch or render remote logos in 0.4; show initials. The draft requires prefetch and validation if logos are displayed.
**ARCHITECTURE divergence to record:** §6.1 mentions a `client_metadata_cache` table. Materialising into `client` is simpler and gives admin visibility. Update §6.1.

### Pattern 4: DCR (RFC 7591) + management (RFC 7592)
- `POST {issuer}/register`. It is advertised as `registration_endpoint` only when the tenant policy ≠ `disabled`. While disabled the route answers 404 (it does not exist).
- Policies:
  - `disabled` (default);
  - `allow_listed`: requires a Bearer **initial access token** issued by an admin. It is stored hashed, has an expiry and an optional use count, and an optional redirect-URI host allow-list. RFC 7591 §3 ties initial access tokens to "limits the parties that can register". Owner question Q1;
  - `open`: no token, rate limited.
- The `system` tenant is forced to `disabled`, like registration.
- Validation (pure `oauth::registration`):
  - redirect URIs exact, https for `application_type=web`, loopback/custom scheme for `native` (OIDC Registration 1.0);
  - `grant_types` ⊆ {authorization_code, refresh_token}; client_credentials only if the policy allows it;
  - `token_endpoint_auth_method` ∈ {none, client_secret_basic, client_secret_post, private_key_jwt}, default `client_secret_basic` (RFC 7591);
  - scopes ⊆ the tenant's DCR-allowed scopes; never admin scopes;
  - `allowed_resources` ⊆ the tenant's DCR-allowed resources;
  - `consent_mode = required`;
  - no `backchannel_logout_uri` unless https and SSRF-checkable;
  - `software_statement`: RFC 7591 says the server "MAY ignore" it. Recommendation: reject with `invalid_software_statement`, which is explicit and keeps us from silently accepting claims we do not verify;
  - unknown metadata ignored (MUST);
  - substituted values returned in the response.
- Response 201 with `client_id`, `client_secret` (+ `client_secret_expires_at: 0`) for confidential clients, `client_id_issued_at`, `registration_access_token` (256-bit, stored SHA-256), `registration_client_uri`.
- RFC 7592 (Experimental): `GET/PUT/DELETE {registration_client_uri}` with the registration access token:
  - an invalid token or an unknown client → 401 (RFC 6750);
  - PUT replaces all metadata, must include a matching `client_id`, must not include the RAT/URI/`client_id_issued_at`/`client_secret_expires_at`, and any included `client_secret` must match;
  - DELETE → 204 and revokes token families.
- Errors are RFC 7591 JSON (`invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement`), status 400.
- Limiter: `POST /register` in the `Auth` class (10/min/IP default), plus a per-tenant cap on dynamic clients.
- Every registration is audited (`client_registered`, actor = system/dynamic with IP). Dynamic clients are flagged in the console and the config export excludes them.

### Pattern 5: Declarative tenant config (CLI YAML, API JSON, core diff)
- **Document (versioned):** `version: 1`, `kind: TenantConfig`, `tenant: {slug, display_name, host, settings}`, plus `clients[]` (static only), `connections[]`, `branding{tenant, clients{}}`, `roles[]`, `attributes[]`, `email_templates{}`, `smtp`, `webhooks[]`, `registration{dcr_policy, cimd_policy, allow_lists…}`. Identity keys are natural keys (slug, `client_id`, connection slug, role name, endpoint name), never UUIDs, so a document applies to a fresh instance.
- **Secrets:** never exported in clear.
  - Export writes `secret: {configured: true}`.
  - In apply input:
    - **absent** = keep the current value (or generate one for new clients/webhooks; the CLI prints it once);
    - `{env: NAME}` / `{file: path}` = **resolved by the CLI on the operator's machine** and sent to the server inline;
    - the admin API accepts only inline values. **The server never reads env/files named by a document.** Otherwise an admin token could read the server environment.
  - Idempotency with secrets: the server opens the stored sealed value and compares in constant time. Equal → no-op.
- **Plan/apply:** pure `service::config::plan(current, desired) -> Plan { creates, updates (field diffs), deletes }`. Deletes appear in the plan but are executed **only with `--prune`**. `apply` validates the whole document first (every resource through the same pure validators the services use), then applies resource by resource **through the existing services** (`ClientService`, `ConnectionService`, `BrandingService`, …), so audit and validation are reused. A partial failure leaves a state that re-running converges. Document this. Re-applying an applied document must yield an empty plan, enforced by a test.
- **Surfaces:**
  - admin API `GET /tenants/{slug}/config` (admin:read), `POST /tenants/{slug}/config/plan` and `/config/apply` (admin:write), all JSON;
  - CLI `anvilid tenant export <slug> [-o file.yaml]`, `anvilid tenant plan -f file.yaml`, `anvilid tenant apply -f file.yaml [--prune] [--yes]`. These open storage directly like `keys rotate` does and call the same core service. YAML↔JSON conversion lives only in `anvilid` (serde-saphyr). `anvilid config` already means installation config (`config show|validate`), so do not reuse that name.
  - Publish a JSON Schema of the document (generated from the serde types or hand-written and tested) in `docs/`.

### Pattern 6: Observability without leaking
- **Request layer** (one, in `anvil-web`): span `http.request` with `route` = matched route template (never the raw URI or query: `/authorize` queries carry `login_hint`, `state`, `code_challenge`; callbacks carry `code`), `tenant` slug, `status`, `latency_ms`. Log fields per ARCHITECTURE §15 (`trace_id, tenant, client_id, route, status, latency_ms`). No client IP in operational logs or spans; the audit log keeps it by design.
- **Metrics:**
  - `anvil_http_requests_total{route_class, status_class}`, `anvil_http_request_duration_seconds{route_class}` (histogram, buckets set explicitly; otherwise the exporter renders summaries);
  - `anvil_tokens_issued_total{grant}`, `anvil_auth_attempts_total{method, outcome}`, `anvil_refresh_reuse_total`, `anvil_ratelimit_rejections_total{route_class}`, `anvil_ratelimit_backend_errors_total`;
  - `anvil_db_pool_connections{state}`;
  - `anvil_jobs_runs_total{job, outcome}`, `anvil_webhook_deliveries_total{outcome}`.
  - **No `tenant`, `client_id`, user or IP labels.** Tenant counts and CIMD URL client ids are unbounded.
  - Call `PrometheusHandle::run_upkeep()` periodically (the listener-less mode does not do it). Install the recorder once per process. Tests use `metrics::with_local_recorder`.
- **Endpoint:** `metrics_listen` (separate bind, e.g. `0.0.0.0:9464` in Kubernetes, unset = off), or `metrics_on_main_port = true`. `/metrics` on the main port is never rate-limited and never tenant-resolved.
- **Traces:** `otel_endpoint` (config key, env `ANVILID_OTEL_ENDPOINT`, ARCHITECTURE §15) turns on an OTLP/HTTP-protobuf batch exporter. With it unset the layer is not installed. The `service.name` default is `anvilid`. Incoming `traceparent` is honoured only from trusted proxies (decided here, documented). Shutdown flushes the provider.
- **Logs:** `log_format = json` already exists. Audit lines stay on stdout, independent of `RUST_LOG`.
- **Redaction test** (`crates/anvilid/tests/telemetry_redaction.rs`):
  - drive login, token, registration, webhook and CIMD flows in-process with an `InMemorySpanExporter`, a capturing fmt layer and the rendered `/metrics`;
  - assert that none of the known email, password, client secret, code, refresh/access token, `login_hint`, webhook secret or IP strings appear anywhere.

### Pattern 7: Drain on SIGTERM (HA restarts with zero errors)
`shutdown_signal()` → set the readiness flag to 503 → sleep `shutdown_drain` (config, default 0 for zero-config/dev, chart and compose set 10 s) → existing graceful shutdown (`with_graceful_shutdown`) → jobs stop (`JOBS_SHUTDOWN_TIMEOUT`). The HAProxy health check (`inter 1s fall 2`) removes the node before it stops accepting. The Helm chart sets `terminationGracePeriodSeconds` > drain + in-flight. No `preStop` exec is needed (distroless has no `sleep`).

### Anti-Patterns to Avoid
- **A second limiter path** ("if redis { … } else { … }" in handlers or layers). Select the backend once at startup behind `Arc<dyn RateLimiter>`.
- **Reading secrets server-side from document-named env vars/files** during config apply. That is an exfiltration channel.
- **Caching `Client`/`Tenant` rows with a TTL for performance.** It breaks immediate client deletion, revocation and settings changes across nodes. Cache only immutable derived data (the parsed signer keyed by the sealed bytes).
- **Raw URI/query in spans or logs.** Use the matched route template.
- **`tenant`/`client_id` metric labels.** Unbounded cardinality, and they identify customers.
- **Fetching CIMD documents before the allow-list check**, or caching fetch errors.
- **Webhook payloads with emails/names by default.** They put PII in a third-party queue (Q4).
- **Retrying non-idempotent POSTs at the load balancer** (`non_idempotent` in nginx, `retry-on` beyond `conn-failure` in HAProxy). A retried refresh-token request trips reuse detection and revokes the family.
- **`serde_yaml`/`serde_yml`** (deprecated / RUSTSEC-2025-0068). **jsonschema default features** (remote `$ref` over HTTP = SSRF, a second TLS stack).

## Feature Notes

### Multi-tenant console (ORG-01)
- Replace `CONSOLE_TENANT` with a `$tenant` route param: `routes/t/$tenant/...`, with `routeTree.gen.ts` regenerated and committed (drift-checked). A `useTenant()` hook reads it.
- The AppShell gets a tenant switcher (lists `/tenants`). New pages: tenants list (slug, display name, issuer, host) and create (slug immutable, host optional, registration mode).
- The issuer shown is the one computed by `anvil_core::model::issuer`. The console shows the discovery URL to copy.
- `/console/` → redirect to the last used tenant (sessionStorage) or `default`. Old deep links `/console/users` → redirect to `/console/t/default/users` for one release.
- The `system` tenant is listed but marked; its connections/clients follow the existing `admin:write` rules.
- e2e `console.spec.ts` and `console-connections.spec.ts` paths change. Add `console-tenants.spec.ts`: create a tenant, switch to it, create a client, run discovery at `/t/{slug}/.well-known/openid-configuration`, delete the tenant.

### RBAC (ORG-05) + consent with resources (carry-over)
- Schema:
  - `role(id, tenant_id, org_id NULL, name, description, permissions JSON array, created_at, updated_at)`;
  - `role_assignment(tenant_id, role_id, user_id, org_id NULL, created_at)`;
  - composite FKs `(tenant_id, user_id) → user`, `(tenant_id, role_id) → role`, cascading.
  - Unique role name per (tenant, org scope). NULL `org_id` uniqueness differs between backends: Postgres unique indexes treat NULLs as distinct unless `NULLS NOT DISTINCT` (PG 15+); SQLite treats them as distinct. Use a partial unique index `WHERE org_id IS NULL` on both, and a second one for `org_id IS NOT NULL` in Phase 6. `org_id` has no FK until Phase 6 creates `organization`.
- Permissions: free strings validated by syntax (`^[A-Za-z0-9:._/-]{1,128}$`, ≤ 100 per role).
- Claim mapping (tenant settings, explicit, no expressions): `claims.roles = {claim: "roles", tokens: ["access_token","id_token","userinfo"], scope: "roles"}` and `claims.permissions = {claim: "permissions", tokens: ["access_token"], scope: null}`. `scope: null` means always included for user-bound tokens. Default claim names follow RFC 9068 §2.2.3.1, which recommends the SCIM attribute names `roles`/`groups`/`entitlements`. Claim names must not collide with protocol/standard claims (`ID_TOKEN_PROTOCOL_CLAIMS`, standard claims) or with attribute claims, which the validator checks.
- Claims are computed at issuance and at every refresh (role changes apply on refresh). This adds one query on user-bound grants (client_credentials tokens have no user). The pure mapping lives in `policy/claims_mapping.rs` and is called from `service/claims.rs` as an additional "claim provider" (ARCHITECTURE §19 ordered providers).
- Consent covering resources: `consent_grant.resources` (sorted, de-duplicated set) merged in the same upsert as scopes. The consent screen re-prompts when the requested resources are not a subset of the granted ones. Revocation is unchanged (revokes families). Existing grants have empty resources, so a client requesting resources re-prompts once after upgrade (UPGRADING note). Update the `ConsentPage::resources` doc comment that calls this a Phase 5 gap.

### Custom attributes (AUTH-14)
- Definitions per tenant, as an ordered list: `{name, schema (JSON Schema fragment), required, user_editable, claim: {name, tokens, scope}?}`. The effective document schema is `{type: object, properties: {...}, required: [...], additionalProperties: false}` assembled by core.
- Validation is behind a core port `AttributeSchemaCheck` (compile + validate). The adapter in `anvil-web` uses jsonschema offline with `PatternOptions::regex()`, meta-validates admin input and caps schema size (e.g. 16 KiB) and depth. This mirrors `EmailTemplateCheck`.
- `user.attributes` already exists in the data model (§6.1). Validate on every write (admin API, account page, JIT/upstream mapping later). On read, emit a claim only if the stored value validates against the current schema; a schema change never deletes data.
- Account page: render editable attributes as no-JS form inputs from a **restricted subset** (string with `enum`/`maxLength`/`format: email|uri|date`, boolean, integer, number). Attributes of other shapes are admin-editable only.
- Claims: same mapping shape as roles. Validate names against collisions. The `attributes` scope (or a per-attribute scope) gates release.

### In-flow passkey enrolment under MFA `required` (carry-over)
`LoginStep::Enroll` currently offers only TOTP (`flow/login.rs`, sealed `pending_totp`). Add a choice: TOTP or passkey. The passkey registration ceremony reuses `PasskeyCeremonies::start_registration/finish_registration` with challenge state in the flow row (`swap_state`, the existing pattern). `webauthn.js` is already allowed on login pages. The resulting `amr` is `["hwk"|"swk","user","mfa"]` (Phase 3 decision) and `acr` is MFA. This is a serial edit of the login-engine files (`flow/login.rs`, `service/flow.rs`, `ui/login.rs`, `templates/login.html`). Keep it in one plan.

### CLI (ADM-07, OPS-07)
- `anvilid backup create --output <file>`:
  - SQLite → `VACUUM INTO '<tmp>'` on a read connection next to the running server (WAL lets the reader run alongside the writer), `PRAGMA integrity_check` on the copy, write the migration version into a sidecar/manifest, then rename into place.
  - Postgres → an explicit error naming `docs/OPERATIONS.md#postgres` (pg_dump / base backups / PITR guidance). This is not a stub: the command states it does not support Postgres. See owner question Q6 about an "AnvilID-consistent export".
  - The KEK is **never** in the backup. Print a warning that the KEK must be backed up separately (ARCHITECTURE §6.2).
- `anvilid backup restore --input <file>`:
  - SQLite only, server stopped. Take the `serve.lock` first to prove that.
  - Check integrity and that the backup's migration version ≤ the binary's.
  - Copy to a temp file in the data dir, fsync, remove `-wal`/`-shm`, atomic rename.
  - Migrations run on the next `serve`.
- `anvilid keys rotate` exists (signing keys, `--immediate`). Webhook secret rotation and client secret rotation are admin API actions. KEK rotation: owner question Q7. The recovery-code pepper and email-code HMACs derive from the KEK, so KEK rotation invalidates them, and it is a large change.
- `anvilid admin setup-url` exists and creates a **new** system admin via a one-time URL. Add `anvilid admin recover --email <existing system-tenant user>`. It issues a one-time recovery URL (setup-token style, 1 h) that sets a new password and, with `--reset-mfa`, removes that user's TOTP/passkeys. It is audited with the system actor and runs with local storage access only. No network endpoint is added.
- `anvilid tenant export|plan|apply` (Pattern 5).
- `anvilid healthcheck [--url http://127.0.0.1:8080/health/ready]`: a minimal local probe for Compose/Docker `HEALTHCHECK` in the distroless image. Use a plain `TcpStream` HTTP/1.1 GET to loopback only. This is an infrastructure probe, not an outbound fetch, so it does not belong on `OutboundClient`. Refuse non-loopback hosts.

### Deployment (OPS-09)
- **Helm chart** `deploy/helm/anvilid` (apiVersion v2):
  - Deployment (`replicaCount`; the template `fail`s if `replicaCount > 1` without `database.url`/`existingSecret`, because SQLite is single-node);
  - Service, optional Ingress, optional ServiceMonitor, PodDisruptionBudget (when replicas > 1), optional HPA;
  - `existingSecret` for `ANVILID_KEK` and the database URL;
  - probes `httpGet /health/live` and `/health/ready`;
  - `securityContext` (non-root uid of distroless `nonroot`, `readOnlyRootFilesystem: true`, drop ALL caps);
  - an emptyDir/PVC at `/data` for SQLite mode;
  - env for `ANVILID_PUBLIC_URL`, `ANVILID_TRUSTED_PROXIES`, `ANVILID_REDIS_URL`, `ANVILID_OTEL_ENDPOINT`, `ANVILID_METRICS_LISTEN`, the drain delay;
  - `values.schema.json`;
  - a `helm test` pod that GETs `/health/ready` (curl image pinned by digest).
- **CI** (`.github/workflows/deploy.yml`, on PR paths `deploy/**` + push main):
  1. `helm lint` + `helm template | kubeconform` (v0.8.0) or `ct lint`.
  2. `helm/chart-testing-action@v2.9.0` (ct 3.15.0) + `helm/kind-action@v1.15.2`.
  3. Build `anvilid:ci` (`scripts/docker-image.sh`) and `kind load docker-image`. The ghcr package is private (03-29 note), so CI cannot pull it.
  4. `ct install` with `ci/sqlite-values.yaml`, then a Postgres variant (a postgres Deployment applied by `kubectl` before `ct install` with `ci/postgres-values.yaml`).
  - Helm 4.3 is current. ct's Helm 4 support is not stated in its README, so **pin Helm 3.x via `azure/setup-helm@v5.1.0` with an explicit version** unless ct 3.15 is confirmed with Helm 4.
- **Compose examples:**
  - `deploy/compose/postgres/compose.yml`: anvilid + Postgres, KEK from env, healthcheck via `anvilid healthcheck`;
  - `deploy/compose/ha/compose.yml`: 3 × anvilid + Postgres + Redis-protocol server + HAProxy;
  - `deploy/compose/observability/compose.yml`: adds an OpenTelemetry Collector with a file/debug exporter and Prometheus, as an overlay.
  - CI smoke test: `up -d`, wait for ready, GET `/metrics` (assert `anvil_http_requests_total`), assert a stderr line parses as JSON, assert the collector received a span with `service.name=anvilid`, `down -v`.
  - The existing `deploy/compose/qual04-postgres.yml` stays test-only.

## Performance (QUAL-05) and HA (OPS-03)

### Token-endpoint benchmark
- Grant: `client_credentials`, `client_secret_basic`, JWT access token (the default), RS256 tenant default. This is the PRD's "token endpoint" with no browser involved, and it needs no DB write per request.
- Tool: k6 (`grafana/k6` image, pinned) with `constant-arrival-rate` (rate 1000, timeUnit 1s, duration 60 s after a 15 s warm-up, preAllocatedVUs 100, maxVUs 400).
  - Thresholds: `http_req_duration: ["p(99)<50"]`, `http_req_failed: ["rate==0"]`, `checks: ["rate==1"]`, plus `dropped_iterations` count == 0 (k6's metric for iterations it could not start at the target rate).
  - k6 exits non-zero when a threshold fails, which fails the job. Write `--summary-export` JSON to the step summary and an artifact. The job records the numbers.
- Configuration for the run: `rate_limit_token_per_second` and `rate_limit_token_client_per_second` above the test rate. Without this, item 2 of the Summary applies. Also `database_max_connections` (new, e.g. 20) and `log_format=json` at `info` (logging per request must not dominate).
- Code work likely needed (measure first; each is independent):
  1. A parsed-signer cache keyed by `(tenant, kid, sha256(sealed))`.
  2. Signing with a cached aws-lc `RsaKeyPair` instead of `jsonwebtoken::crypto::sign`, which re-parses the DER per call. LOW confidence on how much this costs; profile first.
  3. Configurable pool size.
  4. The tenant lookup by host runs a DB query on every request whose `Host` differs from the public host (`tenant.rs`). Make the benchmark use the public host, and consider a negative cache for unknown hosts (safe: a miss only means "not a host tenant").
- Idle memory: `scripts/measure-idle.sh` reports VmRSS but **does not gate it**. Add a `< 100 MB` (102,400 kB) failure check for QUAL-05.

### HA test (`tests/load/run-ha.sh`, compose)
1. Start Postgres + Redis, then **three nodes at the same time on an empty database**. This deliberately exercises the concurrent first start. `SetupRepo::install` already handles the race (`AlreadyInstalled`). `ensure_console_client`, per-tenant key generation and the startup reconciliations must also tolerate a concurrent winner: a unique violation there must be treated as "someone else did it". Verify; this is a likely failure.
2. Complete setup via the printed URL (reuse `scripts/qual04.sh` logic) and create a confidential client via the admin API.
3. k6 at a moderate rate (e.g. 300 req/s) through HAProxy for 120 s. Meanwhile `docker compose restart` node 1, then 2, then 3, spaced 20 s apart (SIGTERM, then drain).
4. Assert `http_req_failed rate==0`.
5. Shared limit: with the limiter quotas back at small values, send K requests for one client spread across the three nodes **directly** (not through HAProxy) within one second. Assert the aggregate allowed count ≈ quota + burst, not 3×.
6. Jobs: with a webhook endpoint pointing at a counting sink container (on an allow-listed CIDR, `outbound_allow_cidrs`), trigger N user events during the restarts. Assert every `webhook-id` arrives, and none arrives twice (graceful restarts only).
7. Record and upload the numbers.
- **HAProxy:** `option httpchk GET /health/ready`, `default-server inter 1s fall 2 rise 2`, `retry-on conn-failure` (the default), `retries 2`. Do not retry on `empty-response` or `response-timeout` for POST.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Redis protocol client, reconnects, scripts | Raw RESP over TcpStream | `redis` 1.8 `ConnectionManager` + `Script` | Reconnect/backoff, EVALSHA fallback, timeouts |
| YAML parsing | A hand parser / deprecated serde_yaml | `serde-saphyr` 2.2 | Panic-free, maintained; serde_yml is RUSTSEC-2025-0068 |
| JSON Schema evaluation | A home-grown schema subset evaluator | `jsonschema` 0.63 (offline, regex engine) | Draft 2020-12 semantics, meta-validation, ReDoS control |
| Prometheus exposition format | Formatting text by hand | `metrics-exporter-prometheus` `PrometheusHandle::render` | Escaping, histograms, upkeep |
| OTLP encoding/export | A protobuf client by hand | `opentelemetry-otlp` http-proto | Batching, retries, standard env vars |
| Load generation + pass/fail | A custom Rust/bash load loop | k6 arrival-rate + thresholds | An open-model load is easy to get wrong (coordinated omission) |
| Webhook HMAC / base64 | New crypto or base64 code | aws-lc-rs HMAC in `anvil-jose`; `anvil_jose::encoding::b64std` | One crypto backend; check-deps.sh rejects other base64 |
| SSRF checks for webhooks/CIMD | URL/IP checks per feature | `OutboundClient` (+ `check_url` at create time) | One guarded client is a locked decision |
| SQLite snapshot | Copying the file while live | `VACUUM INTO` | A file copy during writes is inconsistent; the C backup API needs unsafe |
| Chart testing | Bash around kubectl | `ct lint/install` on kind | Standard, handles install/test/teardown |

**Key insight:** almost everything in this phase is wiring existing single implementations (limiter trait, outbound client, delivery-row worker, audit choke point, services) into new surfaces. Most bugs will come from a second path appearing next to an existing one, so every plan's verification should grep for one.

## Common Pitfalls

### Pitfall 1: The load test measures the rate limiter
**What goes wrong:** 429s at 50 req/s per IP. **Avoid:** set the perf/HA config quotas explicitly. Assert that zero 429s occurred in the throughput run, and run a separate over-quota assertion for the shared limit.

### Pitfall 2: Restarted nodes cause errors
**Why:** the node stops accepting while the LB still routes to it, or a reused keep-alive connection is closed. **Avoid:** drain delay with readiness 503, active LB health checks, LB retry only on connect failure.

### Pitfall 3: Concurrent first start crashes a node
**Why:** startup reconciliation (console client, per-tenant keys) races on unique indexes. **Avoid:** treat unique violations in those idempotent ensures as success. The HA test starts all nodes together on an empty DB.

### Pitfall 4: Brute-force protection is per node behind a load balancer
**Avoid:** the Redis backend implements the backoff store and loose tier too. The contract suite covers `brute_force_gate`.

### Pitfall 5: PII in telemetry through URIs
`/authorize?login_hint=alice@…`, callback `?code=`, `/ui/...?flow=` ids. **Avoid:** matched route templates only. The redaction test fails the build.

### Pitfall 6: Metrics cardinality and the global recorder
**Avoid:** no tenant/client labels. Install the recorder once (it is process-global; parallel tests must use a local recorder). Set histogram buckets. Call `run_upkeep()`.

### Pitfall 7: The OTLP exporter blocks or never flushes
**Why:** an async reqwest client with the thread-based batch processor (explicitly warned against in the docs), or no `shutdown()` on exit. **Avoid:** `reqwest-blocking-client`, and call `provider.shutdown()` in the serve shutdown path.

### Pitfall 8: CIMD as an amplification/SSRF tool
**Avoid:** policy and allow-list before fetch, per-IP fetch limiter key, 5 KiB cap, no redirects (already), never cache errors, render the `client_id` host on consent, no remote logos.

### Pitfall 9: Secret handling in YAML apply
**Avoid:** the server never dereferences env/file references. Secrets are compared via open + constant-time equality for idempotency. Export never contains hashes or sealed blobs. A sealed blob is bound to KEK + tenant UUID + row id AAD and would not open in a fresh instance anyway.

### Pitfall 10: Webhook retries and duplicates
**Avoid:** a stable `webhook-id` = delivery row id, at-least-once documented, 410 disables, the lease covers the 15 s timeout × batch, graceful shutdown waits for in-flight deliveries.

### Pitfall 11: OpenAPI and console generated-file conflicts
Several plans add admin routes. **Avoid:** one OpenAPI-regenerating plan per wave (Phase 4 rule). `routeTree.gen.ts` and `schema.d.ts` are regenerated by the plan that changes routes/the spec.

### Pitfall 12: SQLite vs Postgres NULL uniqueness (`org_id`)
**Avoid:** partial unique indexes `WHERE org_id IS NULL`. Cover both backends in the contract suite.

### Pitfall 13: Attribute schema changes invalidating stored data
**Avoid:** validate on write and filter on read, never rewrite stored attributes. Meta-validate and size-cap admin schemas. Use the `regex` engine (fancy-regex backtracking on user-supplied values is a DoS).

### Pitfall 14: Performance flakiness on shared runners
GitHub public `ubuntu-24.04` runners have **4 vCPU / 16 GB** (verified). In-runner, the load generator, Postgres and anvilid share those 4 vCPU. **Avoid:** owner decision Q2. Run 3 trials and gate on the median. Pin the k6, Postgres and Redis images by digest.

### Pitfall 15: Redis key contents and TLS
**Avoid:** hashed key names (no raw IPs). `rediss://` needs the `tokio-rustls-comp` feature and uses native roots (`rustls-native-certs`). Document it, and verify the distroless image has CA certificates for it. Recommend testing TLS only if an operator asks; the default HA compose uses plain TCP on a private network.

### Pitfall 16: Fuzz targets rot on main
**Avoid:** add a `ci.yml` job, `cargo check --manifest-path fuzz/Cargo.toml --locked --bins` (stable; no sanitizer needed to type-check), plus `push: branches: [main]` paths in `fuzz.yml`. Add new targets: `registration_parse` (RFC 7591 metadata), `cimd_parse` (document + URL rules), `tenant_config_parse` (JSON document into the config model).

### Pitfall 17: 413 vs 400 for streamed bodies
**Where:** the admin JSON rejection mapping (`admin/auth.rs` `JsonRejection`) and `ui::login::bad_form`-style `FormRejection` mapping. **Avoid:** map a `LengthLimitError` / "length limit exceeded" body rejection to 413 in both shared mappers. Update `security_body_limit.rs` to assert exactly 413 for the streamed case.

## Code Examples

### Webhook signature (pure, in `anvil-jose`)
```rust
// Standard Webhooks v1: base64(HMAC-SHA256(secret, "{msg_id}.{timestamp}.{body}"))
pub fn webhook_signature_v1(secret: &[u8], msg_id: &str, ts: i64, body: &[u8]) -> String {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&key);
    ctx.update(msg_id.as_bytes());
    ctx.update(b".");
    ctx.update(ts.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    format!("v1,{}", crate::encoding::b64std(ctx.sign().as_ref()))
}
// Header: webhook-signature: "v1,<current> v1,<previous>" during a rotation window.
// Test vector: compute against the spec's published example in a unit test.
```

### SQLite online backup
```rust
// Next to a running server: WAL lets this reader run alongside the single writer.
sqlx::query("VACUUM INTO ?1").bind(tmp_path.to_str()).execute(&mut *conn).await?;
// Then open tmp read-only: PRAGMA integrity_check == "ok"; read _sqlx_migrations max(version); rename.
```

### k6 token benchmark (sketch)
```javascript
import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';
export const options = {
  scenarios: { token: { executor: 'constant-arrival-rate', rate: 1000, timeUnit: '1s',
                        duration: '60s', preAllocatedVUs: 100, maxVUs: 400 } },
  thresholds: { http_req_duration: ['p(99)<50'], http_req_failed: ['rate==0'],
                checks: ['rate==1'], dropped_iterations: ['count==0'] },
  discardResponseBodies: true,
};
const auth = 'Basic ' + encoding.b64encode(`${__ENV.CLIENT_ID}:${__ENV.CLIENT_SECRET}`);
export default function () {
  const r = http.post(`${__ENV.BASE}/token`, 'grant_type=client_credentials',
    { headers: { Authorization: auth, 'Content-Type': 'application/x-www-form-urlencoded' } });
  check(r, { '200': (x) => x.status === 200 });
}
```

### Limiter backend selection (one path)
```rust
let limiter: Arc<dyn RateLimiter> = match &cfg.redis_url {
    None => Arc::new(InProcessLimiter::new(cfg.limiter.clone(), clock.clone())),
    Some(url) => Arc::new(RedisLimiter::connect(url, cfg.limiter.clone(), clock.clone(),
                    key_hasher, cfg.redis_failure /* Closed | Local */).await?),
};
// AppState gets `limiter`; nothing else in anvil-web knows which backend runs.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| MCP clients register via DCR | MCP prefers pre-registration, then CIMD; DCR deprecated (kept ≥ 12 months) | MCP 2026-07-28 | CIMD is the MCP-critical path; DCR stays for OIDC-17 and older clients |
| CIMD draft-00 (cited by MCP) | draft-ietf-oauth-client-id-metadata-document-03 (2026-11-02): 5 KB cap, no shared-secret auth, `client_id_metadata_document_supported` | 2026-11 | Implement -03 rules; the MCP spec still links -00 |
| Standard Webhooks `v1a` asymmetric | `v2a` (ed25519 over SHA-256 of the signed content); `v1` HMAC unchanged | spec main branch | The locked HMAC `v1` is current; asymmetric is optional later |
| `serde_yaml` | serde-saphyr (or others); serde_yaml deprecated, serde_yml unsound | 2024–2025 | Use serde-saphyr |
| OTel async batch processor + async client | Thread-based batch processor + blocking HTTP client by default | opentelemetry-otlp 0.2x–0.33 | Enable `reqwest-blocking-client` |
| Helm 3 | Helm 4.3 current | 2025–2026 | Pin Helm 3.x for ct unless Helm 4 support is confirmed |

**Deprecated/outdated:** `serde_yml` (RUSTSEC-2025-0068), `serde_yaml` (deprecated), `fred` (no release since 2025-02), nginx without active checks for the drain test.

## Resolved here (no owner decision needed)

1. **Health endpoint names.** CONTEXT says `/healthz` + `/readyz`. The code and PRD/ARCHITECTURE have `/health/live`, `/health/ready` and `/healthz`. Keep all three and add `/readyz` as a route to the same `ready` handler (one implementation). The chart uses `/health/*`. The ratelimit EXEMPT list gains `/readyz`.
2. **Webhook queue.** A dedicated `webhook_delivery` table using the logout-delivery claim pattern (the 0.3 precedent). The context phrase "no second queue" is satisfied by one claim/lease pattern and one worker shape, not one table. Enqueue happens inside `AuditRepo::append`.
3. **CIMD storage.** Materialised `client` rows instead of the `client_metadata_cache` table named in ARCHITECTURE §6.1 (update the doc).
4. **CIMD http loopback in development mode.** Allowed only through the existing `OutboundPolicy` dev-mode rules (allow-listed loopback). This matches the draft's dev/test allowance. In production, https is required.
5. **SQLite backup method.** `VACUUM INTO`. The C backup API is not exposed by sqlx and would need `unsafe`.
6. **YAML surfaces.** JSON in the admin API, YAML only in the CLI, CLI direct storage access (like `keys rotate`), deletes only with `--prune`.
7. **DCR `software_statement`.** Reject with `invalid_software_statement`.
8. **Telemetry IPs.** No client IPs in operational logs, spans or metrics. The audit log keeps them.
9. **Packaging.** Redis/OTel/metrics compiled into the one binary and turned on by runtime config. Update the ARCHITECTURE §2 `otel` feature note.
10. **Load tool / LB.** k6 + HAProxy in compose. Perf and HA run on push to main, nightly and on dispatch, not on every PR.

## Open Questions (owner decision needed)

1. **Q1 — What does DCR "allow-listed" mean?**
   - Recommendation: an admin-issued **initial access token** is required (RFC 7591 §3: "required when the authorization server limits the parties that can register"). Optionally, all redirect-URI hosts must also be in a tenant allow-list.
   - Alternative: host allow-list only, with no token.
   - The choice changes the admin API (initial-access-token CRUD) and the console.
2. **Q2 — Where is "4 vCPU" measured?**
   - Public GitHub runners have 4 vCPU total, shared by k6, Postgres and anvilid.
   - Options:
     - (a) accept the shared 4-vCPU runner as a stricter-than-spec environment;
     - (b) a larger hosted runner (cost);
     - (c) a self-hosted runner.
   - Gate policy: median of 3 runs?
   - Without a decision the gate may flake or may be unachievable.
3. **Q3 — Does 0.4 RBAC also govern console administrators?**
   - ARCHITECTURE §10.3 says system-tenant users are admins "until RBAC (0.4)".
   - Recommendation: system-tenant roles map to admin scopes (read-only vs full admin), and the console token's scopes are intersected with the user's role permissions. Tenant-restricted admins wait for Phase 6 (ADM-02).
   - Alternative: RBAC for end-user tokens only, with console admins unchanged in 0.4.
4. **Q4 — Webhook payload content.**
   - Recommendation: thin payloads (ids, type, actor kind). Integrators fetch details via the admin API, and no PII goes to third parties.
   - Alternative: include email/name. That is convenient, but it is PII outside the system, and the endpoint secrets then protect PII.
5. **Q5 — Infrastructure connections and the "one outbound client" rule.**
   - The OTLP exporter needs its own HTTP client (blocking reqwest from the workspace). Collectors are usually on loopback or a private network over plain http, which `OutboundClient` blocks by design.
   - Redis and the local `healthcheck` probe are also not `OutboundClient` traffic.
   - Recommendation: treat these like SMTP (lettre) and Postgres, as operator-configured infrastructure. Document the exception in ARCHITECTURE §11. `OutboundClient` stays mandatory for every URL supplied by a tenant admin, client or user.
6. **Q6 — "AnvilID-consistent export" for Postgres.**
   - Recommendation for 0.4: pg_dump/PITR guidance plus the tenant YAML export (configuration). The command fails explicitly on Postgres.
   - A full logical data export (users, credentials) overlaps ADM-09 (1.0). Confirm it is not expected in 0.4.
7. **Q7 — KEK rotation.**
   - "Rotate keys" is met by the existing signing-key rotation plus webhook/client secret rotation.
   - KEK rotation re-seals every sealed column and invalidates the KEK-derived HMACs (recovery codes, email codes).
   - Recommendation: defer, and document the limitation.
8. **Q8 — Redis failure mode for non-auth classes.**
   - Locked: auth endpoints fail closed.
   - Recommendation: `token`, `admin` and `default` fall back to the node-local in-process limiter (same implementation), so a Redis outage does not stop token issuance.
   - Alternative: everything fails closed.
9. **Q9 — v0.3.0 tag still pending (04-33 checkpoint).**
   - The 0.3→0.4 upgrade test and the release gate assume 0.3 is released. Phase 5 can start on main, but the owner checklist/tag should land before the 0.4 gate.
10. **Q10 — Default CIMD policy.**
    - Recommendation: `disabled` by default, like DCR (secure default). The tenant settings and docs show how to set `open` or an allow-list for MCP use.
    - Confirm, because the MCP experience then needs one admin step per tenant.

## Suggested plan decomposition (discretion; maximizes parallelism)

**Shared-file ownership:**
- `Cargo.toml`/`Cargo.lock`, `anvil-core/src/model/*`, `ports.rs`, `anvil-storage/src/contract/*` → 05-01.
- `anvilid/src/config.rs`, `anvil-web/src/config.rs`, `anvilid/src/main.rs` telemetry wiring → 05-02.
- Migrations → 05-04 (SQLite 0007) / 05-05 (Postgres 0006).
- OpenAPI regen → at most one plan per wave.
- Login-engine files → one plan (passkey enrolment).
- `admin-ui` route tree → 05-07 first, then feature pages.

| Wave | Plan | Scope | Reqs |
|---|---|---|---|
| 1 | 05-01 Core model + ports + contract suite + all new workspace deps | model {role, attribute, webhook, registration (client source/RAT/CIMD expiry), consent resources, tenant settings: dcr/cimd policy, claim mapping, attribute defs}, ports (RoleRepo, WebhookRepo, audit append with webhook event, AttributeSchemaCheck, ClientMetadataFetcher), contract tests; backends return `Unsupported` until wave 2 (Phase 2/4 precedent); deny/deps pass | foundation |
| 1 | 05-02 Installation config + observability plumbing | config keys (`redis_url`, `rate_limit_redis_failure`, `metrics_listen`, `metrics_on_main_port`, `otel_endpoint`, `otel_service_name`, `shutdown_drain`, `database_max_connections`), metrics recorder + `/metrics`, OTel layer, request span/log layer with route templates, drain on SIGTERM, `/readyz`, pool size, idle-memory gate in measure-idle.sh | OPS-08, OPS-03 |
| 1 | 05-03 CI hygiene + load/HA harness skeleton | fuzz `cargo check` in ci.yml + push paths, 413 unification, tests/load (k6 scripts, run-perf.sh/run-ha.sh), deploy/compose/ha, `.github/workflows/load.yml` (initially reporting, gating at 05-2x) | QUAL-05, OPS-03 |
| 2 | 05-04 SQLite 0007 + repos | role, role_assignment, webhook_endpoint, webhook_delivery, initial_access_token, client columns, consent resources, attributes/settings; upgrade test 0.3→0.4 | foundation |
| 2 | 05-05 Postgres 0006 + repos | same, SKIP LOCKED claims | foundation |
| 2 | 05-06 Redis limiter backend + limiter contract suite | anvil-cache redis.rs, Lua scripts, key hashing, circuit breaker, contract on both backends (testcontainers redis) | OPS-03 |
| 2 | 05-07 Console multi-tenant refactor | `$tenant` routes, switcher, tenants list/create, redirects, e2e path updates | ORG-01 |
| 2 | 05-08 Pure core pieces | oauth/registration.rs, oauth/cimd.rs, policy/claims_mapping.rs, policy/webhook_event.rs, service/config plan (pure), webhook signature in anvil-jose + unit/proptests + fuzz targets | OIDC-17, AGT-02, ORG-05, ADM-05/06 |
| 2 | 05-09 Helm chart + compose examples + deploy CI | deploy/helm, deploy/compose/{postgres,observability}, deploy.yml (lint, kubeconform, ct on kind, compose smoke) | OPS-09 |
| 3 | 05-10 RBAC end to end + consent resources | service/role.rs, claims provider, admin/roles.rs (**OpenAPI owner wave 3**), consent upsert/screen re-prompt | ORG-05 |
| 3 | 05-11 Webhook worker | adapters/webhook.rs, jobs.rs registration, delivery classification, sink-based integration tests | ADM-05 |
| 3 | 05-12 CIMD resolver + fetcher + discovery | service/client_resolver.rs wiring at authorize/token/revoke/introspect/logout, adapters/cimd.rs, limiter key, discovery flag, consent host display | AGT-02, AGT-01 |
| 3 | 05-13 Limiter wiring + failure modes | anvilid limiter selection, 503 on fail-closed, metrics, security tests | OPS-03 |
| 3 | 05-14 CLI backup/restore + admin recover + healthcheck | anvilid/src/{backup,recover,healthcheck}.rs, cli tests | ADM-07, OPS-07 |
| 3 | 05-15 Perf work | signer cache, optional aws-lc RSA signing, host negative cache; local micro-bench | QUAL-05 |
| 4 | 05-16 Custom attributes | jsonschema adapter, service/attribute.rs, admin/attributes.rs (**OpenAPI owner wave 4**), account page editable attributes, claims | AUTH-14 |
| 4 | 05-17 DCR + RFC 7592 + initial access tokens | protocol/registration.rs, service/registration.rs, admin routes folded into 05-16's OpenAPI regen or wave 5, discovery `registration_endpoint` | OIDC-17 |
| 4 | 05-18 Passkey enrolment under `required` | login engine chain | carry-over |
| 4 | 05-19 Declarative config | service/config apply via services, admin/config.rs, anvilid tenant export/plan/apply (serde-saphyr), JSON Schema doc | ADM-06 |
| 5 | 05-20 Webhooks admin API + console (endpoints, secret rotate, delivery log, test/redeliver) (**OpenAPI owner wave 5**) | | ADM-05 |
| 5 | 05-21 Console: roles, attributes, registration policy + IATs, config download/plan view | admin-ui | ORG-05, AUTH-14, OIDC-17, ADM-06 |
| 5 | 05-22 MCP e2e + docs | tests/mcp mock client + RS (RFC 9728 doc, WWW-Authenticate), e2e spec CIMD + resource, docs/MCP.md | AGT-01, AGT-02 |
| 5 | 05-23 HA + perf gates green in CI | load.yml gating, concurrent-start fixes, telemetry redaction test | OPS-03, QUAL-05, OPS-08 |
| 6 | 05-24 e2e + docs | e2e specs (tenants, roles claims, attributes, webhooks via sink, DCR, passkey enrol), UPGRADING 0.3→0.4, OPERATIONS.md, ARCHITECTURE updates (§2, §6.1, §10.3, §10.5, §11, §13, §14, §15, §18) | all |
| 7 | 05-25 Gate | QUAL-01 security map (DCR, CIMD, webhooks SSRF/signature, IAT, RAT, attribute schema, limiter fail-closed, config secret refs, backup restore guard), `just ci`, e2e both backends, conformance all, load/deploy workflows green, release 0.4.0 + pinned migrations | all |

Critical path: 05-01 → 05-04/05 → 05-10/05-12 → 05-17/05-19 → 05-21/05-22 → 05-24 → 05-25.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `cargo test` (unit; storage contract via `storage_contract_tests!`; new limiter contract in `anvil-cache`; HTTP integration in `anvil-web/tests`; binary tests in `anvilid/tests`), proptest, insta, wiremock, testcontainers (Postgres + Redis); Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance`); **new:** k6 (load/HA), chart-testing + kind, docker compose smoke |
| Config file | `justfile`, `tests/e2e/playwright.config.ts`, `scripts/check-security-tests.sh`, new `tests/load/*.js`, `deploy/helm/anvilid/ci/*.yaml`, `ct.yaml` |
| Quick run command | `cargo test -p anvil-core --lib` / `cargo test -p anvil-web --test <file>` / `cargo test -p anvil-cache --test limiter` |
| Full suite command | `just ci` + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all` + (CI only, Docker) `tests/load/run-perf.sh`, `tests/load/run-ha.sh`, deploy workflow |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ORG-01 | create/list/switch tenants in the console; each tenant's discovery has its own issuer; host tenant resolves | e2e + integration | `tests/e2e/run.sh sqlite specs/console-tenants.spec.ts`; `cargo test -p anvil-web --test discovery` | ❌ spec / ✅ discovery.rs (extend) |
| ORG-05 | role CRUD + assignment, cross-tenant assignment refused, roles/permissions claims per mapping and scope, refresh reflects changes, claim-name collision rejected | contract + unit + integration | `cargo test -p anvil-storage-sqlite --test contract roles`; `cargo test -p anvil-core policy::claims_mapping`; `cargo test -p anvil-web --test rbac_claims` | ❌ |
| ORG-05 (carry-over) | consent remembers resources; new resource re-prompts; revoke still revokes families | contract + integration | `cargo test -p anvil-web --test consent` (extend) | ✅ extend |
| ADM-05 | event mapping table; enqueue in the audit transaction only for subscribed enabled endpoints; v1 signature vector; 2xx/410/429/5xx classification; retry schedule; give-up audited; SSRF-blocked URL refused at create and send; secret sealed + write-only; no double delivery under concurrent claims | unit + contract + integration | `cargo test -p anvil-core policy::webhook_event`; `cargo test -p anvil-jose webhook`; `cargo test -p anvil-storage-sqlite --test contract webhooks`; `cargo test -p anvil-web --test webhooks` / `--test security_webhooks` | ❌ |
| ADM-06 | export → apply on a fresh instance round-trips; re-apply = empty plan; deletes only with prune; secrets never in export; env/file refs never resolved server-side; invalid doc rejected before any change | unit + integration + binary | `cargo test -p anvil-core service::config`; `cargo test -p anvil-web --test admin_config`; `cargo test -p anvilid --test tenant_config` | ❌ |
| ADM-07 / OPS-07 | backup while serving produces a consistent DB; restore refuses while serve.lock held, refuses newer migration version; Postgres backup errors explicitly; admin recover issues a one-time URL, audited, resets MFA only with flag; healthcheck refuses non-loopback | binary | `cargo test -p anvilid --test backup` / `--test admin_recover` / `--test healthcheck` | ❌ |
| OIDC-17 | policy disabled → 404 + no metadata; allow-listed without/with bad IAT → 401; open works; validation errors (redirect, grant, auth method, scopes, resources, software_statement); RAT required for 7592 GET/PUT/DELETE, wrong RAT → 401; system tenant always disabled; rate limit | unit + integration | `cargo test -p anvil-core oauth::registration`; `cargo test -p anvil-web --test registration` / `--test security_registration` | ❌ |
| AGT-01 | discovery via RFC 8414 path insertion for path tenants; code+PKCE+`resource` yields `aud` = MCP server; mock RS validates aud and RFC 9728 document | integration + e2e | `cargo test -p anvil-web --test resource_indicators` (extend); `tests/e2e/run.sh sqlite specs/mcp.spec.ts` | ✅ extend / ❌ spec |
| AGT-02 | CIMD URL rules; doc rules (client_id mismatch, secret fields, shared-secret method, jwks+jwks_uri, empty grant intersection); 5 KiB cap; no redirects; private IP blocked; policy/allow-list before fetch; cache honours max-age, errors not cached; fetch failure never redirects; discovery flag per policy | unit + integration | `cargo test -p anvil-core oauth::cimd`; `cargo test -p anvil-web --test cimd` / `--test security_cimd` | ❌ |
| AUTH-14 | admin schema meta-validated and size-capped; remote `$ref` refused; regex engine linear; writes validated (admin, account page); non-editable attribute refused from account page; claims released per mapping; stored invalid value not emitted | unit + integration + e2e | `cargo test -p anvil-web attribute_schema`; `cargo test -p anvil-web --test attributes` / `--test security_attributes`; `specs/attributes.spec.ts` | ❌ |
| OPS-03 | limiter contract identical on both backends (GCRA burst/refill, backoff, loose tier); Redis down → auth 503 fail closed, others per Q8; concurrent first start of 3 nodes; restarts under load 0 errors; shared quota across nodes | contract + integration + HA (CI) | `cargo test -p anvil-cache --test limiter_contract`; `cargo test -p anvil-web --test security_ratelimit` (extend); `tests/load/run-ha.sh` | ❌ / ✅ extend / ❌ |
| OPS-08 | /health/live, /health/ready, /healthz, /readyz; /metrics content and no tenant/client/IP labels; spans exported to in-memory exporter with route templates; redaction across logs, spans, metrics | integration + binary | `cargo test -p anvil-web --test health_metrics`; `cargo test -p anvilid --test telemetry_redaction` | ❌ |
| OPS-09 | helm lint/template/kubeconform; ct install on kind (SQLite and Postgres values); compose example up → ready, metrics, JSON log, collector span | CI | `.github/workflows/deploy.yml` (`ct lint`, `ct install`, compose smoke script `deploy/compose/smoke.sh`) | ❌ |
| QUAL-05 | ≥1000 req/s, p99 < 50 ms, 0 failures, 0 dropped iterations; idle RSS < 100 MB | perf (CI) | `tests/load/run-perf.sh` (k6 thresholds); `just measure <bin> <target>` with gate | ❌ / ✅ measure (add gate) |
| carry-over | passkey enrolment under `required`: choice shown, passkey ceremony completes, amr/acr MFA, abandon/replay of the challenge refused | integration + e2e | `cargo test -p anvil-web --test flow_mfa_policy` (extend); `specs/mfa-policy.spec.ts` (extend, virtual authenticator) | ✅ extend |
| carry-over | streamed oversized body → 413 on every route family | integration | `cargo test -p anvil-web --test security_body_limit` (tighten) | ✅ tighten |
| carry-over | fuzz crate builds on push | CI | `cargo check --manifest-path fuzz/Cargo.toml --locked --bins` in ci.yml | ❌ |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate> --lib` plus the specific `--test <file>` touched (each < 30 s). Redis/Postgres testcontainer tests: skip locally when Docker is down and say so (CONTEXT).
- **Per wave merge:** `just ci` (includes `test-pg`, security map, console check, release graph).
- **Phase gate:** `just ci` green; e2e sqlite + postgres green; conformance `all` green with no expected failures; `load.yml` (perf + HA) and `deploy.yml` green on the release commit in CI, with the numbers recorded; then `/gsd:verify-work`.

### Wave 0 Gaps
- [ ] `crates/anvil-storage/src/contract/{roles,webhooks,registration}.rs` + extensions to `consent.rs`, `clients.rs` (CIMD/DCR fields), `audit.rs` (webhook enqueue in append): 05-01
- [ ] `crates/anvil-cache` feature `contract` + `tests/limiter_contract.rs` instantiating the suite for both backends; testcontainers `redis` feature
- [ ] `crates/anvil-web/tests/support`: webhook sink (wiremock) helper, CIMD document server helper (wiremock + dev-mode allow-list), DCR/IAT helpers, role/attribute fixtures
- [ ] `crates/anvilid/tests/support` for backup/restore/recover and telemetry capture (in-memory span exporter, capturing writer, local metrics recorder)
- [ ] `tests/load/` k6 scripts + `run-perf.sh` / `run-ha.sh`; `deploy/compose/ha/` with HAProxy config; `.github/workflows/load.yml`
- [ ] `deploy/helm/anvilid/ci/{sqlite,postgres}-values.yaml`, `ct.yaml`, `.github/workflows/deploy.yml`, `deploy/compose/smoke.sh`
- [ ] `tests/mcp/` mock MCP client + resource server (Node, zero deps) and `tests/e2e/specs/mcp.spec.ts`
- [ ] Fuzz targets `registration_parse`, `cimd_parse`, `tenant_config_parse` + the ci.yml `cargo check` job
- [ ] `scripts/check-security-tests.sh`: entries for every new control (DCR policy/IAT/RAT, CIMD rules + SSRF, webhook signature/SSRF/secret write-only, attribute schema offline/regex, limiter fail-closed, config secret refs, restore guards, admin recover locality)
- [ ] `scripts/measure-idle.sh`: < 100 MB gate

## Sources

### Primary (HIGH confidence)
- Local codebase at `42f6775`: `anvil-cache/src/limiter/*`, `anvil-web/src/{adapters/outbound.rs, adapters/backchannel.rs, layers/ratelimit.rs, tenant.rs, health.rs, protocol/discovery.rs, admin/mod.rs, lib.rs}`, `anvil-core/src/{ports.rs, service/{audit,bootstrap,key,token,consent,claims}.rs, model/*}`, `anvilid/src/{main,jobs,keys,storage}.rs`, both migration sets, `admin-ui/src`, `deny.toml`, `scripts/{check-deps,check-release-graph,measure-idle,docker-image}.sh`, `.github/workflows/*`, `fuzz/Cargo.toml`, `.planning/STATE.md`, Phase 4 summaries (04-32, 04-36)
- jsonwebtoken 12.0.0 source (local registry): `src/crypto/aws_lc/rsa.rs` (`RsaKeyPair::from_der` per sign)
- sqlx-sqlite 0.9.1 source (local registry): no backup API; `serialize`/`deserialize` only
- Crate manifests downloaded from crates.io (2026-11-26): redis 1.8.3 (features, optional deps, `ClientConfig::builder()` in `src/connection.rs`, ConnectionManagerConfig setters), opentelemetry-otlp 0.33.1, opentelemetry-http 0.33.1, opentelemetry_sdk 0.33.1 (`testing` feature), tracing-opentelemetry 0.34.0, metrics-exporter-prometheus 0.18.3, serde-saphyr 2.2.0, jsonschema 0.63.1; crates.io API versions for all listed crates; testcontainers-modules 0.15.0 manifest (`redis`, `valkey` features)
- [draft-ietf-oauth-client-id-metadata-document-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (2026-11-02)
- [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/latest/basic/authorization), [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration.md), [Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery.md)
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) (Experimental), [RFC 9068 §2.2.3](https://www.rfc-editor.org/rfc/rfc9068.html)
- [Standard Webhooks spec](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
- [opentelemetry-otlp 0.33.1 docs](https://docs.rs/opentelemetry-otlp/0.33.1/opentelemetry_otlp/) (blocking client with batch processor; env vars)
- [jsonschema 0.63.1 docs](https://docs.rs/jsonschema/0.63.1/jsonschema/) (PatternOptions, offline, draft202012, meta)
- [RustSec serde_yml](https://rustsec.org/packages/serde_yml.html) (RUSTSEC-2025-0068)
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) (public: 4 vCPU / 16 GB)
- [nginx proxy_next_upstream](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- GitHub releases API (2026-11-26): chart-testing-action v2.9.0, kind-action v1.15.2, chart-testing v3.15.0, kind v0.33.0, helm v4.3.2, setup-helm v5.1.0, k6 v2.4.0, oha v1.17.0, kubeconform v0.8.0

### Secondary (MEDIUM confidence)
- [chart-testing-action README](https://github.com/helm/chart-testing-action) (inputs, kind example; Helm 4 not mentioned)
- [k6 constant-arrival-rate](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/) (options; `dropped_iterations` from general k6 knowledge)
- metrics-exporter-prometheus `run_upkeep` requirement without the listener, and summary-vs-histogram default (from crate knowledge; verify in docs when implementing)
- HAProxy `option httpchk` / `retry-on` defaults (standard configuration knowledge; verify against the HAProxy version pinned)

### Tertiary (LOW confidence, flagged for validation)
- Cost of `RsaKeyPair::from_der` per signature in aws-lc (profile before optimising)
- The exact governor `allow_burst` vs the GCRA tolerance off-by-one (pin with the contract suite)
- Whether the distroless static image's CA bundle satisfies `rustls-native-certs` for `rediss://`
- Whether `opentelemetry-proto` `gen-tonic-messages` pulls tonic into the graph (harmless for crypto; check `cargo tree`)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions and feature graphs come from the published manifests. No ring or second TLS backend is introduced by the recommended feature sets (redis uses `default-features = false` rustls plus `ClientConfig::builder()`; otlp/http uses workspace reqwest; the prometheus exporter has default features off).
- Architecture: HIGH. Derived from the actual code (limiter trait, outbound client, delivery worker, audit choke point, tenant layer, console constant).
- Specs (DCR, CIMD, MCP, Standard Webhooks): HIGH. Read at the primary sources today.
- Performance/HA tuning: MEDIUM. Reasoned from code paths and LB semantics; needs CI measurement (Q2).
- Pitfalls: HIGH for codebase-derived ones (quotas, signer re-parse, console constant, distroless, concurrent start); MEDIUM for LB/metrics operational details.

**Research date:** 2026-11-26
**Valid until:** 2026-12-26. CIMD is an active draft (-03), MCP revises its spec periodically, and OTel crates release often; re-check versions before 05-01 if more than two weeks have passed.
