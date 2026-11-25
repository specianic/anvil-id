# AnvilID — Architecture & Implementation Specification

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Last updated** | 2026-11-25 |
| **Implements** | [PRD.md](PRD.md). Requirement IDs (e.g. `OIDC-3`) refer to it |

This document is the build plan. It fixes the technology choices, the code structure, the data model,
the security controls and the milestones. Anything not decided here is listed in §20 (Open decisions)
and must be resolved, and recorded here, before the code that depends on it is written.

---

## 1. Architectural principles

1. **Single binary, modular inside.** One executable (`anvilid`) contains every module. Modules are
   Rust crates with explicit dependency rules (§4), not network services.
2. **Pure core, thin edges.** Protocol and domain logic (`anvil-core`) does no I/O. It operates on
   traits for storage, cache, clock, randomness and crypto. HTTP handlers translate requests into
   core calls and core results into responses, and contain no business logic.
3. **Stateless nodes.** All durable state is in the database. Any node can serve any request. HA
   means running more nodes on Postgres.
4. **Atomicity where security depends on it.** Single-use artifacts (authorization codes, refresh
   tokens, recovery codes, nonces) are consumed in one atomic database operation.
5. **Secure defaults, no unsafe toggles.** Insecure behavior (plain PKCE, implicit flow, wildcard
   redirects, `alg: none`) is not configurable because it is not implemented.
6. **Everything observable.** Every request has a trace ID, every security event is audited, and
   every subsystem exports metrics.

## 2. Technology stack

Versions are the latest stable releases as of the date above. Pin them in the workspace
`Cargo.toml` and update them deliberately.

| Concern | Choice | Notes |
|---|---|---|
| Language | Rust (edition 2024), stable toolchain pinned in `rust-toolchain.toml` | See §2.1 for the conditions this choice depends on |
| Async runtime | tokio | |
| HTTP | axum 0.8, tower, tower-http | rustls for TLS when terminating TLS ourselves |
| Crypto backend | **aws-lc-rs** (single backend) | RSA, ECDSA P-256, Ed25519, AES-GCM, HKDF, CSPRNG. FIPS build available later |
| JWT/JWS | jsonwebtoken 12 with the `aws_lc_rs` feature, wrapped by our `anvil-jose` crate | The wrapper enforces algorithm allow-lists per key and computes RFC 7638 `kid`s |
| Database | sqlx 0.9: SQLite (bundled) and PostgreSQL | Two typed implementations of one storage trait (§7). `sqlx::Any` is not used |
| Cache | moka (in-process), redis 1.x (optional) | Behind a `Cache` trait |
| Passwords | argon2 (Argon2id), run on a bounded blocking pool | |
| Passkeys | webauthn-rs 0.6 | Challenge state kept server-side only |
| TOTP | totp-rs 6 | Last-used time step stored to prevent replay |
| Email | lettre 0.11 (rustls) | Outbox table + background sender |
| Templates | minijinja 3 | Login pages: embedded defaults, overridable from a theme directory at runtime |
| Admin UI | React + TypeScript, built with Vite as a static single-page app; TanStack Router and Query; shadcn/ui (Radix) components; TanStack Table. Embedded with rust-embed | Talks only to the public management API. TypeScript types and API client generated from the OpenAPI spec (`openapi-typescript`), so API drift fails the build. No server-side rendering (no Next.js) |
| Config | figment (TOML file + `ANVILID_*` env vars + CLI flags) | |
| CLI | clap 4 | |
| Observability | tracing, tracing-subscriber (JSON), metrics + Prometheus exporter; OpenTelemetry behind the `otel` feature | |
| Rate limiting | governor, with our own keyed limiter (§11) | One limiter implementation |
| HTTP client | reqwest 0.13 (rustls) with SSRF guard | Upstream IdPs, JWKS fetch, webhooks, client metadata documents |
| Time | `time` crate only | `chrono` is banned to avoid mixed types |
| IDs | UUIDv7 | Time-ordered primary keys |
| OpenAPI | utoipa | Spec generated from handler annotations; checked in CI |
| Testing | proptest, insta, wiremock, testcontainers, Playwright, OpenID conformance suite | |
| Supply chain | cargo-deny, cargo-audit, cargo-auditable | |
| Release | cargo-dist, static musl builds (amd64, arm64), mimalloc allocator, distroless image | |

**Banned dependencies** (enforced with cargo-deny): `openssl`, `native-tls`, `ring` as a second crypto
backend, the RustCrypto `rsa` crate for private-key operations (unpatched timing side channel),
`chrono`, `samael`/`xmlsec` (C XML security libraries), `oxide-auth`.

"Single crypto backend" applies to **our own** signing, encryption and key handling: all of it goes
through aws-lc-rs. One exception is accepted: webauthn-rs pulls in RustCrypto crates (via
`crypto-glue`, including `rsa`) for verifying authenticator signatures. Verification uses public keys
only, so the `rsa` timing side channel does not apply. This exception is scoped in `deny.toml` with a
`wrappers = ["crypto-glue"]` entry, so no other crate can use `rsa`.

### 2.1 Conditions on the Rust choice

Rust is chosen on these conditions. If any of them proves unworkable during M0, revisit the language
decision before M1 starts.

1. The OpenID conformance suite runs in CI from M1 onward.
2. One crypto backend (aws-lc-rs) builds statically for musl on amd64 and arm64.
3. Two sqlx storage implementations stay manageable (the M0 spike measures this).
4. SAML ships as an experimental feature until a pure-Rust XML-DSig stack passes an
   attack corpus (§20, D4).

## 3. Deployment topologies

```
 Dev / small             Production, single node        Production, HA
 ─────────────           ─────────────────────          ───────────────────────────────
 anvilid serve           anvilid serve                   LB ─┬─ anvilid ─┐
   └─ SQLite file          └─ PostgreSQL                     ├─ anvilid ─┼─ PostgreSQL
                                                             └─ anvilid ─┘   (+ optional Redis)
```

- **SQLite mode** is single-node. The binary takes an exclusive file lock on the database at startup
  and refuses to start a second instance on the same file.
- **Postgres mode** supports any number of nodes. Coordination happens through the database: advisory
  locks for migrations, row leasing (`FOR UPDATE SKIP LOCKED`) for background jobs.
- **Redis** is optional in HA mode. Without it, rate limits are enforced per node (documented). With
  it, they are shared.
- TLS is normally terminated by a reverse proxy. `anvilid` can also terminate TLS itself
  (rustls, certificate files).

## 4. Code structure

Cargo workspace:

```
crates/
  anvil-core/              Domain model, protocol state machines and the storage port traits
                           (`anvil_core::ports`). No I/O, no axum, no sqlx.
  anvil-jose/              JWK/JWS/JWT, key generation, signing-key lifecycle helpers.
  anvil-storage/           Shared storage contract test suite (feature `contract`) and
                           backend-agnostic helpers.
  anvil-storage-sqlite/    sqlx SQLite implementation + its own migrations/ directory.
  anvil-storage-postgres/  sqlx Postgres implementation + its own migrations/ directory.
  anvil-cache/             Cache trait, moka and redis implementations, keyed rate limiter.
  anvil-web/               axum routers, extractors, middleware, templates, embedded assets.
  anvil-mail/              Email rendering + SMTP transport + outbox worker.
  anvilid/                 The binary: config, CLI, wiring, background scheduler.
admin-ui/                  React admin console (built separately with Vite, embedded at release).
themes/default/            Default login templates and CSS (embedded; overridable).
tests/
  conformance/             OpenID conformance suite harness (CI).
  e2e/                     Playwright tests for the login UI and admin console.
docs/
```

**Dependency rules** (checked in CI with a small script over per-crate `cargo tree -p` output; `cargo metadata` unifies features across the workspace and gives false positives):

- `anvil-core` depends only on `anvil-jose` and pure libraries (serde, time, uuid, url, thiserror,
  async-trait).
- `anvil-storage-*` normal-depend on `anvil-core` (for the ports and domain types) and sqlx, never on
  `anvil-web`. They use `anvil-storage` only as a dev-dependency, for the contract suite.
- `anvil-web` depends on `anvil-core` (including the storage ports), `anvil-cache`, `anvil-mail`.
  It never imports a concrete storage crate.
- Only `anvilid` (the binary) knows the concrete storage and cache implementations.

Rules apply to normal (non-dev) dependencies. `anvil-web` may dev-depend on concrete storage crates
so HTTP and security tests run on both backends (QUAL-02); it never normal-depends on them.

Later modules (federation, directory, permissions, gateway) become crates of their own following the
same pattern: logic in a no-I/O crate, endpoints in `anvil-web`.

## 5. Request handling architecture

```
HTTP request
  → tower layers: request ID, trace span, timeout, body limit, security headers,
                  tenant resolution, rate limit (per route class)
  → axum handler (anvil-web): parse + validate input, load session/client context
  → anvil-core service: protocol/domain decision, using Storage + Cache + Clock + Rng traits
  → result → handler maps it to a response (redirect, JSON, rendered page, OAuth error)
  → audit event emitted by the core service, written via Storage (same transaction when possible)
```

**Core services** (in `anvil-core`, each a struct holding trait objects):

| Service | Responsibility |
|---|---|
| `AuthorizeService` | Validate authorization requests, resolve client/redirect/scope/PKCE, decide between login, consent and code issuance |
| `TokenService` | All grants at `/token`: code exchange, refresh rotation, client credentials, later device/token exchange |
| `ClientAuthenticator` | The single implementation of client authentication (all methods) |
| `FlowEngine` | Login, registration, recovery, verification and settings flows as explicit state machines (§9) |
| `SessionService` | Browser sessions, authentication levels (`acr`, `amr`), RP session tracking for logout |
| `ConsentService` | Grant records, remembered consent, revocation |
| `KeyService` | Signing-key lifecycle, JWKS assembly |
| `UserService`, `ClientService`, `TenantService`, `OrgService` | CRUD behind the management API, with validation and audit |
| `AuditService` | Typed audit events |

**Error model.** Each service returns `Result<T, CoreError>`, where `CoreError` maps
deterministically to an OAuth error code (`invalid_request`, `invalid_grant`, …), an HTTP status, or a
user-facing flow message. Handlers never construct OAuth errors by hand.

## 6. Data model

All tables (except installation-wide ones) carry `tenant_id`, and every storage method takes a
`TenantId`. Isolation is enforced by the storage layer API; it is impossible to query across tenants
from handler code.

### 6.1 Entities (1.0 scope)

| Entity | Key fields | Notes |
|---|---|---|
| `tenant` | id, slug, display_name, issuer_mode (path/host), host, settings (JSON), created_at | One `default` tenant created at bootstrap |
| `user` | id, tenant_id, email, email_verified, phone, phone_verified, username, attributes (JSON, validated against the tenant's schema), status (active/blocked), created_at, updated_at, last_login_at | Unique (tenant_id, lower(email)); unique (tenant_id, username) |
| `credential` | id, tenant_id, user_id, kind (password/webauthn/totp), data (encrypted or hashed per kind), counter (integer, nullable), label, created_at, last_used_at | Password: PHC string. TOTP: encrypted seed; `counter` = last accepted time step. WebAuthn: credential JSON; `counter` = signature counter. Counters are plain columns so replay and clone checks are a single conditional `UPDATE … WHERE counter < ?` |
| `recovery_code` | id, tenant_id, user_id, code_hash, created_at, used_at | One row per code, consumed atomically (`UPDATE … SET used_at … WHERE used_at IS NULL`) |
| `identity_link` | id, tenant_id, user_id, provider_id, subject, email_at_link, created_at | Upstream identities (social/enterprise). Unique (tenant_id, provider_id, subject) |
| `client` | id, tenant_id, client_id, name, type (confidential/public), auth_method, secret_hash, jwks / jwks_uri, redirect_uris, post_logout_redirect_uris, grant_types, scopes, token_format (jwt/opaque), consent_mode (required/skip_first_party), backchannel_logout_uri, branding (JSON), created_at | `client_id` is unique per tenant; URL-form client IDs (CIMD) are cached in `client_metadata_cache` |
| `signing_key` | id, tenant_id, kid, alg, state (next/active/retired), private_key (encrypted with KEK), public_jwk, activated_at, retired_at, expires_at | |
| `browser_session` | id, tenant_id, user_id, auth_time, acr, amr (JSON), ip, user_agent, created_at, last_seen_at, expires_at, idle_expires_at | Session cookie holds an opaque random ID; only its hash is stored |
| `rp_session` | browser_session_id, client_id, sid, created_at | Which clients the session logged in to (for back-channel logout) |
| `flow` | id, tenant_id, kind (login/registration/recovery/verification/settings/consent), state (JSON), csrf_hash, expires_at, browser_session_id? | Short-lived flow state machines (§9) |
| `authorization_request` | id, tenant_id, client_id, params (JSON: redirect_uri, scope, state, nonce, code_challenge, resource, prompt, max_age, acr_values…), created_at, expires_at | Created at `/authorize`, consumed when a code is issued. Also used for PAR |
| `authorization_code` | code_hash (PK), tenant_id, client_id, user_id, browser_session_id, redirect_uri, scope, nonce, code_challenge, resource, auth_time, acr, amr, expires_at, consumed_at, token_family_id? | |
| `token_family` | id, tenant_id, client_id, user_id?, scope, resource, created_at, revoked_at, revoked_reason | Groups a refresh-token chain; revoking the family revokes all of its tokens |
| `refresh_token` | token_hash (PK), tenant_id, family_id, parent_hash?, expires_at, consumed_at | Rotation: each use consumes the token and issues a child |
| `access_token` | token_hash (PK), tenant_id, family_id?, client_id, user_id?, scope, resource, expires_at, revoked_at | Only for opaque tokens; JWT access tokens are not stored. Revocation of a JWT revokes its family |
| `consent_grant` | id, tenant_id, user_id, client_id, scopes, resource?, created_at, revoked_at | |
| `role`, `role_assignment` | role: id, tenant_id, org_id?, name, permissions (JSON). assignment: role_id, user_id, org_id? | RBAC (ORG-5) |
| `organization`, `org_membership`, `org_invitation`, `org_domain`, `connection` | standard fields | 1.0 (ORG-2..4). `connection` = upstream IdP config (social/OIDC/SAML), tenant- or org-scoped, secrets encrypted |
| `audit_event` | id, tenant_id, at, actor (user/client/admin/system + id), action, target, outcome, ip, user_agent, trace_id, details (JSON) | Append-only; retention configurable |
| `email_outbox` | id, tenant_id, to, template, payload (JSON), attempts, next_attempt_at, sent_at, last_error | |
| `job_lease` | name, owner, leased_until | Background job coordination |
| `replay_guard` | tenant_id, kind (jti/dpop/nonce), value_hash, expires_at | `private_key_jwt` assertion `jti`s; later DPoP |
| `admin_setup_token` | token_hash, expires_at, used_at | One-time bootstrap URL (ADM-3) |

### 6.2 Storage of secrets

| Secret | At rest |
|---|---|
| User passwords | Argon2id PHC string |
| Client secrets, refresh/access tokens (opaque), authorization codes, session IDs, setup and recovery tokens, API keys | SHA-256 of a 256-bit random value. The plaintext is shown once and never stored |
| MFA recovery codes | ~80-bit random codes, formatted for typing (e.g. `XXXX-XXXX-XXXX-XXXX`), stored as HMAC-SHA-256 under a key derived from the KEK (a plain hash would be brute-forceable at this length). Shown once |
| TOTP seeds, upstream IdP client secrets, signing private keys, SAML SP keys | AES-256-GCM with a data key derived from the **key-encryption key (KEK)** via HKDF, using the table and row ID as associated data |

**KEK source:** the `ANVILID_KEK` env var or a key file. In zero-config dev mode the binary generates
a KEK into the data directory on first start and logs a warning telling the operator to back it up.
Losing the KEK makes encrypted columns unrecoverable; the docs say so prominently.

## 7. Storage layer

### 7.1 Traits

`anvil-core` defines the storage ports (`anvil_core::ports`): **repository traits grouped by
aggregate**, plus a transaction abstraction:

```rust
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn begin(&self) -> Result<Box<dyn Tx>, StorageError>;
    fn tenants(&self) -> &dyn TenantRepo;
    fn users(&self) -> &dyn UserRepo;
    fn clients(&self) -> &dyn ClientRepo;
    fn grants(&self) -> &dyn GrantRepo;       // authorization requests, codes, tokens, families, consent
    fn sessions(&self) -> &dyn SessionRepo;
    fn keys(&self) -> &dyn KeyRepo;
    fn flows(&self) -> &dyn FlowRepo;
    fn audit(&self) -> &dyn AuditRepo;
    fn jobs(&self) -> &dyn JobRepo;
    // later: orgs(), connections(), roles(), …
}
```

Repository methods express **intent**, not generic CRUD. The security-critical ones are atomic by
contract:

| Method | Contract | SQLite | Postgres |
|---|---|---|---|
| `GrantRepo::consume_code(tenant, code_hash, now)` | Returns the code only if it exists, is unexpired and unconsumed, **and marks it consumed in the same statement**. If it was already consumed, returns `AlreadyConsumed { family_id }` so the caller can revoke that family (OIDC-3) | `UPDATE … SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING *` | same |
| `GrantRepo::rotate_refresh(tenant, token_hash, new_token, now)` | Atomically consumes the presented token and inserts its child. If the presented token was already consumed, revokes the entire family and returns `ReuseDetected` (OIDC-5) | One transaction | One transaction |
| `UserRepo::create(tenant, user)` | Fails with `Conflict` on duplicate email/username (unique index), never "check then insert" | Unique index | Unique index |
| `GrantRepo::record_jti(tenant, jti_hash, exp)` | Insert-or-fail for replay prevention | `INSERT` with primary key | same |

### 7.2 Two implementations, one contract

- `anvil-storage-sqlite` and `anvil-storage-postgres` each use `sqlx::query!`/`query_as!` with their
  own `.sqlx/` offline metadata, so every query is compile-time checked against its real dialect.
- Native types per backend: Postgres `uuid`, `timestamptz`, `jsonb`; SQLite `STRICT` tables, UUIDs as
  `BLOB`, timestamps as integer Unix milliseconds, JSON as `TEXT`.
- **Storage contract test suite** (stays in `anvil-storage/src/contract/`, behind the `contract`
  feature): one set of async tests, generic over
  `Storage`, instantiated for SQLite (in-memory and file) and Postgres (testcontainers). It includes
  **concurrency tests**: N parallel `consume_code` calls must yield exactly one success; parallel
  refresh rotation must yield one success and one `ReuseDetected`.
- SQLite configuration: WAL mode, `busy_timeout`, `foreign_keys=ON`, one writer connection plus a
  reader pool.

### 7.3 Migrations

- Each storage crate's `migrations/` directory (`crates/anvil-storage-sqlite/migrations/`, `crates/anvil-storage-postgres/migrations/`) is embedded with `sqlx::migrate!` and run at
  startup (can be disabled with `--no-migrate`). They are guarded by an advisory lock (Postgres) or
  the exclusive file lock (SQLite).
- Migrations are forward-only and **expand/contract**: a release never drops or renames a column that
  the previous minor release still reads. Destructive cleanups happen one minor release later.
- CI test: create a database with release N-1's migrations and data fixtures, upgrade to N, run the
  contract suite.

### 7.4 Expiry and cleanup

Every expiring row has an `expires_at` column, and every read checks it, so correctness never depends
on cleanup. A background job deletes expired rows in batches (codes, flows, tokens, sessions,
replay guards).

## 8. Keys and token formats

### 8.1 Signing keys

- Each tenant has its own signing keys. The default algorithm is RS256 (required by OIDC) using
  RSA-2048. ES256 and Ed25519 can be enabled per tenant, and clients can request an algorithm through
  registration metadata (`id_token_signed_response_alg`).
- `anvil-jose` builds JOSE headers and JWKs itself rather than relying on jsonwebtoken's types,
  because jsonwebtoken cannot express the fully-specified `Ed25519` algorithm name (RFC 9864). It
  uses jsonwebtoken / aws-lc-rs only for the signature operations. Whether to also accept or emit the
  legacy `EdDSA` name for interoperability with older relying parties is decided in Phase 3.
- Lifecycle: `next` (published in JWKS, not yet signing) → `active` (signing) → `retired` (published
  until every token signed with it has expired) → deleted. Rotation runs as a scheduled job (default
  every 90 days) and on demand (`anvilid keys rotate`). The `next` key is published at least one
  JWKS cache lifetime before activation.
- `kid` = RFC 7638 JWK thumbprint.
- Only one key is `active` per (tenant, alg) at a time, enforced with a partial unique index.

### 8.2 Tokens

| Token | Format | Lifetime (default) |
|---|---|---|
| Authorization code | 256-bit random, base64url; stored hashed | 60 s |
| ID token | JWS. Claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `sid`, `at_hash`, plus scope-based claims | 1 h |
| Access token | RFC 9068 JWT (`typ: at+jwt`) **or** opaque 256-bit random (per client) | 10 min |
| Refresh token | Opaque 256-bit random; stored hashed; rotated on every use | 30 days absolute, 14 days idle |
| Logout token | JWS per OIDC Back-Channel Logout | 2 min |

- `sub` is the user's UUID by default (a pairwise identifier option comes later).
- The issuer is the tenant issuer URL (§12). It is computed in exactly one place.

## 9. Flow engine (login, registration, recovery, consent)

Self-service journeys are modeled as **explicit state machines** in `anvil-core::flow`:

```
Login flow:
  Start ──► IdentifierStep ──► (Password | Passkey | Upstream IdP | Email OTP)
        ──► [SecondFactor when MFA policy requires] ──► Authenticated
        ──► [Consent when required] ──► Complete (redirect back to the authorize continuation)
```

- Each flow is a row in `flow` with a typed state; transitions are pure functions
  `(state, input) -> (new_state, effects)`, which makes them easy to test exhaustively.
- **One engine, two renderers.** Every step produces a **form description** (fields, types,
  validation messages, available methods). The built-in UI renders it with minijinja templates
  (no JavaScript required for password flows). In 1.0, the headless JSON API (UI-5) returns the same
  description, so SPAs and native apps can render their own UI.
- Flows are bound to the browser by a flow cookie and a CSRF token (both hashed in the row) and
  expire after 15 minutes.
- The authorization request is stored separately (`authorization_request`). The login flow refers to
  it, so login, MFA and consent don't have to carry OAuth parameters through every form.

## 10. HTTP surface

Paths below are relative to the tenant base (§12).

### 10.1 Protocol endpoints

| Path | Purpose | PRD |
|---|---|---|
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | Discovery / RFC 8414 metadata | OIDC-8 |
| `GET /jwks` | JSON Web Key Set | OIDC-8 |
| `GET, POST /authorize` | Authorization endpoint | OIDC-1,2,14,16,24 |
| `POST /par` | Pushed authorization requests | OIDC-18 |
| `POST /token` | Token endpoint (all grants) | OIDC-3..6 |
| `GET, POST /userinfo` | UserInfo | OIDC-9 |
| `POST /introspect`, `POST /revoke` | RFC 7662 / RFC 7009 | OIDC-10 |
| `GET, POST /logout` | RP-initiated logout | OIDC-12 |
| `POST /register` | Dynamic client registration (policy-controlled) | OIDC-17 |

### 10.2 Built-in UI and flows

`/ui/login`, `/ui/registration`, `/ui/recovery`, `/ui/verification`, `/ui/consent`, `/ui/account/*`,
plus `/ui/assets/*` (hashed, immutable static files). The headless API mirrors these under
`/api/flows/*` (1.0).

### 10.3 Management API

`/api/admin/v1/…`, documented with OpenAPI 3.1 at `/api/admin/v1/openapi.json`.

- Authentication: OAuth access tokens issued by AnvilID itself, through client credentials (for
  automation) or the admin console's authorization code flow. Scopes: `admin:read`, `admin:write`,
  and per-resource scopes (`admin:users:write`, …).
- Installation-level administration (managing tenants) lives in a dedicated `system` tenant, so admin
  authentication uses the same machinery as everything else.
- The admin console SPA (`/console/`) is a public OAuth client of the `system` tenant and only calls
  this API.

### 10.4 How frontend assets ship in the binary

- **Admin console:** `admin-ui/` is built with `npm run build` into static files with content-hashed
  names. The build step pre-compresses them (brotli and gzip); `anvil-web` embeds the original and
  compressed variants at compile time with rust-embed and serves the best variant for the request's
  `Accept-Encoding` from memory (rust-embed's own `compression` feature does not do content negotiation) at `/console/*`: hashed files with immutable cache headers, every other
  path under `/console/` falls back to `index.html` for client-side routing.
- **Login UI:** templates and CSS in `themes/default/` are embedded the same way. At runtime minijinja
  loads templates from the operator's theme directory first (if configured) and falls back to the
  embedded defaults, so theming never requires recompiling.
- **Development:** run `anvilid serve` alongside the Vite dev server, which hot-reloads the console and
  proxies API calls to the Rust server. Debug builds can read assets from disk instead of the embedded
  copy.
- **Builds without Node:** if `admin-ui/dist` is missing, `cargo build` embeds a placeholder page that
  explains how to build the console. CI and release builds always build the console first and fail if
  it is missing.

### 10.5 Operational endpoints (installation-wide)

`/health/live`, `/health/ready` (checks the database), `/metrics` (can be bound to a separate
listener).

## 11. Cross-cutting security controls

| Control | Implementation |
|---|---|
| Redirect URI validation | Exact string match against registered URIs. The only exception is loopback redirects for native apps (any port, per RFC 8252). Validation happens **before** any redirect is issued. Invalid redirect → an error page, never a redirect |
| PKCE | Required by default for every client (`client.require_pkce = true`); only `S256` is accepted, `plain` is rejected. Only confidential clients may set `require_pkce = false`, and then `nonce` is mandatory for `openid` requests (RFC 9700 §2.1.1). If a client sends `code_challenge` at authorization, `code_verifier` is mandatory at the token endpoint (downgrade defense) |
| Client authentication | One `ClientAuthenticator`. Constant-time comparison (`subtle`) of hashed secrets. `private_key_jwt`: `aud` must equal the issuer, `exp` ≤ 5 min, `jti` recorded in `replay_guard` |
| CSRF | Synchronizer token per flow plus `Sec-Fetch-Site`/`Origin` checks on every state-changing browser request |
| Cookies | `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` (session) or `Strict` (flow). Dev mode on `http://localhost` drops the `__Host-`/`Secure` requirements with a warning |
| Rate limiting | One keyed limiter (`anvil-cache`) with route classes: `auth` (per IP + per account identifier), `token` (per client + per IP), `admin`, `default`. Account lockout uses progressive delays, not permanent locks (prevents trivial denial of service) |
| Brute-force on secrets | Argon2 verification runs on a bounded pool; login attempts against unknown users perform a dummy hash (constant-time behavior) |
| Response headers | Strict CSP (`script-src 'self'`, no inline scripts), `frame-ancestors 'none'` by default, HSTS when HTTPS, `Referrer-Policy: no-referrer` on auth pages |
| SSRF | Any server-side fetch of a client-supplied URL (JWKS URI, client metadata document, back-channel logout, webhooks) goes through a guarded client: HTTPS only (except configured dev allow-list), private/loopback/link-local ranges blocked after DNS resolution, size and time limits |
| Secret hygiene | Secrets wrapped in `secrecy` types (no `Debug`/log output); `zeroize` on drop for key material |
| Test code | No test-only branches in production code; test fakes implement the traits inside `#[cfg(test)]` or test crates only |

## 12. Multi-tenancy and issuer URLs

- **Tenant resolution** (tower layer), in order:
  1. Host match: the request `Host` equals a tenant's configured host → that tenant, base path `/`.
  2. Path prefix: `/t/{slug}/…` → that tenant, base path `/t/{slug}`.
  3. Otherwise → the `default` tenant, base path `/`.
- **Issuer** = `public_url` + base path (e.g. `https://id.example.com` for the default tenant,
  `https://id.example.com/t/acme` for a path tenant, `https://login.acme.com` for a host tenant).
  Computed by one function and used in discovery, tokens, the `iss` response parameter and
  `private_key_jwt` audience checks.
- The `system` tenant (admin console and management API) is path-based at `/t/system` and cannot be
  host-mapped to a customer domain.

## 13. Configuration and bootstrap

- **Zero-config start:** `anvilid serve` with no configuration:
  - Uses `./anvilid-data/` for the SQLite database, KEK and generated keys.
  - Listens on `127.0.0.1:8080`, `public_url` = `http://localhost:8080` (dev mode, with a warning
    banner in logs and UI).
  - On an empty database, creates the `system` and `default` tenants and prints a one-time setup
    URL (`/setup?token=…`, valid 1 h) to create the first admin. There are **no default credentials**.
- **Production minimum:** `ANVILID_PUBLIC_URL=https://id.example.com` and, for Postgres,
  `ANVILID_DATABASE_URL=postgres://…`. Everything else has a default.
- **Precedence:** CLI flags > environment (`ANVILID_*`) > config file (`anvilid.toml`) > defaults.
  `anvilid config show` prints the effective configuration with the source of each value (secrets
  redacted).
- **Trusted proxies:** `ANVILID_TRUSTED_PROXIES` (CIDRs) controls whether `X-Forwarded-*`/`Forwarded`
  headers are honored. Default: none (headers ignored), except loopback in dev mode.
- **CLI commands:** `serve`, `migrate`, `config show|validate`, `admin setup-url` (new bootstrap URL
  for recovery), `keys rotate`, `backup create|restore` (SQLite), `export`/`import` (tenant YAML).

## 14. Background jobs

An in-process scheduler runs periodic jobs, each guarded by a `job_lease` row so only one node runs a
job at a time on Postgres:

| Job | Interval |
|---|---|
| Expired-row cleanup | 5 min |
| Signing-key rotation check | 1 h |
| Email outbox delivery | continuous (polling with backoff) |
| Back-channel logout delivery | event-driven, with retry |
| Webhook delivery (0.4) | event-driven, with retry |
| Audit log retention | daily |

## 15. Observability

- **Logs:** JSON to stdout by default (pretty in dev). Fields: `trace_id`, `tenant`, `client_id`,
  `route`, `status`, `latency_ms`. Secrets are never logged (types prevent it).
- **Metrics** (`/metrics`): request counts and latency by route class; `anvil_auth_attempts_total`
  by method and outcome; tokens issued by grant; refresh reuse detections; rate-limit rejections;
  database pool stats; job runs and failures.
- **Traces:** spans for each request and storage call; OTLP export behind the `otel` feature and
  `ANVILID_OTEL_ENDPOINT`.
- **Audit log:** separate from operational logs, stored in the database and optionally mirrored to
  stdout as `audit` events.

## 16. Testing strategy

| Layer | What | Where |
|---|---|---|
| Unit | State machines, validation, token claims, crypto wrappers; proptest for parsers (redirect URIs, scopes, JWT headers) | each crate |
| Storage contract | One suite against SQLite (memory + file) and Postgres, including concurrency tests | `anvil-storage` |
| HTTP integration | Full router in-process on SQLite: every endpoint, every OAuth error path | `anvil-web/tests` |
| **Security negative tests** | One test per control in §11 proving bad input is rejected (wrong redirect URI, missing/plain PKCE, code reuse, refresh reuse, wrong client secret, cross-tenant access, replayed `jti`, CSRF failure…) | `anvil-web/tests/security_*.rs` |
| Conformance | OpenID conformance suite (Docker) against a freshly started binary; target profiles from OIDC-23 | `tests/conformance`, CI |
| End-to-end | Playwright: login, registration, recovery, passkeys (virtual authenticator), MFA, consent, admin console | `tests/e2e`, CI |
| Upgrade | Migrate N-1 → N with fixtures, then run the contract suite | CI |
| Fuzzing | JWT/JWS parsing, authorization request parsing; later SAML and SCIM | `fuzz/`, nightly CI |
| Performance | Token endpoint and login benchmarks against the targets in PRD §6.3 | nightly CI |

**Definition of done for any feature:** implemented end to end, negative tests for its security
properties, documented (user docs + OpenAPI where relevant), conformance suite still green.

## 17. CI/CD

- **Every PR:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny check`, unit + contract
  (SQLite and Postgres) + integration + security tests, dependency-rule check (§4), OpenAPI drift
  check, `sqlx` offline metadata check.
- **Main branch:** everything above plus conformance suite, Playwright e2e, upgrade test, musl
  release build with binary-size and idle-memory report.
- **Release:** cargo-dist builds (linux musl amd64/arm64, macOS, Windows), container image, SBOM,
  signed checksums/attestations. Changelog generated from conventional commits.

## 18. Milestones

Each milestone has exit criteria. A milestone is done only when all of them are met. Milestones map
to PRD releases.

### M0 — Foundations and spikes (no release)

- Workspace skeleton (§4), CI pipeline, cargo-deny policy, `rust-toolchain.toml`.
- **Spike A:** sqlx dual backend: implement `TenantRepo` + `GrantRepo::consume_code` on both
  backends with the contract suite, including the concurrency test. Measure the duplication cost.
- **Spike B:** static musl build with aws-lc-rs, mimalloc and embedded assets; report binary size and
  idle RSS.
- **Spike C:** run the OpenID conformance suite in CI against a stub discovery endpoint (pipeline
  proof).
- Exit: all three spikes succeed (or the stack decision is revisited per §2.1); CI green.

### M1 — Release 0.1 "First login"

Scope: OIDC-1..9, OIDC-24, AUTH-1..3, UI-1, ORG-1 (data model; default tenant only in UI), ADM-1
(tenants, clients, users), ADM-3, ADM-7 (`serve`, `migrate`, `config`, `admin setup-url`).

Exit criteria:
- A sample app (in `examples/`) logs in through AnvilID with authorization code + PKCE, refreshes,
  and calls UserInfo, on both SQLite and Postgres.
- OpenID conformance **Basic OP** and **Config OP** test plans pass in CI.
- All §11 controls that apply to the scope have negative tests.
- Zero-config start → login in a sample app in ≤ 2 minutes (scripted check in CI).

### M2 — Release 0.2 "Secure by default"

Scope: OIDC-10, 11, 13, 15, 25; AUTH-4, 5, 9, 10; UI-2, UI-7; ADM-4; email outbox; signing-key
rotation job; admin console v1 (users, clients, sessions, audit).

Exit criteria: passkey and TOTP e2e tests pass with a virtual authenticator; **Form Post** conformance
plan passes; brute-force and rate-limit tests pass; accessibility audit (axe) of the login pages clean.

### M3 — Release 0.3 "Real-world logins"

Scope: OIDC-12, 14, 16; AUTH-6, 7, 8, 11, 13; UI-3, UI-4; back-channel logout delivery.

Exit criteria: **RP-Initiated Logout** and **Back-Channel Logout** conformance plans pass; social
login tested against real providers in a staging environment; theming editable live from the console.

### M4 — Release 0.4 "Operate it"

Scope: ORG-1 (multi-tenant console), ORG-5, ADM-5, ADM-6, OIDC-17, AGT-1, AGT-2, AUTH-14; Helm chart;
Redis-backed shared rate limiting; HA test (3 nodes on Postgres under load).

Exit criteria: HA test shows no errors through node restarts; declarative export → import round-trips
a tenant; an MCP client completes authorization using a client metadata document and resource
indicators.

### M5 — Release 1.0 "Credible for business"

Scope: ORG-2, ORG-3, ORG-4; OIDC-18, OIDC-23 (certification filed); UI-5; ADM-8, ADM-9; AGT-3;
federation module (upstream OIDC and SAML SP; SAML marked experimental unless D4 is resolved).

Exit criteria: OpenID certification submitted for all target profiles; external security review
completed and findings fixed; upgrade path from 0.4 tested; documentation site complete (install,
integrations, migration guides).

### Beyond 1.0

Release 2.0 (directory, SAML IdP, forward-auth, extension hooks, token exchange, DPoP, API keys,
Terraform) and 3.0 (permissions engine, identity-aware proxy, Shared Signals, adaptive MFA, FAPI 2.0)
are specified in PRD §8.7. Each gets an architecture addendum before its milestone starts.

## 19. Extension points reserved now

These are designed in from the start so later modules don't require rewrites:

- **Principal types:** `sub` resolution and audit actors use an enum (`User`, `Client`, later `Agent`).
- **Connections:** upstream IdP configuration is a tagged enum (`Social`, `Oidc`, `Saml`, later
  `Ldap`), stored in one table.
- **Token claims pipeline:** claims are assembled by an ordered list of claim providers (standard
  claims, roles, organization, custom attributes); extension hooks (EXT-1) slot in later.
- **Events:** core services emit typed domain events; audit, webhooks and back-channel logout are
  subscribers.

## 20. Open decisions

| ID | Decision | Default proposal | Resolve by |
|---|---|---|---|
| D1 | Path-based vs host-based tenants by default (PRD Q1) | **Decided 2026-11-25:** path-based default, host mapping optional (§12) | ✓ |
| D2 | Opaque vs JWT access tokens by default | **Decided 2026-11-25:** JWT (RFC 9068) by default; opaque per client | ✓ |
| D3 | Admin console stack | **Decided 2026-11-25:** React + Vite static SPA embedded in the binary (best component ecosystem and contributor pool; dogfoods the API). Login pages remain server-rendered. Rust/WebAssembly frameworks (Leptos, Dioxus) were considered and rejected for now: young component ecosystems and a small contributor pool | ✓ |
| D4 | SAML stack: pure-Rust XML-DSig (saml-rs/bergshamra) vs alternatives | Evaluate against a signature-wrapping attack corpus; experimental flag until it passes | before M5 |
| D5 | Permissions engine: embedded tuple store vs integrating OpenFGA/SpiceDB | Decide at the 3.0 addendum | 3.0 |
| D6 | Embedded HA without Postgres (replicated SQLite) | Not planned; revisit on user demand | post-1.0 |
| D7 | sqlx minimum supported Rust version vs our toolchain policy | **Resolved 2026-11-25:** sqlx 0.9.1 requires Rust ≥ 1.94; pin current stable (1.100.0) in `rust-toolchain.toml` | ✓ |
