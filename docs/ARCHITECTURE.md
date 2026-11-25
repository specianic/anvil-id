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
| TOTP | totp-rs 6 | RFC 6238 code computation only (RustCrypto HMAC-SHA-1, see below); the seed is sealed with the KEK. Last-used time step stored to prevent replay. Enrolment QR codes are rendered server-side as inline SVG with qrcodegen (no script) |
| Email | lettre 0.11 (rustls) | Outbox table + background sender |
| Templates | minijinja 3 | Login pages: embedded defaults, overridable from a theme directory at runtime |
| Admin UI | React + TypeScript, built with Vite as a static single-page app; TanStack Router and Query; shadcn/ui (Radix) components; TanStack Table. Embedded with rust-embed | Talks only to the public management API. TypeScript types and API client generated from the OpenAPI spec (`openapi-typescript`), so API drift fails the build. No server-side rendering (no Next.js) |
| Config | figment (TOML file + `ANVILID_*` env vars + CLI flags) | |
| CLI | clap 4 | |
| Observability | tracing, tracing-subscriber (JSON), metrics + Prometheus exporter; OpenTelemetry behind the `otel` feature | |
| Rate limiting | governor (GCRA buckets) and moka (brute-force backoff state), wrapped by our keyed limiter in `anvil-cache` (§11) | One limiter implementation. governor runs on the core `Clock`, so tests drive it with a fake clock |
| HTTP client | reqwest 0.13 (rustls) with SSRF guard | Upstream IdPs, JWKS fetch, webhooks, client metadata documents |
| Time | `time` crate only | `chrono` is banned to avoid mixed types |
| IDs | UUIDv7 | Time-ordered primary keys |
| OpenAPI | utoipa | Spec generated from handler annotations; checked in CI |
| Testing | proptest, insta, wiremock, testcontainers, Playwright, OpenID conformance suite | |
| Supply chain | cargo-deny, cargo-audit, cargo-auditable | |
| Release | Tag-triggered GitHub Actions workflow (`release.yml`), static musl builds (amd64, arm64), macOS builds, mimalloc allocator, distroless image | cargo-dist was planned; a small custom workflow around `scripts/build-musl.sh` is used instead (see `docs/RELEASING.md`). Since 0.2 it builds the admin console once and fails if any binary does not embed it (`scripts/check-console-embedded.sh`) |

**Banned dependencies** (enforced with cargo-deny): `openssl`, `native-tls`, `ring` as a second crypto
backend, the RustCrypto `rsa` crate for private-key operations (unpatched timing side channel),
`chrono`, `samael`/`xmlsec` (C XML security libraries), `oxide-auth`.

"Single crypto backend" applies to **our own** signing, encryption and key handling: all of it goes
through aws-lc-rs. One exception is accepted: webauthn-rs pulls in RustCrypto crates (via
`crypto-glue`, including `rsa`) for verifying authenticator signatures. Verification uses public keys
only, so the `rsa` timing side channel does not apply. This exception is scoped in `deny.toml` with a
`wrappers = ["crypto-glue"]` entry, so no other crate can use `rsa`. The same crates bring in
MPL-2.0 licences, which `deny.toml` accepts per crate rather than globally.

A second, narrower exception: totp-rs computes TOTP codes with RustCrypto `hmac`/`sha1`. This is
code computation over a seed that is stored sealed with aws-lc-rs (AES-256-GCM under the KEK) and
opened only for the check; no key material is generated or stored by RustCrypto code.

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

- `anvil-core` depends only on `anvil-jose` and pure libraries (serde, serde_json, secrecy, time,
  uuid, url, thiserror, async-trait).
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
| `tenant` | id, slug, display_name, issuer_mode (path/host), host, settings (JSON), created_at | One `system` and one `default` tenant created at bootstrap. `host` is unique and set only for host-based tenants. 0.1 settings: registration mode (open/invite_only/disabled), require_verified_email. 0.2 adds `signing_algs` (enabled ID token algorithms, RS256 always) and `captcha` (provider, site key, secret sealed with the KEK) |
| `user` | id, tenant_id, email, email_verified, phone, phone_verified, username, attributes (JSON, validated against the tenant's schema), status (active/blocked), created_at, updated_at, last_login_at | Unique (tenant_id, email); unique (tenant_id, username). Core stores email normalised (trimmed, lowercased). In 0.1 the OIDC standard claims (§5.1, incl. phone and address) are a typed `StandardClaims` record stored as JSON; tenant schemas come later |
| `credential` | id, tenant_id, user_id, kind (password/webauthn/totp), data (encrypted or hashed per kind), external_id (WebAuthn credential ID, nullable), counter (integer, nullable), backup_eligible, label, created_at, last_used_at | Password: PHC string. TOTP: sealed seed; `counter` = last accepted time step. WebAuthn: credential JSON; `counter` = signature counter. Counters are plain columns so replay and clone checks are a single conditional `UPDATE … WHERE counter < ?`. Partial unique indexes: one password and one TOTP per user, `external_id` unique per tenant; SQLite also checks `(kind = 'webauthn') = (external_id IS NOT NULL)`. Password rows migrated from 0.1 get random ids |
| `recovery_code` | tenant_id, user_id, code_hash, created_at, used_at | Primary key (tenant_id, user_id, code_hash). One row per code, consumed atomically (`UPDATE … SET used_at … WHERE used_at IS NULL`). Removing TOTP deletes the user's codes |
| `identity_link` | id, tenant_id, user_id, provider_id, subject, email_at_link, created_at | Upstream identities (social/enterprise). Unique (tenant_id, provider_id, subject) |
| `client` | id, tenant_id, client_id, name, type (confidential/public), application_type (web/native), require_pkce, auth_method, secret_hash, jwks / jwks_uri, redirect_uris, post_logout_redirect_uris, grant_types, scopes, token_format (jwt/opaque), consent_mode (required/skip_first_party), backchannel_logout_uri, branding (JSON), created_at | `client_id` is unique per tenant; URL-form client IDs (CIMD) are cached in `client_metadata_cache` |
| `signing_key` | id, tenant_id, kid, alg, state (next/active/retired), private_key (encrypted with KEK), public_jwk, activated_at, retired_at, expires_at | |
| `browser_session` | id, tenant_id, user_id, auth_time, acr, amr (JSON), ip, user_agent, created_at, last_seen_at, expires_at, idle_expires_at | Session cookie holds an opaque random ID; only its hash is stored |
| `rp_session` | browser_session_id, client_id, sid, created_at | Which clients the session logged in to (for back-channel logout) |
| `flow` | id, tenant_id, kind (login/registration/recovery/verification/settings/consent), state (JSON), csrf_hash, expires_at, browser_session_id? | Short-lived flow state machines (§9) |
| `authorization_request` | id, tenant_id, client_id, params (JSON: redirect_uri, scope, state, nonce, code_challenge, resource, prompt, max_age, acr_values…), created_at, expires_at | Created at `/authorize`, consumed when a code is issued. Also used for PAR |
| `authorization_code` | code_hash (PK), tenant_id, client_id, user_id, browser_session_id, redirect_uri, scope, nonce, code_challenge, resource, auth_time, acr, amr, expires_at, consumed_at, token_family_id | The token family is created in the same transaction as the code, so a code replay that races the exchange still finds and revokes it |
| `token_family` | id, tenant_id, client_id, user_id?, scope, resource, auth_time?, acr?, amr, browser_session_id?, claims request (JSON)?, created_at, absolute_expires_at, revoked_at, revoked_reason | Groups a refresh-token chain; revoking the family revokes all of its tokens. Carries the authentication context so refreshed ID tokens repeat `auth_time` and UserInfo applies `claims.userinfo`. Access tokens carry the family id and UserInfo checks `revoked_at` |
| `refresh_token` | token_hash (PK), tenant_id, family_id, parent_hash?, expires_at, consumed_at | Rotation: each use consumes the token and issues a child |
| `access_token` | token_hash (PK), tenant_id, family_id?, client_id, user_id?, scope, created_at, expires_at, revoked_at | Only for opaque tokens; JWT access tokens are not stored. Revocation of a JWT revokes its family. Opaque client-credentials tokens have no family. `resource` arrives with RFC 8707 |
| `consent_grant` | id, tenant_id, user_id, client_id, scopes, created_at, updated_at, revoked_at | Unique (tenant_id, user_id, client_id). Scopes are a sorted, de-duplicated set; a new grant is merged into the existing one in a single upsert so concurrent first grants lose nothing. Revoking also revokes that client's token families of the user. `resource` arrives with RFC 8707 |
| `role`, `role_assignment` | role: id, tenant_id, org_id?, name, permissions (JSON). assignment: role_id, user_id, org_id? | RBAC (ORG-5) |
| `organization`, `org_membership`, `org_invitation`, `org_domain`, `connection` | standard fields | 1.0 (ORG-2..4). `connection` = upstream IdP config (social/OIDC/SAML), tenant- or org-scoped, secrets encrypted |
| `audit_event` | id, tenant_id, at, actor (user/client/admin/system + id), action, target, outcome (success/failure), ip, user_agent, trace_id, details (JSON object) | Append-only; retention configurable (`audit_retention_days`). Tenant lifecycle events are recorded in the `system` tenant with the tenant id as target. Details never contain secrets, identifiers of failed sign-ins or SMTP error text |
| `email_outbox` | id, tenant_id, to, template, payload (JSON), attempts, next_attempt_at, sent_at, last_error | |
| `email_template` | tenant_id, kind (verification/recovery/invitation/password_changed/recovery_code_used), subject, body_html, body_text, updated_at | Per-tenant override of the theme's email template, validated on save (§13) |
| `smtp_settings` | tenant_id, host, port, username?, password (sealed)?, from_address, tls (starttls/implicit/none), updated_at | Per-tenant SMTP; the password is write-only in the API |
| `job_lease` | name, owner, leased_until | Background job coordination (§14). Leases are 15 minutes and released after each run |
| `replay_guard` | tenant_id, kind (jti/dpop/nonce), value_hash, expires_at | `private_key_jwt` assertion `jti`s; later DPoP |
| `admin_setup_token` | token_hash, expires_at, used_at | One-time bootstrap URL (ADM-3) |
| `self_service_token` | token_hash (PK), tenant_id, kind (verification/recovery/invitation), user_id, email, created_at, expires_at, consumed_at | Emailed one-time links, consumed atomically. Verification succeeds only while the user's email still equals `email` |

0.2 also adds to `client`: `token_format`, `consent_mode`, `id_token_signed_response_alg` (unset =
RS256) and `can_introspect`; and to `browser_session`: `ip`, `user_agent` (shown on the sessions
page). `flow.kind` gains `settings` and `consent`.

**Tenant-scoped foreign keys.** Rows that point at a user reference `(tenant_id, user_id)` →
`user (tenant_id, id)`, so the database itself rejects a row whose user belongs to another tenant.
SQLite has used composite keys since 0.1. On Postgres, 0.2 adds them to `credential`,
`self_service_token`, `browser_session`, `recovery_code`, `consent_grant` and `authorization_code`.
The last one is added `NOT VALID`: 0.1 had no user key on codes, so an upgraded database can still
hold expired codes of deleted users. Every new or changed row is checked. Storage methods also check
the user's tenant before inserting, which gives a clearer error.

### 6.2 Storage of secrets

| Secret | At rest |
|---|---|
| User passwords | Argon2id PHC string |
| Client secrets, refresh/access tokens (opaque), authorization codes, session IDs, setup and recovery tokens, API keys | SHA-256 of a 256-bit random value. The plaintext is shown once and never stored |
| MFA recovery codes | ~80-bit random codes, formatted for typing (e.g. `XXXX-XXXX-XXXX-XXXX`), stored as HMAC-SHA-256 under a key derived from the KEK (a plain hash would be brute-forceable at this length). Shown once |
| TOTP seeds, SMTP passwords, CAPTCHA secrets, upstream IdP client secrets, signing private keys, SAML SP keys | AES-256-GCM with a data key derived from the **key-encryption key (KEK)** via HKDF, using the table and row ID as associated data |
| Email outbox payloads (contain single-use links) | Sealed with the KEK envelope (AES-256-GCM, purpose `anvilid/outbox-payload/v1`, tenant ID as associated data) when the email is created; opened only by the outbox worker immediately before rendering. A payload that cannot be opened is never sent |

**KEK source:** the `ANVILID_KEK` env var or a key file. In zero-config dev mode the binary generates
a KEK into the data directory on first start and logs a warning telling the operator to back it up.
Losing the KEK makes encrypted columns unrecoverable; the docs say so prominently.

## 7. Storage layer

### 7.1 Traits

`anvil-core` defines the storage ports (`anvil_core::ports`): **repository traits grouped by
aggregate**. There is no generic transaction handle:

```rust
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    fn tenants(&self) -> &dyn TenantRepo;
    fn users(&self) -> &dyn UserRepo;          // users, credentials (password, passkey, TOTP, recovery codes), self-service tokens
    fn clients(&self) -> &dyn ClientRepo;
    fn keys(&self) -> &dyn KeyRepo;
    fn sessions(&self) -> &dyn SessionRepo;
    fn flows(&self) -> &dyn FlowRepo;
    fn grants(&self) -> &dyn GrantRepo;        // authorization requests, codes, families, refresh and opaque access tokens, consent, replay guards
    fn setup(&self) -> &dyn SetupRepo;         // installation-wide bootstrap
    fn outbox(&self) -> &dyn OutboxRepo;
    fn audit(&self) -> &dyn AuditRepo;         // 0.2: append, query, retention purge
    fn mail_settings(&self) -> &dyn MailSettingsRepo; // 0.2: email templates, SMTP settings
    fn jobs(&self) -> &dyn JobRepo;            // 0.2: job leases
    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, StorageError>;
    // later: orgs(), connections(), roles(), …
}
```

**Intent methods instead of `begin() -> Box<dyn Tx>`.** An earlier draft of this section had a
generic transaction handle. It was replaced (Phase 2) by making every multi-row change that must be
atomic a single repository method. Reasons: the traits stay dyn-compatible, a caller cannot forget a
commit or hold a transaction across an await on unrelated I/O, and every atomic unit is a named
method that the shared contract suite tests on both backends. The atomic methods in 0.1 are
`GrantRepo::create_code` (family + code), `consume_code`, `rotate_refresh`, `record_jti`,
`UserRepo::create` (user + password + token + email), `delete`, `issue_self_service_token`,
`complete_verification`, `complete_recovery`, `ClientRepo::delete` (client + family revocation),
`SetupRepo::install` and `SetupRepo::complete_setup`. 0.2 adds `UserRepo::create_totp`
(seed + recovery codes), `UserRepo::consume_recovery_code` (with the "code used" notice in the same
transaction), the passkey counter compare-and-swap, `GrantRepo::upsert_consent`/`revoke_consent`
(revoke also revokes that client's families of the user), `SessionRepo::revoke_with_families`, `KeyRepo::promote` (retire the
active key and activate the next one; returns `false` for stale ids), `FlowRepo::swap_state`
(compare-and-swap of a flow's state, used to consume a pending passkey challenge or TOTP secret
exactly once), `JobRepo::try_lease` and `UserRepo::complete_recovery` with an optional
`RecoveryNotice`.

**Audit events are written after the commit, not inside the intent transaction.** Intent methods
take no audit rows. The service appends the event right after the state change commits; an append
failure is returned to the caller (and logged), but the committed change stays. Folding audit rows
into every intent method was considered and rejected: it would widen every atomic method's
signature for a record that is not needed for correctness. The one exception to "audit failure is
returned" is `admin_setup_completed`: the setup secret is shown once, so setup succeeds and the
failure is logged.

Repository methods express **intent**, not generic CRUD. The security-critical ones are atomic by
contract:

| Method | Contract | SQLite | Postgres |
|---|---|---|---|
| `GrantRepo::consume_code(tenant, code_hash, now)` | Returns the code only if it exists, is unexpired and unconsumed, **and marks it consumed in the same statement**. If it was already consumed, returns `AlreadyConsumed { family_id }` so the caller can revoke that family (OIDC-3) | `UPDATE … SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING *` | same |
| `GrantRepo::rotate_refresh(tenant, token_hash, new_token, now)` | Atomically consumes the presented token and inserts its child. If the presented token was already consumed, revokes the entire family and returns `ReuseDetected` (OIDC-5) | One transaction | One transaction |
| `UserRepo::create(tenant, user, password?, token?, email?)` | One transaction. Fails with `Conflict` on duplicate email/username (unique index), never "check then insert"; nothing is persisted on conflict | Unique index | Unique index |
| `GrantRepo::record_jti(tenant, kind, jti_hash, exp, now)` | Insert-or-fail for replay prevention; an expired entry may be replaced | `INSERT` with primary key | same |
| `UserRepo::complete_recovery(tenant, token_hash, phc, now, notice?)` | One transaction: consumes the token, sets the password, marks the email verified, revokes all sessions and token families of the user, enqueues the notice | One transaction | One transaction |
| `SetupRepo::complete_setup(token_hash, now, …)` | One transaction: consumes the setup token, creates the first administrator and the admin client | One transaction | One transaction |

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
  startup (can be disabled with `--no-migrate`). On Postgres the check and the run share one
  connection holding sqlx's advisory lock. SQLite has no cross-process migration lock; `serve`
  holds the exclusive `serve.lock` on the data directory, and a concurrent `anvilid migrate` can at
  worst find nothing left to apply.
- **Destructive-migration guard (0.2).** A migration named `NNNN_destructive_*.sql` is refused at
  startup unless `--allow-destructive-migrations` (`ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS`) is set.
  The pending set is computed without writing anything, so a refusal leaves the database
  untouched.
- **Migration lint (0.2).** `scripts/check-migrations.sh` (in `just ci`) fails if a released
  migration changed (sha256 manifest `scripts/released-migrations.sha256`, extended at every
  release) or if an unreleased migration contains destructive SQL without the `destructive` name or
  the reviewed `-- anvil:non-destructive-rebuild` annotation (used by SQLite table rebuilds that
  copy every row, e.g. 0004).
- Migrations are forward-only and **expand/contract**: a release never drops or renames a column that
  the previous minor release still reads. Destructive cleanups happen one minor release later.
- CI test: create a database with release N-1's migrations and data fixtures, upgrade to N, run the
  contract suite (`tests/upgrade.rs` in both storage crates; 0.1 → 0.2 keeps every row).

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
  uses jsonwebtoken / aws-lc-rs only for the signature operations. **Decided in 0.2:** Ed25519 is
  emitted and accepted only as `Ed25519`; the legacy `EdDSA` name is neither emitted nor accepted.
  ES256 and Ed25519 are opt-in per tenant (`settings.signing_algs`); RS256 is always enabled.
  Disabling an algorithm that a client uses as `id_token_signed_response_alg` is refused with the
  affected client ids. `id_token_hint` is verified against the tenant's enabled algorithms.
- How 0.1 uses jsonwebtoken: only `jsonwebtoken::crypto::{sign, verify}` (aws-lc-rs backend,
  `use_pem`). `anvil-jose` serialises the header and claims, splits and base64url-decodes compact
  JWS itself, and checks `alg` against a per-call allow-list before any key is used (`none` and
  HMAC algorithms are never accepted). aws-lc-rs exports RSA private keys only as PKCS#8, so the key
  is wrapped once at load time in a `PRIVATE KEY` PEM for jsonwebtoken. JWKs and RFC 7638 thumbprints
  are computed in-crate. In 0.1 ID tokens and access tokens are signed with RS256 only (advertised in
  discovery); `private_key_jwt` client assertions may use RS256, PS256 or ES256. Since 0.2 ID tokens
  use the client's `id_token_signed_response_alg` among the tenant's enabled algorithms, and discovery
  lists exactly those.
- Lifecycle: `next` (published in JWKS, not yet signing) → `active` (signing) → `retired` (published
  until every token signed with it has expired) → deleted. Rotation runs as a scheduled job (checked
  hourly under a job lease) and on demand (`anvilid keys rotate [--tenant slug] [--alg RS256|ES256|Ed25519]
  [--immediate]`). As built in 0.2: rotation period 90 days (`key_rotation_days`, 1–3650);
  the `next` key is prepublished min(7 days, period/2) and never less than the JWKS cache lifetime
  before activation; `/jwks` is served with `Cache-Control: max-age=3600` and an ETag (304 on
  `If-None-Match`); a retired key stays published for 1 h 5 min (the longest token lifetime, ID token
  1 h, plus 5 min skew). `--immediate` retires the old key at once (compromise response); without
  it the call is idempotent and returns the existing `next` key. Concurrent rotation runs promote
  exactly once.
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
- **Access token audience (0.2):** `aud` = the client id until RFC 8707 resource indicators ship
  (0.3). The token family is referenced by the `fid` claim.
- **Opaque access tokens** are stored as SHA-256 hashes in `access_token`; JWT access tokens are not
  stored.
- **Introspection (RFC 7662):** only confidential clients may call `/introspect` (public clients get
  `invalid_client`). A client sees its own tokens; a client with `can_introspect` sees every token of
  its tenant. Anything else (another client's token without the flag, another tenant's, expired,
  revoked, consumed, garbage) is `{"active": false}`.
- **Revocation (RFC 7009):** revoking a refresh token or an access token with a family revokes the
  whole family; an opaque token is also revoked itself. Revoking another client's token answers 200
  and changes nothing (no oracle); `can_introspect` never grants revocation. JWT client-credentials
  access tokens have no family and nothing server-side, so `/revoke` answers
  `unsupported_token_type` for them; opaque client-credentials tokens can be revoked. Public clients
  may revoke their own tokens.
- **`amr`/`acr` (0.2):** password `["pwd"]`; password + TOTP or recovery code `["pwd","otp","mfa"]`;
  passkey `["hwk"|"swk","user","mfa"]` (`swk` when the passkey is backup-eligible). MFA sign-ins
  carry `acr` `urn:anvilid:acr:mfa`.

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
- **As built in 0.2:** the login engine runs password, passkey (discoverable, usernameless) and the
  second factor (TOTP or recovery code, required when the user has TOTP enrolled). Passkey sign-in
  satisfies MFA and skips the second factor. The second-factor page is rendered as the answer to the
  password POST, and a KEK-sealed `factor_token` names the user for the per-user throttle (the flow
  state still decides).
- **Consent is its own small state machine** (`FlowKind::Consent`, `flow/consent.rs`), not a step of
  the login engine as the diagram suggests. It reuses the flow binding (cookie + CSRF) and lifetime.
  Allow stores the grant and continues the authorization in-process; Deny answers `access_denied`
  to the client. `prompt=none` without a covering grant is `consent_required`; `prompt=consent`
  forces the screen. Clients with `consent_mode = skip_first_party` never see it.
- **Settings flows** (account security, sessions, connected apps) are created and advanced by the
  account services directly, bound to the owning user. Credential changes require a sign-in within
  the last 15 minutes; signing out sessions and revoking app grants need only the binding.

## 10. HTTP surface

Paths below are relative to the tenant base (§12).

### 10.1 Protocol endpoints

| Path | Purpose | PRD |
|---|---|---|
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | Discovery / RFC 8414 metadata (see path forms below) | OIDC-8 |
| `GET /jwks` | JSON Web Key Set | OIDC-8 |
| `GET, POST /authorize` | Authorization endpoint | OIDC-1,2,14,16,24 |
| `GET /authorize/continue?request={id}` | Resumes a stored authorization request after login (the UI redirects here with 303) | OIDC-1 |
| `POST /par` | Pushed authorization requests | OIDC-18 |
| `POST /token` | Token endpoint (all grants) | OIDC-3..6 |
| `GET, POST /userinfo` | UserInfo | OIDC-9 |
| `POST /introspect`, `POST /revoke` | RFC 7662 / RFC 7009 | OIDC-10 |
| `GET, POST /logout` | RP-initiated logout | OIDC-12 |
| `POST /register` | Dynamic client registration (policy-controlled) | OIDC-17 |

**Discovery path forms.** OpenID Connect Discovery appends the well-known suffix to the issuer
(`{issuer}/.well-known/openid-configuration`, e.g. `/t/acme/.well-known/openid-configuration`).
RFC 8414 §3.1 inserts it between host and path (`/.well-known/oauth-authorization-server/t/acme`).
Both forms are served, with the same document; the tenant layer resolves the inserted form before
`/t/{slug}` prefix matching. The issuer-relative `{issuer}/.well-known/oauth-authorization-server`
also works.

**Built in 0.1:** discovery (both forms), `/jwks`, `/authorize` (GET and POST),
`/authorize/continue`, `/token` (`authorization_code`, `refresh_token`, `client_credentials`) and
`/userinfo` (GET and POST; bearer in the header or the form body, never in the query). Discovery
advertises only what is built: `response_types_supported: ["code"]`, `response_modes_supported:
["query"]`, `prompt_values_supported: ["none", "login"]`, `code_challenge_methods_supported:
["S256"]`, `authorization_response_iss_parameter_supported: true` and `scopes_supported: ["openid",
"profile", "email", "address", "phone"]`. A refresh token is issued when the client is registered for
the `refresh_token` grant. The other rows arrive with their milestones.

**Added in 0.2:** `/introspect` and `/revoke` (client-authenticated; discovery advertises
`introspection_endpoint_auth_methods_supported` without `none`, and
`revocation_endpoint_auth_methods_supported` as the token endpoint list including `none`),
`response_mode=form_post` (`response_modes_supported: ["query", "form_post"]`; the auto-submitting
page has a CSP whose `form-action` allows only the redirect URI's origin, and works without
JavaScript), `id_token_signing_alg_values_supported` = the tenant's enabled algorithms. Request
objects are not supported (`request_parameter_supported: false`); a rejected request object is
answered with `request_not_supported` through the response mode it asked for (exactly `form_post`,
otherwise query) when the redirect URI is valid. `request_uri` is never fetched.

### 10.2 Built-in UI and flows

`/ui/login`, `/ui/registration`, `/ui/recovery`, `/ui/verification`, `/ui/consent`, `/ui/account/*`,
plus `/ui/assets/*` (hashed, immutable static files). The headless API mirrors these under
`/api/flows/*` (1.0).

0.1 ships `/ui/login`, `/ui/registration`, `/ui/recovery` and `/ui/verification`, the installation
setup page `/setup?token=…` (installation-level, see §13) and hashed assets under `/assets/*`. Every UI
POST carries `?flow={id}` and the flow's `csrf_token`; a successful credential POST answers 303.

0.2 adds `/ui/login/passkey` (+ `/options`), the second-factor step (`/ui/login/second-factor`
redirects to `/ui/login` on GET; the page is the answer to the password POST), `/ui/consent`,
`/ui/account/security` (passkeys, TOTP, recovery codes), `/ui/account/sessions` and
`/ui/account/apps`. Account pages send `Cache-Control: no-store`. Pages load only self-hosted
scripts (`webauthn.js` for passkeys, `form_post.js`); every flow still works without JavaScript
except the passkey ceremony itself.

### 10.3 Management API

`/api/admin/v1/…`, documented with OpenAPI 3.1 at `/api/admin/v1/openapi.json`.

- Authentication: OAuth access tokens issued by AnvilID itself, through client credentials (for
  automation) or the admin console's authorization code flow. Scopes: `admin:read`, `admin:write`,
  and per-resource scopes (`admin:users:write`, …).
- As built in 0.1: the API is installation-level, mounted only at `/api/admin/v1` (not under a
  tenant base), and accepts only access tokens of the `system` tenant (obtained at
  `/t/system/token`). Resources: tenants, clients, users. Scopes: `admin:read` (read everything),
  `admin:write` (read and write everything), and `admin:{tenants|clients|users}:{read|write}`
  confined to one resource. Writing a client of the `system` tenant requires `admin:write`, so a
  `admin:clients:write` token cannot mint itself more privileges. Tokens of deleted clients stop
  working immediately. Errors are RFC 9457 problem JSON. The OpenAPI document is committed as
  `docs/openapi/admin-v1.json` and drift-checked in CI (`just openapi-update` regenerates it).
- Added in 0.2 (all under `/api/admin/v1/tenants/{slug}`): `audit-events` (filters, cursor
  paging with `after`/`next_cursor`), `sessions` (list, revoke one; per user list and revoke all),
  `users/{id}/credentials` (list, remove; passwords cannot be removed), `email-templates[/{kind}]`
  (theme default, override with validation errors that carry a line, reset), `smtp` (password
  write-only) and `smtp/test`. Client options gained `token_format`, `consent_mode`,
  `id_token_signed_response_alg` and `can_introspect`; tenant `settings` PATCH is field-wise and
  covers `signing_algs` and `captcha` (secret write-only; needs the tenants write scope). Every new
  route has a resource scope: `admin:audit:read`, `admin:sessions:{read|write}`,
  `admin:settings:{read|write}` (email templates, SMTP), credentials under `admin:users:{read|write}`
  (or `admin:read`/`admin:write`); `security_admin_v02.rs` proves each is enforced. Every admin write is
  audited with the admin actor (token `sub`).
- Installation-level administration (managing tenants) lives in a dedicated `system` tenant, so admin
  authentication uses the same machinery as everything else.
- The admin console SPA (`/console/`) is a public OAuth client of the `system` tenant and only calls
  this API. As built in 0.2: the client is `anvil-console`, reconciled with the public URL at every
  start (no off switch in 0.2). Users of the `system` tenant are the administrators until RBAC
  (0.4); registration in the `system` tenant is always disabled, and clients of other tenants can
  never obtain admin scopes. Sign-out revokes the console's tokens at `/t/system/revoke`.

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
  it is missing (`scripts/check-console-embedded.sh` also checks each release binary).
- **As built in 0.2:** `/console` redirects (308) to `/console/`. The console is mounted on the
  outer router (installation-wide, works before installation; `/t/{slug}/console/` is a 404).
  Files under `assets/` are `public, max-age=31536000, immutable`; `index.html` and other files are
  `no-cache`. The ETag is per encoding variant, with `Vary: Accept-Encoding`. Paths without an
  extension fall back to `index.html`; missing paths with an extension are 404. CSP:
  `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:;
  frame-ancestors 'none'; base-uri 'none'` (the console needs no inline script or style).

### 10.5 Operational endpoints (installation-wide)

`/health/live`, `/health/ready` (checks the database), `/metrics` (can be bound to a separate
listener).

## 11. Cross-cutting security controls

| Control | Implementation |
|---|---|
| Redirect URI validation | Exact string match against registered URIs. The only exception is loopback redirects for native apps (any port, per RFC 8252). Validation happens **before** any redirect is issued. Invalid redirect → an error page, never a redirect |
| PKCE | Required by default for every client (`client.require_pkce = true`); only `S256` is accepted, `plain` is rejected. Only confidential clients may set `require_pkce = false` (public clients always need PKCE); such clients may omit `nonce` as OIDC Core allows for the code flow, and the code stays bound to the client's authentication at the token endpoint. If a client sends `code_challenge` at authorization, `code_verifier` is mandatory at the token endpoint (downgrade defense) |
| Client authentication | One `ClientAuthenticator`. Constant-time comparison (`subtle`) of hashed secrets. `private_key_jwt`: `aud` must equal the issuer, `exp` ≤ 5 min, `jti` recorded in `replay_guard` |
| CSRF | Synchronizer token per flow plus `Sec-Fetch-Site`/`Origin` checks on every state-changing browser request. Fetch-Metadata rules for unsafe methods: (1) if `Sec-Fetch-Site` is present, only `same-origin` or `none` pass; (2) otherwise, if `Origin` is present, it must equal the public origin or the tenant's host origin; (3) if neither header is present the request passes this layer (non-browser clients, older browsers) and the synchronizer token alone decides. The layer fails closed if the allowed origins are unknown. Exempt: `/token` and `/api/admin/*` (client-authenticated, no cookies) and `POST /authorize` (cross-site by design) |
| Cookies | `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` (session) or `Strict` (flow). Dev mode on `http://localhost` drops the `__Host-`/`Secure` requirements with a warning |
| Rate limiting | One keyed limiter (`anvil-cache`, GCRA) with route classes and default quotas: `auth` (POSTs under `/ui/login`, `/ui/registration`, `/ui/recovery` and `/setup`: 10/min per IP, burst 5), `token` (`/token`, `/introspect`, `/revoke`: 50/s per IP, plus 100/s per claimed client id), `admin` (20/s per IP), `default` (50/s per IP). `/health/*`, `/healthz` and `/assets/*` are never limited. All quotas are configurable (§13); `rate_limit_enabled = false` switches the limiter off with a warning. A request without a peer address gets a generic 500, never an invented address. 429 answers carry `Retry-After` (whole seconds, at least 1) and the shape of their surface: OAuth JSON `invalid_request`/`too many requests` with `no-store`, admin problem JSON `urn:anvilid:problem:too_many_requests`, or the themed error page `too_many_requests` |
| Brute-force on secrets | Argon2 verification runs on a bounded pool; login attempts against unknown users perform a dummy hash (constant-time behavior). **Two tiers (0.2):** a strict key (tenant + identifier + IP) allows 5 free failures, then locks progressively (1 s doubling, capped at 15 min; success clears it); a loose key (tenant + identifier, any IP) counts failures per hour and never locks: over the threshold it requires a CAPTCHA when the tenant has one, otherwise it delays. Nobody can lock an account out from arbitrary IPs. Known and unknown identifiers behave identically, the identifier is never logged or audited (`rate_limit_lockout` records key kind and seconds only). The second factor is throttled per user, passkey failures per IP |
| CAPTCHA (0.2) | Optional per tenant (Turnstile or hCaptcha), shown only when the loose tier asks for it. Verification fails closed (HTTP error, timeout, malformed or oversized body, redirects; https endpoints only). The widget is a third-party script by the operator's choice: the page with the widget gets a CSP that allows the provider, every other page keeps `script-src 'self'`. A CAPTCHA can conflict with WCAG 2.2 SC 3.3.8 (accessible authentication); operators enabling it accept that trade-off |
| Trusted proxies (0.2) | The client IP comes from the TCP peer unless the peer is in `trusted_proxies`. Then the configured header (`X-Forwarded-For` or `Forwarded`, never both) is walked right to left, skipping trusted hops, and the first untrusted entry is the client; an unparsable entry stops the walk (the last trusted hop is used), at most 32 hops. IPv4-mapped IPv6 is normalised. Forwarded proto/host never change the issuer or cookie mode (`public_url` decides) |
| Response headers | Strict CSP (`script-src 'self'`, no inline scripts), `frame-ancestors 'none'` by default, HSTS when HTTPS, `Referrer-Policy: no-referrer` on auth pages. Exceptions are per page and narrow: the `form_post` page adds `form-action <redirect origin>`; the CAPTCHA page allows its provider |
| SSRF | 0.2 fetches no client-supplied URL (no `jwks_uri`, no `request_uri`); the CAPTCHA verifier calls only the provider's https endpoint. Any server-side fetch of a client-supplied URL (JWKS URI, client metadata document, back-channel logout, webhooks) goes through a guarded client: HTTPS only (except configured dev allow-list), private/loopback/link-local ranges blocked after DNS resolution, size and time limits |
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
  - Uses `./anvilid-data/` (mode 0700) for the SQLite database (`anvilid.db`) and the KEK file
    (`kek`, mode 0600). Signing keys are generated into the database, sealed with the KEK.
  - Listens on `127.0.0.1:8080`, `public_url` = `http://localhost:8080` (dev mode, with a warning
    banner in logs and UI). The container image sets `ANVILID_LISTEN=0.0.0.0:8080`.
  - On an empty database, creates the `system` and `default` tenants and prints a one-time setup
    URL (`{public_url}/setup?token=…`, valid 1 h) to create the first admin and a management API
    client. There are **no default credentials**. Logs go to stderr; with `log_format = json` the
    plain `Setup URL:` line is also printed on stdout for scripts.
- **Production minimum:** `ANVILID_PUBLIC_URL=https://id.example.com` and, for Postgres,
  `ANVILID_DATABASE_URL=postgres://…`. Everything else has a default.
- **Precedence:** CLI flags > environment (`ANVILID_*`) > config file (`anvilid.toml`, or
  `--config` / `ANVILID_CONFIG`) > defaults. `anvilid config show` prints the effective configuration
  with the source of each value (secrets redacted).
- **Keys in 0.1** (flag `--key-name`, env `ANVILID_KEY_NAME`, file `key_name`): `public_url`,
  `listen`, `data_dir`, `database_url` (default `sqlite://{data_dir}/anvilid.db`), `kek_file`
  (default `{data_dir}/kek`), `smtp_from`, `theme_dir`, `tls_cert` + `tls_key` (built-in TLS
  listener), `breach_check` (`hibp` | `off`), `breach_check_url`, `no_migrate`, `insecure_http`,
  `log_format` (`json` | `pretty`; pretty in dev mode, json otherwise). The secrets `kek` (base64,
  32 bytes) and `smtp_url` are accepted only from the environment or the config file, never as
  flags; `config show` redacts them and any password in `database_url`.
- **Plain HTTP:** a `public_url` with `http://` is accepted only for a loopback host (dev mode). Any
  other host needs `--insecure-http` (development and test setups only), which also selects dev-mode
  cookies.
- **KEK policy:** a configured `kek` wins; otherwise the KEK file is read if it exists. A new KEK is
  generated only for SQLite on first start. For Postgres AnvilID never generates a KEK and never
  creates a data directory, because every node sharing the database must use the same KEK: set
  `ANVILID_KEK` (or provide the file) or startup fails. `anvilid admin setup-url` never generates a
  KEK either.
- **Single writer per data directory:** `serve` takes an exclusive lock on `{data_dir}/serve.lock`
  (before any KEK is generated), so a second `serve` on the same directory fails with a clear error.
- **Trusted proxies:** `ANVILID_TRUSTED_PROXIES` (CIDRs) controls whether `X-Forwarded-*`/`Forwarded`
  headers are honored. Default: none (headers ignored), except loopback in dev mode.
- **Keys added in 0.2:** `trusted_proxies` (CIDRs or single IPs, comma-separated or a TOML array;
  an explicit empty value trusts none even in dev mode; errors name the key and entry position,
  never the value), `trusted_proxy_header` (`x-forwarded-for` | `forwarded`), `rate_limit_enabled`
  (default true), `rate_limit_auth_per_minute` (10, burst n/2), `rate_limit_token_per_second` (50),
  `rate_limit_token_client_per_second` (100), `rate_limit_admin_per_second` (20),
  `rate_limit_default_per_second` (50; a quota of 0 is rejected), `key_rotation_days` (90, 1–3650),
  `audit_retention_days` (365, 0 = keep forever, up to 36500) and `allow_destructive_migrations`
  (default false, §7.3). Brute-force backoff parameters keep their built-in defaults.
- **Startup reconciliation (0.2):** after installation the binary reconciles the console client
  with `public_url`, then ensures every tenant has an active key for each enabled algorithm.
- **Audit stream:** audit events are written to the database and mirrored on stdout as one raw
  JSON object per line (never on stderr), independent of `RUST_LOG`.
- **Email templates (0.2):** per-tenant overrides are checked on save (syntax, unknown variables
  against the kind's variable contract, no include/extends) and render with a fuel limit; the outbox
  worker uses tenant SMTP, then installation SMTP.
- **CLI commands:** `serve`, `migrate`, `config show|validate`, `admin setup-url` (new bootstrap URL
  for recovery), `keys rotate`, `backup create|restore` (SQLite), `export`/`import` (tenant YAML).
  0.1 ships `serve`, `migrate`, `config show|validate` and `admin setup-url`; 0.2 adds `keys rotate`;
  the others arrive with their milestones.

## 14. Background jobs

An in-process scheduler runs periodic jobs, each guarded by a `job_lease` row so only one node runs a
job at a time on Postgres. As built in 0.2: leases last 15 minutes and are released after each run;
jobs are idempotent, so a run longer than its lease can only cause duplicate work. Each node starts
its schedule with a small random delay.

| Job | Interval |
|---|---|
| Expired-row cleanup | 5 min (0.1) |
| Signing-key rotation check | 1 h (0.2) |
| Email outbox delivery | continuous (polling with backoff) |
| Back-channel logout delivery | event-driven, with retry |
| Webhook delivery (0.4) | event-driven, with retry |
| Audit log retention | daily (0.2; not scheduled when `audit_retention_days = 0`) |

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

**Backend matrix.** The storage contract suite always runs on SQLite (memory and file) and Postgres
(testcontainers). The HTTP integration, security and binary tests (`anvil-web/tests`,
`anvilid/tests`) select their backend with `ANVILID_TEST_DB=sqlite|postgres` (default `sqlite`);
`just test` runs them on SQLite and `just test-pg` reruns them on Postgres, so QUAL-02 holds for the
whole suite. `scripts/check-security-tests.sh` (in `just ci`) maps every §11 control to a named,
registered test and fails if one disappears.

**Definition of done for any feature:** implemented end to end, negative tests for its security
properties, documented (user docs + OpenAPI where relevant), conformance suite still green.

## 17. CI/CD

- **Every PR:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny check`, unit + contract
  (SQLite and Postgres) + integration + security tests, dependency-rule check (§4), OpenAPI drift
  check, `sqlx` offline metadata check, migration lint (§7.3), admin console type check against the
  OpenAPI document and build.
- **Main branch:** everything above plus conformance suite (Basic, Config and Form Post OP plans
  via `tests/conformance/run.sh all`), Playwright e2e on SQLite and Postgres (incl. passkey with a
  virtual authenticator, TOTP, consent, sessions, console, axe), upgrade test, musl release build
  with the embedded console, binary-size and idle-memory report.
- `just ci` runs the same Rust gates plus `migrations-check`, `security-tests` and `console-check`
  locally.
- **Release:** tag-triggered `release.yml` (linux musl amd64/arm64 and macOS archives with SHA-256
  checksums, multi-arch container image on ghcr.io, build provenance attestations; see
  `docs/RELEASING.md`). Still to come: Windows builds, SBOM, changelog generated from conventional
  commits.

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
login tested against mock IdPs in CI plus a manual real-provider checklist before release; theming editable live from the console.

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
