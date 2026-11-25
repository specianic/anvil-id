# AnvilID — Architecture & Implementation Specification

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Last updated** | 2026-11-26 (synced with release 0.3) |
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
| HTTP client | reqwest 0.13 (rustls) with SSRF guard | Upstream IdPs, JWKS fetch, webhooks, client metadata documents. Since 0.3 every outbound request goes through one guarded `OutboundClient` (§11) |
| Upstream OIDC/OAuth 2 client (0.3) | Our own relying-party code on the guarded reqwest client plus `anvil-jose` for ID-token verification | The Rust OIDC/OAuth 2 client crates evaluated on 2026-11-25 (`openidconnect` 4.1, `oauth2` 5.0) depend on `chrono` (banned) and, for `openidconnect`, on a second crypto stack including RustCrypto `rsa`. `anvil-jose` already verifies RS256/PS256/ES256/Ed25519 against a JWKS with an alg allow-list |
| i18n (0.3) | fluent-bundle, fluent-langneg, unic-langid | Fluent catalogs embedded in the binary, overridable from the theme directory (§10.6) |
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
| `ConnectionService` (0.3) | Upstream connection CRUD and the only place a connection secret is opened (`open_secret`) |
| `UpstreamService` (0.3) | Upstream sign-in: start, `form_post` hop, callback, link decision (§9.2) |
| `LogoutService` (0.3) | RP-initiated logout decisions and logout-token preparation for the delivery worker (§8.3) |
| `BrandingService` (0.3) | Theme tokens, custom CSS, logos, drafts and preview tokens (§10.7) |

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
| `identity_link` | id, tenant_id, user_id, connection_id, subject, email_at_link, metadata (JSON), created_at, last_used_at | Upstream identities (0.3). Unique (tenant_id, connection_id, subject); composite foreign keys to `user (tenant_id, id)` and `connection (tenant_id, id)`, both cascading. `metadata` keeps provider facts such as the Microsoft `tid`/`oid`, the Google `hd` or the GitHub `login` |
| `client` | id, tenant_id, client_id, name, type (confidential/public), application_type (web/native), require_pkce, auth_method, secret_hash, jwks / jwks_uri, redirect_uris, post_logout_redirect_uris, grant_types, scopes, token_format (jwt/opaque), consent_mode (required/skip_first_party), backchannel_logout_uri, backchannel_logout_session_required, allowed_resources, mfa_policy (nullable), created_at | `client_id` is unique per tenant; URL-form client IDs (CIMD) are cached in `client_metadata_cache` |
| `signing_key` | id, tenant_id, kid, alg, state (next/active/retired), private_key (encrypted with KEK), public_jwk, activated_at, retired_at, expires_at | |
| `browser_session` | id, tenant_id, user_id, auth_time, acr, amr (JSON), ip, user_agent, created_at, last_seen_at, expires_at, idle_expires_at | Session cookie holds an opaque random ID; only its hash is stored |
| `rp_session` | tenant_id, session_id, client_id, created_at | Which clients a browser session signed in to (for back-channel logout). Primary key (tenant_id, session_id, client_id); cascades with the session. Recorded in the `GrantRepo::create_code` transaction, only for a stored session of the same tenant. There is no `sid` column: the OIDC `sid` is the browser session id (§8.3) |
| `logout_delivery` (0.3) | id, tenant_id, client_id, uri, sub, sid, attempts, next_attempt_at, give_up_at, created_at, delivered_at, last_error | Back-channel logout queue. No foreign key to session, user or client, so a delivery survives the deletion that caused it. Rows are enqueued by the revoking storage intents (§7.1) |
| `flow` | id, tenant_id, kind (login/registration/recovery/verification/settings/consent/logout), state (JSON), csrf_hash, expires_at, browser_session_id? | Short-lived flow state machines (§9). `logout` (0.3) is the sign-out confirmation |
| `authorization_request` | id, tenant_id, client_id, params (JSON: redirect_uri, scope, state, nonce, code_challenge, resource, prompt, max_age, acr_values…), created_at, expires_at | Created at `/authorize`, consumed when a code is issued. Also used for PAR |
| `authorization_code` | code_hash (PK), tenant_id, client_id, user_id, browser_session_id, redirect_uri, scope, nonce, code_challenge, resource, auth_time, acr, amr, expires_at, consumed_at, token_family_id | The token family is created in the same transaction as the code, so a code replay that races the exchange still finds and revokes it |
| `token_family` | id, tenant_id, client_id, user_id?, scope, resource, auth_time?, acr?, amr, browser_session_id?, claims request (JSON)?, created_at, absolute_expires_at, revoked_at, revoked_reason | Groups a refresh-token chain; revoking the family revokes all of its tokens. Carries the authentication context so refreshed ID tokens repeat `auth_time` and UserInfo applies `claims.userinfo`. Access tokens carry the family id and UserInfo checks `revoked_at` |
| `refresh_token` | token_hash (PK), tenant_id, family_id, parent_hash?, expires_at, consumed_at | Rotation: each use consumes the token and issues a child |
| `access_token` | token_hash (PK), tenant_id, family_id?, client_id, user_id?, scope, created_at, expires_at, revoked_at | Only for opaque tokens; JWT access tokens are not stored. Revocation of a JWT revokes its family. Opaque client-credentials tokens have no family. `resource` arrives with RFC 8707 |
| `consent_grant` | id, tenant_id, user_id, client_id, scopes, created_at, updated_at, revoked_at | Unique (tenant_id, user_id, client_id). Scopes are a sorted, de-duplicated set; a new grant is merged into the existing one in a single upsert so concurrent first grants lose nothing. Revoking also revokes that client's token families of the user. `resource` arrives with RFC 8707 |
| `role`, `role_assignment` | role: id, tenant_id, org_id?, name, permissions (JSON). assignment: role_id, user_id, org_id? | RBAC (ORG-5) |
| `connection` (0.3) | id, tenant_id, slug, display_name, kind (google/apple/microsoft/github/oidc/oauth2), enabled, config (JSON, tagged `type`: social/oidc/oauth2), secret_enc, trust_email_verified, created_at, updated_at | Upstream IdP configuration, tenant-scoped in 0.3 (org-scoped connections and SAML arrive with ORG-2..4). Unique (tenant_id, slug). `kind` is derived from `config`. The secret (client secret, or the Apple `.p8` key) is sealed with the KEK under associated data tenant ‖ connection id and is write-only in the API |
| `branding`, `branding_logo` (0.3) | branding: tenant_id, scope_key (tenant or client), tokens (JSON), custom_css, logo_sha256, logo_type, updated_at, plus the draft (tokens, custom_css, preview_hash, preview_expires_at). branding_logo: tenant_id, sha256, content_type, bytes | Published theme per scope and its preview draft (§10.7). Logos are content-addressed per tenant. SQLite keeps the draft in columns of `branding`; Postgres keeps it in a separate `branding_draft` table so a scope can have a draft without published branding. The port semantics are the same |
| `organization`, `org_membership`, `org_invitation`, `org_domain` | standard fields | 1.0 (ORG-2..4) |
| `audit_event` | id, tenant_id, at, actor (user/client/admin/system + id), action, target, outcome (success/failure), ip, user_agent, trace_id, details (JSON object) | Append-only; retention configurable (`audit_retention_days`). Tenant lifecycle events are recorded in the `system` tenant with the tenant id as target. Details never contain secrets, identifiers of failed sign-ins or SMTP error text |
| `email_outbox` | id, tenant_id, to, template, payload (JSON), attempts, next_attempt_at, sent_at, last_error | |
| `email_template` | tenant_id, kind (verification/recovery/invitation/password_changed/recovery_code_used; 0.3 adds login_code/email_change/email_changed), subject, body_html, body_text, updated_at | Per-tenant override of the theme's email template, validated on save (§13) |
| `smtp_settings` | tenant_id, host, port, username?, password (sealed)?, from_address, tls (starttls/implicit/none), updated_at | Per-tenant SMTP; the password is write-only in the API |
| `job_lease` | name, owner, leased_until | Background job coordination (§14). Leases are 15 minutes and released after each run |
| `replay_guard` | tenant_id, kind (jti/dpop/nonce), value_hash, expires_at | `private_key_jwt` assertion `jti`s; later DPoP |
| `admin_setup_token` | token_hash, expires_at, used_at | One-time bootstrap URL (ADM-3) |
| `self_service_token` | token_hash (PK), tenant_id, kind (verification/recovery/invitation; 0.3 adds email_change), user_id, email, created_at, expires_at, consumed_at | Emailed one-time links, consumed atomically. Verification succeeds only while the user's email still equals `email` |

0.2 also adds to `client`: `token_format`, `consent_mode`, `id_token_signed_response_alg` (unset =
RS256) and `can_introspect`; and to `browser_session`: `ip`, `user_agent` (shown on the sessions
page). `flow.kind` gains `settings` and `consent`.

0.3 (SQLite migration `0005_release_0_3`, Postgres `0004_release_0_3`) adds `connection`,
`identity_link`, `rp_session`, `logout_delivery`, `branding` and `branding_logo` (Postgres also
`branding_draft`); the client columns `post_logout_redirect_uris`, `backchannel_logout_uri`,
`backchannel_logout_session_required`, `allowed_resources` and `mfa_policy`; and `resource` on
`authorization_code`, `token_family` and `access_token`. Tenant `settings` gains `mfa_policy`
(default `optional`), `email_otp` and `magic_link` (default off), `auto_link` (default on),
`upstream_registration` (unset = follow the registration mode) and `default_locale` (default `en`);
settings JSON written by 0.2 still parses. The `flow`, `self_service_token` and `email_template`
kind checks are widened: Postgres swaps the CHECK constraints, SQLite rebuilds the three tables in
the migration transaction (copy every row, no table references them).

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
| Client secrets, refresh/access tokens (opaque), authorization codes, session IDs, setup, recovery and (0.3) email-change tokens, API keys | SHA-256 of a 256-bit random value. The plaintext is shown once and never stored |
| Email sign-in codes (0.3) | 6-digit code stored in the login flow as HMAC-SHA-256 under a KEK-derived key over flow id ‖ code, so it is useless outside its flow; the magic-link token beside it (256-bit) as SHA-256. Both are consumed together, once |
| MFA recovery codes | ~80-bit random codes, formatted for typing (e.g. `XXXX-XXXX-XXXX-XXXX`), stored as HMAC-SHA-256 under a key derived from the KEK (a plain hash would be brute-forceable at this length). Shown once |
| TOTP seeds, SMTP passwords, CAPTCHA secrets, upstream IdP client secrets (0.3: client secret or Apple `.p8` key, AAD tenant ‖ connection id), signing private keys, SAML SP keys | AES-256-GCM with a data key derived from the **key-encryption key (KEK)** via HKDF, using the table and row ID as associated data |
| Email outbox payloads (contain single-use links and, since 0.3, sign-in codes) | Sealed with the KEK envelope (AES-256-GCM, purpose `anvilid/outbox-payload/v1`, tenant ID as associated data) when the email is created; opened only by the outbox worker immediately before rendering. A payload that cannot be opened is never sent |

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
    fn connections(&self) -> &dyn ConnectionRepo; // 0.3: upstream connections, identity links
    fn branding(&self) -> &dyn BrandingRepo;   // 0.3: themes, logos, preview drafts
    fn logout(&self) -> &dyn LogoutRepo;       // 0.3: RP sessions, back-channel delivery queue
    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, StorageError>;
    // later: orgs(), roles(), …
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
`RecoveryNotice`. 0.3 adds `ConnectionRepo::create_user_with_link` (just-in-time user + identity
link), `SessionRepo::upgrade_auth` (step-up of an active session in place),
`UserRepo::complete_email_change` (consume the token, switch the address, enqueue the notice to the
old address; a taken address returns `Conflict` and leaves the token unconsumed),
`LogoutRepo::claim_due_deliveries` (lease a batch of due deliveries; Postgres uses
`FOR UPDATE SKIP LOCKED`) and `LogoutRepo::complete_delivery`.

**Enqueue-on-revoke (0.3).** `SessionRepo::revoke`, `revoke_with_families`, `revoke_all_for_user`,
`UserRepo::complete_recovery` and `UserRepo::delete` insert, in the same transaction, one
`logout_delivery` per (session revoked by that call × `rp_session` of that session whose client has
a `backchannel_logout_uri`): `sub` = user id, `sid` = session id, `next_attempt_at` = now,
`give_up_at` = now + 24 h. The session ids come from the revoking `UPDATE … RETURNING`, so a call
that revokes nothing enqueues nothing. No service fans out deliveries itself, so no revocation path
can forget them.

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
  contract suite (`tests/upgrade.rs` in both storage crates; 0.1 → 0.2 and 0.2 → 0.3 keep every
  row).

### 7.4 Expiry and cleanup

Every expiring row has an `expires_at` column, and every read checks it, so correctness never depends
on cleanup. A background job deletes expired rows in batches (codes, flows, tokens, sessions,
replay guards; since 0.3 also logout deliveries past `give_up_at` and branding drafts past their
preview expiry). Replaced branding logos are not purged yet (open item for 0.3).

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
| Logout token | JWS per OIDC Back-Channel Logout (`typ: logout+jwt`, signed with the client's ID-token algorithm); §8.3 | 2 min |

- `sub` is the user's UUID by default (a pairwise identifier option comes later).
- The issuer is the tenant issuer URL (§12). It is computed in exactly one place.
- **Access token audience (0.2):** `aud` = the client id until RFC 8707 resource indicators ship
  (0.3). The token family is referenced by the `fid` claim.
- **Resource indicators (RFC 8707, 0.3).** `resource` may be repeated at `/authorize` and `/token`
  (it is the only repeatable parameter; empty values count as absent, duplicates are dropped). Each
  value must be an absolute URI without fragment, query or whitespace, at most 2048 characters, and listed in the
  client's `allowed_resources`; anything else is `invalid_target`. Values are compared and stored
  verbatim. The granted resources are stored on the code, the family and opaque access tokens. The
  code exchange, refresh and client credentials can only narrow them. An out-of-grant resource
  presented at code exchange burns the code and revokes its family; malformed values are refused
  before anything is consumed. Access-token `aud` is the selected resource (a JSON string), several
  resources (an array in request order), or the client id when none was requested. ID-token `aud`
  stays the client id. Introspection returns `aud` in the same shape. Remembered consent is still
  scope-only, so a client with a stored grant is not asked again for a different allowed resource
  (open item, Phase 5).
- **UserInfo audience (0.3).** UserInfo accepts an access token only when its `aud` contains the
  requesting client's id or `{issuer}/userinfo`. A token bound only to other resources is
  `invalid_token` (401), checked before scopes. Clients that request no resource are unaffected.
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
- **`amr`/`acr` added in 0.3:** email code or magic link `["otp"]` (RFC 8176); upstream sign-in
  `["fed"]` (not an RFC 8176 value; AnvilID's name for a federated sign-in). Both carry `acr`
  `urn:anvilid:acr:pwd`. A second factor after either adds `otp` and `mfa` (`["fed","otp","mfa"]`,
  `["otp","mfa"]`) with `acr` `urn:anvilid:acr:mfa`. A step-up never adds the primary method
  (a stepped-up `["fed"]` session never claims `pwd`).

### 8.3 Logout (0.3)

**RP-initiated logout** (OpenID Connect RP-Initiated Logout 1.0) at `GET`/`POST {issuer}/logout`:

- `id_token_hint` is verified against the tenant's enabled algorithms with expiry ignored. It must
  have `typ: JWT` (access and logout tokens are refused), at most 16 KiB, a string `sid` if any, and
  its client (`azp`, else the first `aud`) must exist. `client_id`, when sent with a hint, must be
  the hint's client.
- `post_logout_redirect_uri` must exactly match one of the client's `post_logout_redirect_uris`.
  The redirect keeps the registered string and adds only `state` (when one was sent).
- A valid hint for the current session (or no session) signs out at once: the session and its token
  families are revoked through `revoke_with_families` (which enqueues back-channel deliveries), the
  cookie is cleared, `logout` is audited and the delivery worker is woken. Every other case (no
  hint, a hint for another user or session) 303s to a CSRF-bound confirmation page under
  `/ui/logout` (`FlowKind::Logout`); the hint never travels there. After confirmation the browser
  goes to the validated redirect or to `/ui/signed-out`.
- Refusals are a page with a fixed sentence per error (`logout.invalid_id_token_hint`,
  `redirect_uri_not_registered`, `id_token_hint_required`, `client_mismatch`, `unknown_client`);
  a repeated parameter is `invalid_request`. The sentences are part of the theme contract.
- The post-logout redirect does not wait for back-channel delivery.

**Back-channel logout** (OpenID Connect Back-Channel Logout 1.0):

- `sid` is the browser session id. It is already the `sid` claim of ID tokens since 0.2, so no
  separate per-RP identifier is stored (an earlier draft of §6.1 had an `rp_session.sid` column).
  Deliveries always carry both `sub` (user id) and `sid`.
- Deliveries are enqueued by the revoking storage intents (§7.1). A worker on every node claims due
  rows (batch 20, row lease 2 min), signs a fresh logout token per attempt (claims exactly `iss`,
  `aud`, `iat`, `exp`, `jti`, `sub`, `sid`, `events`; no `nonce`) and POSTs only `logout_token` as a
  form body through the guarded outbound client. The token is signed with the client's ID-token
  algorithm and never with another one.
- The destination is the client's **current** `backchannel_logout_uri`; a removed client, tenant or
  URI gives up.
- Results: 200 or 204 = delivered. 5xx, network error or timeout = retry after
  min(10 s × 2^attempts, 1 h). Any other status (including 201, 202 and 3xx) or a destination the
  outbound policy refuses = give up. A retry that would land after `created_at + 24 h` gives up.
  Give-ups are audited as `backchannel_logout_failed` with a reason
  (`status|blocked|network|timeout|expired|client_removed|internal`), never the token or the URI.
- The worker wakes on every revoking logout and otherwise polls every 10 s. On Postgres,
  `FOR UPDATE SKIP LOCKED` keeps several nodes from claiming the same row.
- The logout token's `iss` is the tenant's canonical issuer (custom host if set, otherwise
  `public_url` + base path), because the worker has no request host. For a tenant with a custom
  host whose user signed in through `/t/{slug}`, this differs from the ID token's `iss`; this is an
  open item before 0.3.

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
- **As built in 0.3:** the login engine adds the upstream sign-in (§9.2), the email code and magic
  link (§9.3), the in-flow second-factor enrolment and step-up (§9.1), and the link confirmation.
  When a different user signs in on a browser that holds another user's session, that session is
  revoked with its token families (`session_revoked`, reason `session_switch`, back-channel
  deliveries enqueued); a same-user sign-in only rotates the session. `login_hint` prefills the
  identifier only when it is an email address.
- **`prompt` (0.3).** `/authorize` accepts `none`, `login`, `consent`, `select_account` and, only for
  tenants with open registration, `create`; discovery lists exactly this per tenant
  (`prompt_values_supported`). `none` with anything else, and `create` with `select_account`, are
  `invalid_request`; `create` on an invite-only or closed tenant is `invalid_request` (redirected
  with `state` and `iss`).
  - `select_account` shows an account chooser (`/ui/select-account`) when a usable session from
    before the request exists: "Continue" answers as that user (consent and step-up still apply),
    "Use another account" goes to sign-in. A sign-in during the request satisfies it. The chooser
    is a user-bound `FlowKind::Consent` flow in its connected-apps form, not a new flow kind.
  - `create` sends the user to registration and resumes with a code once the new account is signed
    in; only a sign-in during the request can answer it (an older session never does). If the
    tenant requires a verified email before sign-in, the request cannot resume: the client gets no
    answer until the user verifies and signs in, and the stored request expires normally.

### 9.1 MFA policy and step-up (0.3)

- Policy values `off`, `optional` (the default, 0.2 behaviour) and `required`, set per tenant
  (`settings.mfa_policy`) and per client (`client.mfa_policy`, unset = no opinion). The effective
  policy is the **strictest** of the two (`required` > `optional` > `off`); organizations join the
  same rule in Phase 6. The decision is a pure function in core (`policy::mfa`).
- `off` never asks for a second factor. `optional` asks users who have one (TOTP; a passkey sign-in
  already counts as MFA). `required` asks, and a user without a second factor enrols an
  authenticator app during sign-in and gets recovery codes once. In-flow passkey registration is
  not offered as an enrolment choice in 0.3.
- An existing single-factor session is re-checked only when the request asks for an `acr` or the
  effective policy is `required`. `acr_values=urn:anvilid:acr:mfa` (or an essential `acr` claim)
  steps the session up in place: same session id and cookie, `amr` gains `otp` and `mfa`,
  `auth_time` = now, audited `step_up_completed`.
- An essential `acr` that cannot be met (no second factor and the policy does not force
  enrolment) is answered with `unmet_authentication_requirements` (OpenID Connect Unmet
  Authentication Requirements 1.0). The user is still signed in single-factor with a truthful
  `acr`. With `prompt=none` a needed step-up is `interaction_required` (or
  `unmet_authentication_requirements` when the `acr` is essential). Discovery advertises
  `acr_values_supported: [urn:anvilid:acr:pwd, urn:anvilid:acr:mfa]`.

### 9.2 Upstream sign-in and account linking (0.3)

Connections (§6.1) are presets for Google, Apple, Microsoft and GitHub, plus generic OIDC (via
discovery) and generic OAuth 2 (with a JSON-pointer claim mapping). Every outbound request
(discovery, JWKS, token, userinfo/API) goes through the guarded outbound client (§11). The provider
rules are pure functions in `anvil-core::upstream`; the HTTP adapter caches discovery for 1 h and
JWKS per URI (Cache-Control max-age clamped to 5 min–24 h, forced refresh at most once a minute,
failures never cached).

- **Start** (`POST /ui/login/upstream/{slug}?flow=`, CSRF-bound, one form per button): sends
  `state` = `{flow id}.{random}`, a nonce and a PKCE S256 challenge (never to Apple, which is
  treated as not supporting PKCE). The flow stores only hashes and KEK-sealed values (AAD tenant ‖
  flow id), written by compare-and-swap. A 10-minute `SameSite=Lax` binding cookie
  (`__Host-anvil_upstream_{tenant}`) ties the callback to the browser.
- **Callback** (`GET|POST /ui/login/upstream/{slug}/callback`; Apple's `form_post` is turned into a
  same-site GET first): checks `state`, the connection and the binding cookie, consumes the pending
  sign-in once, then checks RFC 9207 `iss` (required when the provider advertises it), exchanges
  the code (Apple: a fresh ES256 client secret, 300 s) and validates the ID token in a fixed order:
  alg allow-list and signature (JWKS refreshed once for an unknown `kid`), `iss` (Microsoft `tid`
  as a canonical lowercase UUID, pinned to the tenant for single-tenant connections; Google `hd`
  allow-list), `aud`/`azp`, time, nonce, subject. GitHub and OAuth 2 use the profile API instead;
  GitHub takes only the primary verified email. Every failure is audited as
  `upstream_login_failed` with a reason code and shown as one generic error.
- The callback continues in a **fresh** login flow when another step follows (second factor,
  enrolment, link confirmation), because the provider's return carries neither the `Strict` flow
  cookie nor the CSRF token.
- **Email trust.** An upstream `email_verified` counts only when it is a strict `true` (Apple: also
  the string `"true"`) **and** the connection is trusted (`trust_email_verified`; on by default for
  Google, Apple and GitHub). Microsoft-asserted email is untrusted by default; trusting it needs an
  explicit risk acceptance in the admin API.
- **Link decision** (pure, `upstream::linking`):

  | Situation | Result |
  |---|---|
  | Identity already linked, user active | Sign in as that user |
  | Identity already linked, user blocked | Refuse |
  | Not linked, trusted verified email matches a verified local account, tenant `auto_link` on, not Microsoft | Link automatically (`identity_linked`, mode `auto`) and sign in |
  | Not linked, any other email match | Confirmation: the user signs in to the existing account (password or passkey, plus any required second factor); the link is made right before the session (mode `confirmed`) |
  | Not linked, no match, upstream registration allowed | Create the user just in time with the link (one transaction) |
  | Not linked, no match, registration not allowed | Refuse |

  An unverified or untrusted email never links automatically and never reveals whether an account
  exists. The account page links the signed-in user (mode `account`, §10.2); an identity linked to
  another user is refused. Unlinking is refused when it would leave the user without a password,
  passkey, other link or tenant email sign-in.
- Apple sends the user's name only on the first authorization, as unsigned form data: AnvilID takes
  only the name from it (trimmed, at most 200 characters per part); the email always comes from the
  signed ID token.
- Upstream sign-in does not yet apply `require_verified_email` to accounts created from an
  untrusted provider (open item before 0.3).

### 9.3 Email code and magic link (0.3)

- Off by default; the tenant settings `email_otp` and `magic_link` can be turned on only when SMTP
  is configured. In 0.3 either setting enables the method, and the `login_code` email always carries
  both the 6-digit code and the link (open item: decide whether the two settings should mean
  different things).
- The sign-in page offers "Email me a sign-in code". Every address gets the same answer; only an
  active account with a **verified** address gets the email (re-checked when the code or link is
  used). The code and link are valid 10 minutes, bound to the flow, consumed together once by
  compare-and-swap; five wrong codes invalidate both, a flow sends at most three emails. Sends and
  attempts go through the one limiter (sends: per address and IP, and per address; attempts: per
  user, shared with TOTP).
- The magic link GET only shows a button; the POST signs in only in the browser where the flow
  started (flow cookie plus a KEK-derived CSRF token). Another browser consumes nothing.
- It is a single factor (`amr ["otp"]`); the effective MFA policy then applies as after a password.
  It never satisfies MFA, never marks the address verified, cannot confirm an upstream link and is
  not offered in step-up flows.

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
["query"]`, `prompt_values_supported: ["none", "login"]` (0.3: see below), `code_challenge_methods_supported:
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

**Added in 0.3:** `GET`/`POST /logout` (§8.3), a repeatable `resource` at `/authorize` and `/token`
(§8.2), and the `prompt`, `max_age`, `login_hint` and `acr_values` handling of §9. Discovery adds
`end_session_endpoint`, `backchannel_logout_supported: true`,
`backchannel_logout_session_supported: true`, `prompt_values_supported` per tenant (`none`,
`login`, `consent`, `select_account`, plus `create` when registration is open),
`acr_values_supported: ["urn:anvilid:acr:pwd", "urn:anvilid:acr:mfa"]` and `ui_locales_supported`
(the locales that have a page catalog).

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

0.3 adds, all without JavaScript:

| Route | Purpose |
|---|---|
| `POST /ui/login/upstream/{slug}?flow=`, `GET\|POST /ui/login/upstream/{slug}/callback` | Upstream sign-in start and callback (§9.2). The callback is outside the Fetch-Metadata layer (providers return cross-site) |
| `POST /ui/login/email-code`, `POST /ui/login/email-code/verify`, `GET\|POST /ui/login/email-link` | Email code and magic link (§9.3); 404 when the tenant has neither setting on |
| `GET /ui/select-account?request=`, `POST` | Account chooser for `prompt=select_account` |
| `GET\|POST /ui/logout`, `GET /ui/signed-out` | Sign-out confirmation and the signed-out page (§8.3) |
| `/ui/account/profile`, `/ui/account/email` (+ `/confirm`), `/ui/account/password` | Profile, email change (the new address gets a link and must confirm it; the old address is told), password change or first password |
| `GET /ui/account/linked`, `POST /ui/account/linked/connect/{slug}?flow=`, `POST /ui/account/linked/{id}/unlink?flow=` | Linked upstream identities: list, connect, disconnect |
| `GET /ui/preview?token=` | Theme preview framed by the console (§10.7) |
| `GET /theme/theme.css[?flow=\|?preview=]`, `GET /theme/logo/{sha256}` | Generated theme stylesheet and logos (§10.7) |

Email change, password change and unlink need a sign-in within the last 15 minutes, like the 0.2
credential changes.

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
- Added in 0.3: `connections` (list, create, get, patch, delete, `PUT …/secret` write-only; the view
  shows `secret_configured` and the `redirect_uri` to register at the provider; kind and slug cannot
  change) and `branding` for the tenant and for each client (get, put, delete, `logo` put/delete,
  `preview`, `publish`). Both use the `admin:settings:{read|write}` scope family; writes to the
  `system` tenant also need `admin:write`, because its connections decide who can sign in to the
  console. Client options gained `post_logout_redirect_uris`, `backchannel_logout_uri`,
  `backchannel_logout_session_required`, `allowed_resources` and `mfa_policy`; tenant settings
  gained `mfa_policy`, `email_otp`, `magic_link` (refused without SMTP), `auto_link`,
  `upstream_registration` and `default_locale`. The request body limit is 64 KiB everywhere except
  the logo upload (400 KiB).
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

### 10.6 Internationalization (0.3)

- Page strings live in Fluent catalogs: `themes/default/locales/{lang}/{feature}.ftl`, one file per
  feature, embedded in the binary. Templates call `t("dotted.key", name=value)`; the Fluent message
  id is the key with `.` replaced by `-`. Core emits message keys and arguments only; the web layer
  localizes right before rendering. Output is auto-escaped; plurals use Fluent selectors. Bidi
  isolation marks are off (user values inside translated text are wrapped in `<bdi>`).
- Two files of one locale defining the same id, or a malformed file, fail startup with the file
  name. A missing message renders its dotted key. Operators override single messages, or add
  locales, with `{theme_dir}/locales/{lang}/*.ftl`.
- Negotiation: `ui_locales` (from the authorization request, or the `ui_locales` query parameter of
  a page) > the user's `locale` claim (account pages only) > `Accept-Language` (by q-value) > the
  tenant's `default_locale` > `en`. Unknown or malformed tags fall through and are never an error.
  An honoured `ui_locales` is carried on the page's form actions so later POSTs keep the language.
  Pages set `<html lang dir>`; `dir="rtl"` for Arabic, Hebrew, Persian, Urdu, Pashto and Yiddish,
  and `anvil.css` uses logical properties.
- Scope (UI-04 in 0.3): pages only. Emails are still rendered from one template per kind (the
  English default or the tenant's override), whatever the user's language; localized email
  templates are a later item. Error pages raised by
  middleware (CSRF, rate limit, tenant resolution) use the tenant's default locale.

### 10.7 Theming (0.3)

- Scopes: tenant and client (organizations in Phase 6). Tokens: nine colours plus an optional dark
  set, a system font family, a corner radius (0–32 px), custom CSS and a logo (PNG, JPEG or WebP,
  up to 256 KiB, identified by magic bytes; SVG is refused). Precedence is per field: client >
  tenant > default.
- Validation (pure, `policy::branding`): hex colours only; WCAG contrast below 3:1 for text on
  background, text on surface or text on primary is refused, below 4.5:1 is a warning. Custom CSS
  (up to 32 KiB) passes an allow-list of at-rules and functions; `url()`, `@import`, `expression`,
  `<`, `\` and the like are refused in any casing, also when split by comments or whitespace;
  brackets must nest; every error names its line. The stylesheet generator re-validates stored
  input, so a value that bypassed validation still cannot break out of its declaration.
- Serving: each tenant page links `{tenant_base}/theme/theme.css` right after `anvil.css`
  (`page.theme_css`). Flow pages add `?flow={id}`, so the server picks the client from the flow's
  authorization request; any failure falls back to the tenant theme without an error. The body is
  the merged CSS variables, a logo rule for the `.anvil-logo` element (or `display:none`), then the
  tenant's and the client's custom CSS. It is same-origin, so the strict CSP (`style-src 'self'`,
  no inline styles) is unchanged. Logos are served from `{tenant_base}/theme/logo/{sha256}` with
  `immutable` caching, `nosniff` and `default-src 'none'`.
- Drafts and preview: the console posts a draft and gets a 15-minute preview token and URL. The
  preview page is always addressed through the path form `/t/{slug}/ui/preview` (also for
  host-based tenants), so it is same-origin with the console, and it is the only page that allows
  framing (`frame-ancestors 'self'`). Publishing takes the preview token, so what goes live is what
  the preview showed. Theme changes are audited as `branding_updated`.
- Operators who need more than tokens can still override templates and `anvil.css` from the theme
  directory (§10.4).

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
| Response headers | Strict CSP (`script-src 'self'`, no inline scripts), `frame-ancestors 'none'` by default, HSTS when HTTPS, `Referrer-Policy: no-referrer` on auth pages. Exceptions are per page and narrow: the `form_post` page adds `form-action <redirect origin>`; the CAPTCHA page allows its provider; the theme preview page (0.3) allows `frame-ancestors 'self'` |
| SSRF | 0.2 fetches no client-supplied URL (no `jwks_uri`, no `request_uri`). **Since 0.3 one guarded `OutboundClient` carries every outbound request** (upstream discovery, JWKS, token and profile calls, back-channel logout, CAPTCHA, the breached-password check; webhooks and client metadata documents later). Rules: https only (plain http only in development mode, and only to allow-listed destinations); IP literals are checked before sending and every DNS answer as it resolves, so the address connected to is the address checked; private, loopback, link-local, CGNAT, multicast, documentation, benchmarking and other reserved IPv4/IPv6 ranges are blocked, including IPv4 embedded in IPv6 (mapped, NAT64, 6to4); redirects are never followed; proxy environment variables are ignored; URLs with userinfo are refused; connect timeout 5 s, total 10 s; bodies capped (1 MiB documents, 64 KiB token responses). Error text never echoes the URL, address or body. Operator keys: `outbound_allow_cidrs` (destinations allowed despite the block list; default loopback in development mode, none otherwise; an explicit value, even empty, replaces the default) and `outbound_ca_file` (extra PEM roots, e.g. a private CA; TLS verification is never switched off). Negative tests: `security_ssrf.rs` |
| Upstream sign-in (0.3) | `state` bound to the flow and to a `SameSite=Lax` binding cookie, nonce, PKCE S256 (except Apple), pending state consumed once by compare-and-swap before any provider call, RFC 9207 `iss` checked when advertised, ID tokens fully validated with an RS256-only allow-list for presets (generic OIDC: the provider's algorithms ∩ RS256/PS256/ES256/Ed25519), never `alg: none` or HMAC. Linking only on a trusted verified email or explicit confirmation (§9.2). Negative tests: `security_linking.rs`, `upstream_*.rs` |
| Email sign-in (0.3) | No enumeration (identical answers, and no email, for unknown, unverified and blocked addresses), flow-bound HMAC codes, single use, 10 min, attempt and send caps on the one limiter, magic link consumed only by a same-browser POST (§9.3). Negative tests: `security_email_code.rs` |
| RP-initiated logout (0.3) | Hint verified (enabled algs, `typ: JWT`, size cap), exact post-logout URI match, CSRF-bound confirmation when the hint does not prove the session (§8.3). Negative tests: `security_logout.rs` |
| Theming (0.3) | Allow-list CSS validator, re-validation at render, same-origin stylesheet under the unchanged CSP, logo type sniffing, preview token hashed at rest and valid 15 min (§10.7). Negative tests: `security_theme.rs` |
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
- **Keys added in 0.3:** `outbound_allow_cidrs` (`ANVILID_OUTBOUND_ALLOW_CIDRS`,
  `--outbound-allow-cidrs`; comma list or TOML array) and `outbound_ca_file`
  (`ANVILID_OUTBOUND_CA_FILE`, `--outbound-ca-file`; validated at load, errors name the key, never
  the content); see the SSRF row in §11. The 0.3 login features (MFA policy, email sign-in,
  auto-link, upstream registration, default language) are tenant settings in the management API,
  not configuration keys. Email sign-in can be turned on only when SMTP is available (installation
  `smtp_url` or the tenant's own SMTP settings).
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
| Back-channel logout delivery | 0.3: woken by every revoking logout, otherwise polls every 10 s; runs on every node and claims rows with a 2-minute row lease instead of a `job_lease` (§8.3) |
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
- **Main branch:** everything above plus conformance suite (Basic, Config, Form Post,
  RP-Initiated Logout and Back-Channel Logout OP plans via `tests/conformance/run.sh all`), Playwright e2e on SQLite and Postgres (incl. passkey with a
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
- **Connections:** upstream IdP configuration is a tagged enum stored in one table. 0.3 has
  `Social` (Google, Apple, Microsoft, GitHub presets), `Oidc` and `OAuth2`; `Saml` and later `Ldap`
  join the same enum.
- **Token claims pipeline:** claims are assembled by an ordered list of claim providers (standard
  claims, roles, organization, custom attributes); extension hooks (EXT-1) slot in later.
- **Events:** core services emit typed domain events; audit and webhooks are subscribers.
  Back-channel logout is not an event subscriber: since 0.3 its deliveries are enqueued by the
  revoking storage intents in the same transaction (§7.1), so a revocation cannot commit without
  them.

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
