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
| Observability | tracing, tracing-subscriber (JSON), metrics + Prometheus exporter, OpenTelemetry (OTLP/HTTP traces via tracing-opentelemetry) | As built in 0.4: compiled into every build and switched on at runtime (`otel_endpoint`; `metrics_listen` or `metrics_on_main_port`). There is no `otel` cargo feature; with the keys unset no exporter or recorder is installed (§15) |
| Rate limiting | governor (GCRA buckets) and moka (brute-force backoff state), wrapped by our keyed limiter in `anvil-cache` (§11) | One limiter interface. governor runs on the core `Clock`, so tests drive it with a fake clock. 0.4 adds a Redis backend of the same `RateLimiter` trait (GCRA and backoff as Lua scripts, `now` from the core clock), selected only by `redis_url`; one contract suite pins both backends to the same semantics |
| Attribute schemas (0.4) | jsonschema (draft 2020-12), offline | Remote `$ref` refused, size and depth capped, regex engine without backtracking (§11) |
| Tenant YAML (0.4) | serde-saphyr | Declarative tenant configuration (`anvilid tenant export|plan|apply`, docs/CONFIG-YAML.md) |
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
`chrono` (except through `tsp-ltv`, below), `samael`/`xmlsec` (C XML security libraries), `oxide-auth`.

"Single crypto backend" applies to **our own** signing, encryption and key handling: all of it goes
through aws-lc-rs. One exception is accepted: webauthn-rs pulls in RustCrypto crates (via
`crypto-glue`, including `rsa`) for verifying authenticator signatures. Verification uses public keys
only, so the `rsa` timing side channel does not apply. This exception is scoped in `deny.toml` with a
`wrappers = ["crypto-glue"]` entry, so no other crate can use `rsa`. The same crates bring in
MPL-2.0 licences, which `deny.toml` accepts per crate rather than globally.

A second, narrower exception: totp-rs computes TOTP codes with RustCrypto `hmac`/`sha1`. This is
code computation over a seed that is stored sealed with aws-lc-rs (AES-256-GCM under the KEK) and
opened only for the check; no key material is generated or stored by RustCrypto code.

A third exception, for `chrono` (1.0, decision Q2 option A; **owner review pending**): the SAML
signature verifier `bergshamra-keys` hard-depends on `tsp-ltv` (its X.509 trust facade), which
hard-depends on `chrono`. `deny.toml` allows `chrono` only through `wrappers = ["tsp-ltv"]`, so no
other crate can pull it in, and our own code stays on `time`. `cargo tree -i chrono --target all`
must show `tsp-ltv` as the only parent. The bergshamra crates are built with
`default-features = false, features = ["aws-lc"]`: their signing and verification run on aws-lc-rs
(through `kryptering`), and the RustCrypto provider is not compiled. They bring RustCrypto encoding
crates (`der`, `spki`, `pkcs8`, `x509-cert` 0.2) for certificate parsing only.

A fourth exception, for legacy password-hash verification (1.0, ADM-08, decision Q1; **owner review
pending (07-01)**): imported bcrypt, scrypt and Firebase scrypt hashes are verified with RustCrypto
`scrypt` 0.12.0 (`default-features = false`) and `bcrypt` 0.19.3 (`default-features = false,
features = ["alloc"]`), used only by `anvil-web` (`adapters/password/`). aws-lc-rs provides neither
scrypt nor bcrypt, and calling its C scrypt through FFI would need `unsafe`, which the workspace
denies. This is verification of imported hashes only: each imported hash is verified once at first
login and then re-hashed with Argon2id; no key material is generated or stored by these crates.
PBKDF2, SHA-2 and the AES-256-CTR step of Firebase scrypt stay on aws-lc-rs. `deny.toml` allows
`blowfish` only through `wrappers = ["bcrypt"]` and `salsa20` only through `wrappers = ["scrypt"]`;
`cargo tree -i blowfish --target all` must show only `bcrypt`, and `cargo tree -i salsa20 --target
all` only `scrypt` (`scrypt` itself was already in the graph through `pkcs5`, a webauthn-rs
dependency, before this exception).

### 2.1 Conditions on the Rust choice

Rust is chosen on these conditions. If any of them proves unworkable during M0, revisit the language
decision before M1 starts.

1. The OpenID conformance suite runs in CI from M1 onward.
2. One crypto backend (aws-lc-rs) builds statically for musl on amd64 and arm64.
3. Two sqlx storage implementations stay manageable (the M0 spike measures this).
4. SAML ships as an experimental feature until a pure-Rust XML-DSig stack passes an
   attack corpus (§20, D4). Status in 1.0: the corpus passes in CI; SAML still ships behind the
   runtime flag `saml_experimental` (off by default) until the Phase 7 external review and
   real-IdP interop checklist (`docs/SAML.md`).

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
  it, they are shared. As built in 0.4: Redis holds only rate-limit and brute-force state (key names
  HMAC'd under a KEK-derived key); an unreachable Redis at startup is an error; during an outage a
  5 s circuit breaker fails the `auth` class closed (429) or, with `rate_limit_redis_failure =
  local`, falls back to the in-process limiter, and other classes always fall back to it
  (docs/OPERATIONS.md). Nodes started together on an empty database converge on one installation.
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
| `client` | id, tenant_id, client_id, name, type (confidential/public), application_type (web/native), require_pkce, auth_method, secret_hash, jwks / jwks_uri, redirect_uris, post_logout_redirect_uris, grant_types, scopes, token_format (jwt/opaque), consent_mode (required/skip_first_party), backchannel_logout_uri, backchannel_logout_session_required, allowed_resources, mfa_policy (nullable), created_at | `client_id` is unique per tenant. 0.4 adds `registration_source` (static/dynamic/cimd), `metadata_expires_at` and `registration_access_token_hash`. **As built in 0.4 there is no `client_metadata_cache` table:** a fetched Client ID Metadata Document is validated and materialised as a `client` row with `registration_source = cimd` (`client_id` = the document URL, `metadata_expires_at` = the clamped cache lifetime), upserted in one statement that never overwrites a static or dynamic client. Failed fetches are not stored |
| `signing_key` | id, tenant_id, kid, alg, state (next/active/retired), private_key (encrypted with KEK), public_jwk, activated_at, retired_at, expires_at | |
| `browser_session` | id, tenant_id, user_id, auth_time, acr, amr (JSON), ip, user_agent, created_at, last_seen_at, expires_at, idle_expires_at | Session cookie holds an opaque random ID; only its hash is stored |
| `rp_session` | tenant_id, session_id, client_id, issuer, created_at | Which clients a browser session signed in to (for back-channel logout). Primary key (tenant_id, session_id, client_id); cascades with the session. Recorded in the `GrantRepo::create_code` transaction, only for a stored session of the same tenant. `issuer` is the issuer the client got its code (and ID tokens) from; a later code for the same row overwrites it (latest wins). It is null only for rows written before the 0.3 issuer migration. There is no `sid` column: the OIDC `sid` is the browser session id (§8.3) |
| `logout_delivery` (0.3) | id, tenant_id, client_id, uri, sub, sid, issuer, attempts, next_attempt_at, give_up_at, created_at, delivered_at, last_error | Back-channel logout queue. No foreign key to session, user or client, so a delivery survives the deletion that caused it. Rows are enqueued by the revoking storage intents (§7.1); `issuer` is copied from the RP session |
| `flow` | id, tenant_id, kind (login/registration/recovery/verification/settings/consent/logout), state (JSON), csrf_hash, expires_at, browser_session_id? | Short-lived flow state machines (§9). `logout` (0.3) is the sign-out confirmation |
| `authorization_request` | id, tenant_id, client_id, params (JSON: redirect_uri, scope, state, nonce, code_challenge, resource, prompt, max_age, acr_values, organization…), created_at, expires_at | Created at `/authorize`, consumed when a code is issued. Also used for PAR. 1.0: the organization switcher writes the chosen org into `params.organization` (delete and re-create under the same id, keeping `created_at` and `expires_at`) |
| `authorization_code` | code_hash (PK), tenant_id, client_id, user_id, browser_session_id, redirect_uri, scope, nonce, code_challenge, resource, auth_time, acr, amr, expires_at, consumed_at, token_family_id | The token family is created in the same transaction as the code, so a code replay that races the exchange still finds and revokes it. 1.0 adds `org_id` (the active organization, nullable, no foreign key) |
| `token_family` | id, tenant_id, client_id, user_id?, scope, resource, auth_time?, acr?, amr, browser_session_id?, claims request (JSON)?, created_at, absolute_expires_at, revoked_at, revoked_reason | Groups a refresh-token chain; revoking the family revokes all of its tokens. Carries the authentication context so refreshed ID tokens repeat `auth_time` and UserInfo applies `claims.userinfo`. Access tokens carry the family id and UserInfo checks `revoked_at`. 1.0 adds `org_id`: the active organization is bound to the family (never to a cookie or the session), re-checked at every refresh (membership lost → `invalid_grant` and the family is revoked) |
| `refresh_token` | token_hash (PK), tenant_id, family_id, parent_hash?, expires_at, consumed_at | Rotation: each use consumes the token and issues a child |
| `access_token` | token_hash (PK), tenant_id, family_id?, client_id, user_id?, scope, created_at, expires_at, revoked_at | Only for opaque tokens; JWT access tokens are not stored. Revocation of a JWT revokes its family. Opaque client-credentials tokens have no family. `resource` arrives with RFC 8707 |
| `consent_grant` | id, tenant_id, user_id, client_id, scopes, created_at, updated_at, revoked_at | Unique (tenant_id, user_id, client_id). Scopes are a sorted, de-duplicated set; a new grant is merged into the existing one in a single upsert so concurrent first grants lose nothing. Revoking also revokes that client's token families of the user. `resource` arrives with RFC 8707 |
| `role`, `role_assignment` | role: id, tenant_id, org_id?, name, description, permissions (JSON; Postgres `text[]`), created_at, updated_at. assignment: tenant_id, role_id, user_id | RBAC (ORG-5), built in 0.4. `org_id` is always null in 0.4; names are unique per tenant among tenant-level roles. Assignments have composite foreign keys to `role (tenant_id, id)` and `user (tenant_id, id)`, both cascading, so an assignment cannot cross tenants. **1.0 (decision Q5, hybrid on one table):** a role with `org_id` is owned by that organization (name unique per org, FK to the org, cascading); `role_assignment` gains `org_id`: null = tenant-wide, set = valid only inside that org, with a composite FK to `org_membership (tenant_id, org_id, user_id)` (cascading, so leaving the org removes its assignments). A tenant role can be assigned within an org; an org role only within its own org; roles with `admin:*` permissions never inside an org. Tenant-level queries (claims, the last-administrator guard) see only tenant roles and tenant-wide assignments |
| `attribute_definition` (0.4) | tenant_id, name, schema (JSON Schema fragment), required, user_editable, claim (rule or null), position, created_at, updated_at | Primary key (tenant_id, name). User values live in `user.attributes` (a JSON object) and are validated against the definitions on every write. Deleting a definition keeps stored values |
| `webhook_endpoint`, `webhook_delivery` (0.4) | endpoint: id, tenant_id, name, url, events, enabled, secret_enc, previous_secret_enc, previous_secret_expires_at, disabled_reason, timestamps. delivery: id, tenant_id, endpoint_id, event_type, payload_json (ids only), status (pending/delivered/failed), attempts, next_attempt_at (also the claim lease), last_http_status, last_error (an error class, never response text), created_at, completed_at | Secrets sealed with the KEK. Deliveries are inserted by `AuditRepo::append` in the audit transaction (one per enabled, subscribed endpoint) and cascade with their endpoint; completed rows follow audit retention (docs/WEBHOOKS.md) |
| `initial_access_token` (0.4) | id, tenant_id, description, token_hash (SHA-256, unique), expires_at, uses_remaining (null = unlimited), revoked_at, created_at | RFC 7591 initial access tokens for the `allow_listed` DCR policy; consumed by one conditional `UPDATE`. Purged 7 days after expiry or revocation |
| `connection` (0.3) | id, tenant_id, slug, display_name, kind (google/apple/microsoft/github/oidc/oauth2; 1.0 adds saml), enabled, config (JSON, tagged `type`: social/oidc/oauth2/saml), secret_enc, trust_email_verified, org_id (1.0), created_at, updated_at | Upstream IdP configuration, tenant-scoped in 0.3. Unique (tenant_id, slug), shared by tenant and organization connections. `kind` is derived from `config`. The secret (client secret, or the Apple `.p8` key) is sealed with the KEK under associated data tenant ‖ connection id and is write-only in the API. **1.0:** `org_id` set = an organization connection (OIDC or SAML only, FK to the org, cascading); SAML configs (IdP entity id, https SSO URL, 1-3 pinned PEM certificates, NameID format, attribute mapping, metadata URL for the record) exist only in organizations and carry no secret |
| `branding`, `branding_logo` (0.3) | branding: tenant_id, scope_key (tenant, client, or since 1.0 `org:{uuid}`), tokens (JSON), custom_css, logo_sha256, logo_type, updated_at, plus the draft (tokens, custom_css, preview_hash, preview_expires_at). branding_logo: tenant_id, sha256, content_type, bytes | Published theme per scope and its preview draft (§10.7). Logos are content-addressed per tenant. SQLite keeps the draft in columns of `branding`; Postgres keeps it in a separate `branding_draft` table so a scope can have a draft without published branding. The port semantics are the same |
| `organization` (1.0) | id, tenant_id, slug, display_name, mfa_policy (nullable), settings (JSON: `default_role_ids` for SSO just-in-time members), metadata (JSON), created_at, updated_at | A customer company inside a tenant (ORG-2). Unique (tenant_id, slug); slug rule as for tenants. None in the `system` tenant. Deleting one cascades to everything below plus its connections, roles and assignments, deletes its branding scope and revokes its token families, in one transaction |
| `org_membership` (1.0) | tenant_id, org_id, user_id, created_at | Primary key (tenant_id, org_id, user_id); FKs to the org and the user, both cascading. Removing a member also revokes that user's families bound to the org, in the same transaction |
| `org_invitation` (1.0) | id, tenant_id, org_id, email, role_ids (JSON), token_hash (SHA-256, unique), invited_by_kind, invited_by_id, created_at, expires_at (7 days), accepted_at, accepted_user_id, revoked_at | Single use: accepted by one conditional `UPDATE … WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now` in the same transaction as the membership and its roles (concurrent accepts: one winner). Accepted and revoked are exclusive (CHECK) |
| `org_domain` (1.0) | id, tenant_id, org_id, domain (normalised A-label), token, status (pending/verified), verified_at, last_checked_at, failing_since, connection_id, routing, allow_local_password (default true), created_at | Unique (tenant_id, org_id, domain); a **partial unique index on (tenant_id, domain) where verified** lets only one org per tenant hold a verified domain (the database decides a race). Routing needs a verified claim, `routing` and an enabled connection of the same org. Deleting the target connection clears `connection_id` and keeps the verified claim (SQLite: an `AFTER DELETE` trigger; Postgres: a composite FK, and `ConnectionRepo::delete` clears the target first) |
| `audit_event` | id, tenant_id, at, actor (user/client/admin/system + id), action, target, outcome (success/failure), ip, user_agent, trace_id, details (JSON object) | Append-only; retention configurable (`audit_retention_days`). Tenant lifecycle events are recorded in the `system` tenant with the tenant id as target. Details never contain secrets, identifiers of failed sign-ins or SMTP error text |
| `email_outbox` | id, tenant_id, to, template, payload (JSON), attempts, next_attempt_at, sent_at, last_error | |
| `email_template` | tenant_id, kind (verification/recovery/invitation/password_changed/recovery_code_used; 0.3 adds login_code/email_change/email_changed; 1.0 adds org_invitation), subject, body_html, body_text, updated_at | Per-tenant override of the theme's email template, validated on save (§13) |
| `smtp_settings` | tenant_id, host, port, username?, password (sealed)?, from_address, tls (starttls/implicit/none), updated_at | Per-tenant SMTP; the password is write-only in the API |
| `job_lease` | name, owner, leased_until | Background job coordination (§14). Leases are 15 minutes and released after each run |
| `replay_guard` | tenant_id, kind (jti/dpop/nonce; 1.0 adds saml_assertion_id), value_hash, expires_at | `private_key_jwt` assertion `jti`s; since 1.0 SAML assertion ids (hash of IdP entity id ‖ assertion id, kept until the assertion's `NotOnOrAfter`, at most 1 h); later DPoP |
| `admin_setup_token` | token_hash, expires_at, used_at | One-time bootstrap URL (ADM-3) |
| `self_service_token` | token_hash (PK), tenant_id, kind (verification/recovery/invitation; 0.3 adds email_change), user_id, email, created_at, expires_at, consumed_at | Emailed one-time links, consumed atomically. Verification succeeds only while the user's email still equals `email` |

0.2 also adds to `client`: `token_format`, `consent_mode`, `id_token_signed_response_alg` (unset =
RS256) and `can_introspect`; and to `browser_session`: `ip`, `user_agent` (shown on the sessions
page). `flow.kind` gains `settings` and `consent`.

0.3 (SQLite migrations `0005_release_0_3` and `0006_release_0_3_logout_issuer`, Postgres
`0004_release_0_3` and `0005_release_0_3_logout_issuer`) adds `connection`,
`identity_link`, `rp_session`, `logout_delivery`, `branding` and `branding_logo` (Postgres also
`branding_draft`); the client columns `post_logout_redirect_uris`, `backchannel_logout_uri`,
`backchannel_logout_session_required`, `allowed_resources` and `mfa_policy`; and `resource` on
`authorization_code`, `token_family` and `access_token`. Tenant `settings` gains `mfa_policy`
(default `optional`), `email_otp` and `magic_link` (default off), `auto_link` (default on),
`upstream_registration` (unset = follow the registration mode) and `default_locale` (default `en`);
settings JSON written by 0.2 still parses. The `flow`, `self_service_token` and `email_template`
kind checks are widened: Postgres swaps the CHECK constraints, SQLite rebuilds the three tables in
the migration transaction (copy every row, no table references them). The second migration only
adds the nullable `issuer` column to `rp_session` and `logout_delivery`.

0.4 (SQLite migration `0007_release_0_4`, Postgres `0006_release_0_4`, additive) adds `role`,
`role_assignment`, `attribute_definition`, `webhook_endpoint`, `webhook_delivery` and
`initial_access_token`; `user.attributes`; the three client registration columns above; and
`resources` on `consent_grant` (a sorted set merged like scopes; a remembered grant must cover
every requested scope and resource). Tenant `settings` gains `claims` (role/permission claim
mapping), `dcr` and `cimd` (both default `disabled`, forced `disabled` for `system`). The only
data change is a backfill: the `system` tenant's `administrator` role (`admin:write`) is created
and assigned to every existing system-tenant user.

1.0 (SQLite `0008_release_1_0`, additive, and `0009_release_1_0_rebuild`; Postgres
`0007_release_1_0`, in place) adds `organization`, `org_membership`, `org_invitation` and
`org_domain`; `org_id` on `connection`, `role_assignment`, `authorization_code` and `token_family`
(and the FK on `role.org_id`); `client.organization` (`off`/`optional`/`required`, default `off`);
and the new kinds `saml` (connection), `saml_assertion_id` (replay guard) and `org_invitation`
(email template). SQLite cannot change these constraints in place, so `0009` rebuilds
`connection`, `role`, `role_assignment`, `replay_guard` and `email_template` with
`-- no-transaction`: foreign keys off, one explicit transaction that copies every column of every
row and recreates every index, `pragma_foreign_key_check` into a table whose CHECK refuses any
violation before `COMMIT`, then foreign keys on (with foreign keys on, dropping `connection`
would cascade into `identity_link`). Postgres swaps CHECK constraints and replaces the
`role_assignment` primary key with two partial unique indexes (tenant-wide and in-org). Every 0.4
row becomes tenant-level (`org_id` null, client policy `off`); the upgrade tests prove it row by
row on both backends.

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
| Client secrets, refresh/access tokens (opaque), authorization codes, session IDs, setup, recovery and (0.3) email-change tokens, (1.0) organization invitation tokens, API keys | SHA-256 of a 256-bit random value. The plaintext is shown once and never stored |
| Email sign-in codes (0.3) | 6-digit code stored in the login flow as HMAC-SHA-256 under a KEK-derived key over flow id ‖ code, so it is useless outside its flow; the magic-link token beside it (256-bit) as SHA-256. Both are consumed together, once |
| MFA recovery codes | ~80-bit random codes, formatted for typing (e.g. `XXXX-XXXX-XXXX-XXXX`), stored as HMAC-SHA-256 under a key derived from the KEK (a plain hash would be brute-forceable at this length). Shown once |
| TOTP seeds, SMTP passwords, CAPTCHA secrets, upstream IdP client secrets (0.3: client secret or Apple `.p8` key, AAD tenant ‖ connection id), signing private keys, SAML SP keys (none in 1.0: AuthnRequests and SP metadata are unsigned) | AES-256-GCM with a data key derived from the **key-encryption key (KEK)** via HKDF, using the table and row ID as associated data |
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
    fn roles(&self) -> &dyn RoleRepo;          // 0.4: roles, assignments; 1.0: org roles and in-org assignments
    fn attributes(&self) -> &dyn AttributeRepo; // 0.4: custom attribute definitions
    fn webhooks(&self) -> &dyn WebhookRepo;    // 0.4: endpoints, delivery queue
    fn registration(&self) -> &dyn RegistrationRepo; // 0.4: initial access tokens
    fn organizations(&self) -> &dyn OrgRepo;   // 1.0: orgs, members, invitations, domains, routing
    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, StorageError>;
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
link, plus the verification token and email when the address is not verified),
`ConnectionRepo::delete_link` (unlink with the last-sign-in-method guard, §9.2), `SessionRepo::upgrade_auth` (step-up of an active session in place),
`UserRepo::complete_email_change` (consume the token, switch the address, enqueue the notice to the
old address; a taken address returns `Conflict` and leaves the token unconsumed),
`LogoutRepo::claim_due_deliveries` (lease a batch of due deliveries; Postgres uses
`FOR UPDATE SKIP LOCKED`) and `LogoutRepo::complete_delivery`.

**1.0 (`OrgRepo` and additions).** Atomic intents: `OrgRepo::delete` (cascade, org-bound family
revocation, branding scope), `add_member` (membership plus in-org roles; returns
`AddMemberOutcome::{Added, AlreadyMember, NotFound}`), `remove_member` (membership, its
assignments and the user's org-bound families), `accept_invitation` and
`accept_invitation_with_new_user` (outcome order Invalid, EmailMismatch, AlreadyMember or Conflict;
one conditional update decides concurrent accepts), `mark_verified` (the partial unique index
turns a second org into `Conflict`), `record_check` and `unverify` (re-check streak), plus the
reads `routed_domain` (verified, routing on, enabled connection of the same org),
`routing_connections` (those connections for the whole tenant; the core decides which can route),
`verified_domains_of_org` and the installation-wide `due_for_recheck`. `RoleRepo` gains
`list_org_roles`, `assign_in_org` (the user must be a member; the role a tenant role or this org's),
`unassign_in_org`, `roles_for_user_in_org`, `org_assignments` and `org_holders_of_permission`; its
0.4 methods are defined over tenant roles and tenant-wide assignments only. `ConnectionRepo` gains
`list_for_org` and `has_links`, and `create_user_with_link` takes an optional `NewMembership`
(just-in-time user, link, membership and default roles in one transaction). Non-storage ports:
`DomainTxtLookup` (bounded TXT lookup) and `SamlXml` (verify a response, parse IdP metadata,
encode the Redirect binding). The contract suite has 45 more tests, including 8-way concurrent
invitation accepts and domain verifications.

**Enqueue-on-revoke (0.3).** `SessionRepo::revoke`, `revoke_with_families`, `revoke_all_for_user`,
`UserRepo::complete_recovery` and `UserRepo::delete` insert, in the same transaction, one
`logout_delivery` per (session revoked by that call × `rp_session` of that session whose client has
a `backchannel_logout_uri`): `sub` = user id, `sid` = session id, `next_attempt_at` = now,
`give_up_at` = now + 24 h, `issuer` = the RP session's issuer. The session ids come from the
revoking `UPDATE … RETURNING`, so a call
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
  copy every row, e.g. 0004 and 0009).
- Migrations are forward-only and **expand/contract**: a release never drops or renames a column that
  the previous minor release still reads. Destructive cleanups happen one minor release later.
- CI test: create a database with release N-1's migrations and data fixtures, upgrade to N, run the
  contract suite (`tests/upgrade.rs` in both storage crates; 0.1 → 0.2, 0.2 → 0.3 and, since
  1.0, 0.4 → 1.0 keep every row, the last one including the SQLite `-- no-transaction` rebuild).

### 7.4 Expiry and cleanup

Every expiring row has an `expires_at` column, and every read checks it, so correctness never depends
on cleanup. A background job deletes expired rows in batches (codes, flows, tokens, sessions,
replay guards; since 0.3 also logout deliveries past `give_up_at`, branding drafts past their
preview expiry, branding logos that no published or draft branding references any more, and, on
both backends, expired token families). Deleting a client also deletes its client-scoped branding.

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
  stays the client id. Introspection returns `aud` in the same shape. Known limitation of 0.3:
  remembered consent covers scopes only, so a client with a stored grant is not asked again when it
  requests a different allowed resource. Covering resources changes the consent model (the
  `consent_grant` schema, the consent screen and revocation) and is planned with the Phase 5
  permissions work.
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
- Every web path that revokes sessions wakes the worker through one helper
  (`AppState::wake_logout_worker`): RP-initiated logout and its confirmation, every sign-in (so a
  session switch), signing out sessions on the account page, a password change that signs out
  other sessions, recovery completion, and the admin session and user deletions. Otherwise the
  worker polls every 10 s. On Postgres, `FOR UPDATE SKIP LOCKED` keeps several nodes from claiming
  the same row.
- The logout token's `iss` is the issuer the RP received its ID tokens from: the `issuer` recorded
  on the RP session when the code was issued (path or custom host) and copied to the delivery. The
  tenant's canonical issuer (custom host if set, otherwise `public_url` + base path) is used only
  for deliveries from rows written before that column existed.

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
  state still decides). Since 0.4 a passkey is also a second factor: a user with a passkey gets a
  passkey option at the second-factor step (§9.1).
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
  policy is the **strictest** of the two (`required` > `optional` > `off`). Since 1.0 the active
  organization's `mfa_policy` joins the same rule (strictest of tenant, organization and client;
  `policy::mfa::effective_policy_for`). The decision is a pure function in core (`policy::mfa`).
  During the first password sign-in the organization is not known yet, so its policy is applied
  right after sign-in as a step-up, before any code is issued.
- `off` never asks for a second factor. `optional` asks users who have one (TOTP or, since 0.4, a
  passkey; a passkey sign-in already counts as MFA). `required` asks, and a user without a second
  factor enrols one during sign-in: an authenticator app (recovery codes shown once) or, since 0.4,
  a passkey.
- **Passkey as the second factor (0.4):** whether a user has a second factor is answered in one
  place (`service::authorize::second_factor_methods`: TOTP or at least one passkey; recovery codes
  only back up TOTP), used by the login engine, the step-up path and the authorization decision.
  The second-factor step accepts a TOTP code, a recovery code or a passkey assertion. The passkey
  challenge is issued at that step and stored in its own field of the flow state (a challenge of
  the sign-in page is never accepted there), taken out with a compare-and-swap before verification
  (single use), and the assertion must come from one of the step user's own passkeys (user handle
  and credential id checked before the signature). Success signs in like a passkey sign-in
  (`["hwk"|"swk","user","mfa"]`, MFA `acr`) or upgrades the step-up session in place.
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
  exists. The account page links the signed-in user (mode `account`, §10.2) and then returns to
  `/ui/account/linked` (303); an identity linked to another user is refused. Unlinking is refused
  when it would leave the user without a sign-in method: a password, a passkey, another link, or
  tenant email sign-in (`email_otp` or `magic_link`) with a verified address. The check and the
  delete are one atomic storage intent (`ConnectionRepo::delete_link`, the user row locked), so
  two concurrent unlinks cannot both pass.
- Apple sends the user's name only on the first authorization, as unsigned form data: AnvilID takes
  only the name from it (trimmed, at most 200 characters per part); the email always comes from the
  signed ID token.
- **Verified email.** A just-in-time account gets `email_verified` only from a trusted, verified
  upstream email. Otherwise it is created unverified and its verification email is stored in the
  same transaction as the user and link, as in local registration. Under the tenant's
  `require_verified_email`, an upstream sign-in that resolves to an account with an unverified
  address (just created, or through an existing link) creates no session: it is audited
  `upstream_login_failed` with reason `email_not_verified` and the sign-in page shows
  `registration.check_email` (just created) or `login.email_not_verified`. A trusted provider
  asserting a verified email signs in at once. Linking from the account page is not affected.
- **Binding cookie.** The callback clears the binding cookie only once its `state` and the binding
  cookie matched the pending sign-in (on success and on any later failure). A forged or mismatched
  callback (missing or foreign `state`, no or another binding cookie) leaves it in place, so it
  cannot cancel the browser's pending sign-in.
- **Generic OIDC and UserInfo.** With `fetch_userinfo` on, UserInfo supplies the email, its
  verification and the names. With it off, UserInfo is still called when the ID token has no
  `email` (OIDC Core §5.4 lets a provider return it only there), and only `email` and
  `email_verified` are taken. In both cases the UserInfo `sub` must equal the ID token's, otherwise
  the sign-in fails (`userinfo_subject`). A failed fallback call leaves the identity without an
  email, so an existing link still signs in.

### 9.3 Email code and magic link (0.3)

- Off by default; the tenant settings `email_otp` and `magic_link` can be turned on only when SMTP
  is configured. Either setting offers email sign-in on the sign-in page, and each controls its own
  method: `email_otp` is the 6-digit code, `magic_link` is the link. The `login_code` email, the
  "check your email" page and the accepted inputs follow whichever is on (code only, link only, or
  both); `POST /ui/login/email-code/verify` is 404 without `email_otp` and `/ui/login/email-link`
  404 without `magic_link`. In the `login_code` template `code` and `link` are optional (at least
  one is present), and template overrides that use them without `{% if … is defined %}` are
  refused on save.
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

### 9.4 Organizations in the grant (1.0)

- **Active organization.** `/authorize` takes `organization` (an org id or slug, at most 128
  bytes, not repeated). After sign-in the pure `policy::org_claims::resolve_active_org` decides
  from the client's `organization` policy, the parameter and the user's memberships: `off` +
  parameter → `invalid_request`; a non-member org → `access_denied`; `required` with one membership
  selects it, with several asks the switcher (`interaction_required` under `prompt=none`), with
  none → `access_denied`. An id match wins over a slug; display names never match.
- The active org is stored on the authorization code and the token family (`org_id`), never in a
  cookie or the browser session. The token endpoint re-checks membership at code exchange and at
  every refresh; a lost membership or a deleted org answers `invalid_grant` and revokes the family.
  A code whose `org_id` differs from its family's is refused.
- **Claims.** `org_id` and `org_slug` always come with an active org; `org_roles` (roles held in
  the org, gated by scope `roles`) in the ID token, JWT access token, UserInfo and introspection;
  `org_permissions` in the JWT access token and introspection only. They are recomputed at every
  refresh, inserted before mapped claims, and reserved (no attribute or role mapping can emit
  them). Client credentials tokens never carry them. Since 1.0 opaque tokens get the same role,
  permission, attribute and org claims at introspection and UserInfo as a JWT carries (closing
  the 0.4 gap).
- **`org:admin`.** The scope is issued only while the user holds the permission `org:admin` in the
  active org (re-bounded at each refresh, never beyond the grant), never without an active org,
  never to client credentials, never registrable (DCR, CIMD) and never on `system` tenant clients.
- **Switcher.** `GET|POST /ui/select-organization` lists only the signed-in user's memberships,
  binds a consent-kind flow to the stored request (cookie + CSRF), accepts only a request whose
  client is `required` and which names no org, uses the flow up before writing the choice into the
  stored request, then continues the authorization (where the org MFA can step up). Switching
  orgs is a new authorization request with `organization=…`.

### 9.5 SAML 2.0 SP sign-in (1.0, experimental)

Behind the operator flag `saml_experimental` (off: every route 404, every `SamlService` method
`FeatureDisabled`). Profile and checks in `docs/SAML.md`.

- **Start** (`POST /ui/login/saml/{slug}/start?flow=`, CSRF): an unsigned HTTP-Redirect
  AuthnRequest (request id `_` + 32 hex, `ForceAuthn` for `prompt=login`), a 59-byte RelayState
  (flow id + nonce, stored hashed), the shared `SameSite=Lax` binding cookie; pending state stored
  in the login flow by compare-and-swap, valid 10 minutes.
- **ACS** (`POST /ui/login/saml/{slug}/acs`, outside the Fetch-Metadata layer, no cookies, 256 KiB
  body limit): RelayState → flow, pending request consumed once, then the `SamlXml` adapter
  (size and markup caps, one uppsala parse with DTDs forbidden, document rules, a strict profile
  pre-check before any bergshamra call, bergshamra-dsig verification on aws-lc against the pinned
  certificates only with the verified reference resolved to the pinned Assertion node, extraction
  from that node only), then core `saml::validate::check` (destination, `InResponseTo`, status,
  issuers, instants with 90 s skew, bearer confirmation, conditions, audience, authn statement;
  21 reason codes), then the database replay guard on the assertion id. Only the extracted
  identity is sealed into the flow (AAD flow ‖ tenant).
- **Continue** (`GET /ui/login/saml/{slug}/continue`): requires the binding cookie, then the shared
  upstream completion `UpstreamService::complete_identity` (the same code as organization OIDC).
  IdP-initiated responses are refused (no pending request matches). Every failure is one generic
  page and `saml_login_failed` with a reason code.

### 9.6 Enterprise connections and home-realm discovery (1.0)

- **Organization connections** (OIDC or SAML, `connection.org_id`) reuse the 0.3 upstream
  machinery and one completion path. They are hidden from the sign-in page. Email trust is
  domain-bound (`upstream::linking::enterprise_email_trust`): the email's domain must equal one of
  that org's verified domains and the upstream must not say `email_verified: false` (OIDC: strict
  `true`; SAML: the verified domain alone). Org A's IdP can never auto-link or add a membership on
  org B's domain. Just-in-time users get the link, the membership and the org's existing default
  roles in one transaction (`create_user_with_link` with a membership); an existing linked
  non-member becomes a member. JIT is decided by `upstream::linking::jit_allowed`: an org connection
  whose email is trusted for the org (one of its verified domains) creates accounts whatever the
  tenant's registration setting; tenant connections, and org connections asserting any other
  address, follow `upstream_registration` (unset = registration mode `open`).
- **Domain verification.** `policy::home_realm::normalize_domain` (lowercase, A-labels, no public
  suffix, IP, wildcard, single label, URL parts or reserved names), a 128-bit token, the record
  `_anvilid-challenge.{domain}.` TXT `anvilid-domain-verification={token}`, checked by the one
  `service::domain_check::check_domain` through the `DomainTxtLookup` port (hickory, FQDN only, no
  cache, 2 s × 2 attempts, 5 s overall); every failure is the same `pending` answer. The partial
  unique index gives a domain to one org per tenant. The daily `domain_recheck` job (§14) keeps a
  failure streak and unverifies after 7 days.
- **Identifier-first sign-in.** A tenant with a routable connection (`OrgRepo::routing_connections`
  filtered by `FlowService::idp_routable`: enabled, org-owned, OIDC, or SAML only with the flag on;
  the same rule as routing) starts the login flow at `EmailFirst` instead of the combined form. The
  brute-force lock and CAPTCHA pages answered before the flow runs render the same initial form
  (`FlowService::initial_login_form`), and the email-first form also answers from the password
  step (the email is routed again). The email is routed by its
  domain only (`OrgRepo::routed_domain`: verified, routing on, enabled connection of the same org;
  SAML only with the flag on): `allow_local_password = false` → straight to the IdP
  (`service::flow::start_idp`, SAML or OIDC with the page's flow binding); `true` (default) →
  `SsoChoice` (single sign-on or password); no route → the same password step for every address,
  without reading any account. `login_hint` is routed at `GET /ui/login`; `organization` naming an
  org with exactly one enabled connection goes to that IdP. Passkey and upstream starts are
  accepted in every primary step.
- **Local-method policy.** For a routed domain with `allow_local_password = false`, password,
  email-code and magic-link sign-in (including codes requested earlier) are refused with
  `hrd.use_sso`; passkeys stay allowed. Admin-side guards (`service::org_domain::check_routing`,
  pure): routing needs a verified domain and an enabled same-org target; turning passwords off
  also needs routing and a target with at least one identity link. Disabling or deleting the
  target stops routing. The tenant admin is always the recovery path.

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
| `POST /register`, `GET, PUT, DELETE /register/{client_id}` | Dynamic client registration (RFC 7591) and management (RFC 7592), policy-controlled; built in 0.4. 404 while the tenant's policy is `disabled` | OIDC-17 |

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

**Added in 1.0:** the `organization` parameter at `/authorize` (§9.4); discovery's
`claims_supported` lists `org_id`, `org_slug`, `org_roles` and `org_permissions`.

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

1.0 adds, all without JavaScript:

| Route | Purpose |
|---|---|
| `POST /ui/login/identify?flow=` | Identifier-first sign-in: the email page and the single-sign-on choice (`choice=sso\|password\|change`), §9.6 |
| `GET /ui/select-organization?request=`, `POST /ui/select-organization?flow=&request=` | Organization switcher (§9.4) |
| `GET /ui/invitation?token=`, `POST /ui/invitation`, `POST /ui/invitation/register` | Organization invitation: the GET only shows the offer; accept (signed in) or register for the invited address (registering signs in through the shared session code, `FlowService::sign_in_registered_user`). CSRF: a `__Host-anvil_invitation` nonce cookie (SameSite=Strict, 1 h) plus an HMAC over tenant, nonce and token under a KEK-derived key; `no-store`, `no-referrer` |
| `GET /ui/login?return_to=` | Where a sign-in without an authorization request returns: an exact allowlist (`policy::return_to`: `/ui/invitation?token=` plus 1-128 base64url characters, nothing else; anything else is ignored). Stored in the login flow state only sealed with the KEK (`return_to_sealed`, AAD tenant and flow id, resealed when the login continues in a new flow); one `FlowService::continuation` helper gives every sign-in outcome its target, and an authorization request bound to the flow always wins |
| `POST /ui/login/saml/{slug}/start?flow=`, `POST /ui/login/saml/{slug}/acs`, `GET /ui/login/saml/{slug}/continue?state=`, `GET /saml/{slug}/metadata` | SAML SP (§9.5; 404 with the flag off). The ACS is outside the Fetch-Metadata layer |

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
- Added in 0.4: `roles` (CRUD, members, per-user assign/unassign), `attributes` (definitions and
  per-user values), `webhooks` (endpoints, write-only secrets shown once, rotation, test, delivery
  log, redelivery), `initial-access-tokens` (value shown once, stored hashed) and `config`
  (declarative export, plan, apply). Tenant settings gain `claims`, `dcr` and `cimd`; the tenant
  view gains the server-computed `issuer` and `discovery_url`; the client view gains
  `registration_source` and `metadata_expires_at`. Roles, attributes and webhooks use
  `admin:settings:{read|write}` (role assignment and user attribute values `admin:users:{read|write}`,
  initial access tokens `admin:clients:{read|write}`), plus `admin:write` for the `system` tenant.
  81 operations; `security_admin_v04.rs` and `security_rbac.rs` prove the scopes.
- Added in 1.0: `organizations` (tag `organizations`, scopes `admin:organizations:{read|write}`):
  organization CRUD, members, member roles within the org (`?scope=org|tenant`), org roles,
  invitations (the token is never returned), connections (OIDC or SAML; `saml-metadata` import from
  XML or an SSRF-guarded URL; the SP values in the view), domains (`verify`, routing settings) and
  org branding, all under `/tenants/{slug}/organizations/{org}/…`; `keys` (`GET
  /tenants/{slug}/keys`, `POST …/keys/rotate` through `KeyRotationService::rotate_now`, scopes
  `admin:settings:*`, never private material); the client field `organization`; tenant settings
  `claims.org_roles|org_permissions`; the tenant view `features.saml`; the `org_invitation`
  email template kind. Tenant-level `connections` lists org connections read-only (`409` on
  change). Two user-side lookups (06-29): `GET /tenants/{slug}/users/{user_id}/organizations`
  (`listUserOrganizations`, tag `organizations`: memberships with the user's roles in each org;
  scopes `admin:users:{read|write}`, `admin:organizations:{read|write}` or `admin:read|write`) and
  `GET /tenants/{slug}/users?email=` (`listUsers` filter, 0 or 1 users; the users scopes). 123
  operations; `security_admin_v10.rs` proves the scopes.
- **Organization admins (1.0, decision Q1).** The `{org}` sub-routes use a second extractor,
  `OrgAdminAuth`, with one `Principal` enum (`SystemAdmin`, `OrgAdmin { tenant, org, user }`). It
  accepts a system-tenant token (scopes checked by the handler) or a JWT access token of tenant
  `{slug}` itself, verified by the same `AccessTokenVerifier` against the tenant's canonical issuer,
  whose `aud` contains `{public_url}/api/admin/v1` (RFC 8707 `resource`; the client must still allow
  it), with scope `org:admin` and an `org_id` equal to the path org, a live family bound to that org
  and user, and the user active, a member and still holding `org:admin` there
  (`OrgService::org_admin_principal`, every request). Opaque tokens are refused. Every other route
  keeps `AdminAuth` (system tokens only), and `AdminAuth::require` refuses an org admin, so an
  org-admin token gets `401` outside its org's sub-routes and `403` for another org or for
  tenant-admin-only actions (org update/delete, direct member add). An org admin cannot remove or
  demote the last `org:admin` holder (`409`); tenant admins can (recovery path). **Tenant-restricted
  system administrators** (system roles limited to a tenant list) are **deferred to Phase 7**: they
  would need a second principal shape checked on every tenant-level and installation route.
- **RBAC admin scopes (0.4).** In the `system` tenant a user's roles decide which admin scopes the
  console token can carry: the requested admin scopes are intersected, at code exchange and at
  every refresh, with the scopes the user's role permissions grant (`admin:write` covers every
  admin scope, `admin:read` every read scope, `admin:{r}:write` also `admin:{r}:read`). A system
  user without a role gets no admin scope. Roles of other tenants never grant admin scopes. The
  last active `admin:write` holder cannot be unassigned, deleted, blocked or stripped of the
  permission (409), and nobody can create, edit, assign or unassign a role beyond their own admin
  scopes. Client credentials tokens are unaffected (no user).
- Installation-level administration (managing tenants) lives in a dedicated `system` tenant, so admin
  authentication uses the same machinery as everything else.
- The admin console SPA (`/console/`) is a public OAuth client of the `system` tenant and only calls
  this API. As built in 0.2: the client is `anvil-console`, reconciled with the public URL at every
  start (no off switch in 0.2). Users of the `system` tenant were the administrators until RBAC
  (0.4; see above); registration in the `system` tenant is always disabled, and clients of other tenants can
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

As built in 0.4: `/healthz` and `/readyz` are aliases. The probes and `/metrics` sit outside tenant
resolution and rate limiting. Readiness answers `503 draining` from SIGTERM until the process
stops (`shutdown_drain`), `503 unavailable` when the storage check fails. `/metrics` is served on
`metrics_listen` (a separate plain-HTTP listener that serves nothing else) or, with
`metrics_on_main_port`, on the main listener; otherwise it answers 404 (§15).

### 10.6 Internationalization (0.3)

- Page strings live in Fluent catalogs: `themes/default/locales/{lang}/{feature}.ftl`, one file per
  feature, embedded in the binary. Templates call `t("dotted.key", name=value)`; the Fluent message
  id is the key with `.` replaced by `-`. Core emits message keys and arguments only; the web layer
  localizes right before rendering. Output is auto-escaped; plurals use Fluent selectors. Bidi
  isolation marks are off (user values inside translated text are wrapped in `<bdi>`).
- Two files of one locale defining the same id, or a malformed file, fail startup with the file
  name. A missing message falls back to English, then renders its dotted key. Every locale shipped
  in the binary must have exactly the English message ids per file, with the same variables and
  plural selectors (`crates/anvil-web/tests/i18n_catalogs.rs`), so a shipped translation is never
  partial. Operators override single messages, or add locales, with
  `{theme_dir}/locales/{lang}/*.ftl`.
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

- Scopes: tenant and client; since 1.0 organization (`org:{uuid}`). Tokens: nine colours plus an
  optional dark set, a system font family, a corner radius (0–32 px), custom CSS and a logo (PNG,
  JPEG or WebP, up to 256 KiB, identified by magic bytes; SVG is refused). Precedence is per
  field: client > organization > tenant > default; custom CSS is concatenated tenant,
  organization, client. The organization layer is picked from the flow's authorization request
  (`organization`, canonical id first, then slug; unknown orgs fall back silently).
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
| Cookies | `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` (session) or `Strict` (flow). Dev mode on `http://localhost` drops the `__Host-`/`Secure` requirements with a warning. Names carry a per-tenant suffix (path-based tenants share a host, and `__Host-` cookies cannot be scoped by path): since 0.3 the first 16 hex characters of SHA-256 over the tenant UUID's 16 bytes, stable for the tenant's life (earlier releases used the UUIDv7's first 12 hex characters, its creation millisecond, so tenants created in the same millisecond shared cookie names) |
| Rate limiting | One keyed limiter (`anvil-cache`, GCRA) with route classes and default quotas: `auth` (POSTs under `/ui/login`, `/ui/registration`, `/ui/recovery` and `/setup`, and since 0.4 every method under `/register`: 10/min per IP, burst 5), `token` (`/token`, `/introspect`, `/revoke`: 50/s per IP, plus 100/s per claimed client id), `admin` (20/s per IP), `default` (50/s per IP). `/health/*`, `/healthz` and `/assets/*` are never limited. All quotas are configurable (§13); `rate_limit_enabled = false` switches the limiter off with a warning. A request without a peer address gets a generic 500, never an invented address. 429 answers carry `Retry-After` (whole seconds, at least 1) and the shape of their surface: OAuth JSON `invalid_request`/`too many requests` with `no-store`, admin problem JSON `urn:anvilid:problem:too_many_requests`, or the themed error page `too_many_requests` |
| Brute-force on secrets | Argon2 verification runs on a bounded pool; login attempts against unknown users perform a dummy hash (constant-time behavior). **Two tiers (0.2):** a strict key (tenant + identifier + IP) allows 5 free failures, then locks progressively (1 s doubling, capped at 15 min; success clears it); a loose key (tenant + identifier, any IP) counts failures per hour and never locks: over the threshold it requires a CAPTCHA when the tenant has one, otherwise it delays. Nobody can lock an account out from arbitrary IPs. Known and unknown identifiers behave identically, the identifier is never logged or audited (`rate_limit_lockout` records key kind and seconds only). The second factor is throttled per user, passkey failures per IP |
| CAPTCHA (0.2) | Optional per tenant (Turnstile or hCaptcha), shown only when the loose tier asks for it. Verification fails closed (HTTP error, timeout, malformed or oversized body, redirects; https endpoints only). The widget is a third-party script by the operator's choice: the page with the widget gets a CSP that allows the provider, every other page keeps `script-src 'self'`. A CAPTCHA can conflict with WCAG 2.2 SC 3.3.8 (accessible authentication); operators enabling it accept that trade-off |
| Trusted proxies (0.2) | The client IP comes from the TCP peer unless the peer is in `trusted_proxies`. Then the configured header (`X-Forwarded-For` or `Forwarded`, never both) is walked right to left, skipping trusted hops, and the first untrusted entry is the client; an unparsable entry stops the walk (the last trusted hop is used), at most 32 hops. IPv4-mapped IPv6 is normalised. Forwarded proto/host never change the issuer or cookie mode (`public_url` decides) |
| Response headers | Strict CSP (`script-src 'self'`, no inline scripts), `frame-ancestors 'none'` by default, HSTS when HTTPS, `Referrer-Policy: no-referrer` on auth pages. Exceptions are per page and narrow: the `form_post` page adds `form-action <redirect origin>`; the CAPTCHA page allows its provider; the theme preview page (0.3) allows `frame-ancestors 'self'` |
| SSRF | 0.2 fetches no client-supplied URL (no `jwks_uri`, no `request_uri`). **Since 0.3 one guarded `OutboundClient` carries every outbound request** (upstream discovery, JWKS, token and profile calls, back-channel logout, CAPTCHA, the breached-password check; since 0.4 also webhook deliveries and Client ID Metadata Document fetches). Rules: https only (plain http only in development mode, and only to allow-listed destinations); IP literals are checked before sending and every DNS answer as it resolves, so the address connected to is the address checked; private, loopback, link-local, CGNAT, multicast, documentation, benchmarking and other reserved IPv4/IPv6 ranges are blocked, including IPv4 embedded in IPv6 (mapped, NAT64, 6to4); redirects are never followed; proxy environment variables are ignored; URLs with userinfo are refused; connect timeout 5 s, total 10 s; bodies capped (1 MiB documents, 64 KiB token responses). Error text never echoes the URL, address or body. Operator keys: `outbound_allow_cidrs` (destinations allowed despite the block list; default loopback in development mode, none otherwise; an explicit value, even empty, replaces the default) and `outbound_ca_file` (extra PEM roots, e.g. a private CA; TLS verification is never switched off). Negative tests: `security_ssrf.rs`. **Operator infrastructure is exempt (0.4):** the OTLP trace exporter (its own blocking HTTP client), the Redis client and the `anvilid healthcheck` loopback probe, like Postgres and SMTP, reach destinations the operator configured and may be private; they never take a URL from a client or a tenant |
| Upstream sign-in (0.3) | `state` bound to the flow and to a `SameSite=Lax` binding cookie, nonce, PKCE S256 (except Apple), pending state consumed once by compare-and-swap before any provider call, RFC 9207 `iss` checked when advertised, ID tokens fully validated with an RS256-only allow-list for presets (generic OIDC: the provider's algorithms ∩ RS256/PS256/ES256/Ed25519), never `alg: none` or HMAC. Linking only on a trusted verified email or explicit confirmation (§9.2). Negative tests: `security_linking.rs`, `upstream_*.rs` |
| Email sign-in (0.3) | No enumeration (identical answers, and no email, for unknown, unverified and blocked addresses), flow-bound HMAC codes, single use, 10 min, attempt and send caps on the one limiter, magic link consumed only by a same-browser POST (§9.3). Negative tests: `security_email_code.rs` |
| RP-initiated logout (0.3) | Hint verified (enabled algs, `typ: JWT`, size cap), exact post-logout URI match, CSRF-bound confirmation when the hint does not prove the session (§8.3). Negative tests: `security_logout.rs` |
| Theming (0.3) | Allow-list CSS validator, re-validation at render, same-origin stylesheet under the unchanged CSP, logo type sniffing, preview token hashed at rest and valid 15 min (§10.7). Negative tests: `security_theme.rs` |
| Dynamic registration (0.4) | Tenant policy `disabled` (404, not advertised) / `allow_listed` (initial access token, hashed, expiring, use-counted, consumed atomically; a refused request does not consume it; redirect-host allow-list) / `open`; always disabled for `system`. `software_statement` and `jwks_uri` refused, `admin:*` scopes never registrable, `max_clients` soft cap, `auth` rate class. Registration access tokens are 256-bit and stored hashed. Negative tests: `security_registration.rs` |
| Client ID Metadata Documents (0.4) | Policy and host allow-list checked before any fetch; fetched only through `OutboundClient` (https only, 5 KiB, status 200, no redirects), per-host budget across the installation, 16 concurrent fetches per node; `client_id` must equal the document URL exactly; secrets, shared-secret auth methods and `jwks_uri` refused; failures never cached; consent names the client by its host and labels the self-asserted name unverified. Negative tests: `security_cimd.rs` |
| Webhooks (0.4) | Endpoint URLs pass the outbound policy at creation and at every send; Standard Webhooks v1 HMAC signatures, secrets sealed with the KEK and shown once; ids-only payloads (no email, name, IP); redirects never followed. Negative tests: `security_webhooks.rs` |
| RBAC and attributes (0.4) | Cross-tenant role assignment impossible (composite keys and service checks), admin scopes bounded by roles, last-administrator guard, escalation guard (§10.3). Mapped claims never override protocol or standard claims. Attribute schemas: offline only (remote `$ref` refused), 16 KiB and depth 32 caps, linear-time regex. Negative tests: `security_rbac.rs`, `security_attributes.rs` |
| Organizations and org admins (1.0) | Org-admin tokens accepted only on their own org's sub-routes, re-checked per request (audience, `org:admin`, `org_id`, live org-bound family, membership, permission); opaque tokens refused; `org:admin` bounded per active org and never registrable; no `admin:*` permission inside an org; last-org-admin guard; membership loss revokes org-bound families and refreshes answer `invalid_grant`; mapped claims never produce `org_*`. Negative tests: `security_admin_v10.rs`, `org_claims.rs`, `org_switch.rs`, `security_org_scopes.rs` |
| Invitations (1.0) | Token 256-bit, SHA-256 at rest, 7 days, single use by one conditional update; GET consumes nothing; same-browser POST (nonce cookie + HMAC); accepted only for a verified matching email or a new account for the invited address; identical answers for every invalid token and for known/unknown addresses at creation. Negative tests: `org_invitations.rs`, `security_admin_v10.rs` |
| SAML SP (1.0, experimental) | Operator flag; DTDs forbidden; size, depth and markup caps; strict profile pre-check before the signature library; pinned signature locations and references; trusted keys only; claims from the verified node only; RelayState, `InResponseTo` and binding cookie; database replay guard; transient NameID, encryption and IdP-initiated responses refused. Negative tests: `security_saml.rs` (D4 corpus, 67 cases), `saml_login.rs`, `saml_xml_adapter.rs`; fuzz targets `saml_response_parse`, `saml_metadata_parse` |
| Domains and home-realm discovery (1.0) | Domain normalisation refuses public suffixes, IPs, wildcards and reserved names; FQDN-only, uncached, time-bounded TXT lookup; one uniform failure answer; one verified owner per tenant (database index); routing by domain only (no account lookup, identical password step for every non-routed address); domain-bound enterprise email trust; lockout guards on routing and `allow_local_password`; local methods refused for SSO-only domains, passkeys kept. Negative tests: `security_domains.rs`, `hrd_login.rs`, `security_linking.rs`, `enterprise_oidc.rs`, `security_enumeration.rs`; fuzz target `org_domain_parse` |
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
- **Keys added in 0.4:** `redis_url` (secret: environment or file only; `redis://` or
  `rediss://`), `rate_limit_redis_failure` (`closed` | `local`), `metrics_listen`,
  `metrics_on_main_port`, `otel_endpoint` (credentials in URLs are redacted; exporter headers come
  from `OTEL_EXPORTER_OTLP_HEADERS`), `otel_service_name`, `shutdown_drain` (at most 1 h) and
  `database_max_connections` (Postgres pool per node, 1-1000). All default to off or to the 0.3
  behaviour; docs/OPERATIONS.md has the reference.
- **Startup reconciliation (0.2):** after installation the binary reconciles the console client
  with `public_url`, then ensures every tenant has an active key for each enabled algorithm.
- **Audit stream:** audit events are written to the database and mirrored on stdout as one raw
  JSON object per line (never on stderr), independent of `RUST_LOG`.
- **Email templates (0.2):** per-tenant overrides are checked on save (syntax, unknown variables
  against the kind's variable contract, no include/extends) and render with a fuel limit; the outbox
  worker uses tenant SMTP, then installation SMTP.
- **CLI commands:** `serve`, `migrate`, `config show|validate`, `admin setup-url` (new bootstrap URL
  for recovery), `keys rotate`, `backup create|restore` (SQLite), `export`/`import` (tenant YAML).
  0.1 ships `serve`, `migrate`, `config show|validate` and `admin setup-url`; 0.2 adds `keys rotate`.
  As built in 0.4: `backup create|restore` (SQLite only; Postgres is refused with a pointer to
  pg_dump/PITR), `admin recover` (shell-only administrator recovery), `healthcheck` (loopback
  readiness probe for distroless images) and `tenant export|plan|apply` (the planned
  `export`/`import` pair became a plan/apply workflow, docs/CONFIG-YAML.md).

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
| Back-channel logout delivery | 0.3: woken by every path that revokes sessions (§8.3), otherwise polls every 10 s; runs on every node and claims rows with a 2-minute row lease instead of a `job_lease` (§8.3) |
| Webhook delivery (0.4) | As built: runs on every node; polls every 2 s (a full batch is followed at once), claims up to 8 due rows with a 45 s row lease (`FOR UPDATE SKIP LOCKED` on Postgres) instead of a `job_lease`, sends them concurrently, retries on a fixed schedule over about 3 days (docs/WEBHOOKS.md) |
| Audit log retention | daily (0.2; not scheduled when `audit_retention_days = 0`) |
| Domain re-check (1.0) | daily (`domain_recheck` lease): verified domains not checked for 23 h, in batches across tenants; a failure starts a streak, 7 days of failures unverify the domain (audited, webhook `organization.domain_unverified`) |

## 15. Observability

- **Logs:** JSON to stdout by default (pretty in dev). Fields: `trace_id`, `tenant`, `client_id`,
  `route`, `status`, `latency_ms`. Secrets are never logged (types prevent it).
- **Metrics** (`/metrics`): request counts and latency by route class; `anvil_auth_attempts_total`
  by method and outcome; tokens issued by grant; refresh reuse detections; rate-limit rejections;
  database pool stats; job runs and failures.
- **Traces:** spans for each request and storage call; OTLP export behind the `otel` feature and
  `ANVILID_OTEL_ENDPOINT`.
- **As built in 0.4** (differences from the plan above):
  - Operational logs go to **stderr** (JSON outside dev mode); the audit stream is on stdout. One
    request layer writes the `http.request` span and the access line (target `anvil_web::access`)
    with `method`, `route` (the matched template, never the raw path or query), `tenant`,
    `status`, `latency_ms` and `request_id`. No client IP, email or client id is recorded in
    operational telemetry.
  - Metrics (all names in `anvil_web::observability`): `anvil_http_requests_total{route_class,
    status_class}`, `anvil_http_request_duration_seconds{route_class}`,
    `anvil_ratelimit_rejections_total{route_class}`, `anvil_auth_attempts_total{outcome}` (no
    method label), `anvil_tokens_issued_total{grant}`, `anvil_refresh_reuse_total`,
    `anvil_jobs_runs_total{job,outcome}`, `anvil_webhook_deliveries_total{outcome}`,
    `anvil_ratelimit_backend_errors_total{operation,reason}`. No database pool metric. Labels are
    bounded classes only.
  - Traces: OpenTelemetry is compiled in (no `otel` feature) and enabled by `otel_endpoint`
    (OTLP/HTTP protobuf, batch exporter, flushed at shutdown). Spans cover requests; storage calls
    are not separate spans in 0.4. An incoming `traceparent` is honoured only from
    `trusted_proxies` peers. Audit events are never exported.
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
| Fuzzing | JWT/JWS parsing, authorization request parsing; since 1.0 SAML responses, SAML metadata and domain normalisation; later SCIM | `fuzz/`, nightly CI |
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

Status (0.4 in progress): built are the multi-tenant console, RBAC with role claims and
role-bounded admin scopes, custom user attributes, webhooks, dynamic client registration, CIMD,
resource-aware consent, the declarative tenant configuration (`anvilid tenant export|plan|apply`),
the Redis limiter backend, metrics/traces/health/drain, SQLite online backup and restore,
`admin recover`, the Helm chart and Compose examples, and in-flow passkey enrolment. Evidence per
exit criterion: the HA restart test is `tests/load/run-ha.sh` (three nodes behind HAProxy, run by
the `load` workflow); the round trip is `crates/anvilid/tests/tenant_config.rs`
(`round_trip_into_fresh_instance`); the MCP flow is covered by `crates/anvil-web/tests/cimd.rs` and
the MCP e2e suite. The release gate decides from CI runs of these tests. Divergences from the plan
above are recorded where they occur: §2 (telemetry compiled in), §6.1 (no
`client_metadata_cache`), §10.3 (RBAC admin scopes), §11 (operator infrastructure outside
`OutboundClient`), §13 (CLI), §14 (webhook worker) and §15.

### M5 — Release 1.0 "Credible for business"

Scope: ORG-2, ORG-3, ORG-4; OIDC-18, OIDC-23 (certification filed); UI-5; ADM-8, ADM-9; AGT-3;
federation module (upstream OIDC and SAML SP; SAML marked experimental unless D4 is resolved).

Exit criteria: OpenID certification submitted for all target profiles; external security review
completed and findings fixed; upgrade path from 0.4 tested; documentation site complete (install,
integrations, migration guides).

Status (1.0 in progress, Phase 6): built are organizations with members, invitations, org roles
(hybrid model on one assignment table), org claims and the switcher (ORG-2); org OIDC connections
and the SAML 2.0 SP with just-in-time membership (ORG-3, SAML experimental behind
`saml_experimental`); DNS TXT domain verification with the daily re-check and identifier-first
home-realm discovery (ORG-4); organization admins on the management API; the signing-keys API;
and console pages for organizations, org SSO and keys (ADM-2). The 0.4 → 1.0 upgrade is tested on
both backends (`tests/upgrade.rs`). User docs: `docs/ORGANIZATIONS.md`, `docs/SAML.md`,
`docs/UPGRADING.md`. Open items: **tenant-restricted system admins deferred to Phase 7**; **SAML
experimental until the Phase 7 external review and interop checklist** (D4); the remaining M5 scope (certification, external review, PAR, headless flow API, user
import/export) belongs to Phase 7.

### Beyond 1.0

Release 2.0 (directory, SAML IdP, forward-auth, extension hooks, token exchange, DPoP, API keys,
Terraform) and 3.0 (permissions engine, identity-aware proxy, Shared Signals, adaptive MFA, FAPI 2.0)
are specified in PRD §8.7. Each gets an architecture addendum before its milestone starts.

## 19. Extension points reserved now

These are designed in from the start so later modules don't require rewrites:

- **Principal types:** `sub` resolution and audit actors use an enum (`User`, `Client`, later `Agent`).
- **Connections:** upstream IdP configuration is a tagged enum stored in one table. 0.3 has
  `Social` (Google, Apple, Microsoft, GitHub presets), `Oidc` and `OAuth2`; 1.0 adds `Saml`
  (organization connections only) in the same enum and table; `Ldap` joins later.
- **Token claims pipeline:** claims are assembled by an ordered list of claim providers (standard
  claims, roles, organization, custom attributes); extension hooks (EXT-1) slot in later. As built
  in 1.0, organization claims are inserted by the token builders before mapped extras, and the
  reserved names keep any mapping from producing or overriding them.
- **Principals:** the management API's `Principal` enum (1.0: `SystemAdmin`, `OrgAdmin`) is where
  a tenant-restricted administrator variant would go (deferred to Phase 7).
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
| D4 | SAML stack: pure-Rust XML-DSig (saml-rs/bergshamra) vs alternatives | **Spike verdict 2026-11-26 (06-01):** `bergshamra-dsig` 0.12.0 on the aws-lc provider only + `uppsala` 0.12.1 as the single XML parser + our own narrow SAML SP layer. The spike (`crates/anvil-web/tests/saml_dsig_spike.rs`) signs a minimal SAML assertion (enveloped exc-c14n, RSA-SHA256 and ECDSA-P256-SHA256, `Reference URI="#_a1"`) under keys generated at test time and verifies it with `DsigContext::new(keys).with_trusted_keys_only(true).with_strict_verification(true).with_require_reference_digests(true).with_skip_time_checks(true)` and `verify::verify_all_document_with_source` on one `uppsala::Parser::new().with_forbid_dtd(true)` document; the reference resolves to the Assertion node, a one-character change fails, and a key embedded in `KeyInfo` is never trusted. Costs: the scoped `chrono` exception (§2, wrapper `tsp-ltv`). SAML stays behind a runtime experimental flag through 1.0 (Q3) until the Phase 7 external review and a real-IdP interop checklist; the attack-corpus gate is 06-09. Verified locally on Linux; macOS targets are verified by the release-build workflow at the 1.0 gate (06-26). **Status after the corpus (06-09):** the adapter (`adapters/saml_xml.rs`) parses once with DTDs forbidden, runs a strict profile pre-check before any bergshamra call, verifies against pinned certificates only and reads claims only from the verified node; the 67-case attack corpus (`tests/security_saml.rs`: XSW1-8 and variants, exclusion, key injection, comment injection, parser differentials, void canonicalisation, algorithm downgrade, file references, XML bombs) is green in CI, and three fuzz targets run nightly. SAML is built (06-18) but stays **experimental** (operator flag `saml_experimental`, off by default; IdP-initiated SSO refused, decision Q4); the external review and the real-IdP interop checklist (`docs/SAML.md`) are Phase 7. The `chrono` exception (§2) awaits the owner's review | **open:** experimental; corpus green; external review and interop checklist in Phase 7 |
| D5 | Permissions engine: embedded tuple store vs integrating OpenFGA/SpiceDB | Decide at the 3.0 addendum | 3.0 |
| D6 | Embedded HA without Postgres (replicated SQLite) | Not planned; revisit on user demand | post-1.0 |
| D7 | sqlx minimum supported Rust version vs our toolchain policy | **Resolved 2026-11-25:** sqlx 0.9.1 requires Rust ≥ 1.94; pin current stable (1.100.0) in `rust-toolchain.toml` | ✓ |
