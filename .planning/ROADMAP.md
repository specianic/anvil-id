# Roadmap: AnvilID

## Overview

AnvilID 1.0 is built in release-sized steps that mirror docs/ARCHITECTURE.md §18. Phase 1 (M0) proves
the stack: dual SQLite/Postgres storage, a static musl binary and the OpenID conformance suite in CI.
Phase 2 (0.1) delivers the core value: a zero-config binary that issues tokens exactly to spec through
authorization code + PKCE with every security check tested. Phases 3–5 (0.2–0.4) harden it (passkeys,
MFA, consent, audit), make it fit real-world logins (social, logout profiles, theming, i18n) and make
it operable (multi-tenant console, RBAC, webhooks, declarative config, HA, MCP basics). Milestone M5
(1.0) is split into two phases: Phase 6 delivers the B2B features (organizations, per-org SAML/OIDC
SSO, home-realm discovery), and Phase 7 completes the protocol surface and the release gate (PAR,
headless flow API, user import/export, OpenID certification, external security review).

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundations and Spikes (M0)** - Workspace, CI and the three stack spikes (dual storage, static binary, conformance in CI) (completed 2026-11-25)
- [x] **Phase 2: Release 0.1 "First login"** - Zero-config binary with spec-correct auth code + PKCE, refresh, client credentials, password login and bootstrap admin (completed 2026-11-25)
- [x] **Phase 3: Release 0.2 "Secure by default"** - Passkeys, TOTP, consent, sessions, brute-force protection, audit log, introspection/revocation, key rotation, admin console v1 (completed 2026-11-25)
- [ ] **Phase 4: Release 0.3 "Real-world logins"** - Social login, account linking, MFA policy, logout profiles, theming, i18n, account page, resource indicators
- [ ] **Phase 5: Release 0.4 "Operate it"** - Multi-tenant console, RBAC, webhooks, declarative config, DCR, MCP basics, HA on Postgres, observability, Helm
- [ ] **Phase 6: Release 1.0 "Credible for business" (Organizations and SSO)** - Organizations, per-org SAML/OIDC SSO with JIT, home-realm discovery, complete admin console
- [ ] **Phase 7: Release 1.0 "Credible for business" (Certification and release)** - PAR, headless flow API, agent consent, user import/export, API stability, OpenID certification, external security review

## Phase Details

### Phase 1: Foundations and Spikes (M0)
**Goal**: The chosen stack is proven viable: the workspace builds and tests with one command, CI enforces the architecture rules, and the three risk spikes succeed (or the stack decision is revisited per ARCHITECTURE.md §2.1)
**Depends on**: Nothing (first phase)
**Requirements**: FND-01, FND-02, FND-03, FND-04, FND-05
**Success Criteria** (what must be TRUE):
  1. A contributor runs one command to build, lint and test the Cargo workspace, and every PR runs fmt, clippy, cargo-deny and tests in CI
  2. CI fails a PR that adds an I/O dependency to the core crate or imports a concrete storage crate from the web crate
  3. The shared storage contract suite (tenant repository + atomic `consume_code`, including a concurrency test showing exactly one winner) passes on both SQLite and Postgres, and the duplication cost is recorded
  4. CI produces static musl release binaries for amd64 and arm64 (aws-lc-rs, mimalloc, embedded assets) and reports binary size and idle memory
  5. CI starts a fresh binary and runs the OpenID conformance suite against it end to end
**Plans**: 8 plans in 5 waves

Plans:
- [x] 01-01-PLAN.md — Workspace skeleton, toolchain, Cargo.lock, storage ports in anvil-core, justfile (wave 1)
- [x] 01-02-PLAN.md — cargo-deny policy, dependency-rule checker + self-test, ci.yml (wave 2)
- [x] 01-03-PLAN.md — Spike A: shared contract suite + SQLite backend + .sqlx (wave 2)
- [x] 01-04-PLAN.md — anvil-web router (discovery, assets, 501s) + `anvilid serve` with mimalloc (wave 2)
- [x] 01-05-PLAN.md — Spike A: Postgres backend on testcontainers + duplication cost (wave 3)
- [x] 01-06-PLAN.md — Spike C: conformance harness (Config OP plan, ratchet) + conformance.yml (wave 3)
- [x] 01-07-PLAN.md — Spike B: storage wiring in anvilid, static musl build, size/RSS, release-build.yml (wave 4)
- [x] 01-08-PLAN.md — Phase gate: `just ci`, push + CI green (checkpoint), spike verdicts (wave 5)

### Phase 2: Release 0.1 "First login"
**Goal**: Anyone can start one binary with zero configuration and have a sample app log users in through a standards-correct OIDC provider, with every in-scope security control enforced and covered by a negative test
**Depends on**: Phase 1
**Requirements**: OIDC-01, OIDC-02, OIDC-03, OIDC-04, OIDC-05, OIDC-06, OIDC-07, OIDC-08, OIDC-09, OIDC-24, AUTH-01, AUTH-02, AUTH-03, UI-01, ADM-01, ADM-03, OPS-01, OPS-02, OPS-05, SEC-01, SEC-04, SEC-06, SEC-07, QUAL-01, QUAL-02, QUAL-04
**Success Criteria** (what must be TRUE):
  1. The sample app in `examples/` logs a user in with authorization code + PKCE (S256), refreshes with rotation, and calls UserInfo, on both SQLite and Postgres
  2. OpenID conformance **Basic OP** and **Config OP** test plans pass in CI
  3. A scripted CI check goes from zero-config `docker run` to a completed login in the sample app in 2 minutes or less; on an empty database the operator gets a one-time setup URL and there are no default credentials
  4. Every ARCHITECTURE.md §11 control in scope has a passing negative test (wrong/unregistered redirect URI, missing or `plain` PKCE, code reuse, refresh reuse revoking the family, bad client secret, replayed `jti`, CSRF failure), and the test suite runs on both backends
  5. A user can self-register, verify their email, log in with a password and recover the account through built-in pages with no external assets, and an admin can manage tenants, clients and users through the OpenAPI management API
**Plans**: 23 plans in 7 waves

Plans:
- [x] 02-01-PLAN.md — Dependency foundation (all manifests, lockfile, recipes, workflows) + anvil-jose (keys, KEK, JWKS, signing, client assertions, PKCE) (wave 1)
- [x] 02-02-PLAN.md — Domain model, storage/service ports, CoreError, FormDescription, core module skeleton, full contract suite, transitional backend shims (wave 1)
- [x] 02-03-PLAN.md — Default theme: page + email templates, CSS, stable selector contract (wave 1)
- [x] 02-04-PLAN.md — Sample RP (examples/node-rp, openid-client) + Playwright skeleton and helpers (wave 1)
- [x] 02-05-PLAN.md — SQLite backend for all 0.1 ports, contract green, plaintext inspection (wave 2)
- [x] 02-06-PLAN.md — Postgres backend for all 0.1 ports, contract green, plaintext inspection (wave 2)
- [x] 02-07-PLAN.md — Core authorize: request validation, redirect matching, PKCE policy, prompt/max_age decisions, code issuance (wave 2)
- [x] 02-08-PLAN.md — Core token side: client auth, KeyService, grants, token minting, AT verification, UserInfo (wave 2)
- [x] 02-09-PLAN.md — Core flows (login, registration, verification, recovery, setup form) + SessionService (wave 2)
- [x] 02-10-PLAN.md — Core management: tenant/client/user services, admin scopes, BootstrapService (wave 2)
- [x] 02-11-PLAN.md — anvil-mail: templates, SMTP transport, outbox worker (wave 2)
- [x] 02-12-PLAN.md — Web shell: AppState, tenant resolution, errors, CSRF/CSP/cookies, renderer, Argon2/HIBP adapters, test harness (wave 2)
- [x] 02-13-PLAN.md — Discovery (both paths), JWKS, /authorize + continue, authorize-side security tests (wave 3)
- [x] 02-14-PLAN.md — /token and /userinfo, token-side security tests (wave 3)
- [x] 02-15-PLAN.md — UI handlers (login, registration, verification, recovery, setup) + CSRF/cookie/CSP/enumeration tests (wave 3)
- [x] 02-16-PLAN.md — OpenAPI 3.1 management API with admin scopes + drift check (wave 3)
- [x] 02-17-PLAN.md — Fuzz targets (JWT, assertion, authorize, redirect) + SEC-06 release-graph gate (wave 3)
- [x] 02-18-PLAN.md — Binary wiring: zero-config, figment config, CLI, bootstrap, TLS listener, jobs, conformance ratchet refresh (wave 4)
- [x] 02-19-PLAN.md — Conformance gate: Basic OP + Config OP over TLS (wave 5)
- [x] 02-20-PLAN.md — Container image < 50 MB, QUAL-04 ≤ 2 min on both backends, Playwright self-service e2e (wave 5)
- [x] 02-21-PLAN.md — Phase gate: security-test map, `just ci`, docs sync, push + CI green (checkpoint) (wave 6)
- [x] 02-22-PLAN.md — Gap closure: seal email outbox payloads at rest with the KEK; worker opens before render; plaintext tests on both backends (wave 3)
- [x] 02-23-PLAN.md — Gap closure (OPS-01): tag-triggered release pipeline; v0.1.0 published from `release/0.1` (binaries, checksums, multi-arch image) (wave 7)

Note: the multi-tenant data model and the `serve`, `migrate`, `config` and `admin setup-url` CLI commands land here; ORG-01 and ADM-07 are mapped to Phase 5, where they are completed.

### Phase 3: Release 0.2 "Secure by default"
**Goal**: Users can sign in with modern, phishing-resistant methods under hardened defaults, and admins can see and control what happens in their tenant
**Depends on**: Phase 2
**Requirements**: OIDC-10, OIDC-11, OIDC-13, OIDC-15, OIDC-25, AUTH-04, AUTH-05, AUTH-09, AUTH-10, UI-02, UI-07, ADM-04, SEC-02, SEC-05, OPS-04, OPS-06
**Success Criteria** (what must be TRUE):
  1. Passkey (including usernameless) and TOTP enrollment and login e2e tests pass with a virtual authenticator
  2. OpenID conformance **Form Post** plan passes; resource servers can introspect and clients can revoke tokens; tokens can be signed with RS256, ES256 or Ed25519, and signing keys rotate on schedule with JWKS overlap
  3. Brute-force and rate-limit tests pass (per-account and per-IP throttling, correct client IP behind a trusted proxy), and the axe accessibility audit of the login pages is clean, with the password flow working without JavaScript
  4. Users see a consent screen that is remembered and revocable, can list and revoke their sessions, and admins can review users, clients, sessions and the audit log in admin console v1
  5. An upgrade test migrates a 0.1 database to 0.2 in CI without data loss, and destructive migrations refuse to run without an explicit flag
**Plans**: 29 plans in 7 waves

Plans:
- [x] 03-01-PLAN.md — All Phase 3 dependencies (deny rsa wrapper) + anvil-jose ES256/Ed25519 JWS/JWK, per-alg at_hash, TOTP, peppered recovery codes (wave 1)
- [x] 03-02-PLAN.md — Core model/ports for all of Phase 3, AuditAction + AuditService, pre-declared modules, full contract suite, backend shims (wave 1)
- [x] 03-03-PLAN.md — Admin console SPA scaffold (Vite/React/TanStack/shadcn, OpenAPI types, oidc-client-ts), Users + Clients pages, Node CI job (wave 1)
- [x] 03-04-PLAN.md — E2E infra (CDP authenticator, axe, TOTP helper, nojs project) + WCAG 2.2 AA baseline of Phase 2 pages (wave 1)
- [x] 03-05-PLAN.md — SQLite 0.2 migrations (incl. no-transaction token_family rebuild) + all new repos, contract green (wave 2)
- [x] 03-06-PLAN.md — Postgres 0.2 migration + all new repos, contract green (wave 2)
- [x] 03-07-PLAN.md — The single keyed limiter in anvil-cache (governor GCRA + progressive backoff, two-tier gate) (wave 2)
- [x] 03-08-PLAN.md — Trusted-proxy client IP + RequestContext, ConnectInfo in the binary, skeleton route modules, TestApp::storage_arc (wave 2)
- [x] 03-09-PLAN.md — webauthn-rs adapter for PasskeyCeremonies, SVG QR renderer, webauthn.js (wave 2)
- [x] 03-10-PLAN.md — Rotation planner + KeyRotationService, per-client ID-token alg, JWKS cache headers (wave 3)
- [x] 03-11-PLAN.md — form_post response mode via one core response builder (wave 3)
- [x] 03-12-PLAN.md — Core login flow: usernameless passkey, TOTP/recovery second factor, attempts, audit, transactional recovery notice (wave 3)
- [x] 03-13-PLAN.md — Limiter wiring: route-class layer on by default, per-client token limit, brute-force helpers, CAPTCHA (wave 3)
- [x] 03-14-PLAN.md — Account security: passkey registration, TOTP enrolment + recovery codes, removal (wave 3)
- [x] 03-15-PLAN.md — Tenant email templates (fuel, compile check) + per-tenant SMTP + synchronous test send (wave 3)
- [x] 03-16-PLAN.md — Destructive-migration guard + flag, 0.1→0.2 upgrade tests on both backends, migration lint/immutability (wave 3)
- [x] 03-17-PLAN.md — Consent (decide/remember/deny/revoke) + connected apps page (wave 4)
- [x] 03-18-PLAN.md — Opaque vs JWT access tokens, /introspect, /revoke, Phase 3 discovery metadata (wave 4)
- [x] 03-19-PLAN.md — Sessions: idle/absolute timeouts, throttled touch, list/revoke (wave 4)
- [x] 03-20-PLAN.md — Login UI: passkey button, second-factor page, brute-force protection + CAPTCHA escalation (wave 4)
- [x] 03-21-PLAN.md — Core management: admin audit, new client/tenant settings, console client reconciliation (wave 4)
- [x] 03-22-PLAN.md — Console embedding at /console/* (pre-compressed negotiation, caching, SPA fallback, placeholder) (wave 4)
- [x] 03-23-PLAN.md — Management API 0.2: sessions, credentials, audit query, email templates/SMTP, new fields, OpenAPI (wave 5)
- [x] 03-24-PLAN.md — Binary wiring: proxy/rate-limit/rotation/retention config, leased jobs, `keys rotate`, audit JSON to stdout (wave 5)
- [x] 03-25-PLAN.md — Console pages (sessions, audit, email/SMTP, user tabs, client editing) + console e2e with axe (wave 6)
- [x] 03-26-PLAN.md — E2E: passkeys (usernameless, clone rollback, negatives) and TOTP/recovery codes (wave 6)
- [x] 03-27-PLAN.md — E2E: consent + sessions; full axe/no-JS/keyboard audit of Phase 3 pages (wave 6)
- [x] 03-28-PLAN.md — Conformance: Form Post OP plan in CI; Basic/Config re-run with consent-free clients (wave 6)
- [x] 03-29-PLAN.md — Phase gate: security-test map, `just ci`, release console check, migration pinning, docs sync, push + CI green (checkpoint) (wave 7)
- [x] 03-30-PLAN.md — Gap closure: account_security audit filtering, password-changed notice inside the recovery transaction (worker fills `email` from recipient) (wave 4)
- [x] 03-31-PLAN.md — Gap closure: deliver request_not_supported via the requested response mode (outer, else from the unverified request object) (wave 6)
- [x] 03-32-PLAN.md — Gap closure: SQLite uses the shared anvil-jose base64url; Postgres composite (tenant_id, user_id) FKs on every user-owned table (wave 7)
- [x] 03-33-PLAN.md — Gap closure: dedupe ETag/If-None-Match and date helpers, reuse audit request context, anvil-core tokio test runtime, flexible Turnstile width, release `artifact-metadata: write` (wave 7)
- [x] 03-34-PLAN.md — Gap closure: single base64 implementation (anvil_jose::encoding b64std/b64url) + check-deps guard; anvil-cache tokio, unused `anvilid` workspace dep, stale flow-engine doc (wave 8)

### Phase 4: Release 0.3 "Real-world logins"
**Goal**: AnvilID handles the login journeys real products need: social and passwordless sign-in, safe account linking, MFA policy and step-up, standard logout, and branded, translated pages
**Depends on**: Phase 3
**Requirements**: OIDC-12, OIDC-14, OIDC-16, AUTH-06, AUTH-07, AUTH-08, AUTH-11, AUTH-13, UI-03, UI-04, SEC-03
**Success Criteria** (what must be TRUE):
  1. OpenID conformance **RP-Initiated Logout** and **Back-Channel Logout** plans pass in CI
  2. Social login with Google, Apple, Microsoft, GitHub and a generic OIDC provider is tested against mock IdPs in CI (plus a documented manual real-provider checklist run before release); upstream identities link only on verified email or explicit confirmation, and upstream secrets are stored encrypted
  3. An admin edits theme settings in the console and sees the login pages change live; pages render in the language chosen from `ui_locales` or the browser
  4. A user can log in with email OTP or magic link, and manage profile, email, password, passkeys, MFA, sessions and connected apps from the account page
  5. Admin MFA policy (off/optional/required) is enforced per tenant and client, and clients can request step-up via `acr_values`, `prompt` and `max_age`, and audience-bound tokens via resource indicators
**Plans**: 37 plans in 11 waves

Plans:
- [x] 04-01-PLAN.md — Core foundation: all Phase 4 model/ports (connections, branding, logout deliveries, UpstreamClient), errors, audit actions, anvil-jose email code, Fluent/moka deps, contract suite, backend shims (wave 1)
- [x] 04-02-PLAN.md — The single SSRF-guarded outbound client + operator config, CAPTCHA/HIBP migrated, AppState handles, pre-registered web modules (wave 1)
- [x] 04-03-PLAN.md — E2E infra: Node mock IdP (Apple-like, GitHub-like), upstream/logout helpers, sample RP logout + back-channel endpoint, run.sh spec glob (wave 1)
- [x] 04-04-PLAN.md — SQLite 0005 (CHECK rebuilds, new tables/columns), repos, enqueue-on-revoke, upgrade + plaintext tests (wave 2)
- [x] 04-05-PLAN.md — Postgres 0004, repos (SKIP LOCKED delivery leasing), enqueue-on-revoke, upgrade + plaintext tests (wave 2)
- [x] 04-06-PLAN.md — i18n infrastructure: Fluent catalogs, negotiation, t(), localized forms, all templates converted, en catalog, ui_locales_supported (wave 2)
- [x] 04-07-PLAN.md — Pure upstream logic: provider presets, ID-token validation, claim normalisation, link decision (TDD) (wave 2)
- [x] 04-08-PLAN.md — Pure protocol decisions: end-session table, logout token + delivery classification, RFC 8707, MFA policy (TDD) (wave 2)
- [x] 04-09-PLAN.md — Pure theming rules: token/contrast validation, CSS validator, merge, stylesheet, logo sniffing (TDD) (wave 2)
- [x] 04-10-PLAN.md — Conformance harness: logout/backchannel selections, callback CA + leaf, outbound settings, browser tasks (wave 2)
- [x] 04-11-PLAN.md — Admin API 0.3: connections CRUD with sealed write-only secrets, client logout/resource/MFA fields, tenant settings, OpenAPI regen (wave 3)
- [x] 04-12-PLAN.md — Resource indicators end to end: multi-valued resource, invalid_target, downscoping, aud, introspection, UserInfo audience rule (wave 3)
- [x] 04-13-PLAN.md — RP-initiated logout: /logout GET+POST, hint validation, confirmation flow, signed-out/error pages, discovery fields (wave 3)
- [x] 04-14-PLAN.md — Upstream transport adapter on the guarded client: discovery, JWKS cache, token exchange, API calls, MockProvider (wave 3)
- [x] 04-15-PLAN.md — Account page: profile, email change with re-verification, password change, nav; login_code/email_change/email_changed emails (wave 3)
- [x] 04-16-PLAN.md — Login engine: MFA policy enforcement, in-flow enrolment, acr_values step-up, unmet acr, session switch, login_hint (wave 4)
- [x] 04-17-PLAN.md — Back-channel logout delivery worker: sign at send, status classification, retries, binary wiring with wake (wave 4)
- [x] 04-18-PLAN.md — Theming backend: BrandingService, theme CSS/logo routes, base.html link, branding API + preview, OpenAPI regen (wave 4)
- [x] 04-19-PLAN.md — Console: connections pages, client logout/resource/MFA fields, tenant login settings (wave 4)
- [x] 04-20-PLAN.md — prompt=select_account and prompt=create, discovery prompt/acr values (wave 5)
- [x] 04-21-PLAN.md — Upstream sign-in + account linking: Lax binding cookie, Apple form_post hop, link confirmation, JIT, Link purpose (wave 5)
- [x] 04-22-PLAN.md — Console theme editor with live preview (wave 5)
- [x] 04-23-PLAN.md — Conformance: RP-Initiated Logout + Back-Channel Logout plans green and in `all` (wave 5)
- [x] 04-24-PLAN.md — Email OTP + magic link sign-in (wave 6)
- [x] 04-25-PLAN.md — Linked identities on the account page (connect, guarded unlink) (wave 6)
- [x] 04-26-PLAN.md — Provider suites against wiremock mocks: Google, Microsoft, Apple, GitHub, generic OAuth2 (wave 6)
- [x] 04-27-PLAN.md — E2E: social sign-in across sites, linking journeys, console connections (wave 7)
- [x] 04-28-PLAN.md — E2E: RP-initiated + back-channel logout, MFA policy/step-up, prompt values (wave 7)
- [x] 04-29-PLAN.md — E2E: email code/magic link, account page, live theming (wave 7)
- [x] 04-30-PLAN.md — German catalog, catalog parity test, i18n e2e (wave 7)
- [x] 04-31-PLAN.md — Docs: ARCHITECTURE (incl. sid divergence, SSRF), PRD, UPGRADING 0.2→0.3, theme README, manual social-login checklist (wave 7)
- [x] 04-34-PLAN.md — Gap closure (storage): logout-token iss per RP session (SQLite 0006 / Postgres 0005), atomic unlink guard, logo + client-branding purge, Postgres token-family purge, verification-aware create_user_with_link (wave 8)
- [x] 04-35-PLAN.md — Gap closure: independent email_otp / magic_link (optional login_code variables, per-toggle routes) (wave 8)
- [x] 04-36-PLAN.md — Gap closure: back-channel wake on every revocation path, upstream buttons on lock/CAPTCHA/passkey pages, console client card, body-limit regression test (wave 8)
- [x] 04-37-PLAN.md — Gap closure: require_verified_email for upstream accounts, binding-cookie clear rule, link redirect, docs for the closed gaps (wave 9)
- [x] 04-32-PLAN.md — Phase gate: security-test map, `just ci`, version 0.3.0 + migration pins, push main, all workflows green (wave 10)
- [ ] 04-33-PLAN.md — Release: manual real-provider checklist sign-off (checkpoint), tag v0.3.0 at the recorded release commit 9f88363 + verify (wave 11)

### Phase 5: Release 0.4 "Operate it"
**Goal**: Operators can run AnvilID for many tenants in production with high availability, and integrators can automate and extend it (RBAC, webhooks, declarative config, DCR, MCP clients)
**Depends on**: Phase 4
**Requirements**: ORG-01, ORG-05, ADM-05, ADM-06, ADM-07, OIDC-17, AGT-01, AGT-02, AUTH-14, OPS-03, OPS-07, OPS-08, OPS-09, QUAL-05
**Success Criteria** (what must be TRUE):
  1. The HA test (3 stateless nodes on one Postgres, shared rate limiting, under load) shows no errors through node restarts, and the token endpoint meets the PRD §6.3 targets (≥1,000 req/s at p99 < 50 ms on 4 vCPU; idle memory < 100 MB)
  2. A tenant's configuration exported as YAML re-applies idempotently and round-trips into a fresh instance; the CLI can also back up and restore online, rotate keys and recover admin access
  3. An MCP client completes authorization using a Client ID Metadata Document and resource indicators, and dynamic client registration obeys the admin policy (disabled / allow-listed / open)
  4. An operator manages multiple isolated tenants (each with its own issuer) from the console, defines roles, permissions and custom attributes that appear in tokens, and receives signed, retried webhooks for lifecycle events
  5. The in-repo Helm chart and Docker Compose examples deploy a working instance that exposes health endpoints, Prometheus metrics, OpenTelemetry traces and JSON logs
**Plans**: 33 plans in 10 waves

Plans:
- [x] 05-01-PLAN.md — Foundation A: every Phase 5 runtime + dev dependency, domain model, errors, audit actions, compile fixes, OpenAPI (wave 1)
- [x] 05-02-PLAN.md — Foundation B: storage + non-storage ports, pre-added service fields/AppState accessors, TRANSITIONAL shims, module skeletons, contract suite (wave 2)
- [x] 05-03-PLAN.md — CI hygiene: fuzz build on push, unified 413 for streamed bodies, k6 load/HA harness skeleton + HA compose (wave 1)
- [x] 05-04-PLAN.md — Multi-tenant console: $tenant routes, tenant switcher, tenants list/create, redirects, e2e (wave 1)
- [x] 05-05-PLAN.md — Installation config + observability: health aliases, readiness drain, metrics (one owner per metric), OTLP traces, request layer, pool size, worker abstraction, limiter hook, pre-declared AppState handles, idle-memory gate (wave 2)
- [x] 05-06-PLAN.md — SQLite 0007 + Phase 5 repos, webhook enqueue in audit append, administrator backfill, upgrade test (wave 3)
- [x] 05-07-PLAN.md — Postgres 0006 + Phase 5 repos (SKIP LOCKED webhook claims), backfill, upgrade test (wave 3)
- [x] 05-08-PLAN.md — Redis limiter backend behind the one RateLimiter trait + limiter contract suite + failure policy (wave 2)
- [x] 05-09-PLAN.md — Pure RFC 7591 and CIMD draft-03 validators (dev-only http-loopback flag, jwks_uri rejected) (TDD) + fuzz targets (wave 3)
- [x] 05-10-PLAN.md — Pure claim mapping, webhook event mapping, Standard Webhooks signature, config plan diff, offline JSON Schema adapter (wave 3)
- [x] 05-11-PLAN.md — Carry-over: in-flow passkey enrolment under MFA required (wave 2)
- [x] 05-12-PLAN.md — RBAC end to end: RoleService, claims, admin scopes bounded by roles, lockout + escalation guards, role admin API (wave 4)
- [x] 05-13-PLAN.md — Carry-over: resource-aware remembered consent + CIMD consent display (wave 4)
- [x] 05-14-PLAN.md — Webhooks: WebhookService, enqueue from AuditService, leased signed delivery worker (lease sized to batch/concurrency) (wave 4)
- [x] 05-15-PLAN.md — CIMD: ClientResolver, fetcher on OutboundClient, materialised clients, discovery flag, abuse controls (wave 4)
- [x] 05-16-PLAN.md — Shared limiter wiring + failure modes, concurrency-safe first start for N nodes (wave 4)
- [x] 05-17-PLAN.md — CLI: online SQLite backup/restore, Postgres guidance, admin recover (incl. fresh admin on lockout), healthcheck (wave 4)
- [x] 05-18-PLAN.md — Token-endpoint performance: content-addressed signer cache, optional direct aws-lc signing, host negative cache (wave 3)
- [x] 05-19-PLAN.md — Custom attributes: AttributeService + account-page editing (wave 4)
- [x] 05-20-PLAN.md — Declarative tenant config: export/plan/apply (system tenant rules), admin JSON routes, YAML CLI, JSON Schema (wave 5)
- [x] 05-21-PLAN.md — DCR: RFC 7591/7592 endpoints under policy, initial access tokens (wave 5)
- [x] 05-22-PLAN.md — Helm chart (database.type, Redis guard for replicas), Compose examples, Docker HEALTHCHECK, deploy CI (wave 5)
- [x] 05-23-PLAN.md — Admin API: attributes, webhooks + delivery log, DCR/CIMD policy, IATs, client/tenant DTO fields (wave 6)
- [x] 05-24-PLAN.md — Console pages: roles, attributes, webhooks, registration policy, config, e2e (wave 7)
- [x] 05-25-PLAN.md — MCP: mock client/resource server e2e with CIMD + resource indicators, docs/MCP.md (wave 7)
- [x] 05-26-PLAN.md — HA + perf gates in CI (restarts, shared limit, exactly-once webhooks, PRD targets, host VmRSS), telemetry redaction test; sole wave-7 owner of Rust fixes (wave 7)
- [x] 05-27-PLAN.md — Feature e2e (attributes, webhooks, DCR, RBAC claims) + UPGRADING/OPERATIONS/WEBHOOKS/ARCHITECTURE docs (wave 7)
- [x] 05-30-PLAN.md — Gap: passkey accepted as the second factor under MFA required (no enrolment loop), negative tests (wave 8)
- [x] 05-31-PLAN.md — Gap: one hmac_sha256 in anvil-jose for the limiter, shared outbound client for the CLI, jobs shutdown timeout >= webhook timeout, stale comments (wave 8)
- [x] 05-32-PLAN.md — Gap: no admin scopes on non-system static clients, 1 MiB config document limit, schema bounds, OIDC path-insertion discovery (wave 8)
- [x] 05-33-PLAN.md — Gap: Attributes nav on every account page, CIMD consent CSS, console client secrets shown once (wave 8)
- [x] 05-28-PLAN.md — Phase gate: security map (incl. gap-plan tests), plaintext scan of 0.4 secrets, just ci, version 0.4.0 + migration pins, requirements, all workflows green incl. deploy + load; owner checkpoint after 3 failed perf runs (wave 9)
- [ ] 05-29-PLAN.md — Release v0.4.0 after owner sign-off, tagged at the recorded release commit f80dcb4 (v0.3.0 tagged first; `latest` = 0.4.0) (wave 10)

### Phase 6: Release 1.0 "Credible for business" (Organizations and SSO)
**Goal**: SaaS builders can serve business customers: organizations with members and roles, each able to bring its own SAML or OIDC identity provider, with users routed automatically by email domain
**Depends on**: Phase 5
**Requirements**: ORG-02, ORG-03, ORG-04, ADM-02
**Success Criteria** (what must be TRUE):
  1. A tenant admin creates an organization, invites members, assigns org-scoped roles, and the org claim appears in tokens; a user in several orgs can switch between them
  2. An organization admin configures an OIDC or SAML 2.0 connection and users log in through it with just-in-time provisioning; SAML stays flagged experimental unless it passes the signature-wrapping attack corpus (decision D4)
  3. After a domain is verified by DNS TXT record, a user entering an email on that domain is routed to the organization's IdP
  4. Every managed object (tenants, users, clients, organizations, connections, branding, keys, sessions, audit log) can be administered from the console
**Plans**: 31 plans in 11 waves

Plans:
- [ ] 06-01-PLAN.md — Dependencies (bergshamra-dsig on aws-lc, uppsala, hickory, psl, flate2), scoped chrono deny exception (Q2), D4 spike, ARCHITECTURE verdict (wave 1)
- [ ] 06-02-PLAN.md — Foundation A: org/SAML model, org_id fields, errors, audit actions + webhook events, reserved org claims, compile fixes, TRANSITIONAL converters, OpenAPI (wave 1)
- [ ] 06-03-PLAN.md — E2E infra: mock SAML IdP (xml-crypto) and a suite-wide mock DNS with an HTTP control channel, self-tests (wave 1)
- [ ] 06-04-PLAN.md — Foundation B: ports (OrgRepo, DomainTxtLookup, SamlXml), shims, AppDeps/AppConfig + operator keys, module/route skeletons, contract suite (wave 2)
- [x] 06-05-PLAN.md — Pure core: domain rules + routing, TXT record format, active-org resolution + org claims + org:admin bounding, org MFA, SAML request/validation (TDD) (wave 2)
- [ ] 06-06-PLAN.md — Carry-over: passkey picker narrowed to the step user at the second factor (wave 2)
- [ ] 06-07-PLAN.md — SQLite 0008 additive + 0009 no-transaction rebuild, org repos, 0.4 -> 1.0 upgrade with row counts (wave 3)
- [ ] 06-08-PLAN.md — Postgres 0007, org repos, 0.4 -> 1.0 upgrade (wave 3)
- [ ] 06-09-PLAN.md — SAML XML adapter (one parser, strict pre-check, verify-then-read), D4 attack corpus, fuzz targets (wave 3)
- [ ] 06-10-PLAN.md — DNS TXT adapter (hickory, FQDN, bounded, uncached) + single domain check, UDP stub tests (wave 3)
- [ ] 06-11-PLAN.md — Signing keys admin API (list, rotate) (wave 3)
- [ ] 06-12-PLAN.md — Org admin API: orgs, members, org roles, invitations; org-admin principal (Q1: audience, per-request org:admin re-check, last-admin lockout) (wave 4)
- [ ] 06-13-PLAN.md — Org in the grant: organization parameter, org claims in all token surfaces, refresh re-check, opaque/introspection claims (wave 4)
- [ ] 06-14-PLAN.md — Enterprise OIDC per org: shared completion path, domain-bound email trust, JIT membership (wave 4)
- [ ] 06-15-PLAN.md — org:admin reservation (DCR/CIMD/system tenant), client org policy rules, tenant YAML excludes org objects (wave 4)
- [ ] 06-16-PLAN.md — Console: signing keys page + e2e (wave 4)
- [ ] 06-17-PLAN.md — Org SSO admin API: OIDC/SAML connections (flag, metadata import), DNS-verified domains + routing, org branding (wave 5)
- [ ] 06-18-PLAN.md — SAML login: start, ACS POST, continue GET, replay cache, SP metadata, behind the experimental flag (wave 5)
- [ ] 06-19-PLAN.md — Org switcher + org MFA strictest-wins (wave 5)
- [ ] 06-20-PLAN.md — Invitation acceptance (email template, pages, registration via invite) + daily domain re-check job (wave 5)
- [ ] 06-21-PLAN.md — Console: organizations section (members, invitations, roles, user memberships, client policy) + e2e (wave 5)
- [ ] 06-22-PLAN.md — Identifier-first login with home-realm discovery, allow_local_password policy, enumeration-safe (wave 6)
- [ ] 06-23-PLAN.md — Console: org SSO tabs (connections incl. SAML, domains, branding), e2e runner env + e2e (wave 6)
- [ ] 06-24-PLAN.md — E2E: org switch, invitations, SAML, HRD (+ no-JS) (wave 7)
- [ ] 06-25-PLAN.md — Docs: ORGANIZATIONS, SAML (experimental profile, interop checklist), UPGRADING 0.4 -> 1.0, ARCHITECTURE/OPERATIONS/CONFIG/WEBHOOKS/theme (wave 7)
- [ ] 06-28-PLAN.md — Gap: email-first decision follows the flag-aware routable rule, lock/CAPTCHA page shows the email-first form, org JIT allowed under closed registration for the org's verified domains (wave 8)
- [ ] 06-29-PLAN.md — Gap: admin API per-user organizations + listUsers ?email=, console on them, connection page uses SecretRotation (wave 8)
- [ ] 06-30-PLAN.md — Gap: remove forwarding effective_policy, stale contract comments, Cargo.lock-based single aws-lc check (wave 8)
- [ ] 06-31-PLAN.md — Gap: invitation return-to after sign-in (allowlisted, sealed), sign-in after invitation registration, docs (wave 9)
- [x] 06-26-PLAN.md — Phase gate: security map (incl. gap-plan tests), plaintext scan, just ci, version 1.0.0-beta.1 + migration pins, requirements; owner checkpoint (push + Q8 tags); all workflows green (wave 10)
- [ ] 06-27-PLAN.md — Prerelease v1.0.0-beta.1 after owner sign-off (v0.3.0/v0.4.0 tagged first; 1.0.0 ships in Phase 7) (wave 11)

### Phase 7: Release 1.0 "Credible for business" (Certification and release)
**Goal**: AnvilID 1.0 ships as a certified, externally reviewed, stable platform that teams can migrate onto from other systems
**Depends on**: Phase 6
**Requirements**: OIDC-18, OIDC-23, UI-05, AGT-03, ADM-08, ADM-09, QUAL-03, SEC-08
**Success Criteria** (what must be TRUE):
  1. OpenID conformance passes in CI for Basic OP, Config OP, Form Post, RP-Initiated Logout and Back-Channel Logout, and certification is submitted for all target profiles
  2. An external security review is completed and its findings fixed; the project publishes a security policy
  3. An admin imports users with existing password hashes (bcrypt, scrypt incl. Firebase, PBKDF2, Argon2, salted SHA-2) who can then log in with their old passwords, and can export users individually, in bulk and as a GDPR data-subject export
  4. Clients can use pushed authorization requests, SPAs and native apps can drive login through the versioned headless flow API, and the consent screen clearly identifies agent clients with incremental scope step-up
  5. The upgrade path from 0.4 to 1.0 is tested, public APIs are versioned with a documented compatibility policy, and the documentation site covers install, integrations and migration guides
**Plans**: 27 plans in 10 waves (review/SAML gap plans 07-28+ are added once private findings or owner decisions exist)

Plans:
- [ ] 07-01-PLAN.md — Legacy-hash verifiers (bcrypt, scrypt, Firebase, PBKDF2, SHA-2) with KATs, scoped RustCrypto deny exception; owner checkpoint approves the crypto exception (wave 1)
- [ ] 07-02-PLAN.md — Import policy (core): stored `$anvil-*` encoding, caps and floors, vendor-format conversion, fuzz target (TDD) (wave 1)
- [ ] 07-03-PLAN.md — Foundation A: client PAR/agent/native fields, tenant PAR/headless settings, PAR + hash-profile models, audit actions, admin:users:export scope, hasher port, single scope rule (role.rs), console audit keys, TRANSITIONAL converter refusals (wave 1)
- [ ] 07-04-PLAN.md — Skeletons: PAR/flows/import/export/profile modules and empty routers, CLI `users import|export`, rate-limit classes (wave 1)
- [ ] 07-05-PLAN.md — Extract the shared ui::flow_driver (guard, CAPTCHA, submit, record, methods) with no UI behaviour change (wave 1)
- [ ] 07-06-PLAN.md — SECURITY.md, external review scope + brief, threat model; owner checkpoint enables private vulnerability reporting (wave 1)
- [ ] 07-07-PLAN.md — Docs site skeleton: mdBook, SUMMARY, check script (no tracking, no research, links), docs.yml with owner-dispatched publish, out-of-book links made absolute (wave 1)
- [ ] 07-08-PLAN.md — Foundation B: storage ports, SQLite 0010 + repos, contract suite (PAR single winner, password CAS), Postgres shims, SQLite upgrade from 0.4 and beta.1; preflight requires 06-26 complete (wave 2)
- [ ] 07-09-PLAN.md — PasswordDispatcher: caps before hashing (incl. stored Argon2 params), legacy routing in the bounded pool, rehash flag, wiring (wave 2)
- [ ] 07-10-PLAN.md — Headless flow API v1, browser mode: DTO over flow_driver, origin allow-list + CSRF header + JSON-only layers, flows-v1.json drift test, SPA e2e (wave 2)
- [ ] 07-11-PLAN.md — Postgres 0008 + repos + .sqlx, upgrade from 0.4 and beta.1 (wave 3)
- [ ] 07-12-PLAN.md — Client/tenant field exposure (admin API, YAML, DCR, CIMD) with one validation function (agents never skip consent, native eligibility) (wave 3)
- [ ] 07-13-PLAN.md — PAR (RFC 9126): /par, request_uri consumption at /authorize, require flags, discovery, negative tests (wave 3)
- [ ] 07-14-PLAN.md — User import service, Firebase hash profiles (sealed signer key), first-login CAS rehash, CLI import, IMPORT-EXPORT docs (wave 3)
- [ ] 07-15-PLAN.md — User export service: single, bulk stream, GDPR bundle with redaction, no-secrets guarantee, CLI export with opt-in hash flag (wave 3)
- [ ] 07-16-PLAN.md — Agent consent: agent badge, provenance, incremental step-up (deny keeps grant), en/de catalogs, e2e (wave 4)
- [ ] 07-17-PLAN.md — Admin API: import, hash profiles, single/bulk/GDPR export with admin:users:export, body-limit branch, docs (wave 4)
- [ ] 07-18-PLAN.md — Headless native mode: PAR + PKCE + flow token, code as JSON, first-party only, negative tests (wave 4)
- [ ] 07-19-PLAN.md — Certification package: conformance green with PAR metadata, tag-run evidence retention, setup.sh --public, CERTIFICATION runbook (wave 4)
- [ ] 07-20-PLAN.md — Console: client PAR/agent/native fields, tenant PAR/origins, users import + export, hash profiles, e2e (wave 5)
- [ ] 07-21-PLAN.md — Compatibility policy, 1.0 OpenAPI baselines + in-repo breaking-change test, config-version tests, UPGRADING 1.0 (incl. Q8 deferral) (wave 5)
- [ ] 07-22-PLAN.md — Docs site content: install, integration and migration guides (owner checkpoint picks vendors), SUMMARY, ARCHITECTURE (wave 6)
- [ ] 07-23-PLAN.md — Phase gate: security map, plaintext scans, just ci, 1.0.0-rc.1 + 1.0 migration pins, ticks (OIDC-23/SEC-08 wait); owner checkpoint (push + rc tag); all workflows green (wave 7)
- [ ] 07-24-PLAN.md — Owner: OpenID certification on the hosted suite and submission; public status (wave 8)
- [ ] 07-25-PLAN.md — Owner: external security review commissioned and completed, findings private; triggers review gap plans (wave 8)
- [ ] 07-26-PLAN.md — Owner: real-IdP SAML interop checklist, SAML flag and chrono decisions, AUTH-07 status (wave 9)
- [ ] 07-27-PLAN.md — Release v1.0.0 after owner sign-off: version, pins, ticks OIDC-23/SEC-08, tag, verify, publish Pages (wave 10)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundations and Spikes (M0) | 8/8 | Complete    | 2026-11-25 |
| 2. Release 0.1 "First login" | 23/23 | Complete    | 2026-11-25 |
| 3. Release 0.2 "Secure by default" | 34/34 | Complete    | 2026-11-25 |
| 4. Release 0.3 "Real-world logins" | 36/37 | In Progress|  |
| 5. Release 0.4 "Operate it" | 32/33 | In Progress|  |
| 6. Release 1.0 (Organizations and SSO) | 26/31 | In Progress|  |
| 7. Release 1.0 (Certification and release) | 0/27 | Planned | - |

---
*Roadmap created: 2026-11-25*
