# Requirements: AnvilID

**Defined:** 2026-11-25
**Core Value:** A standards-correct, secure OIDC provider that anyone can run in two minutes.

Source of truth for wording and detail: [docs/PRD.md](../docs/PRD.md) §8–9. IDs below match the PRD IDs
(zero-padded: `OIDC-01` = PRD `OIDC-1`). Release targets in brackets come from the PRD release plan and
[docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) §18.

## v1 Requirements (milestone: AnvilID 1.0)

### Foundations (ARCHITECTURE.md M0)

- [x] **FND-01**: Contributor can build, lint and test the Cargo workspace (crate layout per ARCHITECTURE.md §4) with one command, and CI runs fmt, clippy, cargo-deny and tests on every PR
- [x] **FND-02**: CI enforces the crate dependency rules (core has no I/O deps; web never imports a concrete storage crate)
- [ ] **FND-03**: Spike A: a tenant repository and atomic `consume_code` work on both SQLite and Postgres, proven by a shared contract suite including a concurrency test
- [ ] **FND-04**: Spike B: a static musl release binary (amd64 + arm64) with aws-lc-rs, mimalloc and embedded assets builds in CI, with binary size and idle memory reported
- [ ] **FND-05**: Spike C: the OpenID conformance suite runs in CI against a freshly started binary

### OAuth 2.1 / OpenID Connect server

- [ ] **OIDC-01**: A client can complete authorization code flow with PKCE; only S256 is accepted; PKCE is required by default and only confidential clients may opt out (then nonce is mandatory) [0.1]
- [ ] **OIDC-02**: Redirect URIs are matched exactly (loopback port flexibility only for native apps); invalid redirects show an error page and never redirect [0.1]
- [ ] **OIDC-03**: Authorization codes are single-use, ≤60 s, bound to client/redirect/PKCE; reuse revokes the tokens issued from that code [0.1]
- [ ] **OIDC-04**: Clients authenticate with client_secret_basic, client_secret_post, private_key_jwt (aud = issuer, jti replay rejected) or none; secrets hashed, compared in constant time [0.1]
- [ ] **OIDC-05**: Refresh tokens rotate on every use; reuse revokes the whole token family [0.1]
- [ ] **OIDC-06**: A client can obtain tokens with the client credentials grant [0.1]
- [ ] **OIDC-07**: ID tokens are signed with the active key (kid set) and carry nonce, at_hash, auth_time, acr/amr [0.1]
- [ ] **OIDC-08**: Relying parties can discover the provider (OIDC discovery + RFC 8414 metadata) and fetch a JWKS that reflects key rotation with overlap [0.1]
- [ ] **OIDC-09**: A client can call UserInfo and receive scope-based claims [0.1]
- [ ] **OIDC-10**: Resource servers can introspect (RFC 7662) and clients can revoke (RFC 7009) tokens [0.2]
- [ ] **OIDC-11**: Tokens can be signed with RS256, ES256 or Ed25519 [0.2]
- [ ] **OIDC-12**: RPs can log users out via RP-initiated logout and receive back-channel logout notifications [0.3]
- [ ] **OIDC-13**: Users see a consent screen (skippable for first-party clients), consent is remembered and revocable [0.2]
- [ ] **OIDC-14**: Authorization requests honor prompt (none/login/consent/select_account/create), max_age, login_hint, acr_values [0.3]
- [ ] **OIDC-15**: Access tokens are RFC 9068 JWTs by default or opaque per client, audience-restricted [0.2]
- [ ] **OIDC-16**: Clients can request audience-bound tokens with resource indicators (RFC 8707) [0.3]
- [ ] **OIDC-17**: Clients can register dynamically (RFC 7591/7592) under an admin policy: disabled / allow-listed / open [0.4]
- [ ] **OIDC-18**: Clients can use pushed authorization requests (RFC 9126) [1.0]
- [ ] **OIDC-23**: The OpenID conformance suite passes in CI for Basic OP, Config OP, Form Post, RP-Initiated Logout and Back-Channel Logout; certification filed [1.0]
- [ ] **OIDC-24**: Authorization responses include the `iss` parameter (RFC 9207) [0.1]
- [ ] **OIDC-25**: Authorization responses support `query` and `form_post` response modes [0.2]

### Authentication and self-service

- [ ] **AUTH-01**: User can log in with a password (Argon2id, policy, optional breached-password check) [0.1]
- [ ] **AUTH-02**: User can self-register (can be disabled or invite-only) and verify their email [0.1]
- [ ] **AUTH-03**: User can recover their account by email without revealing whether an account exists [0.1]
- [ ] **AUTH-04**: User can register and log in with passkeys, including usernameless; clone detection via signature counter [0.2]
- [ ] **AUTH-05**: User can enroll TOTP with recovery codes and use it as a second factor [0.2]
- [ ] **AUTH-06**: User can log in with email OTP or magic link [0.3]
- [ ] **AUTH-07**: User can log in with Google, Apple, Microsoft, GitHub or any generic OIDC/OAuth2 provider [0.3]
- [ ] **AUTH-08**: Admin can set MFA policy (off/optional/required) per tenant, org or client; clients can request step-up via acr_values [0.3]
- [ ] **AUTH-09**: Brute-force attempts are throttled per account and per IP with progressive delays; CAPTCHA (Turnstile/hCaptcha) can be enabled [0.2]
- [ ] **AUTH-10**: User can list and revoke their sessions; idle and absolute timeouts apply; admins can revoke sessions [0.2]
- [ ] **AUTH-11**: Upstream identities link to existing accounts only on verified email or explicit confirmation [0.3]
- [ ] **AUTH-13**: User can manage profile, email (re-verified), password, passkeys, MFA, sessions and connected apps from an account page [0.3]
- [ ] **AUTH-14**: Admin can define custom user attributes per tenant with JSON Schema, controlling validation, editability and claims [0.4]

### Login UI and branding

- [ ] **UI-01**: Login, registration, recovery, consent, MFA and account pages are served by the binary with no external assets [0.1]
- [ ] **UI-02**: Login pages meet WCAG 2.2 AA, are responsive, and the password flow works without JavaScript [0.2]
- [ ] **UI-03**: Admin can theme pages (logo, colors, fonts, radius, custom CSS) live from the console, with per-tenant/org/client overrides [0.3]
- [ ] **UI-04**: Pages are translated, with language chosen from ui_locales or the browser [0.3]
- [ ] **UI-05**: SPAs and native apps can drive flows through a versioned headless API that returns server-driven form descriptions [1.0]
- [ ] **UI-07**: Admin can edit email templates per tenant and configure SMTP with a test send [0.2]

### Tenants, organizations and roles

- [ ] **ORG-01**: Operator can run multiple isolated tenants, each with its own issuer (path-based by default, host-based optional) [0.1 data model, 0.4 UI]
- [ ] **ORG-02**: Tenant admin can create organizations with membership, invitations, org-scoped roles, org claim in tokens and an org switcher [1.0]
- [ ] **ORG-03**: Organization admin can configure enterprise SSO connections (SAML 2.0 SP, OIDC RP) with JIT provisioning [1.0]
- [ ] **ORG-04**: Users are routed to their organization's IdP by email domain; domains are verified by DNS TXT record [1.0]
- [ ] **ORG-05**: Admin can define roles and permissions at tenant and org level, emitted as token claims [0.4]

### Administration, API and operations

- [ ] **ADM-01**: Every console action is available through an OpenAPI 3.1 management API authenticated with OAuth tokens and fine-grained admin scopes [0.1]
- [ ] **ADM-02**: Admin can manage tenants, users, clients, organizations, connections, branding, keys, sessions and the audit log from the console [0.2–1.0]
- [ ] **ADM-03**: On an empty database the operator gets a one-time setup URL to create the first admin; there are no default credentials [0.1]
- [ ] **ADM-04**: Every security-relevant event and admin action is audited, queryable in the console and streamable as JSON [0.2]
- [ ] **ADM-05**: Integrators receive signed, retried webhooks for user and session lifecycle events [0.4]
- [ ] **ADM-06**: Operator can export and idempotently apply a tenant's configuration as YAML [0.4]
- [ ] **ADM-07**: Operator can use the `anvilid` CLI to serve, migrate, back up/restore, import/export, rotate keys and recover admin access [0.1+]
- [ ] **ADM-08**: Admin can import users with password hashes (bcrypt, scrypt incl. Firebase, PBKDF2, Argon2, salted SHA-2) [1.0]
- [ ] **ADM-09**: Admin can export users individually and in bulk, including a GDPR data-subject export [1.0]

### Machine and agent identity

- [ ] **AGT-01**: MCP clients can obtain audience-bound tokens (RFC 8414 metadata, RFC 8707 resource indicators), with docs for publishing RFC 9728 resource metadata [0.4]
- [ ] **AGT-02**: Clients can identify themselves with Client ID Metadata Documents under admin policy [0.4]
- [ ] **AGT-03**: The consent screen clearly identifies agent clients and requested scopes, and supports incremental scope step-up [1.0]

### Operations (PRD §9.1)

- [ ] **OPS-01**: Operator can download one static binary (linux amd64/arm64, macOS) or a container image under 50 MB
- [ ] **OPS-02**: AnvilID runs on embedded SQLite by default and on PostgreSQL for production, with no other required dependency
- [ ] **OPS-03**: Operator can run multiple stateless instances on one Postgres without extra coordination services
- [ ] **OPS-04**: Migrations run automatically, are tested between consecutive minor versions, and are never destructive without an explicit flag
- [ ] **OPS-05**: Operator can start with zero configuration; in production only the public URL is expected
- [ ] **OPS-06**: AnvilID behaves correctly behind reverse proxies via trusted-proxy configuration
- [ ] **OPS-07**: Operator can back up and restore online (SQLite snapshot; Postgres guidance)
- [ ] **OPS-08**: Operator can monitor health endpoints, Prometheus metrics, OpenTelemetry traces and structured JSON logs
- [ ] **OPS-09**: Operator can deploy with the in-repo Helm chart and Docker Compose examples

### Security (PRD §9.2)

- [ ] **SEC-01**: Defaults follow RFC 9700 and OAuth 2.1
- [ ] **SEC-02**: Signing keys are generated at first start, encrypted at rest with a KEK, and rotated on schedule with overlap
- [ ] **SEC-03**: All secrets are stored hashed; TOTP seeds and upstream IdP secrets are encrypted
- [ ] **SEC-04**: Browser endpoints have CSRF protection, hardened cookies and a strict CSP
- [ ] **SEC-05**: Authentication and token endpoints are rate limited by default
- [ ] **SEC-06**: Release builds contain no test-only behavior
- [ ] **SEC-07**: CI audits dependencies and fuzzes JWT and authorization-request parsers
- [ ] **SEC-08**: The project publishes a security policy; an external security review is completed before 1.0

### Quality (PRD §9.3, §6.3)

- [ ] **QUAL-01**: Each security requirement has an automated negative test proving bad input is rejected
- [ ] **QUAL-02**: The same test suite runs against SQLite and Postgres
- [ ] **QUAL-03**: Public APIs are versioned; breaking changes only in major versions
- [ ] **QUAL-04**: Zero-config `docker run` → OIDC login in a sample app takes ≤ 2 minutes (scripted check)
- [ ] **QUAL-05**: Idle memory < 100 MB; token endpoint ≥ 1,000 req/s at p99 < 50 ms on 4 vCPU with Postgres

## v2 Requirements (after 1.0)

Tracked but not in the current roadmap. Details in docs/PRD.md §8.

- **OIDC-19**: Device authorization grant (RFC 8628) [1.x]
- **OIDC-20**: Token exchange (RFC 8693) [1.x]
- **OIDC-21**: DPoP sender-constrained tokens [2.0]
- **OIDC-22**: FAPI 2.0 security profile [3.0]
- **AUTH-12**: SMS OTP via pluggable providers [2.0]
- **UI-06**: Embeddable web components [2.0]
- **UI-08**: Delegated external login/consent apps [2.0]
- **ORG-06**: Self-service SSO/SCIM setup portal for customer IT admins [2.0]
- **ADM-10**: Terraform provider [2.0]
- **ADM-11**: Audited admin impersonation [2.0]
- **ADM-12**: Importers for Keycloak realm exports and Ory Kratos/Hydra [1.x]
- **AGT-04**: Token exchange delegation and identity assertion grants for agents [2.0]
- **AGT-05**: Agents as first-class principals [2.0]
- **AGT-06**: Scoped, revocable API keys [2.0]
- **DIR-01**: SCIM 2.0 server per organization [2.0]
- **DIR-02**: LDAP read-only facade [2.0]
- **SAML-01**: SAML 2.0 IdP [2.0]
- **GW-01**: Forward-auth endpoint for reverse proxies [2.0]
- **GW-02**: Identity-aware reverse proxy [3.0]
- **PERM-01**: Embedded relationship-based authorization engine [3.0]
- **PERM-02**: Policy-based (ABAC) conditions [3.0]
- **EXT-01**: Synchronous extension hooks (HTTP callouts, then WASM) [2.0]
- **SEC-09**: Shared Signals Framework (CAEP/RISC) [3.0]
- **SEC-10**: Risk-based adaptive MFA [3.0]

## Out of Scope

| Feature | Reason |
|---------|--------|
| Implicit grant, hybrid flow, ROPC, `plain` PKCE | Deprecated by OAuth 2.1 / RFC 9700; insecure; not implemented at all |
| Own clustering / consensus layer | HA = stateless nodes on Postgres; a custom replication engine is a multi-year effort |
| Embedded JS/Python scripting runtimes | Security and footprint; extension points come later as HTTP callouts and WASM |
| Workforce IGA (access reviews, app catalog, push-MFA app) | Not the 1.0 audience |
| Hosted cloud offering | Possible future business outside this repository |
| Feature paywalls / relicensing | MIT forever; everything ships in the open-source binary |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| FND-01 | Phase 1 | Complete |
| FND-02 | Phase 1 | Complete |
| FND-03 | Phase 1 | Pending |
| FND-04 | Phase 1 | Pending |
| FND-05 | Phase 1 | Pending |
| OIDC-01 | Phase 2 | Pending |
| OIDC-02 | Phase 2 | Pending |
| OIDC-03 | Phase 2 | Pending |
| OIDC-04 | Phase 2 | Pending |
| OIDC-05 | Phase 2 | Pending |
| OIDC-06 | Phase 2 | Pending |
| OIDC-07 | Phase 2 | Pending |
| OIDC-08 | Phase 2 | Pending |
| OIDC-09 | Phase 2 | Pending |
| OIDC-10 | Phase 3 | Pending |
| OIDC-11 | Phase 3 | Pending |
| OIDC-12 | Phase 4 | Pending |
| OIDC-13 | Phase 3 | Pending |
| OIDC-14 | Phase 4 | Pending |
| OIDC-15 | Phase 3 | Pending |
| OIDC-16 | Phase 4 | Pending |
| OIDC-17 | Phase 5 | Pending |
| OIDC-18 | Phase 7 | Pending |
| OIDC-23 | Phase 7 | Pending |
| OIDC-24 | Phase 2 | Pending |
| OIDC-25 | Phase 3 | Pending |
| AUTH-01 | Phase 2 | Pending |
| AUTH-02 | Phase 2 | Pending |
| AUTH-03 | Phase 2 | Pending |
| AUTH-04 | Phase 3 | Pending |
| AUTH-05 | Phase 3 | Pending |
| AUTH-06 | Phase 4 | Pending |
| AUTH-07 | Phase 4 | Pending |
| AUTH-08 | Phase 4 | Pending |
| AUTH-09 | Phase 3 | Pending |
| AUTH-10 | Phase 3 | Pending |
| AUTH-11 | Phase 4 | Pending |
| AUTH-13 | Phase 4 | Pending |
| AUTH-14 | Phase 5 | Pending |
| UI-01 | Phase 2 | Pending |
| UI-02 | Phase 3 | Pending |
| UI-03 | Phase 4 | Pending |
| UI-04 | Phase 4 | Pending |
| UI-05 | Phase 7 | Pending |
| UI-07 | Phase 3 | Pending |
| ORG-01 | Phase 5 | Pending |
| ORG-02 | Phase 6 | Pending |
| ORG-03 | Phase 6 | Pending |
| ORG-04 | Phase 6 | Pending |
| ORG-05 | Phase 5 | Pending |
| ADM-01 | Phase 2 | Pending |
| ADM-02 | Phase 6 | Pending |
| ADM-03 | Phase 2 | Pending |
| ADM-04 | Phase 3 | Pending |
| ADM-05 | Phase 5 | Pending |
| ADM-06 | Phase 5 | Pending |
| ADM-07 | Phase 5 | Pending |
| ADM-08 | Phase 7 | Pending |
| ADM-09 | Phase 7 | Pending |
| AGT-01 | Phase 5 | Pending |
| AGT-02 | Phase 5 | Pending |
| AGT-03 | Phase 7 | Pending |
| OPS-01 | Phase 2 | Pending |
| OPS-02 | Phase 2 | Pending |
| OPS-03 | Phase 5 | Pending |
| OPS-04 | Phase 3 | Pending |
| OPS-05 | Phase 2 | Pending |
| OPS-06 | Phase 3 | Pending |
| OPS-07 | Phase 5 | Pending |
| OPS-08 | Phase 5 | Pending |
| OPS-09 | Phase 5 | Pending |
| SEC-01 | Phase 2 | Pending |
| SEC-02 | Phase 3 | Pending |
| SEC-03 | Phase 4 | Pending |
| SEC-04 | Phase 2 | Pending |
| SEC-05 | Phase 3 | Pending |
| SEC-06 | Phase 2 | Pending |
| SEC-07 | Phase 2 | Pending |
| SEC-08 | Phase 7 | Pending |
| QUAL-01 | Phase 2 | Pending |
| QUAL-02 | Phase 2 | Pending |
| QUAL-03 | Phase 7 | Pending |
| QUAL-04 | Phase 2 | Pending |
| QUAL-05 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 84 total
- Mapped to phases: 84
- Unmapped: 0 ✓

---
*Requirements defined: 2026-11-25*
*Last updated: 2026-11-25 after roadmap creation*
