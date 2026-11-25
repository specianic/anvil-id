# AnvilID — Product Requirements Document

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Last updated** | 2026-11-25 |
| **Companion doc** | [ARCHITECTURE.md](ARCHITECTURE.md) — how we build it |

---

## 1. Summary

AnvilID is an open-source (MIT) identity and access platform. It aims to be **the easiest identity server
to self-host while still covering what serious applications need**: standards-compliant OAuth 2.1 and
OpenID Connect, passkeys and MFA, organizations and enterprise SSO, user provisioning, and
authorization.

It ships as **one binary**. It starts with **zero required configuration** on embedded storage, scales out
on Postgres, and includes a polished login UI and admin console. Over time it grows into a full identity
suite: identity, federation, directory, permissions and an access proxy. All of it ships as modules of the
same binary, never as a mesh of services that you have to wire together yourself.

## 2. Problem

Teams that need identity today choose between three unsatisfying options:

1. **Hosted identity services** are fast to adopt but expensive at scale. They charge per user and per
   enterprise SSO connection, put core features behind enterprise tiers, and create lock-in through
   proprietary extension mechanisms and hard-to-export password hashes.
2. **Full-featured self-hosted servers** cover the protocols, but they are heavy to run, hard to theme and
   painful to upgrade. Others are split into several services and leave you to build the login UI yourself.
3. **Lightweight self-hosted servers** are a joy for the first ten minutes but deliberately narrow: no
   SAML, no SCIM, no multi-tenancy, limited admin tooling.

Nobody combines the operational simplicity of the third group with the coverage of the second, under a
license that doesn't paywall the features businesses actually need (SSO, SCIM, organizations).

## 3. Vision and positioning

> **"Enterprise identity coverage with homelab simplicity. Everything free, in one binary."**

Positioning pillars:

| Pillar | What it means concretely |
|---|---|
| **Easiest to run** | One process. Embedded storage by default. Under 2 minutes from `docker run` to a working OIDC login. Under 100 MB RAM idle. Upgrades mean replacing the binary. |
| **Correct by construction** | Spec-compliant OAuth 2.1 and OIDC, verified by the OpenID conformance suite in CI and certified. Secure defaults that cannot be turned into insecure ones by accident. |
| **No SSO tax** | Unlimited organizations, SSO connections, SCIM directories and MFA in the open-source core. No feature paywall in the binary. |
| **Batteries included, headless optional** | A good-looking, brandable login UI and admin console are built in. A stable flow API lets teams build fully custom UIs when they want to. |
| **Ready for machines and agents** | First-class machine-to-machine and AI-agent authorization (MCP-compliant authorization server, token exchange, fine-grained scopes). |
| **Easy to leave, easy to arrive** | Import users from other providers, password hashes included. Everything is exportable. |

## 4. Target users

| Persona | Context | What they need from AnvilID |
|---|---|---|
| **P1: SaaS developer** (primary) | Building a B2B or B2C product; wants auth handled; may be migrating off a hosted provider for cost or control | Hosted login, social login, passkeys, organizations, per-customer enterprise SSO, management API, SDK-free integration through standard OIDC libraries, password-hash import |
| **P2: Platform / DevOps engineer** | Runs internal apps and services; replacing a heavier self-hosted IdP | Single binary, Postgres for HA, declarative config, Helm chart, Terraform, metrics, boring upgrades |
| **P3: Self-hoster / homelab** | Wants SSO across Grafana, Nextcloud, Gitea, Proxmox… | 2-minute setup, low memory, forward-auth for apps without OIDC, copy-paste integration guides |
| **P4: Customer's IT admin** (secondary) | Connects their corporate IdP to a P1 product | A self-service portal to configure SAML/OIDC SSO and SCIM without emailing support |
| **P5: AI / agent developer** | Building MCP servers or agents that act on behalf of users | An MCP-compliant authorization server, dynamic client onboarding, delegated scoped tokens |

**Primary wedge for 1.0:** P1 and P2. P3 benefits from the same simplicity at no extra cost. P4 and
P5 features follow, built on the same core.

## 5. Product principles

These are tie-breakers when requirements conflict.

1. **Defaults over options.** Every setting has a safe, sensible default. A feature that needs
   configuration before it is safe is not done.
2. **One binary, many roles.** New capabilities become modules in the same binary that can be enabled.
   We do not require extra services for core features.
3. **Standards first.** Use standard protocols for every integration surface (OIDC, OAuth, SAML, SCIM,
   WebAuthn, LDAP). Avoid proprietary SDK lock-in. Our SDKs are conveniences, never requirements.
4. **Nothing pretends.** A feature either works end to end and is tested, or it doesn't exist. No
   placeholder endpoints, no simulated data.
5. **Boring upgrades.** Every release can be upgraded to from the previous minor release automatically,
   and migrations are tested in CI.
6. **Security fixes are free.** Security fixes ship in the open-source release immediately.
7. **MIT forever.** No CLA (contributors sign off with DCO). Public commitment never to relicense the
   core.

## 6. Goals, non-goals and success metrics

### 6.1 Goals for 1.0

- G1: A production-grade OAuth 2.1 / OIDC provider that passes the OpenID conformance suite (Basic,
  Config, and the RP-initiated logout profiles at minimum).
- G2: Complete, polished end-user authentication: password, passkeys, TOTP, email OTP/magic link, social
  login, recovery.
- G3: B2B foundations: tenants, organizations, per-organization SSO connections (SAML and OIDC),
  domain-based routing.
- G4: Operator experience that beats every alternative in the same class on time-to-first-login,
  footprint and upgrade safety.

### 6.2 Non-goals for 1.0

- Being a full workforce IAM / IGA product (access reviews, app catalog provisioning, push-MFA app).
- Custom scripting runtimes embedded in the server (JavaScript or Python sandboxes).
- Implicit grant, resource-owner password grant, or any flow deprecated by OAuth 2.1.
- Our own clustering or consensus layer. HA is achieved with stateless instances on Postgres.
- A hosted cloud offering (a possible later business, not part of this PRD).

### 6.3 Success metrics

| Metric | Target for 1.0 |
|---|---|
| Time from `docker run` to an OIDC login in a sample app | ≤ 2 minutes, no config file |
| Required configuration for a local start | 0 values (public URL auto-detected for localhost) |
| Idle memory (embedded storage, single tenant) | < 100 MB, target 50 MB |
| Token endpoint throughput (single instance, Postgres, 4 vCPU) | ≥ 1,000 req/s at p99 < 50 ms |
| OpenID conformance | All targeted profiles pass in CI; certification filed |
| Upgrade safety | Every minor release upgrades automatically from the previous one, verified in CI |
| Security | Zero known critical or high vulnerabilities at release; external review of the protocol core before 1.0 |

## 7. Product suite

AnvilID is one binary composed of modules. The **Core** modules are always on. **Optional** modules
are enabled with a flag or from the admin console.

| Module | Capability | Comparable to | Phase |
|---|---|---|---|
| **Identity** (core) | Users, credentials, self-service registration, login, recovery, verification, sessions | Ory Kratos, Keycloak users | 0.x |
| **OAuth/OIDC server** (core) | Authorization server and OpenID provider | Ory Hydra, Keycloak | 0.x |
| **Console** (core) | Admin UI, management API, audit log | Keycloak admin console | 0.x–1.0 |
| **Login UI** (core) | Built-in, themeable hosted login, consent and account pages | Hosted login pages | 0.x |
| **Organizations** (core) | Tenants, organizations, membership, invitations, org-scoped roles | Hosted B2B org features | 1.0 |
| **Federation** | Upstream social, OIDC and SAML identity providers; per-org enterprise SSO | Keycloak brokering, Ory Polis | 1.0 |
| **Directory** | SCIM 2.0 server (inbound provisioning); LDAP read-only facade | Ory Polis SCIM, Authentik LDAP outpost | 2.0 |
| **SAML IdP** | AnvilID acting as SAML identity provider for legacy apps | Keycloak SAML | 2.0 |
| **Permissions** | Relationship-based (Zanzibar-style) and role-based authorization with a check API | Ory Keto, OpenFGA | 3.0 |
| **Gateway** | Forward-auth endpoint for reverse proxies, then an identity-aware proxy | Ory Oathkeeper, Authelia | 2.0 (forward-auth), 3.0 (proxy) |
| **Agents** | MCP authorization, token exchange, agent identities, delegated access | Agent-identity offerings from hosted providers | 1.0 (MCP basics), 2.0+ |

## 8. Functional requirements

Requirement IDs are stable and referenced from the architecture milestones. Priority: **P0** blocks the
phase, **P1** is expected in the phase, **P2** is opportunistic.

### 8.1 OAuth 2.1 / OpenID Connect server (`OIDC`)

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| OIDC-1 | Authorization code grant with PKCE; only **S256** accepted, `plain` rejected. PKCE is required by default for every client (`require_pkce`); only confidential clients may turn it off (public clients never can); such opted-out clients may omit `nonce` as OIDC Core allows for the code flow, with the code bound to the client's authentication at the token endpoint. Needed for OpenID certification | 0.1 | P0 |
| OIDC-2 | Exact redirect URI matching (localhost port flexibility for native apps only, per RFC 8252) | 0.1 | P0 |
| OIDC-3 | Authorization codes are single-use, short-lived (≤ 60 s), and bound to client, redirect URI and PKCE challenge; reuse revokes the tokens issued from that code | 0.1 | P0 |
| OIDC-4 | Client authentication: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` (public clients). Secrets stored hashed; constant-time comparison. For `private_key_jwt`, the assertion's `aud` must be exactly the issuer identifier, and `jti` replay is rejected | 0.1 | P0 |
| OIDC-5 | Refresh tokens with rotation and reuse detection (reuse revokes the whole token family) | 0.1 | P0 |
| OIDC-6 | Client credentials grant | 0.1 | P0 |
| OIDC-7 | ID tokens signed with the active key (`kid` set); `nonce`, `at_hash`, `auth_time`, `acr`/`amr` supported | 0.1 | P0 |
| OIDC-8 | Discovery (`/.well-known/openid-configuration`), RFC 8414 metadata, JWKS with key rotation and overlap | 0.1 | P0 |
| OIDC-9 | UserInfo endpoint with scope-based claims (`profile`, `email`, `phone`, `address`) | 0.1 | P0 |
| OIDC-10 | Token introspection (RFC 7662) and revocation (RFC 7009) | 0.2 | P0 |
| OIDC-11 | Signing algorithms: RS256 (required by OIDC), ES256, Ed25519 (using the current fully-specified algorithm name rather than the deprecated `EdDSA`) | 0.2 | P1 |
| OIDC-12 | RP-initiated logout and back-channel logout (P0); front-channel logout (P2) | 0.3 | P0 |
| OIDC-24 | Authorization response includes the `iss` parameter (RFC 9207) | 0.1 | P0 |
| OIDC-25 | Response modes `query` and `form_post` | 0.2 | P0 |
| OIDC-13 | Consent: per-client skip for first-party apps; remembered consent; revocable by the user | 0.2 | P0 |
| OIDC-14 | `prompt` (`none`, `login`, `consent`, `select_account`, `create`), `max_age`, `login_hint`, `acr_values` | 0.3 | P0 |
| OIDC-15 | Access tokens as RFC 9068 JWTs or opaque (configurable per client); audience-restricted | 0.2 | P0 |
| OIDC-16 | Resource indicators (RFC 8707) | 0.3 | P0 |
| OIDC-17 | Dynamic client registration (RFC 7591/7592) with policy: disabled / allow-listed / open | 0.4 | P1 |
| OIDC-18 | Pushed authorization requests (RFC 9126) | 1.0 | P1 |
| OIDC-19 | Device authorization grant (RFC 8628) | 1.x | P1 |
| OIDC-20 | Token exchange (RFC 8693) | 1.x | P1 |
| OIDC-21 | DPoP (RFC 9449) sender-constrained tokens | 2.0 | P1 |
| OIDC-22 | FAPI 2.0 security profile | 3.0 | P2 |
| OIDC-23 | Pass the OpenID conformance suite in CI (self-hosted suite) for the Basic OP, Config OP, Form Post, RP-Initiated Logout and Back-Channel Logout profiles; file for certification at 1.0. Implicit and hybrid flows are intentionally not supported | 1.0 | P0 |

### 8.2 Authentication and self-service (`AUTH`)

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| AUTH-1 | Password login with Argon2id hashing; configurable policy; breached-password check (k-anonymity range API, can be turned off for air-gapped use) | 0.1 | P0 |
| AUTH-2 | Self-service registration (can be disabled or invite-only) with email verification | 0.1 | P0 |
| AUTH-3 | Account recovery by email link or code; recovery never reveals whether an account exists | 0.1 | P0 |
| AUTH-4 | Passkeys / WebAuthn: register, log in (including usernameless / discoverable), manage; signature counter and clone detection | 0.2 | P0 |
| AUTH-5 | TOTP with recovery codes | 0.2 | P0 |
| AUTH-6 | Email OTP and magic link | 0.3 | P1 |
| AUTH-7 | Social login: Google, Apple, Microsoft, GitHub, plus generic OIDC and OAuth 2 | 0.3 | P0 |
| AUTH-8 | MFA policy per tenant / organization / client: off, optional, required; step-up via `acr_values` | 0.3 | P0 |
| AUTH-9 | Brute-force protection: per-account and per-IP throttling, progressive delays, temporary lockout; CAPTCHA integration (Turnstile, hCaptcha) | 0.2 | P0 |
| AUTH-10 | Sessions: list and revoke own sessions; idle and absolute timeouts; admin revoke | 0.2 | P0 |
| AUTH-11 | Account linking of upstream identities, only on verified email or explicit user confirmation | 0.3 | P0 |
| AUTH-12 | SMS OTP through pluggable providers | 2.0 | P2 |
| AUTH-14 | Custom user attributes defined per tenant with JSON Schema (type, required, validation, which attributes the user can edit, which are emitted as claims) | 0.4 | P1 |
| AUTH-13 | Account page: profile, email change with re-verification, password, passkeys, MFA, sessions, connected apps | 0.3 | P0 |

### 8.3 Login UI and branding (`UI`)

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| UI-1 | Built-in login, registration, recovery, consent, MFA and account pages, served by the binary with no external assets required | 0.1 | P0 |
| UI-2 | Accessible (WCAG 2.2 AA), responsive, works without JavaScript for the core password flow | 0.2 | P0 |
| UI-3 | Theming without a template language: logo, colors, fonts, radius, custom CSS, editable live from the console; per-tenant, per-org and per-client overrides | 0.3 | P0 |
| UI-4 | Internationalization with community-contributed translations; language from `ui_locales` or the browser | 0.3 | P1 |
| UI-5 | Headless mode: a documented, versioned flow API so SPAs and native apps can render their own UI. Each flow step describes its form (fields, types, messages) in the API response, so a client renders it generically instead of hardcoding screens. The built-in UI uses the same flow engine | 1.0 | P1 |
| UI-8 | Delegated login and consent: a tenant can point login and consent to an external app it hosts, which accepts or rejects the request through the management API (for teams that need full control) | 2.0 | P2 |
| UI-6 | Embeddable web components for login and account management | 2.0 | P2 |
| UI-7 | Email templates editable per tenant; SMTP configuration with a test-send | 0.2 | P0 |

### 8.4 Tenants, organizations and roles (`ORG`)

AnvilID uses two levels. A **tenant** is a fully isolated identity domain: its own issuer, users, clients and
keys. An **organization** is a group of users *inside* a tenant: a customer company of a B2B app.

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| ORG-1 | Multiple tenants per installation, each with its own issuer URL (path- or host-based) and isolated data | 0.1 (data model), 0.4 (UI) | P0 |
| ORG-2 | Organizations within a tenant: membership, invitations, org-scoped roles, organization claim in tokens, organization switcher | 1.0 | P0 |
| ORG-3 | Per-organization enterprise SSO connections (SAML 2.0 SP and OIDC RP) with JIT provisioning | 1.0 | P0 |
| ORG-4 | Home-realm discovery by email domain; domain verification with a DNS TXT record | 1.0 | P0 |
| ORG-5 | Roles and permissions (RBAC) at tenant and organization level, emitted as token claims | 0.4 | P0 |
| ORG-6 | Self-service SSO/SCIM setup portal: a shareable link for the customer's IT admin | 2.0 | P1 |

### 8.5 Administration, API and operations (`ADM`)

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| ADM-1 | Management REST API covering every console action, described with OpenAPI 3.1; authenticated with OAuth tokens (client credentials) and fine-grained admin scopes | 0.1 | P0 |
| ADM-2 | Admin console: tenants, users, clients, organizations, connections, branding, keys, sessions, audit log | 0.2–1.0 | P0 |
| ADM-3 | First-run bootstrap: on an empty database, print a one-time setup URL to create the first admin (with a passkey or password). No default credentials | 0.1 | P0 |
| ADM-4 | Audit log of every security-relevant event and admin action; queryable in the console; also streamed as structured JSON to stdout or a webhook | 0.2 | P0 |
| ADM-5 | Signed, retried webhooks for user and session lifecycle events | 0.4 | P1 |
| ADM-6 | Declarative configuration: import/export a tenant (clients, connections, branding, roles) as YAML; idempotent apply for GitOps | 0.4 | P1 |
| ADM-7 | CLI (`anvilid`) for serve, migrate, backup/restore, import/export, key rotation, admin recovery | 0.1+ | P0 |
| ADM-8 | User import with password hashes (bcrypt, scrypt incl. the Firebase variant, PBKDF2, Argon2, salted SHA-2), with guides for common source providers | 1.0 | P0 |
| ADM-12 | Importers for other self-hosted platforms: Keycloak realm exports, Ory Kratos identities and Ory Hydra clients | 1.x | P1 |
| ADM-9 | User export (per user and bulk), including the GDPR data-subject export | 1.0 | P0 |
| ADM-10 | Terraform provider | 2.0 | P1 |
| ADM-11 | Admin impersonation, audited and visible to the user | 2.0 | P2 |

### 8.6 Machine and agent identity (`AGT`)

| ID | Requirement | Phase | Pri |
|---|---|---|---|
| AGT-1 | MCP-compliant authorization server: RFC 8414 metadata, RFC 8707 resource indicators, audience-bound tokens, and documentation for publishing Protected Resource Metadata (RFC 9728) from resource servers | 0.4 | P0 |
| AGT-2 | Client ID Metadata Documents (URL-based client IDs) with policy controls (the client onboarding method the MCP specification prefers over dynamic registration) | 0.4 | P0 |
| AGT-3 | Consent screen that clearly identifies agent clients and requested scopes; incremental scope step-up | 1.0 | P1 |
| AGT-4 | Token exchange for delegation (on-behalf-of) and identity assertion grants for enterprise-managed agent access | 2.0 | P1 |
| AGT-5 | Agents as first-class principals (owner, expiry, scopes, audit trail) | 2.0 | P2 |
| AGT-6 | API keys (per user and per organization), scoped and revocable | 2.0 | P1 |

### 8.7 Later-phase modules (requirements summarized; detailed specs written when the phase starts)

| ID | Requirement | Phase |
|---|---|---|
| DIR-1 | SCIM 2.0 server per organization (inbound users and groups from corporate IdPs) | 2.0 |
| DIR-2 | LDAP read-only facade for legacy apps (bind and search over AnvilID users and groups) | 2.0 |
| SAML-1 | SAML 2.0 IdP (Web SSO profile, Redirect/POST bindings, signed assertions, metadata) | 2.0 |
| GW-1 | Forward-auth endpoint compatible with Traefik, Caddy and Nginx `auth_request` | 2.0 |
| GW-2 | Identity-aware reverse proxy with rule-based access | 3.0 |
| PERM-1 | Embedded relationship-based authorization engine with schema, check, expand and list APIs; the check API is designed to be compatible with existing Zanzibar-style APIs (Ory Keto / OpenFGA) to ease migration | 3.0 |
| PERM-2 | Policy-based (ABAC) conditions on top of relationships | 3.0 |
| EXT-1 | Synchronous extension points (pre-registration, post-login, token claims) through HTTP callouts, then sandboxed WASM | 2.0 |
| SEC-1 | Shared Signals Framework (CAEP/RISC) transmitter and receiver | 3.0 |
| SEC-2 | Risk-based adaptive MFA | 3.0 |

## 9. Non-functional requirements

### 9.1 Deployment and operations

- **NFR-OPS-1:** One statically linked binary for Linux (amd64, arm64) and macOS; an official container
  image under 50 MB.
- **NFR-OPS-2:** Embedded SQLite storage by default; PostgreSQL for production and HA. No other
  required runtime dependency.
- **NFR-OPS-3:** Horizontally scalable: instances are stateless apart from the database. Multiple
  instances on one Postgres work without extra coordination services.
- **NFR-OPS-4:** Database migrations run automatically at startup (can be turned off), are tested
  between consecutive minor versions, and are never destructive without an explicit flag.
- **NFR-OPS-5:** Configuration through environment variables or a single file. Every value has a
  default; the only value expected in production is the public URL.
- **NFR-OPS-6:** Correct behavior behind reverse proxies (trusted-proxy configuration for forwarded
  headers).
- **NFR-OPS-7:** Built-in online backup and restore (SQLite snapshot; Postgres guidance).
- **NFR-OPS-8:** Health (`/health/live`, `/health/ready`), Prometheus metrics, OpenTelemetry traces,
  structured JSON logs.
- **NFR-OPS-9:** Helm chart and Docker Compose examples maintained in-repo.

### 9.2 Security

- **NFR-SEC-1:** Follow the OAuth 2.0 Security BCP (RFC 9700) and OAuth 2.1 requirements by default.
- **NFR-SEC-2:** Signing keys generated at first start, stored encrypted at rest with a key-encryption
  key from configuration or the environment, and rotated on a schedule with overlap.
- **NFR-SEC-3:** All secrets (client secrets, recovery codes, API keys) are stored hashed; TOTP seeds and
  upstream IdP secrets are encrypted.
- **NFR-SEC-4:** CSRF protection on every state-changing browser endpoint; secure, `HttpOnly`,
  `SameSite` cookies; strict CSP on built-in pages.
- **NFR-SEC-5:** Rate limiting on all authentication and token endpoints, on by default.
- **NFR-SEC-6:** No test-only behavior compiled into release builds.
- **NFR-SEC-7:** Dependency auditing (`cargo audit` / `cargo deny`) and fuzzing of parsers (JWT, SAML,
  SCIM filters) in CI.
- **NFR-SEC-8:** Published security policy, coordinated disclosure, CVEs fixed in the open-source
  release immediately.

### 9.3 Quality

- **NFR-Q-1:** Each security requirement in §8 has an automated test proving that bad input is
  rejected.
- **NFR-Q-2:** The OpenID conformance suite runs in CI.
- **NFR-Q-3:** The same test suite runs against SQLite and Postgres.
- **NFR-Q-4:** Public APIs are versioned; breaking changes only in major versions with a migration
  guide.

## 10. Release plan (summary)

| Release | Theme | Headline scope |
|---|---|---|
| **0.1 "First login"** | Minimum credible OIDC provider | Auth code + PKCE, refresh rotation, client credentials, discovery/JWKS/UserInfo, password login, registration, recovery, built-in UI, bootstrap admin, management API, SQLite and Postgres |
| **0.2 "Secure by default"** | Hardening and modern auth | Passkeys, TOTP, introspection/revocation, consent, sessions, brute-force protection, audit log, ES256/EdDSA, email templates |
| **0.3 "Real-world logins"** | Federation and polish | Social login, account linking, MFA policy, logout profiles, theming, i18n, account page, resource indicators |
| **0.4 "Operate it"** | Operators and integrators | Multi-tenant console, RBAC, webhooks, declarative config, DCR, MCP authorization basics |
| **1.0 "Credible for business"** | B2B and certification | Organizations, per-org SAML/OIDC SSO, home-realm discovery, password-hash import, PAR, headless flow API, OpenID certification, external security review |
| **2.0 "Competitive"** | Directory and extensibility | SCIM, LDAP facade, SAML IdP, forward-auth, self-service SSO portal, extension hooks, token exchange, DPoP, API keys, Terraform |
| **3.0 "Suite"** | Authorization and advanced security | Permissions engine, identity-aware proxy, Shared Signals, adaptive MFA, FAPI 2.0 |

Detailed milestones, exit criteria and dependencies are in [ARCHITECTURE.md](ARCHITECTURE.md).

## 11. Licensing and sustainability

- Everything in this repository is MIT licensed. Contributions use the Developer Certificate of
  Origin, not a CLA.
- No feature is withheld from the open-source binary.
- Possible future revenue (outside this repository): managed hosting, support SLAs, long-term-support
  builds, compliance packages.

## 12. Risks and open questions

| # | Risk / question | Mitigation / decision owner |
|---|---|---|
| R1 | Scope is very large; the suite vision can dilute 1.0 quality | Hard phase gates; nothing ships without exit criteria met; later modules are specified only when their phase starts |
| R2 | A security flaw in an identity product is existential | Security rules in CLAUDE.md, conformance suite in CI, fuzzing, external review before 1.0 |
| R3 | SAML is notoriously hard to implement safely (XML signature wrapping) | SAML SP in 1.0 uses a vetted library and a dedicated test corpus of known attacks; SAML IdP deferred to 2.0 |
| R4 | Supporting SQLite and Postgres from one codebase limits SQL features | Restrict queries to a portable subset; both backends tested in CI (see ARCHITECTURE.md) |
| R5 | Embedded SQLite cannot be shared across instances | Documented: SQLite is single-instance; HA requires Postgres |
| Q1 | Should tenants be path-based (`/t/{tenant}`) or host-based by default? | Decided: path-based by default, host-based optional (ARCHITECTURE.md D1) |
| Q2 | Should we file additional certification profiles (Dynamic OP after DCR, FAPI 2.0 later) beyond the 1.0 set? | Decide after the 1.0 certification |
