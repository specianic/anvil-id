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

- [ ] **Phase 1: Foundations and Spikes (M0)** - Workspace, CI and the three stack spikes (dual storage, static binary, conformance in CI)
- [ ] **Phase 2: Release 0.1 "First login"** - Zero-config binary with spec-correct auth code + PKCE, refresh, client credentials, password login and bootstrap admin
- [ ] **Phase 3: Release 0.2 "Secure by default"** - Passkeys, TOTP, consent, sessions, brute-force protection, audit log, introspection/revocation, key rotation, admin console v1
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
- [ ] 01-01-PLAN.md — Workspace skeleton, toolchain, Cargo.lock, storage ports in anvil-core, justfile (wave 1)
- [ ] 01-02-PLAN.md — cargo-deny policy, dependency-rule checker + self-test, ci.yml (wave 2)
- [ ] 01-03-PLAN.md — Spike A: shared contract suite + SQLite backend + .sqlx (wave 2)
- [ ] 01-04-PLAN.md — anvil-web router (discovery, assets, 501s) + `anvilid serve` with mimalloc (wave 2)
- [ ] 01-05-PLAN.md — Spike A: Postgres backend on testcontainers + duplication cost (wave 3)
- [ ] 01-06-PLAN.md — Spike C: conformance harness (Config OP plan, ratchet) + conformance.yml (wave 3)
- [ ] 01-07-PLAN.md — Spike B: storage wiring in anvilid, static musl build, size/RSS, release-build.yml (wave 4)
- [ ] 01-08-PLAN.md — Phase gate: `just ci`, push + CI green (checkpoint), spike verdicts (wave 5)

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
**Plans**: TBD

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
**Plans**: TBD

### Phase 4: Release 0.3 "Real-world logins"
**Goal**: AnvilID handles the login journeys real products need: social and passwordless sign-in, safe account linking, MFA policy and step-up, standard logout, and branded, translated pages
**Depends on**: Phase 3
**Requirements**: OIDC-12, OIDC-14, OIDC-16, AUTH-06, AUTH-07, AUTH-08, AUTH-11, AUTH-13, UI-03, UI-04, SEC-03
**Success Criteria** (what must be TRUE):
  1. OpenID conformance **RP-Initiated Logout** and **Back-Channel Logout** plans pass in CI
  2. Social login with Google, Apple, Microsoft, GitHub and a generic OIDC provider is tested against real providers in a staging environment; upstream identities link only on verified email or explicit confirmation, and upstream secrets are stored encrypted
  3. An admin edits theme settings in the console and sees the login pages change live; pages render in the language chosen from `ui_locales` or the browser
  4. A user can log in with email OTP or magic link, and manage profile, email, password, passkeys, MFA, sessions and connected apps from the account page
  5. Admin MFA policy (off/optional/required) is enforced per tenant and client, and clients can request step-up via `acr_values`, `prompt` and `max_age`, and audience-bound tokens via resource indicators
**Plans**: TBD

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
**Plans**: TBD

### Phase 6: Release 1.0 "Credible for business" (Organizations and SSO)
**Goal**: SaaS builders can serve business customers: organizations with members and roles, each able to bring its own SAML or OIDC identity provider, with users routed automatically by email domain
**Depends on**: Phase 5
**Requirements**: ORG-02, ORG-03, ORG-04, ADM-02
**Success Criteria** (what must be TRUE):
  1. A tenant admin creates an organization, invites members, assigns org-scoped roles, and the org claim appears in tokens; a user in several orgs can switch between them
  2. An organization admin configures an OIDC or SAML 2.0 connection and users log in through it with just-in-time provisioning; SAML stays flagged experimental unless it passes the signature-wrapping attack corpus (decision D4)
  3. After a domain is verified by DNS TXT record, a user entering an email on that domain is routed to the organization's IdP
  4. Every managed object (tenants, users, clients, organizations, connections, branding, keys, sessions, audit log) can be administered from the console
**Plans**: TBD

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
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundations and Spikes (M0) | 1/8 | In Progress|  |
| 2. Release 0.1 "First login" | 0/TBD | Not started | - |
| 3. Release 0.2 "Secure by default" | 0/TBD | Not started | - |
| 4. Release 0.3 "Real-world logins" | 0/TBD | Not started | - |
| 5. Release 0.4 "Operate it" | 0/TBD | Not started | - |
| 6. Release 1.0 (Organizations and SSO) | 0/TBD | Not started | - |
| 7. Release 1.0 (Certification and release) | 0/TBD | Not started | - |

---
*Roadmap created: 2026-11-25*
