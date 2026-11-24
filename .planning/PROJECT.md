# AnvilID

## What This Is

AnvilID is an open-source (MIT) identity and access platform: an OAuth 2.1 / OpenID Connect provider
with built-in login UI, admin console, passkeys/MFA, organizations and enterprise SSO. It ships as one
binary that starts with zero configuration on embedded SQLite and scales out on Postgres. It is for SaaS
developers and platform engineers who want Keycloak-class coverage without Keycloak-class operational
weight, and it grows over time into a full identity suite (federation, directory, permissions, access
proxy) delivered as modules of the same binary.

Full product definition: [docs/PRD.md](../docs/PRD.md). Build plan: [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

## Core Value

**A standards-correct, secure OIDC provider that anyone can run in two minutes.** If everything else
fails, authorization code + PKCE login, token issuance and refresh must work exactly to spec, with every
security check enforced and tested, from a zero-config single binary.

## Requirements

Detailed requirements with stable IDs live in docs/PRD.md §8 and are mirrored into
`.planning/REQUIREMENTS.md` for roadmap traceability.

### Validated

(None yet — ship to validate)

### Active

- [ ] Authorization code + PKCE (S256 only), refresh rotation with reuse detection, client credentials
- [ ] Discovery, JWKS with key rotation, UserInfo, introspection, revocation, logout profiles
- [ ] Passes the OpenID conformance suite in CI; OpenID certification filed at 1.0
- [ ] Password, passkeys, TOTP, email OTP/magic link, social login, account recovery
- [ ] Built-in accessible, themeable login UI (server-rendered, works without JavaScript)
- [ ] Admin console (React) and a complete, OpenAPI-documented management API
- [ ] Multi-tenancy (path-based tenants), organizations, per-org SAML/OIDC SSO, home-realm discovery
- [ ] MCP-compliant authorization server basics (resource indicators, client ID metadata documents)
- [ ] User import with password hashes; declarative tenant config; audit log; webhooks
- [ ] Single static binary, zero-config start, SQLite default, Postgres for HA, boring upgrades

### Out of Scope

- Implicit grant, hybrid flow, resource-owner password grant, `plain` PKCE — deprecated by OAuth 2.1 / RFC 9700; not implemented at all
- Own clustering/consensus layer — HA is stateless nodes on Postgres; a custom replication engine is a multi-year investment
- Embedded scripting runtimes (JS/Python sandboxes) — extension points come later as HTTP callouts and WASM
- Workforce IGA (access reviews, app catalog provisioning, push-MFA app) — not the 1.0 audience
- Hosted cloud offering — possible future business, not part of this repository
- Feature paywalls or relicensing — MIT forever, everything in the open-source binary

## Context

- Greenfield rebuild. An earlier prototype was retired; no code or history is carried over.
- Market positioning: the gap between heavy full-featured self-hosted IdPs and lightweight-but-narrow
  ones. Differentiators: no SSO tax (unlimited orgs/SSO/SCIM free), single binary, boring upgrades,
  theming without a template language, MCP/agent readiness, migration importers.
- Standards baseline: OAuth 2.0 Security BCP (RFC 9700) and the OAuth 2.1 draft; OIDC Core/Discovery;
  RFC 9207 issuer identification; RFC 8707 resource indicators; MCP authorization specification.
- Delivery plan: milestones M0 (foundations and spikes) through M5 (1.0), defined with exit criteria in
  docs/ARCHITECTURE.md §18.

## Constraints

- **Tech stack**: Rust (edition 2024), axum 0.8, sqlx 0.9 (separate SQLite and Postgres implementations, no `sqlx::Any`), aws-lc-rs as the only crypto backend, jsonwebtoken 12, minijinja login templates, React + Vite admin console embedded in the binary — decided in docs/ARCHITECTURE.md §2
- **Banned dependencies**: openssl, native-tls, ring as second backend, RustCrypto `rsa` for private-key ops, chrono, samael/xmlsec, oxide-auth — security and static-build reasons
- **Deployment**: one statically linked binary (musl amd64/arm64); no required runtime dependency besides the database — core product promise
- **Security**: no test hooks or stubs in production paths; every security control has a negative test; atomic consumption of single-use artifacts — identity product, a flaw is existential
- **Quality**: same test suite on SQLite and Postgres; OpenID conformance suite in CI from M1
- **Public repository**: never commit secrets, keys, internal hostnames, personal data, or unverified claims about other products

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Rust over Go | Mature Rust libs for milestones 1–3; Kanidm/Rauthy prove viability; conditions in ARCHITECTURE.md §2.1 | — Pending (validated in M0) |
| SQLite default + Postgres for HA via two typed sqlx implementations | Zero-config start; compile-time-checked queries per dialect; contract test suite prevents drift | — Pending (M0 spike A) |
| Path-based tenants by default (`/t/{slug}`), host mapping optional | Works with zero DNS setup | ✓ Decided |
| JWT (RFC 9068) access tokens by default, opaque per client | Resource servers validate locally; opaque available when revocation immediacy matters | ✓ Decided |
| React + Vite static SPA admin console embedded in the binary | Best component ecosystem and contributor pool; dogfoods the management API | ✓ Decided |
| Login pages server-rendered (minijinja), overridable themes | Works without JS, strict CSP, theming without recompiling | ✓ Decided |
| SAML via pure-Rust XML-DSig, experimental until it passes an attack corpus | C xmlsec breaks the static binary; SAML is high-risk | — Pending (before M5) |

---
*Last updated: 2026-11-25 after initialization*
