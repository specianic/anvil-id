# Phase 3: Release 0.2 "Secure by default" - Context

**Gathered:** 2026-11-25
**Status:** Ready for research (planning waits for Phase 2)
**Source:** docs/ARCHITECTURE.md and docs/PRD.md — decisions there are locked

<domain>
## Phase Boundary

Hardening and modern authentication on top of 0.1: passkeys (incl. usernameless) via webauthn-rs,
TOTP + recovery codes, introspection (RFC 7662) and revocation (RFC 7009), consent screen with
remembered/revocable consent, `form_post` response mode, RS256/ES256/Ed25519 signing with scheduled
key rotation and JWKS overlap, opaque-vs-JWT access tokens per client, brute-force protection and
rate limiting (one keyed limiter, governor), sessions list/revoke with idle/absolute timeouts, trusted
proxy handling, WCAG 2.2 AA login pages, editable email templates + SMTP test send, audit log, admin
console v1 (React + Vite SPA embedded in the binary; users, clients, sessions, audit), migration
upgrade test 0.1 → 0.2 and destructive-migration guard.
</domain>

<decisions>
## Implementation Decisions (locked)

- webauthn-rs 0.6; challenge state server-side only; signature counter / clone detection
- totp-rs; encrypted seed; last-used time step stored to prevent replay; recovery codes hashed
- Rate limiting per ARCHITECTURE.md §11: route classes auth/token/admin/default; per IP + per account; progressive delays, not permanent locks; dummy hash for unknown users
- Key rotation job per §8.1/§14 with job_lease; kid = RFC 7638 thumbprint; Ed25519 uses the fully-specified algorithm name
- Admin console per D3: React + TypeScript + Vite static SPA, TanStack Router/Query, shadcn/ui, TanStack Table; types generated from the OpenAPI spec (openapi-typescript); embedded with rust-embed at /console/* per §10.4; it is a public OAuth client of the `system` tenant
- Audit log per §6.1 `audit_event`, typed events emitted by core services; queryable via management API; mirrored to stdout
- Accessibility: axe audit in Playwright e2e
- Migrations expand/contract per §7.3; CI upgrade test N-1 → N

### Claude's Discretion
- Plan decomposition and wave structure; console page layout
</decisions>

<deferred>
## Deferred Ideas
- Social login, email OTP/magic link, MFA policy, logout profiles, theming, i18n — Phase 4
</deferred>

---
*Phase: 03-release-0-2-secure-by-default — context from ARCHITECTURE.md/PRD.md*
