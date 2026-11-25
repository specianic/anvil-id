# Phase 2: Release 0.1 "First login" - Context

**Gathered:** 2026-11-25
**Status:** Ready for research (planning waits for Phase 1 spike results)
**Source:** docs/ARCHITECTURE.md and docs/PRD.md — decisions there are locked

<domain>
## Phase Boundary

First usable release: zero-config binary, spec-correct OIDC provider (auth code + PKCE S256, refresh
rotation with reuse detection, client credentials, discovery/JWKS/UserInfo, RFC 9207 `iss`), password
login + self-registration + email verification + recovery through built-in server-rendered pages,
bootstrap setup URL, management API for tenants/clients/users, both SQLite and Postgres, Basic OP and
Config OP conformance plans passing in CI, sample app in `examples/`.

Builds on Phase 1's workspace, storage contract suite and CI.
</domain>

<decisions>
## Implementation Decisions (locked)

- Protocol logic in `anvil-core` as pure services (AuthorizeService, TokenService, ClientAuthenticator, FlowEngine, SessionService, KeyService) per ARCHITECTURE.md §5; handlers in `anvil-web` contain no business logic; CoreError maps deterministically to OAuth errors
- Data model per ARCHITECTURE.md §6.1 (subset needed for 0.1); secrets storage per §6.2 (SHA-256 of 256-bit random for codes/tokens/secrets/session IDs; Argon2id passwords; AES-256-GCM with HKDF-derived keys from KEK for private keys)
- Atomic contracts per §7.1: consume_code single statement; rotate_refresh one transaction with family revocation on reuse; unique-index user creation; jti replay guard
- Keys: per-tenant RS256 (RSA-2048) via aws-lc-rs, kid = RFC 7638 thumbprint, next/active/retired lifecycle (rotation job can come in Phase 3, but the model exists now)
- Tokens per §8.2: code 60 s; ID token 1 h; access token RFC 9068 JWT by default (D2 decided), 10 min; refresh opaque, rotated, 30 d absolute / 14 d idle
- Flow engine per §9: explicit state machines, form descriptions rendered by minijinja templates; password flow works without JS; flow cookie + CSRF token
- Tenancy per §12 (D1 decided): host match → `/t/{slug}` → default tenant; issuer computed in one function; `system` tenant for admin API
- Management API per §10.3: `/api/admin/v1`, OAuth client-credentials tokens with admin scopes, OpenAPI 3.1 via utoipa
- Bootstrap per §13: zero-config `anvilid serve` → `./anvilid-data/`, 127.0.0.1:8080, dev-mode warnings, generated KEK, one-time `/setup?token=` URL, no default credentials
- Security controls per §11 with one negative test each (CLAUDE.md rule)
- Email: lettre via an outbox table; in tests use a capturing transport implemented in test code only
- Conformance suite (pipeline from Phase 1) must pass Basic OP + Config OP

### Claude's Discretion
- Sample app language/framework in `examples/` (any small standard OIDC RP)
- Plan decomposition and wave structure
</decisions>

<deferred>
## Deferred Ideas
- Passkeys, TOTP, introspection/revocation, consent screen, form_post, ES256/Ed25519, rate limiting, audit log UI — Phase 3
- Admin console UI — Phase 3+
</deferred>

---
*Phase: 02-release-0-1-first-login — context from ARCHITECTURE.md/PRD.md*

## Decisions after research (2026-11-25)

- **C1 PKCE (user decision):** per-client `require_pkce`, default true; only confidential clients may disable it, and then `nonce` is mandatory for `openid` requests. `plain` always rejected; downgrade defense (challenge sent ⇒ verifier required). PRD OIDC-1 and ARCHITECTURE §11 updated.
- **C2 prompt/max_age:** the minimal subset Basic OP needs moves into 0.1: `prompt=none` (with `login_required` error), `prompt=login`, `max_age`, `id_token_hint`, login-session reuse. The rest of OIDC-14 (`select_account`, `create`, `acr_values` step-up) stays in Phase 4.
- **C3 crate cycle:** storage port traits and their domain types live in `anvil_core::ports`; `anvil-storage` holds the contract suite (applied in Phase 1 plans).
- **C4 discovery paths:** serve both forms for path tenants: OIDC `{issuer}/.well-known/openid-configuration` and RFC 8414 `/.well-known/oauth-authorization-server/t/{slug}` (inserted form).
- **C5 HTTPS in conformance CI:** use AnvilID's own rustls listener with a certificate generated at CI time in a temp dir (no extra proxy dependency; exercises our TLS path).
- **C6 test placement:** `anvil-web` may dev-depend on concrete storage crates so HTTP/security tests run on both backends; dependency rules apply to normal deps only.
- **Q2 admin credentials in 0.1:** the setup page creates the first admin user and displays a one-time management API client credential (client credentials, admin scopes).
- **Q5/Q6:** planner's discretion, documented in the plan: password login `amr=["pwd"]`; access-token `aud` = the client_id until resource indicators (Phase 4).
