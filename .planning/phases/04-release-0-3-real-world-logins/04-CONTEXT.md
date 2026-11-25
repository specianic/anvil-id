# Phase 4: Release 0.3 "Real-world logins" - Context

**Gathered:** 2026-11-25
**Status:** Ready for research
**Source:** docs/ARCHITECTURE.md, docs/PRD.md, ROADMAP Phase 4, user decisions

<domain>
## Phase Boundary

The login journeys real products need, on top of 0.2:
- Social login: Google, Apple, Microsoft, GitHub, plus generic OIDC and OAuth2 upstream providers (AUTH-07)
- Safe account linking: link upstream identities only on verified email or explicit confirmation (AUTH-11)
- Upstream IdP secrets encrypted at rest (SEC-03)
- Email OTP and magic link sign-in (AUTH-06)
- MFA policy off/optional/required per tenant/org/client; step-up via `acr_values` (AUTH-08)
- Full OIDC-14: `prompt` (incl. `select_account`, `create`), `max_age`, `login_hint`, `acr_values` (the minimal subset already shipped in 0.1)
- RP-initiated logout + back-channel logout (OIDC-12), conformance plans RP-Initiated Logout and Back-Channel Logout passing in CI
- Resource indicators (RFC 8707) → audience-bound access tokens (OIDC-16)
- Account page completeness: profile, email change with re-verification, password, passkeys, MFA, sessions, connected apps (AUTH-13)
- Theming editable live from the console with per-tenant/org/client overrides, no template language required (UI-03)
- i18n: pages translated, language from `ui_locales` or the browser (UI-04)
</domain>

<decisions>
## Implementation Decisions (locked)

- **Social provider testing (user decision 2026-11-25):** CI tests every provider adapter against local mock IdPs (wiremock-based mocks of each provider's endpoints/claims quirks, plus AnvilID itself running as a generic OIDC upstream in e2e). Real-provider testing is a documented manual pre-release checklist the owner runs with their own app registrations. No provider secrets in CI. Apple is in scope (adapter + mocks), real-Apple verification is part of the manual checklist.
- Apple Sign In specifics: client secret is an ES256 JWT signed with the team's private key (sealed with the KEK); ID token verified against Apple's JWKS (never skip signature validation); name/email only on first login.
- Upstream connections stored in the `connection` table (ARCHITECTURE §6.1 / §19 tagged enum: Social, Oidc, Saml later), tenant-scoped (org-scoped arrives in Phase 6); secrets sealed with the KEK (SEC-03); all outbound fetches (discovery, JWKS, token, userinfo) through the SSRF-guarded HTTP client with timeouts.
- Upstream OIDC flows use PKCE + state + nonce; ID tokens fully validated (iss, aud, exp, nonce, signature via the provider JWKS with caching); GitHub (OAuth2, no OIDC) uses the verified primary email from the API only.
- Account linking: automatic link only when the upstream asserts a verified email matching an existing account's verified email AND tenant policy allows auto-linking; otherwise the user must sign in to the existing account (password/passkey) to confirm the link. Never link on unverified email.
- Email OTP / magic link: single-use, short-lived, hashed at rest, rate limited via the one limiter, consumed only on POST (link scanners), no account enumeration; emails via sealed outbox payloads.
- MFA policy evaluated in core (pure function), enforced in the login flow; `acr_values` step-up re-prompts for the second factor; `amr`/`acr` reflect what happened.
- Logout: RP-initiated logout validates `id_token_hint` (any enabled alg), `post_logout_redirect_uri` exact-match against the client's registered list, `state` echoed; back-channel logout tokens (OIDC Back-Channel Logout) delivered by a leased background job with retries via the SSRF-guarded client; `sid` claim tracked per RP session (rp_session table).
- Resource indicators: `resource` parameter validated against client-allowed resources; access-token `aud` becomes the resource(s); default remains client_id when absent.
- Theming: tokens (logo, colors, fonts, radius, custom CSS) stored per tenant/org/client, rendered as CSS variables; custom CSS sanitized/served same-origin under the strict CSP; console editor with live preview.
- i18n: message catalogs (Fluent or JSON) embedded, community-contributable; English complete, plus at least one second language to prove the pipeline; selection: ui_locales > Accept-Language > tenant default.
- CLAUDE.md rules apply (no stubs, one implementation per concern, negative test per security control, storage only via traits, public repo hygiene).

### Claude's Discretion
- Exact plan decomposition and waves (maximize parallel plans with disjoint files; shared files in an early foundation plan)
- Mock IdP implementation approach; which second language
</decisions>

<deferred>
## Deferred Ideas
- Organizations and per-org SSO (Phase 6), SAML (Phase 6, experimental), front-channel logout (P2), SMS OTP (2.0)
</deferred>

---
*Phase: 04-release-0-3-real-world-logins*

## Decisions after research (orchestrator, 2026-11-25)

- **Back-channel logout timing:** the post-logout redirect does not wait for back-channel delivery; delivery is asynchronous via the leased job with retries.
- **UserInfo audience:** accept only access tokens whose `aud` includes the requesting client's `client_id` or `{issuer}/userinfo`; tokens audience-bound solely to another resource are rejected at UserInfo (`invalid_token`). (Only affects clients that request resources — a 0.3 feature.)
- **Unmet essential `acr`:** return `unmet_authentication_requirements` (OpenID Connect Unmet Authentication Requirements 1.0).
- **MFA policy precedence:** strictest wins across tenant / client (and org in Phase 6): `required` > `optional` > `off`.
- **`amr` values:** email OTP and magic link → `otp` (RFC 8176); social / upstream OIDC sign-in → `fed` (documented, not RFC 8176-registered); combined with a second factor → add `mfa` as today.
- **Apple PKCE:** treat as unsupported (don't send); verify in the manual real-provider checklist.
- **Theme preview for host-based tenants:** preview goes through the `/t/{slug}` path form (tenant resolution already supports it); the console preview uses it for every tenant.
- **UI-04 scope:** pages only; localized email templates are deferred (record in PRD/REQUIREMENTS notes as a later item).
- **`sid`:** equals the browser session id (already in 0.2 ID tokens); the separate `rp_session.sid` column from ARCHITECTURE §6.1 is dropped — sync the doc.
- **Docs:** ROADMAP Phase 4 success criterion 2 and ARCHITECTURE M3 exit criterion are reworded from "staging environment" to "mock IdPs in CI + manual real-provider checklist" (user decision).
- **Logout plan variant string:** confirm on the first harness run.
- **v0.3.0 release gate (user decision 2026-11-25):** the release plan (04-33) PAUSES before tagging until the owner runs `docs/social-login-checklist.md` against real providers or explicitly waives named items. Publishing after that checkpoint (tag + release workflow) is authorized, as for v0.1.0/v0.2.0.
