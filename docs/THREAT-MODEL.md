# Threat model

This document names what AnvilID protects, where trust changes hands, who is assumed to attack it,
and which controls defend each boundary. Each control points to its **control group** in the QUAL-01
security map, `scripts/check-security-tests.sh` (run with `just security-tests`). A group is the part of
the map's `control` label before the first colon, or the whole label when it has no colon (for
example `redirect`, `pkce`, `saml corpus (D4)`, `id token claims`); every row of a group names a negative test that proves the control rejects bad input. The
control specification itself is `docs/ARCHITECTURE.md` §11.

It deliberately contains no exploit details. It is an input to the external review
([SECURITY-REVIEW-SCOPE.md](SECURITY-REVIEW-SCOPE.md)); vulnerabilities are reported as described
in [SECURITY.md](https://github.com/specianic/anvil-id/blob/main/SECURITY.md).

**Phase 7 controls** (pushed authorization requests, the headless flow API, password import, user
export, agent consent) are listed per boundary and marked **mapped at the 07-23 gate**: their tests are
added to the security map by the 1.0 release-candidate gate, which is the version under review.

## Assets

| Asset | Why it matters |
| --- | --- |
| Signing private keys (per tenant) | Forge ID tokens and access tokens for every relying party of the tenant |
| The key-encryption key (KEK) | Opens every sealed secret: signing keys, TOTP seeds, upstream, SMTP, CAPTCHA and webhook secrets, outbox payloads |
| User credentials | Passwords (Argon2id, imported legacy hashes until first login), passkeys, TOTP seeds, recovery codes |
| Sessions and tokens | Browser sessions, authorization codes, refresh-token families, access tokens, PAR `request_uri`s, flow tokens |
| Client credentials | Client secrets (hashed), registration and initial access tokens, `private_key_jwt` keys |
| Admin authority | Management clients, admin scopes and roles, org-admin principals, the setup token, local admin recovery |
| Personal data | Profiles and custom attributes, emails, linked identities, consents, sessions, audit entries |
| Tenant and organization boundaries | Data, keys, cookies and admin authority of one tenant or organization must not reach another |
| Availability | Login and token issuance for every application that depends on AnvilID |
| Release artefacts | Binaries, container image and attestations that operators install |

## Attacker models

| Attacker | Capabilities assumed |
| --- | --- |
| Anonymous internet user | Sends arbitrary HTTP requests to every public endpoint, at volume, from many IPs; controls their own browser |
| Malicious web site | Makes a victim's browser send cross-site requests, frames pages, opens popups, runs script on its own origin |
| Malicious or compromised relying party | Holds valid client credentials; crafts authorization, PAR, token and logout requests; may register itself through DCR or CIMD where the tenant allows it |
| Malicious agent client | A self-registered or CIMD-identified automated client that asks for broad or escalating scopes |
| Authenticated end user | Has a valid account and session in one tenant; tries to reach other users, tenants or organizations, or escalate |
| Malicious upstream or SAML IdP | Returns crafted discovery documents, tokens, profiles, metadata or SAML responses; or an attacker who replays or alters responses in transit to the browser |
| Compromised tenant or org administrator | Holds admin or org-admin authority in one scope; tries to escalate to the installation, another tenant or another organization |
| Network position near outbound targets | Controls DNS answers or URLs that AnvilID is asked to fetch (CIMD, webhooks, upstream discovery, SAML metadata) |
| Holder of a database or backup copy | Reads the database or a backup file without the KEK |
| Supply-chain attacker | Publishes a malicious or vulnerable dependency, or tampers with release artefacts after the build |

Out of the model: an attacker with the KEK and the database together, root on the host, or control of
the operator's own infrastructure (PostgreSQL, Redis, SMTP, proxy) is not defended against beyond the
hardening noted below.

## Trust boundaries

### 1. Browser to the hosted UI (login, registration, recovery, account, consent pages)

Attackers: anonymous user, malicious web site, authenticated end user.

Controls and their map groups:

- CSRF synchronizer token and Fetch-Metadata/Origin checks: `csrf`, `303 after a credential POST`.
- Cookies (`__Host-`, `Secure`, `HttpOnly`, `SameSite`, per-tenant names): `cookies`.
- Strict CSP, `frame-ancestors`, HSTS, `Referrer-Policy`, `no-store`: `headers`, `cache`.
- Theme CSS validator and logo checks: `theme`.
- Enumeration resistance: `enumeration`, `identifier-first`, `routed domains`, `domain rules`.
- Brute force, lockout, CAPTCHA, client IP behind proxies: `brute force`, `captcha`, `trusted proxies`,
  `rate limit`, `limiter`.
- Factors and MFA: `passkey`, `passkey second factor`, `passkey enrolment`, `passkey picker`, `totp`,
  `recovery code`, `second factor`, `mfa policy`, `step-up`, `email code`, `org MFA`.
- Sessions and account pages: `sessions`, `session switch`, `account`, `account pages`, `credentials`,
  `email change`.
- Consent: `consent`, `resources`.
- First-run setup and invitations: `setup`, `invitations`, `return-to`.
- Body limits: `body limit`.
- Agent consent (agent marker, provenance, incremental step-up, agents never skip consent):
  **mapped at the 07-23 gate**.

### 2. Relying party to the protocol endpoints

Attackers: malicious relying party, anonymous user, malicious agent client.

- Redirect URI exact match before any redirect: `redirect`.
- PKCE S256 and the downgrade defence: `pkce`.
- Authorization code single use, expiry and binding: `code`.
- Client authentication and assertions: `client auth`, `private_key_jwt`, `static clients`,
  `secrets hashed at rest (SQLite)`, `secrets hashed at rest (Postgres)`.
- Response and grant restrictions: `no implicit / hybrid response types`, `no ROPC / unknown grants`,
  `request objects`, `form_post`, `iss in authorization responses (RFC 9207)`, `login hint`.
- Tokens: `id token alg`, `id token at_hash`, `id token claims`, `refresh`, `client credentials`,
  `bearer`, `jws`, `introspection`, `revocation`, `claims`, `org claims`.
- Logout: `logout`, `back-channel`.
- Dynamic registration and CIMD: `dcr`, `cimd`, `org:admin`.
- MCP-style resource access: `resources`, `mcp`.
- Rate limits on token-class routes: `rate limit`, `limiter`.
- Pushed authorization requests (client authentication, `request_uri` single use, lifetime and client
  binding, `require_pushed_authorization_requests`): **mapped at the 07-23 gate**.

### 3. Administrator to the management API and console

Attackers: compromised tenant or org administrator, authenticated end user, anonymous user.

- Admin scope and route coverage: `admin`, `admin v0.2`, `admin v0.3`, `admin v0.4`, `admin v1.0`,
  `admin audit`, `console`.
- RBAC (isolation, scope bounding, escalation, last administrator): `rbac`, `org roles`.
- Organization administration: `org-admin principal`, `orgs`, `org`, `org:admin`, `org switcher`,
  `org config`, `org branding`.
- Declarative configuration: `config`.
- Keys API and rotation: `keys API`, `key rotation`.
- Custom attributes and claim mapping: `attributes`, `claims`.
- Webhook management: `webhook`.
- Mail templates and SMTP test: `mail templates`, `smtp test`.
- Local admin recovery: `admin recover`.
- User import (floors, caps, idempotency, audit, no hash logging) and user export (allow-list
  redaction, GDPR export, CLI-only opt-in hash export): **mapped at the 07-23 gate**.

### 4. Headless SPA and native clients to the flow API

Attackers: malicious web site (against the browser mode), malicious relying party or third-party app
(against the native mode), anonymous user.

- The flow engine's existing controls apply unchanged (boundary 1: brute force, CAPTCHA, factors,
  enumeration), because the headless API drives the same engine.
- Browser mode (exact-origin allow-list, credentialed CORS only for those origins, CSRF header,
  JSON-only bodies, separate Fetch-Metadata variant): **mapped at the 07-23 gate**.
- Native mode (PAR-bound start, first-party admin-set flag never registrable through DCR or CIMD,
  hashed flow token, refusal of browser signals, one binding kind per flow): **mapped at the 07-23
  gate**.

### 5. Upstream identity providers and SAML IdPs to AnvilID

Attackers: malicious upstream or SAML IdP, response tampering through the browser.

- Upstream OIDC and social sign-in (state, binding cookie, nonce, `iss`, ID token validation,
  verified-email rules): `upstream`, `connections`, `org connections`.
- Account linking and unlinking: `linking`, `cross-org email trust`, `org JIT`.
- Domain verification and routing: `domain`, `domain verification`, `domain rules`, `routing guards`,
  `routed domains`.
- SAML response verification, the signature-wrapping corpus and the XML adapter: `saml corpus (D4)`,
  `saml adapter`.
- SAML conditions, replay and flow binding: `saml conditions`, `saml flow`, `saml replay`,
  `saml request`, `saml connections`.

SAML stays behind the operator flag `saml_experimental` (off by default) through 1.0; see
[SAML.md](SAML.md).

### 6. AnvilID to outbound destinations (SSRF)

Attackers: anyone who can make AnvilID fetch a URL (relying parties through CIMD, administrators
through webhooks, upstream and SAML metadata configuration), network position over DNS.

- The guarded outbound client: `ssrf`.
- Per-feature use of it: `cimd`, `webhook`, `upstream`, `captcha`, `org connections`.
- Fetch budgets and limits: `cimd`, `limiter`.

### 7. Storage, backups and the KEK

Attackers: holder of a database or backup copy, authenticated users across tenants.

- Tenant isolation in every repository method: `tenant isolation`, `credentials`.
- Secrets hashed or sealed at rest: `secrets hashed at rest (SQLite)`, `secrets hashed at rest
  (Postgres)`, `release 1.0 secrets at rest`, `connections`, `webhook`.
- Secret hygiene in output: `secret hygiene`, `telemetry`.
- Single-winner state changes under concurrency: `code`, `jobs`, `invitations`, `setup`.
- Migrations and backup/restore: `migrations`, `backup`.

Released-migration immutability is enforced by `scripts/check-migrations.sh` rather than the map.

### 8. Operator and CLI

Attackers: a local user without operator rights, a mistaken operator, a compromised configuration
source.

- Configuration display and redaction: `secret hygiene`, `config`.
- Healthcheck restricted to loopback: `healthcheck`.
- Local admin recovery and setup: `admin recover`, `setup`.
- Backup and restore guards: `backup`.
- Destructive-migration guard: `migrations`.

### Supply chain (cross-cutting)

Attackers: supply-chain attacker.

These controls are scripts and CI checks, not unit tests, and are listed in the map header as
"deliberately not mapped":

- Test code kept out of the release binary: `scripts/check-release-graph.sh`.
- One aws-lc-rs/aws-lc-sys version: `scripts/check-deps.sh`.
- Dependency policy (advisories, licences, sources, banned crates and scoped exceptions such as
  the SAML `chrono` exception): `deny.toml` (`just deny`).
- Release integrity: pinned actions, checksums and build-provenance attestations in
  `.github/workflows/release.yml` (`docs/RELEASING.md`).
- Parsers exposed to untrusted input are fuzzed: `fuzz/fuzz_targets/`.

Browser-level journeys are covered by the Playwright specs in `tests/e2e/specs` and the OpenID
conformance plans in `tests/conformance`, as the map header describes.

## Residual risks accepted for 1.0

- SAML is experimental and off by default until the external review and the real-IdP interop
  checklist are complete.
- Imported accounts can be slower to verify than native ones until their first login rehashes them.
- A CAPTCHA provider's script runs on the CAPTCHA page when an operator enables it.
- KEK rotation is not supported; losing the KEK makes sealed data unrecoverable, and an attacker with
  both the KEK and the database can open sealed secrets.
- Denial of service by traffic volume is mitigated by rate limits but not prevented.
