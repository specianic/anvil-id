# External security review: scope and reviewer brief

This document defines the scope of the external security review that has to be completed before
AnvilID 1.0 (requirement SEC-08, PRD R2 and NFR-SEC-8). It is written for the reviewer and is public.
It describes surfaces, inputs and process only: it contains no findings, and findings are never
committed to this repository before their fixes ship (see [Findings handling](#findings-handling)).

The security policy for outside reporters is [SECURITY.md](../SECURITY.md). The assets, trust
boundaries, attacker models and the mapping of controls to tests are in
[THREAT-MODEL.md](THREAT-MODEL.md).

## Version to review

**The 1.0.0 release candidate tagged at the 07-23 gate.** Review that tag (source, the released
archives and the container image built from it). If fixes land during the review, the reviewer is
told which commits changed which surface.

Everything in the binary is in scope unless it is listed under [Out of scope](#out-of-scope).

## In-scope surfaces

### Protocol endpoints (OAuth 2.x / OpenID Connect)

- Discovery and JWKS (per tenant issuer, path-based and host-based tenants).
- `/authorize` (GET and POST): redirect URI exact match before any redirect, PKCE S256 only and the
  downgrade defence, `response_mode=form_post`, RFC 9207 `iss`, `prompt`/`max_age`, resource
  indicators (RFC 8707), refusal of implicit and hybrid response types and of request objects.
- `/token`: authorization code (single use, family revocation on reuse), refresh-token rotation,
  client credentials; client authentication (`client_secret_basic`, `client_secret_post`,
  `private_key_jwt` with `aud` = issuer only and jti replay guard, `none` for public clients).
- `/userinfo`, `/introspect`, `/revoke`.
- **Pushed authorization requests (RFC 9126, `/par`)**: client authentication as at `/token`,
  `request_uri` entropy, 60 s lifetime and single use, binding to the pushing client, refusal of a
  nested `request_uri`, the per-client `require_pushed_authorization_requests` policy and the
  re-check of client policy at use.
- **Dynamic client registration (RFC 7591/7592)**: tenant policy (disabled, allow-listed, open),
  initial and registration access tokens, redirect-host allow-list, refused metadata
  (`software_statement`, `jwks_uri`, `admin:*` scopes, `org:admin`), caps and rate limit.
- **Client ID Metadata Documents (CIMD)**: allow-list before any fetch, the guarded fetch (size, status,
  no redirects, budget), `client_id` equality, refused secrets and `jwks_uri`, unverified names on
  consent.
- RP-Initiated Logout and Back-Channel Logout (hint validation, post-logout URI match, confirmation
  CSRF, logout token claims, delivery worker).
- ID token and access token issuance: signing algorithms per tenant, claims, mapped claims never
  overriding protocol claims, the `org` claims and their re-check at refresh.

### Headless flow API (both modes)

The versioned JSON API under `/t/{slug}/api/flows/v1/` that drives the same flow engine as the
hosted pages.

- **Browser mode (SPA)**: per-tenant exact-origin allow-list, credentialed CORS only for those
  origins, the flow cookie plus a CSRF token in a custom header, JSON-only bodies, the separate
  Fetch-Metadata variant of the flows router (the UI router's layer must be unchanged).
- **Native mode (first-party apps)**: start only from a PAR `request_uri` bound to a client flagged
  for native headless use (admin-set, first-party, PKCE required, never settable through DCR or
  CIMD), the hashed flow token binding, refusal when browser signals are present, the code returned
  in JSON and redeemed with `code_verifier`, steps that require a browser.
- Both modes: no second implementation of throttling, CAPTCHA, lockout or session logic; flows bound
  to one binding kind; the OpenAPI document `flows-v1` matches the implementation.

### Flow engine, sessions and account pages

- Login, registration, recovery and verification flows; identifier-first and home-realm discovery;
  passkeys (registration, sign-in, second factor, in-flow enrolment), TOTP, recovery codes, email
  code and magic link; MFA policy and step-up; session switching.
- Session cookies, idle and absolute limits, session revocation and the revocation of the session's
  token families; the account pages (security settings, sessions, connected apps, email change).
- Enumeration resistance (login, recovery, registration, invitations, domain routing) and the
  dummy-hash path for unknown users.
- Consent, including **agent clients**: the agent marker and provenance display, incremental scope
  step-up (only new scopes prompted, a denied step-up keeps the existing grant), agents never
  skipping consent.
- Upstream sign-in (social and generic OIDC) and account linking.

### Password import verifiers and caps

- The legacy verifiers for imported hashes: bcrypt, scrypt (including the Firebase variant), PBKDF2,
  Argon2 (imported PHC strings) and salted SHA-2, all behind the one password hasher.
- Parameter **floors** (refused or flagged weak parameters, refused schemes and variants) and hard
  **caps** on memory, iterations and cost, enforced at import and again at verify, including for
  Argon2 parameters read from stored hashes; verification on the one bounded pool.
- Constant-time comparison; transparent rehash to Argon2id on first successful login with a
  compare-and-swap against concurrent password changes; idempotent, audited import; imported hashes
  never logged.
- The timing behaviour between schemes, and between unknown and known accounts.
- The crypto-policy exception for the legacy-hash crates (scoped in `deny.toml`, verification only),
  if the owner approved it (otherwise bcrypt/scrypt import is absent and documented).

### Export redaction

- Single-user, bulk (streamed, paginated) and GDPR data-subject export through the admin API and
  CLI: allow-list DTOs, no password hashes, sealed values, TOTP seeds, token hashes or other users'
  personal data; the opt-in, audited CLI-only password-hash export; authorization of every export
  route.

### Admin API and console authorization

- Admin tokens, scopes and RBAC (scope bounding by roles, escalation guard, last-administrator
  guard), org-admin principals (own-org routes only, per-request re-check, opaque tokens refused),
  the system tenant rules.
- Declarative tenant configuration (apply, export without secrets, no server-side file or
  environment reads, lockout guards), the keys API, audit log, webhooks management.
- The embedded console (a client of the admin API; its static assets and CSP).

### SAML SP (experimental)

SAML stays behind the operator flag `saml_experimental` (off by default) through 1.0. The flag is
removed only after this review and the real-IdP interop checklist in [SAML.md](SAML.md); the review
result is an input to that owner decision.

- The D4 signature-wrapping corpus (`security_saml.rs`, 67 cases in nine groups) and whether it is
  complete for the parser and verifier actually used.
- The strict profile pre-check before signature verification (pinned signature locations and
  references, structure, algorithm and transform allow-list), DTD and entity refusal, size, depth
  and markup caps.
- Conditions and subject confirmation, RelayState, `InResponseTo`, the binding cookie, the database
  replay guard (across instances), refusal of unsolicited, IdP-initiated, encrypted and transient
  NameID responses, claims taken only from the verified node.
- Metadata import (SSRF-guarded URL, trusted keys only).
- **The XML stack**: `bergshamra-dsig`, `bergshamra-keys` and `bergshamra-xml` for XML signatures
  on aws-lc-rs, `uppsala` as the only XML parser, and the adapter between them and AnvilID.
- **The `chrono` exception**: `chrono` enters only through `tsp-ltv` under `bergshamra-keys`; AnvilID
  code judges validity with `time` only. The reviewer is asked to confirm the exception does not
  affect any security decision (see [SAML.md](SAML.md#dependencies-and-the-chrono-exception)).

### Organizations, domains and enterprise SSO

- Organization connections (write-only secrets), domain verification (normalisation, TXT lookup,
  uniform failure), one verified owner per domain, routing guards, local-method refusal on SSO-only
  domains, invitations (hashed token, single use, same-browser POST), cross-org email trust, org JIT.

### Cryptography and key management

- KEK sealing of secrets at rest (connection secrets, webhook secrets, TOTP seeds, sealed flow
  values, signing private keys, SMTP and CAPTCHA secrets, email outbox payloads), signing-key
  generation and rotation, JWKS publication, the single crypto backend (aws-lc-rs).
- Secrets hashed or sealed at rest in both backends; no secrets in `Debug` output, logs, traces or
  metrics.

### Outbound requests (SSRF guard)

- The one guarded outbound client used for upstream discovery, JWKS, token and profile calls,
  back-channel logout, CAPTCHA, the breached-password check, webhooks, CIMD fetches and SAML
  metadata: scheme rules, address checks at resolve time, blocked ranges, no redirects, no proxy
  environment, caps and timeouts, error text that never echoes the target.

### Browser protections

- CSRF (synchronizer token plus Fetch-Metadata/Origin rules and their exemptions), cookie attributes
  and per-tenant names, the strict CSP and its narrow per-page exceptions, `frame-ancestors`, HSTS,
  `Referrer-Policy`, the theme CSS validator and logo sniffing.

### Multi-tenant isolation

- Tenant scoping in every repository method (composite keys in PostgreSQL), issuer separation,
  cookie separation, cross-tenant role assignment, cross-tenant token and session use.

### Webhooks

- Endpoint URL policy at creation and at every send, Standard Webhooks signatures, sealed secrets shown
  once, ids-only payloads, exactly-once delivery claims and leases.

### Rate limiting and abuse resistance

- The one keyed limiter (in-process and Redis, fail-closed outage, hashed keys), route classes, the
  two-tier brute-force protection, CAPTCHA fail-closed verification, trusted-proxy client IP
  resolution, body limits per route.

### Operations: migrations, backup and restore, CLI

- Migrations (destructive guard, released-migration immutability, upgrade 0.4 to 1.0), backup and
  restore guards (running server, foreign or corrupt files, wrong KEK, newer binary), first-run
  setup (no default credentials, single use), local admin recovery, the loopback-only healthcheck,
  `config show` redaction.

### Supply chain

- The dependency policy (`deny.toml`: advisories, licences, sources, banned crates and the scoped
  exceptions), the single aws-lc version check (`scripts/check-deps.sh`), the release-graph check
  that keeps test code out of the release binary (`scripts/check-release-graph.sh`).
- The release workflow (`.github/workflows/release.yml`): pinned actions, static
  binaries, the container image (runs as non-root), checksums and build-provenance
  attestations (`docs/RELEASING.md`).

## Review package inputs

All of these are in the repository at the reviewed tag:

| Input | Where |
| --- | --- |
| Security test map (control to named negative test, QUAL-01) | `scripts/check-security-tests.sh` (`just security-tests`) |
| Threat model | `docs/THREAT-MODEL.md` |
| Cross-cutting control specification | `docs/ARCHITECTURE.md` §11 |
| SAML D4 corpus report | `.planning/phases/06-release-1-0-orgs-and-sso/06-26-SUMMARY.md`, section "D4 corpus report" |
| SAML design, dependencies and the `chrono` exception | `docs/SAML.md` |
| Fuzz targets | `fuzz/fuzz_targets/` (authorize, client assertion, JWT, redirect match, registration, CIMD, tenant config, org domain, SAML response, SAML metadata); `scripts/fuzz.sh`, `.github/workflows/fuzz.yml` |
| Dependency policy | `deny.toml`, `scripts/check-deps.sh` |
| Release workflow and attestations | `.github/workflows/release.yml`, `docs/RELEASING.md` |
| OpenID conformance harness | `tests/conformance/` (five OP plans) |
| Browser-level behaviour | `tests/e2e/specs/` (Playwright) |
| Admin and flow API documents | `docs/openapi/` |
| Operations, upgrade and organization notes | `docs/OPERATIONS.md`, `docs/UPGRADING.md`, `docs/ORGANIZATIONS.md`, `docs/WEBHOOKS.md`, `docs/MCP.md` |

## Reviewer brief

### Build and run

Requirements: a stable Rust toolchain (the version pinned in the repository), `just`, and Docker
only for the PostgreSQL, Redis, end-to-end and conformance runs.

```sh
cargo build --release -p anvilid
./target/release/anvilid serve --data-dir ./review-data
```

Without configuration the server runs in development mode on `http://127.0.0.1:8080` with SQLite and
a generated KEK in the data directory, and prints a one-time setup URL. For a production-like setup
use `--public-url https://…` with `--tls-cert`/`--tls-key` (or a TLS proxy and
`--trusted-proxies`); development mode relaxes cookie prefixes and allows plain http, so findings
about production behaviour should be checked without it. `anvilid config show` lists every setting
and its source. PostgreSQL: set `ANVILID_DATABASE_URL` and `ANVILID_KEK`; Redis limiter:
`ANVILID_REDIS_URL`. SAML needs `--saml-experimental` (or `ANVILID_SAML_EXPERIMENTAL=true`).

The release archives and the container image of the reviewed tag can be used instead of a source
build; verify them as described in `docs/RELEASING.md`.

Useful test commands: `just ci` (everything that does not need external services, plus the
PostgreSQL and Redis suites when Docker is available), `just security-tests` (the control map),
`just e2e`, `just conformance`, `just fuzz <target>`.

### Test accounts

There are no default credentials. Provision a fresh instance with the existing scripts, which use
public interfaces only:

- `tests/conformance/setup.sh <setup-url> <out-config> <out-backchannel-config>` completes first-run
  setup through `/setup` with a random administrator password, obtains an admin token with the
  management client, creates static clients and a user with every standard claim, and writes the
  generated credentials only into the two output files.
- `tests/e2e/run.sh` starts a fresh instance in a temporary data directory with SMTP capture, the
  SAML flag and a local DNS resolver for domain verification, and the Playwright helpers in
  `tests/e2e/lib/` create administrators, tenants, organizations and users through the admin API.
- After setup, more tenants, clients, users, roles and organizations can be created through the
  console (`/console/`) or the admin API (`/api/admin/v1`, OpenAPI document at
  `/api/admin/v1/openapi.json`).

Use a fresh data directory per test campaign and delete it afterwards. Generated keys and
credentials are local to that directory.

### Known limitations (not findings)

These are documented design decisions for 1.0:

- SAML 2.0 is experimental and off by default; IdP-initiated SSO, encrypted assertions and Single
  Logout are not supported.
- Implicit and hybrid flows, request objects (`request`, and `request_uri` other than PAR) and the
  resource owner password grant are intentionally not supported.
- `jwks_uri` is refused for dynamic and CIMD clients; KEK rotation is not supported.
- Tenant-restricted system administrators are deferred past 1.0.
- A PAR `request_uri` is strictly single use (a browser reload gets an error page).
- The native headless mode follows the shape of an IETF draft for first-party applications; it is
  restricted to first-party clients and does not claim conformance to the draft.
- Imported accounts can take measurably longer to verify than native ones until their first login
  rehashes them (the account exists in both cases; unknown accounts always use the dummy hash).
- Enabling CAPTCHA allows the chosen provider's script on the CAPTCHA page only.
- Further items: `docs/UPGRADING.md` ("Limitations in 1.0") and `docs/ORGANIZATIONS.md`.

### Out of scope

- Deployments the operator configured insecurely against the documentation (development mode on a
  public network, rate limiting switched off, untrusted proxies listed as trusted).
- The operator's own infrastructure: PostgreSQL, Redis, SMTP, the OTLP collector, the reverse proxy
  and the host.
- Third-party services (social and enterprise identity providers, CAPTCHA providers), except how
  AnvilID validates what they return.
- The example applications under `examples/` and the test harnesses under `tests/`, except where
  they are needed to run the review.
- Denial of service by raw traffic volume; resource exhaustion through a single request is in scope.
- Social engineering and physical attacks.

## Findings handling

- Every finding is filed as a **private GitHub draft security advisory** on this repository (one
  advisory per finding), or handed to the owner through a private channel the owner names. A
  temporary private fork attached to the advisory is used to develop the fix.
- Findings, reproductions, severity notes and exploit details **never go to the public repository**
  (no issues, pull requests, commit messages, documents or test names that describe them) before the
  fix ships in a release.
- Fixes are released as described in [SECURITY.md](../SECURITY.md): a patch release, the published
  advisory and a CVE where applicable.
- After release, the repository gets only a public summary: the review completion date, the number
  of findings and the versions that fixed them.
