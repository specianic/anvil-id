# Phase 7: Release 1.0 "Credible for business" (Certification and release) - Research

**Researched:** 2026-11-26
**Domain:** PAR (RFC 9126), headless flow API, agent consent, legacy password-hash import, user/GDPR export,
API compatibility policy, docs site, OpenID certification, external security review, release gate
**Confidence:** HIGH for the code reuse map, PAR and the hash algorithms (verified against RFCs, the Firebase
source and local test-vector runs). MEDIUM for the certification logistics and the headless binding design.
LOW items are marked where they appear.

## Summary

Phase 7 is mostly reuse plus three new protocol surfaces (PAR, headless API, legacy hash verification). The
code already has the right extension points. There is one `PasswordHasher::verify` call site, in the login
flow (`service/flow.rs` `Effect::VerifyPassword`), and it already re-hashes when `needs_rehash` is set. There is
one flow engine with a `FormDescription` contract that core fills without display text. The consent model
already computes `missing_scopes`, stores the union on Allow and knows the client's provenance
(`ClientSource::{Static,Dynamic,Cimd}`, plus `cimd_host`). The authorization request is stored separately, so a
pushed request can turn into a normal stored request. The OpenAPI drift test, the security-test map, the
migration sha256 manifest and the 0.4 → 1.0 upgrade tests on both backends all exist and only need extending.

The two hard constraints the plans must respect:

1. **The 1.0 migrations are already pinned** in `scripts/released-migrations.sha256` (commit faf95a6,
   1.0.0-beta.1). These are SQLite `0008`/`0009` and Postgres `0007`. Every Phase 7 schema change goes into
   new files (SQLite `0010_…`, Postgres `0008_…`), and the upgrade tests must cover beta.1 → 1.0 as well as
   0.4 → 1.0.
2. **The crypto-backend policy.** aws-lc-rs 1.19 provides PBKDF2 (HMAC-SHA1/256/384/512), SHA-2 digests and
   AES-256-CTR, so PBKDF2, salted SHA-2 and the AES step of Firebase scrypt stay on aws-lc-rs. aws-lc-rs has
   no scrypt and no bcrypt module, and `unsafe_code = "deny"` rules out raw `aws-lc-sys` FFI. So scrypt
   (including the scrypt core of Firebase scrypt) and bcrypt need RustCrypto `scrypt` 0.12.0 and `bcrypt`
   0.19.3 (Keats, using RustCrypto `blowfish`). That is a **fourth, verification-only exception** to "single
   crypto backend". It should be scoped in `deny.toml` with `wrappers`, documented in ARCHITECTURE §2 next to
   the webauthn, totp and chrono exceptions, and marked "owner review pending", following the chrono
   precedent.

Owner-only work becomes explicit checkpoints:

- OpenID certification. Logs must come from the hosted suite at `www.certification.openid.net`, which needs a
  publicly reachable deployment. Submission also needs a payment code or the open-source waiver, which
  requires OIDF membership, plus a DocuSign declaration.
- Commissioning the external review.
- The real-IdP SAML interop run.
- The still-pending AUTH-07 provider checklist.
- Enabling GitHub private vulnerability reporting.
- Tagging v1.0.0 and publishing GitHub Pages.

Review findings must be tracked privately (draft security advisories). They are not committed to this
public repo until fixed.

**Primary recommendation:** Build in this order:

1. Foundations first, in one plan: migrations, ports and contract suites.
2. The password-verifier module, isolated and backed by known-answer tests (KATs).
3. PAR, import, export, agent consent and the headless browser mode in parallel. Headless reuses the UI
   handlers' orchestration, refactored into one shared function.
4. Headless native mode, bound to PAR plus PKCE.
5. The policy, docs and certification packages.
6. The release gate with owner checkpoints, then a gap plan for review findings once they exist.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- All CLAUDE.md rules apply (no stubs, one implementation per concern, negative test per security control, storage only
  through traits, public-repo hygiene, no unverified claims about other products).
- **Owner-only actions are checkpoints, never faked:** submitting OpenID certification, commissioning/conducting the
  external security review, and publishing releases/tags are owner actions. Plans prepare everything (conformance green
  in CI with exported evidence, a certification submission package, a review scope/threat-model/brief, a findings tracker)
  and then stop at an explicit checkpoint. Findings from the review are fixed in a follow-up gap plan once they exist.
- **Security policy (SEC-08):** SECURITY.md with private reporting channel placeholder the owner fills, supported-versions
  table, disclosure process; no personal contact data committed.
- **Password-hash import (ADM-08):** verify legacy hashes on first login and transparently rehash to the current
  algorithm; each scheme isolated behind one verifier interface with known-answer test vectors from primary sources;
  constant-time comparison; refuse weak/unknown parameters explicitly; import is idempotent and audited; imported hashes
  never logged or exported in clear. Firebase scrypt per its published parameters.
- **User export (ADM-09):** single, bulk (streamed/paginated), and GDPR data-subject export (all personal data held about
  a user, incl. sessions, consents, links, audit entries about them); secrets never exported.
- **PAR (OIDC-18 or as numbered):** RFC 9126 pushed authorization requests, `request_uri` single-use and short-lived,
  client authentication required, optional `require_pushed_authorization_requests` per client; discovery metadata.
- **Headless flow API (UI-05 or as numbered):** versioned JSON API driving the same login flows (no second flow engine),
  CSRF/binding equivalent for SPA and native clients, documented and covered by the OpenAPI drift test.
- **Agent clients (AGT-03):** consent screen clearly identifies agent/MCP clients (CIMD/DCR provenance) with incremental
  scope step-up (requesting additional scopes prompts only for the new ones).
- **API versioning & compatibility policy (QUAL-03 or as numbered):** documented policy for admin API, headless API,
  config YAML, migrations; deprecation process; tested upgrade path 0.4 → 1.0 (the Phase 6 upgrade tests extended).
- **Docs site:** static site generated from docs/ (install, integrations, migration guides), built in CI; no third-party
  tracking; hostable on GitHub Pages (publishing is an owner action).
- **Phase 6 carry-overs:** tenant-restricted system admins (Q1 second half) — plan it or justify deferring past 1.0;
  SAML experimental flag stays until the external review + interop checklist (Q3), so the review scope must include SAML.

### Claude's Discretion
- Plan decomposition and waves (parallel plans with disjoint files incl. hidden shared files; foundations first).
- Docs site generator (prefer a small, maintained static generator or plain mdBook-style tool; no JS tracking).
- Exact requirement-ID mapping where ROADMAP numbering differs from PRD wording.

### Deferred Ideas (OUT OF SCOPE)
- SCIM provisioning, fine-grained authorization engine (D5, 3.0)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description (REQUIREMENTS.md / PRD wording) | Research Support |
|----|-------------|-----------------|
| OIDC-18 | "Clients can use pushed authorization requests (RFC 9126)" [1.0]. PRD OIDC-18: "Pushed authorization requests (RFC 9126)", P1 | §PAR design; RFC 9126 rules verified; RFC 10070 audience rule (issuer only), already enforced in `anvil-jose/src/client_assertion.rs`; new storage `pushed_authorization_request` with atomic consume; discovery + client metadata |
| OIDC-23 | "The OpenID conformance suite passes in CI for Basic OP, Config OP, Form Post, RP-Initiated Logout and Back-Channel Logout; certification filed" [1.0]. PRD OIDC-23 adds: "(self-hosted suite) … file for certification at 1.0. Implicit and hybrid flows are intentionally not supported" | The CI harness already passes all five plans (`tests/conformance/run.sh all`). Certification needs hosted-suite logs, a public deployment, a payment code or waiver and a DocuSign declaration → owner checkpoint (§Certification) |
| UI-05 | "SPAs and native apps can drive flows through a versioned headless API that returns server-driven form descriptions" [1.0]. PRD UI-5: "a documented, versioned flow API … Each flow step describes its form (fields, types, messages) … The built-in UI uses the same flow engine" | §Headless design: `/t/{slug}/api/flows/v1/*`, a DTO over `FormDescription`, browser mode (cookie + CSRF header + origin allow-list) and native mode (PAR-bound flow token, PKCE, code in JSON); new `docs/openapi/flows-v1.json` with drift test |
| AGT-03 | "The consent screen clearly identifies agent clients and requested scopes, and supports incremental scope step-up" [1.0] | §Agent consent: provenance from `ClientSource` + `cimd_host`, an explicit `agent` marker, `missing_scopes` drives "new" vs "already granted", Allow already stores the union |
| ADM-08 | "Admin can import users with password hashes (bcrypt, scrypt incl. Firebase, PBKDF2, Argon2, salted SHA-2)" [1.0]. PRD ADM-8 adds: "with guides for common source providers" | §Password import: verified algorithms + KATs, crate choices, parameter floors/caps, storage encoding, one bounded pool, rehash via the existing path |
| ADM-09 | "Admin can export users individually and in bulk, including a GDPR data-subject export" [1.0] | §Export: data inventory from the ports, NDJSON streaming over keyset pagination, Art. 15/20 in general terms, redaction of other people's data |
| QUAL-03 | "Public APIs are versioned; breaking changes only in major versions". PRD NFR-Q-4 adds: "with a migration guide" | §Compatibility policy: surfaces list, deprecation process, OpenAPI baseline breaking-change check, config `version`, migration manifest; upgrade tests 0.4 → 1.0 and beta.1 → 1.0 |
| SEC-08 | "The project publishes a security policy; an external security review is completed before 1.0". PRD NFR-SEC-8: "Published security policy, coordinated disclosure, CVEs fixed in the open-source release immediately"; R2: "external review before 1.0" | §Security policy & review: SECURITY.md, GitHub private reporting (owner enables), review scope/threat model/brief, private findings tracker, gap plan |

Also gated by ROADMAP success criterion 5 and the ARCHITECTURE M5 exit criteria (not separate IDs): the
upgrade path from 0.4 is tested, and the documentation site is complete (install, integrations, migration
guides).
</phase_requirements>

## Standard Stack

### Core (already present, reused, no change)
| Library | Version | Purpose in Phase 7 |
|---------|---------|---------|
| aws-lc-rs | 1.19 | PBKDF2 (`pbkdf2::PBKDF2_HMAC_SHA1/256/384/512`, `pbkdf2::verify`), SHA-256/512 (`digest`), AES-256-CTR (`cipher::DecryptingKey::ctr` + `DecryptionContext::Iv128`) for Firebase, PAR `request_uri` and flow-token randomness (via `anvil_jose::encoding::random_*`) |
| argon2 | 0.6.0 | Imported Argon2 (i/d/id, v=16/19) PHC strings, verified by the existing `Argon2Pool` |
| subtle | 2.6.1 | Constant-time comparison of derived hashes (`ConstantTimeEq`) |
| utoipa / utoipa-axum | 6.0.0 / 0.3.0 | Admin API additions; second OpenAPI document `flows-v1` |
| tower-http | 0.6.11 (`cors`) | Credentialed CORS for the headless browser mode (a new layer next to `public_cors()`) |
| serde-saphyr | 2.2.0 | Not needed for import (NDJSON/JSON); stays CLI YAML only |

### New dependencies (versions verified on crates.io 2026-11-26)
| Library | Version | Purpose | Graph impact / policy |
|---------|---------|---------|---------|
| `scrypt` (RustCrypto) | 0.12.0, `default-features = false` (no `phc`, `mcf`, `rayon`) | scrypt for imported scrypt and Firebase scrypt | Deps: `pbkdf2` 0.13, `salsa20` 0.11, `sha2` 0.11, `cfg-if`. **All already in Cargo.lock** (through `pkcs5`/`crypto-glue`), so it adds little lock churn. Licence MIT OR Apache-2.0 |
| `bcrypt` (Keats) | 0.19.3, `default-features = false, features = ["alloc"]` (`verify` needs `alloc`; `alloc` pulls `getrandom` 0.4, already locked at 0.4.3) | bcrypt `$2a$`/`$2b$`/`$2y$` verification | New: `blowfish` 0.10 (RustCrypto, MIT OR Apache-2.0). `base64` 0.23, `subtle` and `zeroize` are already present. Licence MIT |
| mdBook (CI tool, not a crate dependency) | 0.5.4 (2026-07-06) | Docs site | Installed in CI only (pinned binary or `cargo install --locked --version 0.5.4`) |
| oasdiff (CI tool, optional) | pin at plan time | OpenAPI breaking-change check against a committed 1.0 baseline | OpenAPI 3.1 support was reported as beta (LOW, see Open Questions); fallback is a small Rust test |

`deny.toml` additions (the policy text belongs in ARCHITECTURE §2):

```toml
# Legacy password-hash verification only (ADM-08): imported hashes are verified once, then re-hashed with
# Argon2id. No key material is generated or stored by these crates. PBKDF2/SHA-2/AES-CTR stay on aws-lc-rs.
{ crate = "blowfish", wrappers = ["bcrypt"], reason = "bcrypt verification of imported hashes only (ADM-08)" },
{ crate = "salsa20",  wrappers = ["scrypt"], reason = "scrypt verification of imported hashes only (ADM-08)" },
```

(These go in `[bans] deny`. Do not try to wrap `pbkdf2` or `sha2`: they already have several parents.)
**Verify with `just deny` and `just deps` in the plan.** No cargo command ran during this research. Licence,
advisory and source checks are expected to pass, because both crates are on crates.io under allowed licences.
`multiple-versions` is only `warn`.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| RustCrypto `scrypt` | `aws-lc-sys` `EVP_PBE_scrypt` FFI | Needs `unsafe`, which the workspace denies; rejected |
| `bcrypt` crate | hand-rolled EksBlowfish over `blowfish` | Hand-rolled crypto; rejected |
| `bcrypt` crate | `pwhash` | Older and broader; nothing gained |
| mdBook | Zola 0.23.6 (2026-09-12) | Fine, but needs a theme and templates; mdBook gives navigation and search with zero config |
| mdBook | MkDocs + a theme | Adds a Python toolchain to CI; no advantage for this repo |

## Architecture Patterns

### Recommended module layout (new files; keeps parallel plans disjoint)

```
crates/anvil-core/src/
├── oauth/par.rs                 # pure: request_uri format (urn:ietf:params:oauth:request_uri:<b64url 32B>), lifetime, which front-channel params are ignored
├── service/par.rs               # ParService: authenticate client (ClientAuthService), validate via authorize_request, store, consume
├── service/user_import.rs       # UserImportService: record validation, idempotency, audit (admin API + CLI share it)
├── service/user_export.rs       # UserExportService: single, bulk page, GDPR bundle assembly (ports only)
├── policy/password_import.rs    # pure: scheme enum, parameter floors/caps, the stored encoding (parse/format)
├── flow/headless.rs             # pure: FormDescription → versioned DTO mapping helpers, method nodes
└── model/password_profile.rs    # tenant-level hash parameter sets (Firebase signer key sealed)
crates/anvil-web/src/
├── adapters/password/{mod,bcrypt,scrypt,firebase,pbkdf2,sha2}.rs   # verifiers, KATs in-file
├── protocol/par.rs              # POST /par
├── api_flows/{mod,login,registration,recovery,verification,dto,openapi}.rs   # /api/flows/v1
├── ui/flow_driver.rs            # shared guard → submit → record orchestration (moved out of ui/login.rs etc.)
├── layers/cors.rs               # + headless_cors(allowed origins, credentials)
└── admin/{user_import,user_export}.rs
crates/anvilid/src/users.rs      # `anvilid users import|export` (same services, no HTTP, like tenant_config.rs)
crates/anvil-storage/src/contract/{par,password_profiles,user_export}.rs
crates/anvil-storage-sqlite/migrations/0010_release_1_0_par_import.sql
crates/anvil-storage-postgres/migrations/0008_release_1_0_par_import.sql
docs/openapi/flows-v1.json
docs/{SECURITY-REVIEW-SCOPE.md, THREAT-MODEL.md, COMPATIBILITY.md, IMPORT-EXPORT.md, HEADLESS.md, PAR.md}
SECURITY.md  book.toml  docs/SUMMARY.md  .github/workflows/docs.yml
```

### Pattern 1: PAR (RFC 9126), verified rules mapped onto existing code

- `POST /par` is form-encoded, client-authenticated through the **same** `ClientAuthService` as `/token`. It
  covers the secret methods and `private_key_jwt` with the shared jti replay store, and `none` for public
  clients. RFC 9126 §2: "client authentication follows token endpoint rules". It sits in rate-limit class
  `Token` (add `/par` to the `TOKEN` list in `layers/ratelimit.rs`). No CORS, no Fetch-Metadata
  (client-authenticated, like `/token`).
- Audience: RFC 10070 (published November 2026, updates RFC 9126) makes the issuer the **sole** permitted
  `aud`. It removes the old rule that also accepted the token endpoint or PAR endpoint URL.
  `client_assertion.rs` already enforces exactly that, so there is no code change. Add a negative test where
  `aud` is the PAR endpoint URL.
- Validate with `oauth::authorize_request` exactly as `/authorize` would. Exceptions: errors are JSON (RFC
  6749 §5.2 format, `invalid_request` default, 400), never redirects, and never interaction errors
  (`consent_required` etc. must not come back from `/par`). A `request_uri` inside the pushed body is
  refused. `request` (JAR) stays unsupported: answer `request_not_supported` (JSON).
- Success is 201 `{"request_uri":"urn:ietf:params:oauth:request_uri:<43 b64url chars>","expires_in":60}`.
  Store only `sha256(request_uri)`, `client_id`, the validated `AuthorizationParams` JSON, `expires_at` and
  `consumed_at`.
- `/authorize?client_id=…&request_uri=…` must have a `request_uri` with the PAR URN prefix; anything else
  keeps today's `request_uri_not_supported`. Consume atomically:
  `UPDATE … SET consumed_at=now WHERE tenant_id=? AND uri_hash=? AND consumed_at IS NULL AND expires_at>now RETURNING …`.
  Exactly one winner, like `consume_code`. The `client_id` query parameter must equal the bound client.
  Unknown, expired, consumed or mismatched → **error page, no redirect** (no trusted redirect URI yet).
  Other front-channel parameters are ignored; only the pushed ones count. Then re-check the client's current
  policy (RFC 9126 §7.4: the client may have changed between push and use) and continue into the existing
  `create_authorization_request` path.
- Policy. `require_pushed_authorization_requests` is a per-client boolean. It is settable in the admin API,
  config YAML and DCR (RFC 9126 §6 client metadata) and stored in a new `client` column (additive). When the
  flag is true, a plain `/authorize` is refused with `invalid_request` (error page, or a redirect when the
  redirect URI is valid, matching today's error delivery). An optional tenant-level flag drives the AS
  metadata `require_pushed_authorization_requests` (default false).
- Discovery adds `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests`. Keep
  `request_uri_parameter_supported: false`. That OIDC flag means request objects by reference, which are still
  never fetched. Document this so the Config OP plan stays green.
- Pushed redirect URIs must still match a registered URI exactly. RFC 9126 §2.4 allows relaxing this for
  authenticated clients; we deliberately do not.
- Strict single use: a browser reload of `/authorize?request_uri=` gets an error page. RFC 9126 says the
  server SHOULD treat it as one-time and MAY allow reloads. Document the choice.
- Purge expired rows in the existing cleanup job (§7.4).

### Pattern 2: Legacy password verification behind the one `PasswordHasher`

Keep the port. Today `Argon2Pool` is the only `PasswordHasher`. Make the web adapter a dispatcher (one
implementation of the port) that routes on the stored string's scheme:

| Stored form (the credential's existing `secret`/`data` TEXT column, no schema change) | Verifier | Backend |
|---|---|---|
| `$argon2id$…`, `$argon2i$…`, `$argon2d$…` (PHC) | existing `Argon2Pool` | argon2 crate |
| `$2a$`/`$2b$`/`$2y$` + 2-digit cost (60 chars, MCF) | `bcrypt::verify` | bcrypt/blowfish |
| `$anvil-scrypt$ln=<log2 N>,r=<r>,p=<p>$<salt b64>$<hash b64>` | `scrypt::scrypt` + ct-compare | RustCrypto scrypt |
| `$anvil-firebase-scrypt$profile=<uuid>$<salt b64>$<hash b64>` | Firebase (below) | scrypt + aws-lc AES-CTR |
| `$anvil-pbkdf2$alg=sha1\|sha256\|sha512,i=<n>$<salt b64>$<hash b64>` | `aws_lc_rs::pbkdf2::verify` | aws-lc-rs |
| `$anvil-sha2$alg=sha256\|sha512,pos=prefix\|suffix$<salt b64>$<hash b64>` | `digest` + ct-compare | aws-lc-rs |

- One internal encoding (our own `$anvil-…$` strings, parsed and formatted in `policy/password_import.rs`).
  Every vendor format is converted to it **at import time**: Django/passlib PBKDF2, Firebase CSV/JSON
  fields, plain hex/base64 SHA-2 plus salt. The login path then never parses vendor formats.
- Every legacy match returns `needs_rehash = true`. The existing `FlowService::rehash` replaces the credential
  with Argon2id. Make that write a **compare-and-swap on the old value**, so a concurrent password change is
  never overwritten. The `UserRepo` method is new; today `set_password` is an upsert.
- All verifiers run inside the **same bounded semaphore and `spawn_blocking` pool** as Argon2. scrypt and
  Firebase need `128·N·r` bytes of memory, so the permit model matters. Unknown or garbled strings take the
  dummy-hash path and return `valid=false`, with no early return, preserving uniform timing.
- **Firebase** needs a tenant-level *hash profile*. Its fields are `signer_key` (secret, sealed with the KEK,
  AAD = tenant + profile id; include it in the plaintext-at-rest scans), `salt_separator`, `rounds` and
  `mem_cost`. The stored string references the profile id. `verify` therefore needs the profile material. Let
  core resolve it, because core already loads the credential in `Effect::VerifyPassword`, and pass it in
  through a port extension (`verify_with(credential, Option<&HashProfileMaterial>)`). The web adapter must not
  read storage.

**Firebase modified scrypt, verified.** Read in `firebase/scrypt` (`main.c`, `lib/scryptenc/scryptenc.c`) and
re-computed locally against the repo's published vectors; both matched:

```
salt'  = base64dec(user_salt) || base64dec(salt_separator)
dk     = scrypt(password, salt', N = 2^mem_cost, r = rounds, p = 1, dkLen = 64)
hash   = AES-256-CTR(key = dk[0..32], IV/counter block = 16 zero bytes).encrypt(base64dec(signer_key))
valid  = ct_eq(hash, base64dec(stored_password_hash))
```

The CTR mode is libcperciva `crypto_aesctr_init(key, nonce=0)`: an 8-byte nonce followed by an 8-byte
big-endian block counter. For inputs under 2^64 blocks this equals standard AES-CTR with a zero 128-bit IV. In
aws-lc-rs, use `DecryptingKey::ctr` with `DecryptionContext::Iv128(zero)` (CTR decrypt equals encrypt).
`EncryptingKey` does not take a caller-supplied IV in its safe API.

### Pattern 3: Import and export services (one service each, two front ends)

- `UserImportService` (core) is used by `POST /api/admin/v1/tenants/{slug}/users/import` and by `anvilid users
  import <file.ndjson>`, which opens storage with the server config like `tenant_config.rs` does.
- Input is NDJSON, one user per line: email, email_verified, claims, attributes, optional `password: {scheme,
  …params}`, optional `id`. The admin route gets a raised body limit through a branch of the **single**
  body-limit middleware, as was done for config plan/apply (1 MiB, POST exact path), and a per-request record
  cap (for example 1,000). The CLI streams files of any size in batches.
- Idempotency key is (tenant, normalized email). Per-record outcomes: `created`, `unchanged` (same content
  hash), `conflict` (exists with different data; never silently overwritten unless `--update`), `rejected`
  (with a reason code such as `weak_parameters`, `unknown_scheme` or `invalid_email`). A dry-run mode returns
  the report without writing.
- Audit: one `users_imported` event per batch (counts, source label) plus `user_created` per user. **The hash
  never goes into audit details, logs, errors or the report.** `Debug` of every import DTO redacts.
  `PasswordCredential` already redacts its `phc`.
- `UserExportService` has three modes:
  - `GET …/users/{id}/export`: single user, JSON.
  - `GET …/users/export`: bulk, NDJSON, streamed by walking `UserRepo::list` keyset pages. Never load
    everything.
  - `GET …/users/{id}/export?profile=gdpr`: GDPR bundle (below). New scope `admin:users:export`, or reuse
    `admin:users:read` plus an audit event (`user_exported`)? Recommend a **separate scope**: exports are
    bulk PII exfiltration paths, so least privilege. Add it to `ALL_ADMIN_SCOPES`, so the drift test's scope
    assertion follows.

### Pattern 4: GDPR data-subject export (general terms, not legal advice)

GDPR Art. 15(1) and (3) give the data subject a copy of the personal data "in a commonly used electronic form",
plus information such as categories, recipients, retention and source. Art. 15(4): the copy "shall not
adversely affect the rights and freedoms of others". Art. 20(1): data the person "has provided to a
controller" goes out "in a structured, commonly used and machine-readable format". The software's job is the
machine-readable data. Purposes, recipients and retention policy are the operator's statements; leave a
documented slot in the export for them.

Inventory (every item is read through an existing port):

- The user row and standard claims.
- Custom attribute values (`AttributeRepo`).
- Credential **metadata** only: passkey names and dates, TOTP enrolled yes/no, recovery codes remaining as a
  count. Never secrets, seeds or hashes.
- Sessions (`SessionRepo::list_for_user`): IP and user agent if stored.
- Consent grants (scopes, resources, dates) and token families: client, created, revoked. Never token
  hashes.
- Identity links: connection name and upstream `sub`, i.e. the Art. 15(1)(g) source.
- Org memberships and roles at tenant and org level.
- Audit events where `target = user` or `actor_id = user` (`AuditQuery` already has both filters).
- Pending self-service tokens as existence only.
- Webhook deliveries that mention the user: recommend **excluding** them and documenting it as operational
  data whose payload is a copy of the above.

Redaction: audit entries name other actors, typically an admin's user id or email. Replace them with a role
label (`administrator`) to respect Art. 15(4).

### Pattern 5: Headless flow API (one engine, second renderer)

The UI handlers currently do the web-side orchestration themselves:
`guard_attempt` → `FlowService::submit` → `record_attempt` → CAPTCHA → outcome → cookies (`ui/login.rs`
etc.). **Move that orchestration into one shared module (`ui/flow_driver.rs`)** that returns a typed outcome.
Both the HTML handlers and the JSON handlers call it and differ only in encoding. Otherwise throttling, CAPTCHA
and session switching get a second implementation, which breaks the "one implementation per concern" rule.

- Paths: `/t/{slug}/api/flows/v1/{login|registration|recovery|verification}`.
  - `POST …/{kind}` starts a flow (with `?request={auth_request_id}` or a PAR `request_uri`, see native).
  - `GET …/{kind}/{flow_id}` returns the current step.
  - `POST …/{kind}/{flow_id}` submits JSON input.
  - Passkey sub-routes mirror the UI ones.
  - Rate-limit class: POSTs are `Auth`.
- Response DTO (versioned, in `flows-v1.json`):
  `{ "flow": {id, kind, expires_at}, "step": "...", "form": {fields:[{name, kind, label_key, required, autocomplete, value?, messages}], messages, methods:[...]}, "result"?: {...} }`.
  - Labels are **keys** (`label_key`, message `key` + `args`); core already produces no display text.
    Optionally fill `label`/`text` from `ui_locales` with the existing `i18n::localize_form`.
  - `FormDescription` needs a `methods` list (password, passkey, email_code, upstream {slug,name}, sso), so a
    client can render choices. Add it to core; templates ignore unknown fields.
  - Never expose the internal struct directly. Map it to a DTO, so the engine can change without breaking
    v1.
- **Browser mode (SPA).** The flow cookie (existing `cookie_hash`) plus the CSRF token is returned in JSON and
  must come back in an `X-CSRF-Token` header (or body).
  - Allowed origins come from an explicit per-tenant allow-list (`headless.allowed_origins`, exact https
    origins), served with credentialed CORS. The current Fetch-Metadata layer admits only `same-origin`/`none`.
    The flows router needs a variant that also admits `same-site`/`cross-site` **only** when `Origin` is in the
    allow-list. Never `*` with credentials.
  - Document that the SPA must be **same-site** with the issuer: cross-site cookies are blocked by browsers.
  - On completion the session cookie is set on the AnvilID origin and the JSON gives
    `{"result":{"continue_to":"/t/x/authorize/continue?request=…"}}`. The SPA navigates top-level there and
    the normal code redirect follows.
- **Native mode (first-party apps).** There is no cookie jar and no ambient credential, so CSRF does not
  apply. The binding is a high-entropy **flow token** returned once at start and sent as
  `Authorization: AnvilFlow <token>` (or a dedicated header). It is stored hashed in the existing
  `cookie_hash` column, and the flow state JSON records `binding: "token"`, so a flow is never usable with
  both kinds. That avoids a `flow.kind` CHECK rebuild.
  - Start requires a PAR `request_uri` issued to a client flagged `headless_native = true`. That client must
    be first-party (consent skip) and PKCE-required, so the client and PKCE challenge are already bound by an
    authenticated or PKCE'd push.
  - Completion returns `{"result":{"code":"…","iss":"…","state":"…"}}` in JSON instead of a redirect. The app
    redeems the code at `/token` with `code_verifier`. No SSO browser session is created.
  - Refuse native mode when the request carries browser signals (`Sec-Fetch-Site`/`Origin`).
  - This mirrors the shape of the IETF draft "OAuth 2.0 for First-Party Applications"
    (draft-ietf-oauth-first-party-apps-04, WG consensus, not an RFC). The draft insists on first-party-only
    use, rate limiting per session, and "NOT RECOMMENDED … in browser-based applications". Don't claim
    conformance to it.
- Steps that need a browser (upstream social/OIDC, SAML, WebAuthn when the native app has no
  associated-domain setup) return `{"step":"browser_required","url":…}`. CAPTCHA returns `captcha_required`
  with the site key in browser mode and is refused in native mode, where the client must fall back to the
  browser.

### Pattern 6: Agent consent (AGT-03)

- **Identification.** Provenance already exists: `ClientSource::Dynamic` (self-registered) and `Cimd` (name
  from a self-published document; host shown, name marked unverified). Add an explicit client marker
  (`client_kind: "application" | "agent"`). It is settable by admins and DCR/CIMD policy, and defaults to
  `agent` for clients that request MCP-style resources? *Owner decision; see Open Questions.* The consent page
  shows an "AI agent / automated client" badge. It also shows provenance text: "Registered by an
  administrator", "Registered itself (dynamic registration), details unverified" or "Identified by its
  metadata document at `host`". The requested **resources** (RFC 8707, the MCP server) are already listed.
- **Incremental step-up.** `ConsentService` already has the existing grant. Pass
  `new_scopes = missing_scopes(granted, requested)` and `new_resources` to the page and render them as "New
  permissions". Show already-granted scopes collapsed as "Already allowed". Allow keeps storing the union. Add
  tests:
  1. A second request with one extra scope shows only that scope as new.
  2. `prompt=none` with a new scope still gives `consent_required`.
  3. Deny of a step-up does **not** revoke the existing grant.
  4. A `skip_first_party` client never sees the page, even if marked agent? Recommend: agent clients can
     never be `skip_first_party` (validation error). That is a security choice worth a negative test.
- Template `consent.html` keeps its stable selectors. Add new ids (`consent-agent`, `consent-provenance`,
  `consent-new-scopes`, `consent-granted-scopes`) and Fluent keys in **both** `en` and `de` catalogs.

### Pattern 7: Compatibility policy (QUAL-03)

| Surface | Version marker | Rule |
|---|---|---|
| Management API | path `/api/admin/v1`, OpenAPI `info.version: v1` | Additive only in 1.x (new operations, optional fields, new enum values documented as open). Removing or renaming fields, operations or scopes means v2 |
| Headless flow API | path `/api/flows/v1` | Same rule; new steps/methods/message keys are additive, and clients must ignore unknown ones |
| Protocol endpoints | standards (OIDC/RFC) | Follow the specs; discovery advertises what is built |
| Config YAML | document `version: 1` | Unknown keys refused (already); a new major document version only in 2.0 |
| CLI flags / env vars / config keys | release notes | Deprecated names keep working for the rest of the major version with a warning (`Config.warnings`) |
| Database schema | migrations + `released-migrations.sha256` | Forward-only, automatic, consecutive minor versions tested; destructive only behind `--allow-destructive-migrations` (OPS-04 rules unchanged) |
| Webhook payloads | `type` + documented schema | Additive only within 1.x |
| Token claims | documented claim set | Additive; reserved names never repurposed |

Deprecation process: announce in CHANGELOG/UPGRADING, warn at runtime (header `Deprecation`, plus `Sunset` for
HTTP APIs, or a config warning), and remove in the next major only. CI enforcement:

- Commit `docs/openapi/admin-v1.baseline-1.0.json` and `flows-v1.baseline-1.0.json` at the 1.0 gate. A check
  fails on removals: oasdiff `breaking --fail-on ERR`, or a Rust test comparing the operation, response-field
  and required-field sets, if oasdiff's 3.1 support proves unreliable.
- Upgrade tests: 0.4 → final 1.0 **and** 1.0.0-beta.1 schema → final 1.0, on both backends.

### Pattern 8: Docs site (mdBook 0.5.4)

- `book.toml` at the repo root with `src = "docs"`, `[build] create-missing = false` (a broken SUMMARY entry
  fails the build) and `[output.html] site-url = "/anvil-id/"` (or the owner's Pages path). No analytics, no
  external fonts or CDNs. mdBook bundles its fonts and search locally (MEDIUM; verify on the built output with
  the check below).
- `docs/SUMMARY.md` lists only public pages:
  - Install: binary, Docker, Helm, Compose.
  - Configuration.
  - Integrations: generic OIDC app, SPA with PKCE, the headless API, the MCP docs, webhooks, SAML/OIDC SSO.
  - Migration: import formats, per-source guides, UPGRADING.
  - Operations, Security (SECURITY.md, review summary once public), Compatibility policy, Reference (admin
    API and flows API OpenAPI, rendered with a link to the JSON).
- Planning docs (PRD, ARCHITECTURE) are a judgment call. They are public in the repo already, so they can be
  listed under "Design".
- **`docs/research/` must never reach the output.** It is gitignored, so CI checkouts don't have it, but a
  local `mdbook build` would copy non-markdown files from `src`. Add a CI assertion that `book/` contains no
  `research/` path.
- CI job `docs.yml`: build on PRs touching `docs/**`/`book.toml`. Run `scripts/check-docs-site.sh`, which
  greps the output for `<script src="http`, `<link href="http`, `googletagmanager`, `analytics` (expect none)
  and for internal broken links. Upload the artifact. Publishing (`actions/deploy-pages`) runs only on
  `workflow_dispatch` or tag. The **owner** enables Pages and triggers the run.

### Anti-Patterns to Avoid
- **A second login orchestration in the JSON handlers.** Extract `flow_driver` first.
- **Vendor-format parsing at login.** Convert at import into the `$anvil-…$` encoding.
- **Editing pinned migrations** (`0008`/`0009` SQLite, `0007` Postgres). `migrations-check` fails, and sqlx
  refuses checksum changes on databases that ran beta.1.
- **New values in CHECK-constrained enum columns** (for example `flow.kind`). These force a SQLite table
  rebuild. Keep new discriminators in JSON state or in new tables.
- **Committing review findings or a findings tracker with details** to the public repo before fixes ship.
- **CORS `*` with credentials**, or reusing `public_cors()` for flows.
- **Accepting `aud` = PAR endpoint** "because RFC 9126 said so". RFC 10070 removed that.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| bcrypt | EksBlowfish setup, radix-64 | `bcrypt::verify` (constant-time `subtle` compare inside) | Many edge cases: 72-byte truncation, `$2a$` vs `$2b$`, base64 alphabet |
| scrypt | ROMix/Salsa20/8 | `scrypt::scrypt` | Memory-hard core; subtle bugs |
| PBKDF2 | HMAC loop | `aws_lc_rs::pbkdf2::verify` | Already the house backend |
| AES-CTR | XOR with a hand-written counter | `aws_lc_rs::cipher` CTR | Counter-block layout errors |
| Constant-time compare | `==` on slices | `subtle::ConstantTimeEq` | Timing leaks |
| Client auth at `/par` | new auth code | `ClientAuthService` (one implementation) | jti replay store, secret hashing, aud rules |
| Atomic single-use | read-then-delete | `UPDATE … RETURNING` like `consume_code` | Races; the contract suite already has the concurrency pattern |
| OpenAPI generation | hand-written JSON | utoipa + drift test | Drift |
| Docs site | custom generator | mdBook | Navigation, search, no tracking |
| Breaking-change detection | ad-hoc diff | oasdiff (or a minimal set-comparison test if 3.1 support is shaky) | Many rules |

**Key insight:** the parts of ADM-08 that look like crypto are security-critical parsing and parameter policy.
The primitives exist; the work is the strict format conversion, caps and floors, timing uniformity and
redaction.

## Common Pitfalls

### Pitfall 1: Memory and CPU bombs in imported parameters
**What goes wrong:** An import line with scrypt `ln=24`, Argon2 `m=4194304` or PBKDF2 `i=2^31` makes each login
attempt allocate GiBs or burn seconds. Unauthenticated attackers can trigger the verify for a known email.
**Why it happens:** Today `Argon2Pool::verify` trusts the stored PHC parameters, which was safe while it only
verified its own hashes.
**How to avoid:** Hard **caps** at import (refuse) *and* at verify (fail closed, log once), for example:
- scrypt `128·N·r·p` ≤ 64 MiB;
- Argon2 `m` ≤ 256 MiB, `t` ≤ 10, `p` ≤ 8;
- PBKDF2 `i` ≤ 5,000,000;
- bcrypt cost ≤ 16.

All verification runs in the one bounded pool.
**Warning signs:** No negative test that imports an over-cap hash.

### Pitfall 2: "Refuse weak parameters" vs real migrations
**What goes wrong:** Floors set too high block legitimate migrations; no floors at all import trivially
crackable data unflagged.
**How to avoid:** Explicit, documented floors, reason code `weak_parameters`. Proposed:
- bcrypt cost ≥ 4 (format minimum), with a `weak` flag below 10;
- PBKDF2 ≥ 1,000 iterations (the RFC 8018 §4.2 recommended minimum), with a `weak` flag below 100,000;
- salt ≥ 8 bytes for PBKDF2 and salted SHA-2;
- refuse unsalted digests, MD5 and SHA-1 plain digests, bcrypt `$2x$` (the bugged variant, which the `bcrypt`
  crate *accepts*, so check the prefix yourself) and unknown schemes.

Salted SHA-2 is single-iteration by nature. Accept it (it is in the requirement), report it as `weak`, and it
is rehashed at first login. The owner confirms the numbers (Open Questions).

### Pitfall 3: bcrypt 72-byte truncation
**What goes wrong:** `bcrypt::verify` truncates passwords past 72 bytes, as most source systems did;
`non_truncating_verify` errors instead.
**How to avoid:** Use `verify`, so behaviour matches the source system, and document it. After the first login
the password lives as Argon2id over the full input.

### Pitfall 4: Rehash race overwrites a fresh password change
**How to avoid:** CAS on the old credential value (new `UserRepo` method). Contract test with two concurrent
writers.

### Pitfall 5: Timing oracle between schemes
**What goes wrong:** An unknown email takes the Argon2 dummy (about 20 ms) while a Firebase user takes scrypt
N=2^14 (about 50–100 ms). Timing then reveals "imported account".
**How to avoid:** This is accepted as inherent: the account exists in both cases, and the enumeration rule is
about unknown versus known accounts. Make sure an *unknown* email and a *known, wrong password* do not differ
by scheme: unknown emails always use the dummy. Document it. The rehash at first login removes the difference
over time.

### Pitfall 6: Pinned 1.0 migrations
See the Summary. Also add the new files to `released-migrations.sha256` **only at the 1.0 gate**, not
earlier.

### Pitfall 7: PAR request_uri that leaks or never expires
**How to avoid:** 32 random bytes (≥ 256 bits); store only the SHA-256. Lifetime 60 s, consumed once, purged by
the cleanup job. Negative tests:
- reuse;
- expiry (fake clock);
- another client's `client_id`;
- non-URN `request_uri`;
- PAR without client auth for a confidential client;
- `request_uri` inside the push;
- `aud` = PAR URL;
- `require_pushed_authorization_requests` client using plain `/authorize`.

### Pitfall 8: The headless browser mode breaks the CSRF model
**What goes wrong:** Relaxing Fetch-Metadata globally, or answering cookies cross-site.
**How to avoid:** The flows router gets its own layer: allow-listed origins only, credentialed CORS only for
them, the CSRF token in a custom header (which also forces a CORS preflight), JSON-only bodies
(`Content-Type: application/json`, else 415). The UI router keeps today's layer untouched. Negative tests:
foreign origin, missing CSRF, form-encoded body, native token used in browser mode and vice versa.

### Pitfall 9: Native headless becomes a password-collection API for third parties
**How to avoid:** Only clients flagged `headless_native`, which requires first-party (consent skip),
`require_pkce`, and an admin-only flag (never via DCR/CIMD: extend `is_registration_forbidden_*`). Start only
from a PAR `request_uri` bound to that client. Negative tests for a DCR client and a CIMD client.

### Pitfall 10: Export leaks secrets or other people's data
**How to avoid:** Allow-list DTOs (not `Serialize` on models). A test serializes a fully populated fixture
and asserts the absence of `$argon2`, `$2b$`, `$anvil-`, sealed blobs, TOTP seeds, token hashes and admin
emails. Reuse the 06-26 plaintext-scan approach.

### Pitfall 11: Shared hidden files between parallel plans
`docs/openapi/admin-v1.json` and `admin-ui/src/api/schema.d.ts` (regenerated). Also
`scripts/check-security-tests.sh`, `model/audit.rs` (`AuditAction::ALL`, `as_str`/`parse` and the webhook
mapping: three places), `ports.rs`, `layers/ratelimit.rs`, `protocol/discovery.rs`, the Fluent catalogs
(`en`, `de`), workspace `Cargo.toml`/`Cargo.lock` and `deny.toml`. Put all port, migration and audit-action
additions in the foundation plan. Serialize the admin-API plans, or give one plan ownership of
`openapi-update` + `schema.d.ts`. The gate plan merges the security map.

### Pitfall 12: Certification logs are published
OIDF publishes the full logs with the certification. Use a throwaway deployment with fresh keys and clients,
and revoke them after submission, as the OIDF submission page advises.

### Pitfall 13: Review findings disclosed early
**How to avoid:** The tracker lives in GitHub draft security advisories (private) or the owner's private
channel. The repo gets only a public summary after fixes ship. The gap plan's commits must not describe
exploit details before release.

### Pitfall 14: SAML graduation by accident
SAML stays behind `saml_experimental` until the review **and** the real-IdP interop checklist are both done.
Removing the flag is an owner decision recorded in D4, not part of a feature plan.

## Code Examples

### Firebase scrypt verify (sketch; check API names against crate docs when implementing)
```rust
// Source: firebase/scrypt main.c + lib/scryptenc/scryptenc.c (algorithm); vectors from tests/01-known-value.sh
fn firebase_verify(pw: &[u8], salt: &[u8], sep: &[u8], signer_key: &[u8], rounds: u32, mem_cost: u8,
                   expected: &[u8]) -> Option<bool> {  // None = parameter/setup error (caller fails closed)
    let mut s = Vec::with_capacity(salt.len() + sep.len());
    s.extend_from_slice(salt); s.extend_from_slice(sep);
    let mut dk = zeroize::Zeroizing::new([0u8; 64]);
    let params = scrypt::Params::new(mem_cost, rounds, 1 /*, len per 0.12 API */).ok()?; // caps checked before
    scrypt::scrypt(pw, &s, &params, &mut *dk).ok()?;
    let key = aws_lc_rs::cipher::UnboundCipherKey::new(&aws_lc_rs::cipher::AES_256, &dk[..32]).ok()?;
    let ctr = aws_lc_rs::cipher::DecryptingKey::ctr(key).ok()?;          // CTR: decrypt == encrypt
    let mut buf = signer_key.to_vec();
    let iv = aws_lc_rs::iv::FixedLength::from([0u8; 16]);
    ctr.decrypt(&mut buf, aws_lc_rs::cipher::DecryptionContext::Iv128(iv)).ok()?;
    Some(subtle::ConstantTimeEq::ct_eq(buf.as_slice(), expected).into())
}
```

### Known-answer vectors (primary sources; the ones marked ✓ were recomputed locally on 2026-11-26)
| Scheme | Inputs | Expected | Source |
|---|---|---|---|
| Firebase scrypt ✓ | signer key `jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==`, sep `Bw==`, rounds 8, mem_cost 14, salt `42xEC+ixf3L2lw==`, pw `user1password` | `lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==` | firebase/scrypt README |
| Firebase scrypt ✓ | same, pw `hunter2` | `70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==` | firebase/scrypt tests/01-known-value.sh |
| scrypt ✓ | P="", S="", N=16, r=1, p=1, dkLen=64 | `77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906` | RFC 7914 §12 |
| scrypt ✓ | P="password", S="NaCl", N=1024, r=8, p=16, 64 | `fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640` | RFC 7914 §12 |
| PBKDF2-HMAC-SHA256 ✓ | P="passwd", S="salt", c=1, 64 | `55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783` | RFC 7914 §11 |
| PBKDF2-HMAC-SHA1 ✓ | P="password", S="salt", c=1 / 4096, 20 | `0c60c80f961f0e71f3a9b524af6012062fe037a6` / `4b007901b765489abead49d926f721d065a429c1` | RFC 6070 (RFC 8018 has no vectors) |
| bcrypt ✓ | pw `U*U` | `$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW` verifies | Openwall crypt_blowfish test vectors |
| Argon2i (PHC string) | pw `password`, salt `somesalt`, t=2, m=65536, p=4, len 24 | `$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | P-H-C/phc-winner-argon2 README |
| Argon2d/i/id raw | P=32×0x01, S=16×0x02, K=8×0x03, X=12×0x04, m=32, t=3, p=4, tag 32 | d: `512b391b…4acb`, i: `c814d9d1…6ce8`, id: `0d640df5…e659` (full values in RFC 9106 §5) | RFC 9106 §5 (needs the raw API with secret + AD, not PHC) |
| SHA-256 / SHA-512 | "abc" | `ba7816bf…f20015ad` / `ddaf35a1…a54ca49f` | FIPS 180-4 examples; build salted vectors from these |

### PAR consume (both backends, mirrors `consume_code`)
```sql
UPDATE pushed_authorization_request
   SET consumed_at = ?3
 WHERE tenant_id = ?1 AND uri_hash = ?2 AND consumed_at IS NULL AND expires_at > ?3
RETURNING client_id, params, expires_at;
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| RFC 9126: the AS accepts issuer, token-endpoint or PAR-endpoint URL as client-assertion `aud` | Issuer is the sole `aud` (RFC 10070, updates RFC 7523 and RFC 9126) | Nov 2026 | Already enforced; add a PAR-specific negative test |
| Native apps embed web views or collect passwords ad hoc | Browser-based flow (RFC 8252); "first-party apps" challenge endpoint as an IETF draft (-04, WG consensus, not an RFC) | ongoing | Native headless limited to first-party, PAR + PKCE bound; don't claim draft conformance |
| OIDF certification fee | OpenID Connect certification $700 (member) / $3,500 (non-member) per new deployment, multiple profiles per calendar year; open-source waiver for OIDF members whose primary maintainers are unpaid | fee page current on 2026-11-26 ("subject to change") | Owner decision on membership and waiver |

**Deprecated/outdated:**
- Accepting multiple audiences in client assertions (see above).
- bcrypt `$2x$`: refuse at import.

## Certification (OIDC-23) — what a submission needs (MEDIUM; checked on openid.net 2026-11-26)

1. All five plans "FINISHED". Warnings are allowed. Our expected skip
   (`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`) is a SKIPPED result for an
   unsupported optional feature; confirm acceptability with the OIDF if unsure. Form Post must be run "for each
   of basic/hybrid/implicit that your system supports" (only basic here). The logout profiles run "for each
   response type" supported (only `code`). Other profiles need one run per plan.
2. The certification package's "Conformance Test Suite Software" field must read `www.certification.openid.net`
   plus the suite version. That points to running on the **hosted** suite, which needs a **publicly reachable
   HTTPS deployment** of the release candidate. The self-hosted CI suite is evidence for us, not the submission
   artefact. Owner: provision a throwaway public instance and run the plans there; "Publish for certification"
   gives one ZIP per plan.
3. Payment code from the OIDF certification payment page, or the **open-source waiver**. Waiver criteria: OIDF
   member in good standing, affiliated with the deployment, no primary maintainer paid for project work, one
   waiver per year covering OP profiles submitted together, requested at certification@oidf.org.
4. Submission form at submissions.openid.net. It asks for the entity name, "Deployment Name & Version", the
   declaration signer and the authorized contact, which is personal data and must **never be committed**.
   Upload the ZIPs, then sign the DocuSign "Declaration of Conformance".
5. Publication on the certified list. "A different protocol endpoint is a different deployment and requires a
   separate certification." Certifications do not expire; the date is part of the record.

Prepared by plans (committed): `docs/CERTIFICATION.md`, covering the runbook, plan list with exact variant
strings (from `tests/conformance/README.md`), the setup script reuse against a public host, the evidence
checklist and the post-submission key and client revocation. CI also retains the `conformance-results`
artifact for the release commit (raise retention for the tag run).

## Security policy and external review (SEC-08)

- `SECURITY.md` (root):
  - Supported versions: 1.0.x supported; 0.x unsupported after 1.0.
  - Reporting through **GitHub private vulnerability reporting**. The owner enables it under Settings →
    Advanced Security → Private vulnerability reporting (only repo owners and admins can). Add a placeholder
    for an alternative contact the owner fills.
  - Coordinated disclosure: acknowledgement and fix targets, advisory + CVE via GitHub Security Advisories,
    and "fixes ship in the open-source release" (NFR-SEC-8).
  - No personal data.
- Review package (committed, public-safe):
  - `docs/SECURITY-REVIEW-SCOPE.md`: the in-scope surfaces, below.
  - `docs/THREAT-MODEL.md`: assets, trust boundaries, attacker models, existing controls mapped to tests via
    the security map.
  - A reviewer brief: how to run, the test accounts setup script, known limitations.

  In-scope surfaces:
  - every protocol endpoint, including PAR and DCR/CIMD;
  - headless API both modes;
  - the flow engine and session handling;
  - password import verifiers and caps;
  - export redaction;
  - admin API authZ (RBAC, org admins, scope bounding);
  - **SAML SP** (corpus, profile checks, the bergshamra/uppsala stack and the chrono exception);
  - KEK sealing and key rotation;
  - the SSRF guard;
  - CSRF and CSP;
  - multi-tenant isolation;
  - webhooks;
  - rate limiting;
  - migrations and backup/restore;
  - supply chain (deny policy, release pipeline, image).
- Findings tracker: a private GitHub draft advisory per finding (with a temporary private fork for fixes) or an
  owner-held sheet. The repo only gets a public "review completed on <date>, N findings fixed in vX" note after
  release.

## Tenant-restricted system admins (Phase 6 carry-over) — recommendation: defer past 1.0

It is not a numbered 1.0 requirement. ARCHITECTURE §10.3 notes it "would need a second principal shape checked
on every tenant-level and installation route". It is security-sensitive surface added right before the
external review, and the org-admin principal already covers delegated administration per organization. Defer
to 1.x and record the justification in ARCHITECTURE §19/§20 and UPGRADING "Limitations in 1.0". The owner can
overrule (Open Questions).

## Owner-only checkpoints (explicit, never faked)

1. **Approve the legacy-hash crypto exception** (RustCrypto `scrypt`/`bcrypt`, scoped wrappers), and
   complete the pending `chrono` exception review (D4/Q2).
2. **Enable GitHub private vulnerability reporting** and fill the SECURITY.md alternative contact.
3. **Commission the external security review.** Choose the reviewer, budget and dates; hand over the scope
   package; receive findings privately. A gap plan fixes them; the owner confirms "review completed".
4. **Real-IdP SAML interop checklist** (`docs/SAML.md`) and the decision whether `saml_experimental` stays on
   by default after the review.
5. **AUTH-07 real-provider checklist** (04-33), still pending. It should be closed before the 1.0 tag.
6. **OpenID certification:** OIDF membership/fee/waiver decision; a public throwaway deployment; run the five
   plans on the hosted suite; submit ZIPs, payment code and DocuSign; afterwards revoke the deployment's keys
   and clients.
7. **Release:** add the final 1.0 migrations to `released-migrations.sha256`, set version 1.0.0, tag
   `v1.0.0`, publish binaries and image (existing `release.yml`), enable and publish GitHub Pages.

## Open Questions (owner decision needed)

1. **Crypto exception.** Approve RustCrypto `scrypt` 0.12.0 + `bcrypt` 0.19.3 (blowfish, salsa20 scoped via
   `wrappers`) for verification of imported hashes only? Without them, scrypt, Firebase and bcrypt import
   cannot be built without unsafe FFI. Recommendation: approve.
2. **Certification logistics.** OIDF membership (needed for both the member fee and the open-source waiver)?
   Does the project meet the waiver's "no paid primary maintainer" criterion? Which public hostname, entity
   name and "Deployment Name & Version" should be used? (The hosted-suite requirement is inferred from the
   package field; confirm with certification@oidf.org.)
3. **External reviewer.** Who reviews, with what budget and timeline? Is SAML graduation in scope as a review
   outcome?
4. **Password hashes in bulk export.** PRD principle "Easy to leave … everything is exportable" pulls toward
   exporting Argon2id PHC strings for migration away. CONTEXT says "secrets never exported" and "imported
   hashes never … exported in clear". Recommendation: GDPR export never includes hashes. Bulk export may
   include PHC strings only behind an explicit CLI-only flag (`--include-password-hashes`), audited, never via
   the HTTP API. Default excluded. Needs an owner yes or no.
5. **Headless browser mode origins.** Allow cross-origin, same-site SPAs through a per-tenant origin allow-list
   (recommended), or only same-origin deployments behind a reverse proxy (simpler, no CORS)?
6. **Native headless.** Accept the PAR + PKCE + first-party-only design returning the code in JSON (shaped like
   the IETF first-party-apps draft, which is not yet an RFC)? Or limit UI-05 to browser SPAs for 1.0 and keep
   native apps on RFC 8252 browser flows? Recommendation: build it, admin-only flag, documented as AnvilID's
   own API.
7. **What is an "agent client"?** An explicit `client_kind = agent` set by admins plus a DCR/CIMD policy
   default, or derived purely from provenance (DCR/CIMD = agent)? Recommendation: explicit marker, DCR/CIMD
   policy may default it, and agents can never skip consent.
8. **Tenant-restricted system admins.** Defer to 1.x (recommended) or build in Phase 7?
9. **Release history.** Only `v0.1.0` and `v0.2.0` are tagged. Should 0.3, 0.4 and 1.0.0-beta.1 be tagged
   before 1.0 so the "upgrade from 0.4" promise refers to real artefacts? Was beta.1 distributed? (The
   beta.1 → 1.0 schema test is recommended either way.)
10. **Import floors and caps.** Confirm the proposed numbers (Pitfalls 1–2).
11. **Preserve source user ids?** Allow an optional `id` (UUID) in import so `sub` survives an
    AnvilID-to-AnvilID migration? Recommendation: yes, UUID only, conflict-checked. Other providers' ids go
    into a custom attribute.
12. **Migration guide sources** (PRD ADM-8 "guides for common source providers"). Which providers? Each guide
    must be checked against that vendor's current export documentation before it is committed (public-repo
    rule). Firebase is verifiable from its published scrypt repo.
13. **OpenAPI breaking-change tool.** oasdiff's OpenAPI 3.1 support was described as beta in its README (LOW).
    Accept oasdiff in CI, or use the minimal in-repo set-comparison test?

## Suggested plan decomposition (discretion; maximizes parallelism)

| Wave | Plan | Scope | Owns (hidden shared files) |
|---|---|---|---|
| 1 | 07-01 Foundations | Migrations SQLite `0010`, Postgres `0008`: `pushed_authorization_request`, `password_hash_profile`, client columns `require_pushed_authorization_requests`, `client_kind`, `headless_native`, tenant settings `headless`/`par`. Every new port method (`GrantRepo` PAR create/consume/purge, `UserRepo::replace_password_if`, profile repo, export reads). New `AuditAction`s (`users_imported`, `user_exported`, `par_*` if any). Contract suites. Upgrade tests 0.4 → final and beta.1 → final on both backends | `ports.rs`, `model/audit.rs`, migrations, `tests/upgrade.rs` ×2 |
| 1 | 07-02 Password verifiers | `adapters/password/*`, the dispatcher replacing direct `Argon2Pool` use, caps, KATs, `policy/password_import.rs`, deny.toml + ARCH §2 text, fuzz target `password_hash_parse` | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `fuzz/` |
| 1 | 07-03 Security policy + review package | SECURITY.md, THREAT-MODEL, REVIEW-SCOPE, brief; **checkpoint: owner enables private reporting** | docs only |
| 1 | 07-04 Docs site skeleton | book.toml, SUMMARY, `docs.yml`, `check-docs-site.sh` | `.github/workflows/docs.yml` |
| 2 | 07-05 PAR | core + `/par` + authorize integration + discovery + DCR/config/admin field + security tests | `protocol/discovery.rs`, `layers/ratelimit.rs` |
| 2 | 07-06 Import | `UserImportService`, admin route + body-limit branch, CLI `users import`, hash profiles admin API, rehash CAS | `docs/openapi/admin-v1.json` (serialize with 07-07: run after it, or merge in one plan) |
| 2 | 07-07 Export | `UserExportService`, single/bulk/GDPR routes + CLI `users export`, redaction tests, scope `admin:users:export` | admin OpenAPI (see above) |
| 2 | 07-08 Headless core + browser mode | `flow_driver` extraction (UI unchanged, all e2e green), `FormDescription.methods`, `/api/flows/v1` browser mode, flows CORS/Fetch-Metadata variant, `flows-v1.json` + drift test | `ui/*` handlers, `layers/csrf.rs`, `layers/cors.rs` |
| 2 | 07-09 Agent consent | `client_kind`, provenance text, new/granted scope split, template + Fluent `en`/`de`, e2e `consent-agent.spec.ts` | `consent.html`, locales |
| 3 | 07-10 Headless native | flow-token binding, PAR-bound start, code-in-JSON completion, `headless_native` flag rules (DCR/CIMD forbidden), security tests | `api_flows/*` |
| 3 | 07-11 Console | import (upload + report), export buttons, PAR/agent/headless client fields, hash profiles page; `schema.d.ts` regen; e2e | `admin-ui/**` |
| 3 | 07-12 Compatibility policy | `docs/COMPATIBILITY.md`, OpenAPI baselines + breaking check, config version test, deprecation helpers (header/warning), UPGRADING 1.0 final | `docs/openapi/*.baseline-1.0.json` |
| 4 | 07-13 Docs content | Install, integrations (OIDC app, SPA, headless, MCP), migration guides (Firebase + owner-picked sources), IMPORT-EXPORT, PAR, HEADLESS | `docs/**` |
| 4 | 07-14 Certification package | `docs/CERTIFICATION.md`, conformance artifact retention, discovery check with PAR metadata in the Config OP run; **checkpoint: owner certification** | `.github/workflows/conformance.yml` |
| 5 | 07-15 Phase gate | security map entries, `just ci`, e2e both backends, conformance `all`, fuzz on release commit, requirements ticks (OIDC-23 and SEC-08 stay unticked until the owner checkpoints close); **checkpoints: external review commissioned, SAML interop, AUTH-07, release tag + Pages** | `scripts/check-security-tests.sh`, `REQUIREMENTS.md` |
| later | 07-16+ Review gap plan(s) | Created when findings exist; private until fixed | — |

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `cargo test`: unit tests (KATs in-file), the storage contract via `storage_contract_tests!` (SQLite + Postgres testcontainers), HTTP integration in `crates/anvil-web/tests`, binary/CLI tests in `crates/anvilid/tests`; proptest; Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance/run.sh all`); cargo-fuzz (`fuzz/`). **New:** mdBook build + `scripts/check-docs-site.sh`; OpenAPI breaking check |
| Config file | `justfile`, `tests/e2e/playwright.config.ts`, `scripts/check-security-tests.sh`, `scripts/check-migrations.sh`, `fuzz/Cargo.toml`, new `book.toml` |
| Quick run command | `cargo test -p anvil-web --lib adapters::password` / `cargo test -p anvil-web --test <file>` / `cargo test -p anvil-storage-sqlite --test contract par` |
| Full suite command | `just ci` + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all` + `mdbook build && scripts/check-docs-site.sh` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OIDC-18 | `/par` 201 with URN + `expires_in`; stored hashed; client auth required (confidential), secret/basic/post/private_key_jwt; `aud` = PAR URL refused; jti replay shared with `/token`; `request_uri` in body refused; `request` → `request_not_supported`; no interaction errors | integration (security) | `cargo test -p anvil-web --test security_par` | ❌ |
| OIDC-18 | `/authorize?request_uri`: single use (concurrent: one winner), expiry (fake clock), client_id mismatch, non-URN, unknown → error page without redirect; front-channel params ignored; client policy re-checked; `require_pushed_authorization_requests` enforced; discovery metadata | contract + integration | `cargo test -p anvil-storage-sqlite --test contract par`; `cargo test -p anvil-web --test par` / `--test discovery` (extend) | ❌ / ✅ extend |
| OIDC-18 | DCR accepts and echoes `require_pushed_authorization_requests`; config YAML round trip | integration | `cargo test -p anvil-web --test dcr` (extend); `cargo test -p anvilid --test tenant_config` (extend) | ✅ extend |
| OIDC-23 | Five plans pass with PAR metadata in discovery; no new expected failures | conformance | `tests/conformance/run.sh all` (CI `conformance.yml`) | ✅ |
| OIDC-23 | Certification filed | manual (owner checkpoint) | none: owner submits on submissions.openid.net | n/a |
| UI-05 | Browser mode: start/get/submit login, registration, recovery, verification with JSON DTO; CSRF header required; foreign origin 403; form-encoded body 415; credentialed CORS only for allow-listed origins; session cookie + `continue_to`; throttling and CAPTCHA identical to UI (same `flow_driver`) | integration (security) | `cargo test -p anvil-web --test headless_flows` / `--test security_headless` | ❌ |
| UI-05 | Native mode: start only from PAR `request_uri` of a `headless_native` client; flow token required, wrong token refused, cookie-bound flow refused with a token and vice versa; code in JSON redeemable only with the right `code_verifier`; browser signals refused; DCR/CIMD cannot get `headless_native` | integration (security) | `cargo test -p anvil-web --test headless_native` / `--test security_headless` | ❌ |
| UI-05 | `docs/openapi/flows-v1.json` equals generated | drift | `cargo test -p anvil-web --test openapi_drift` (extend) | ✅ extend |
| UI-05 | Built-in UI unchanged after the `flow_driver` extraction | e2e | `tests/e2e/run.sh sqlite` (login, nojs, mfa, passkey, email-code specs) | ✅ |
| UI-05 | Sample SPA drives login through the API | e2e | `specs/headless.spec.ts` | ❌ |
| AGT-03 | Agent badge and provenance per `ClientSource`; CIMD host shown, name unverified; resources listed | integration + e2e | `cargo test -p anvil-web --test consent_agent`; `specs/consent-agent.spec.ts` | ❌ |
| AGT-03 | Step-up shows only new scopes and resources; Allow stores union; Deny keeps old grant; `prompt=none` + new scope → `consent_required`; agent clients cannot be `skip_first_party` | unit + integration | `cargo test -p anvil-core flow::consent service::consent`; `--test consent_agent` | ✅ extend / ❌ |
| ADM-08 | KATs per scheme (table above); `$2x$` refused; caps refused at import and fail closed at verify; floors → `weak_parameters`; unknown scheme refused; constant-time compare used; parse fuzz | unit + fuzz | `cargo test -p anvil-web --lib adapters::password`; `cargo test -p anvil-core --lib policy::password_import`; `just fuzz password_hash_parse 60` | ❌ |
| ADM-08 | Import: idempotent rerun (`unchanged`), conflict not overwritten, dry run writes nothing, audited without hash, Firebase signer key sealed (plaintext scan), per-request cap, body-limit branch | integration + contract | `cargo test -p anvil-web --test user_import` / `--test security_import`; `cargo test -p anvil-storage-sqlite --test contract password_profiles`; plaintext scan test (extend 06-26) | ❌ / ✅ extend |
| ADM-08 | First login with an imported hash succeeds, credential becomes Argon2id; wrong password fails; rehash CAS loses to a concurrent change | integration + contract | `cargo test -p anvil-web --test user_import`; contract `users` (extend) | ❌ / ✅ extend |
| ADM-08 | CLI `anvilid users import` same outcomes | binary | `cargo test -p anvilid --test users_cli` | ❌ |
| ADM-09 | Single, bulk (NDJSON streaming over pages, > 1 page), GDPR bundle contents; scope `admin:users:export` enforced; audit `user_exported`; serialized fixture contains no hashes, seeds, sealed blobs, token hashes or admin identities | integration (security) | `cargo test -p anvil-web --test user_export` / `--test security_export` | ❌ |
| ADM-09 | CLI `anvilid users export` | binary | `cargo test -p anvilid --test users_cli` | ❌ |
| QUAL-03 | 0.4 → final 1.0 and beta.1 → final 1.0 keep every row; contract suite on upgraded DBs | upgrade | `cargo test -p anvil-storage-sqlite --test upgrade`; `cargo test -p anvil-storage-postgres --test upgrade` | ✅ extend |
| QUAL-03 | No breaking change vs the 1.0 baseline (admin + flows); config `version: 1` enforced; released migrations immutable | lint | `scripts/check-api-compat.sh`; `scripts/check-migrations.sh` | ❌ / ✅ |
| QUAL-03 / M5 | Docs site builds, no external scripts/trackers, no `research/` in output, no broken internal links | CI | `mdbook build && scripts/check-docs-site.sh` | ❌ |
| SEC-08 | SECURITY.md present with supported-versions table and reporting section; no personal contact | lint | `scripts/check-docs-site.sh` (or a small check in `just ci`) | ❌ |
| SEC-08 | External review completed, findings fixed | manual (owner checkpoint) + gap plan tests | per finding: a negative test added to the security map | n/a |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate> --lib` plus the touched `--test <file>` (each < 30 s). Postgres
  testcontainers only when Docker is up; say so when skipped.
- **Per wave merge:** `just ci`.
- **Phase gate:** `just ci` green; e2e on sqlite and postgres; conformance `all` green with no new expected
  failures; docs site check green; fuzz dispatched on the release commit; then `/gsd:verify-work`. OIDC-23 and
  SEC-08 stay open until the owner checkpoints close.

### Wave 0 Gaps
- [ ] `crates/anvil-storage/src/contract/{par,password_profiles,user_export}.rs` + `users.rs` extension (CAS
  rehash, concurrency)
- [ ] Upgrade fixtures: beta.1 (schema after SQLite 0009 / Postgres 0007) → final, both `tests/upgrade.rs`
- [ ] `crates/anvil-web/tests/support`: PAR helper (push + authorize), headless client helpers (browser cookie
  jar + header; native token), import fixture builder producing each scheme from the KAT table
- [ ] Fuzz target `password_hash_parse` (and `par_body` if the push parser differs from `authorize_parse`)
- [ ] `tests/e2e/specs/{headless,consent-agent,console-users-import}.spec.ts`; a minimal same-site SPA fixture
  for headless
- [ ] `scripts/check-docs-site.sh`, `scripts/check-api-compat.sh`, `.github/workflows/docs.yml`
- [ ] `scripts/check-security-tests.sh` entries for every new control: PAR (single use, expiry, client binding,
  auth, aud, require flag), headless (CSRF header, origin allow-list, content type, token binding, native
  eligibility, browser-signal refusal), import (caps, floors, `$2x$`, unknown scheme, redaction, sealed
  profile), export (scope, redaction), agent consent (no skip for agents, step-up deny keeps grant)
- [ ] Framework installs: mdBook 0.5.4 in CI; oasdiff if chosen

## Sources

### Primary (HIGH confidence)
- RFC 9126 (rfc-editor.org/rfc/rfc9126) — PAR endpoint, response, errors, single use, metadata, security considerations
- RFC 10070 (datatracker draft-ietf-oauth-rfc7523bis → RFC 10070, Nov 2026) — issuer as sole client-assertion `aud`; updates RFC 9126
- firebase/scrypt (github.com/firebase/scrypt: README.md, main.c, lib/scryptenc/scryptenc.c, tests/01-known-value.sh) — algorithm and vectors, recomputed locally
- RFC 7914 §11–12, RFC 6070 — scrypt and PBKDF2 vectors, recomputed locally with Python hashlib
- RFC 9106 §5 (rfc-editor.org/rfc/rfc9106.txt) — Argon2 tags; P-H-C/phc-winner-argon2 README — PHC-encoded Argon2i vector
- Openwall crypt_blowfish vector `$2a$05$CCC…` — verified locally with Python bcrypt
- docs.rs aws-lc-rs 1.19.0 (modules; `pbkdf2` algorithms; `cipher` CTR with explicit IV on decrypt)
- crates.io API (2026-11-26): bcrypt 0.19.3 deps/features, scrypt 0.12.0 deps/features, mdbook 0.5.4; GitHub releases: mdBook v0.5.4, Zola v0.23.6
- Rust-bcrypt source (`src/lib.rs`): accepts `2a/2b/2y/2x`, `verify` truncates, `subtle` compare
- Repository: `crates/anvil-web/src/adapters/argon2.rs`, `crates/anvil-core/src/service/flow.rs` (single verify site, rehash), `crates/anvil-core/src/flow/{consent,form,engine}.rs`, `crates/anvil-core/src/service/consent.rs`, `crates/anvil-core/src/oauth/authorize_request.rs`, `crates/anvil-web/src/layers/{csrf,cors,ratelimit}.rs`, `crates/anvil-jose/src/client_assertion.rs`, `scripts/released-migrations.sha256`, `scripts/check-migrations.sh`, `crates/anvil-web/tests/openapi_drift.rs`, `tests/conformance/*`, `deny.toml`, `Cargo.lock`
- GDPR Art. 15 and Art. 20 text (gdpr-info.eu)

### Secondary (MEDIUM confidence)
- openid.net/certification/fees, …/how-to-submit-your-certification-request, …/op_submission, …/open-source-project-certification-policy, …/what-is-self-certification-faq — fees, submission steps, hosted-suite field, waiver criteria (pages can change; the fee page says so)
- datatracker draft-ietf-oauth-first-party-apps-04 — design reference only, not an RFC
- docs.github.com, configuring private vulnerability reporting — enablement steps

### Tertiary (LOW confidence, flagged for validation)
- oasdiff OpenAPI 3.1 maturity (README "beta" vs a 2026 blog)
- mdBook output free of external requests by default: verify with `check-docs-site.sh` on the built site
- `scrypt` 0.12 `Params::new` signature and `argon2` 0.6 verifying argon2i/argon2d PHC through the existing `verify_password` path: confirm with the KATs at implementation time

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions and deps from crates.io; aws-lc-rs modules from docs.rs; the policy impact computed from Cargo.lock.
- Architecture: HIGH for PAR, import, export and consent (code inspected; the specs verified). MEDIUM for the headless binding design (sound against the existing CSRF model, but a new surface the external review must cover).
- Pitfalls: HIGH. Most come from code facts: pinned migrations, the Argon2 parameter trust, the CHECK columns, the bcrypt `$2x$` acceptance.
- Certification logistics: MEDIUM. Official pages read, but the hosted-suite requirement is inferred from the package field.

**Research date:** 2026-11-26
**Valid until:** 2026-12-26 (fees, draft statuses and tool versions move; the code facts hold until the plans change them)
