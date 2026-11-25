# Phase 3: Release 0.2 "Secure by default" - Research

**Researched:** 2026-11-25
**Domain:** Passkeys/TOTP, OAuth token lifecycle (RFC 7662/7009, RFC 9068), JOSE multi-algorithm signing, rate limiting, React admin SPA embedded in a Rust binary, migration safety
**Confidence:** HIGH for the crate APIs (crate sources for webauthn-rs 0.6.2, totp-rs 6.0.0, jsonwebtoken 12.0.0, governor 0.10.4, rust-embed 8.14.0 and sqlx-core 0.9.1 were downloaded and read), MEDIUM for frontend tooling and interop, LOW where flagged

## Summary

Phase 3 builds on the 0.1 core (Phase 2) and adds no new architecture. It adds features to existing services (`AuthorizeService`, `TokenService`, `FlowEngine`, `SessionService`, `KeyService`, `ConsentService`, `AuditService`), one new cross-cutting layer (the keyed limiter and the trusted-proxy client-IP extractor), and a new front-end project (`admin-ui/`). The locked stack works, but reading the source turned up several facts that **contradict or refine the architecture docs**. Per CLAUDE.md, raise them before planning rather than diverge silently:

1. **webauthn-rs 0.6.2 depends on the RustCrypto stack (non-optional).** `webauthn-rs-core` depends on `crypto-glue` 0.2.2, which pulls `rsa ^0.10.0-rc.18`, `p256/p384/p521`, `aes-gcm`, `argon2 0.5`, `md5` and others. Phase 1's cargo-deny policy bans the RustCrypto `rsa` crate, so **`cargo deny check` will fail as soon as webauthn-rs is added.** WebAuthn only uses RSA to *verify* (public-key operations; the Marvin timing attack, RUSTSEC-2023-0071, concerns private-key decryption and signing). The fix is a cargo-deny `wrappers = ["crypto-glue"]` exception for `rsa`, plus an ARCHITECTURE.md §2 note that "single crypto backend" applies to *our* signing and encryption, with RustCrypto confined to webauthn verification. No aws-lc-based Rust WebAuthn server library exists to replace it.
2. **jsonwebtoken 12 cannot emit `"alg":"Ed25519"`.** Its `Algorithm` enum has only `EdDSA`, `Header.alg` is that enum, `jwk::KeyAlgorithm` has no `Ed25519`, and `Jwk::thumbprint` returns an error for an `EllipticCurve` parameter with curve Ed25519 (it does work for `OctetKeyPair`). `anvil-jose` must therefore serialize JWS headers and JWKs with its own serde types. It can still use jsonwebtoken's public `crypto::sign(msg, &EncodingKey, Algorithm::EdDSA)` for the signature bytes, which are identical for `EdDSA` and `Ed25519`.
3. **Usernameless passkeys need two adjustments.** (a) The webauthn-rs feature `conditional-ui` gates `start_discoverable_authentication`, `identify_discoverable_authentication` and `finish_discoverable_authentication_v2`. (b) `start_passkey_registration` hard-codes `residentKey: "discouraged"`. To create discoverable credentials, set `ccr.public_key.authenticator_selection.resident_key = Some(Required)` and `require_resident_key = true` on the returned challenge. This is safe: the server-side `RegistrationState` ignores `require_resident_key` when verifying.
4. **Recovery codes vs §6.2.** §6.2 says "SHA-256 of a 256-bit random value". A user cannot type a 256-bit code. Use codes of about 80 bits, hashed with **HMAC-SHA-256 under a KEK-derived pepper** (HKDF info `"recovery-code"`), so a leaked database cannot be brute-forced offline. Consume them atomically (§1 principle 4) from one row per code, not from a JSON list. Both points need a doc update.
5. **Atomic counters.** The WebAuthn signature counter and the TOTP last-used step both need compare-and-swap updates (`… WHERE counter < ?`). Store them in a plain integer column on `credential`, not inside the encrypted `data` blob.
6. **totp-rs 6 `qr` feature** pulls `qrcodegen-image`, which pulls the `image` 0.25 crate (binary size). Use `otpauth` only and render an SVG QR code with `qrcodegen` 1.8. The research note's features (`qr`, `gen_secret`) should change.
7. **rust-embed `compression`** compresses into the binary with include-flate and decompresses on access. It does *not* serve pre-compressed brotli/gzip as §10.4 describes. Have Vite emit `.br`/`.gz` sidecar files and negotiate `Accept-Encoding` in our handler.
8. **TypeScript 7.0** is now `latest` on npm, but `openapi-typescript` 7.13 declares `peerDependencies: { typescript: "^5.x" }`. Pin TypeScript 5.9.x in `admin-ui/`.

**Primary recommendation:** Put all Phase 3 schema changes, storage-trait additions and audit-event variants in Wave 1. Then run the features in parallel on disjoint crates and modules (jose/keys, limiter/proxy, passkeys, TOTP, introspect/revoke, authorize: form_post + consent, sessions/account, mail templates, admin-ui). Finish with a verification wave: e2e with a CDP virtual authenticator and axe, the Form Post conformance plan, and the 0.1 → 0.2 upgrade test.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
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

### Deferred Ideas (OUT OF SCOPE)
- Social login, email OTP/magic link, MFA policy, logout profiles, theming, i18n — Phase 4
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| OIDC-10 | Introspection (RFC 7662) and revocation (RFC 7009) | §"Introspection & revocation" pattern; JWT revocation via `token_family`; `active:false` rules; client auth through the existing `ClientAuthenticator` |
| OIDC-11 | RS256 / ES256 / Ed25519 signing | aws-lc-rs key generation; Ed25519 JWS/JWK built in our own `anvil-jose` code (jsonwebtoken lacks `Ed25519`); `at_hash` uses SHA-512 for Ed25519; interop caveats |
| OIDC-13 | Consent screen, remembered, revocable | `ConsentService` + `consent_grant`; subset check; revoking consent revokes token families; minimal `/ui/account/apps`; conformance test client set to `skip_first_party` |
| OIDC-15 | JWT (RFC 9068) or opaque access tokens per client, audience-restricted | `client.token_format`; opaque stored hashed in `access_token`; JWT carries a family reference for revocation; audience open question |
| OIDC-25 | `query` and `form_post` response modes | Form Post plan = the entire Basic plan run with `response_mode=form_post`; auto-submit page using self-hosted JS; per-response CSP `form-action` |
| AUTH-04 | Passkeys incl. usernameless; clone detection | webauthn-rs 0.6.2 API, `conditional-ui` feature, resident-key override, server-side state in `flow`, counter CAS, `CredentialPossibleCompromise` handling |
| AUTH-05 | TOTP + recovery codes as second factor | totp-rs 6 `Builder`/`check()` returns the matched step; CAS on last step; HMAC-peppered recovery codes; second-factor rate limit |
| AUTH-09 | Brute-force throttling per account and IP, progressive delays; CAPTCHA can be enabled | governor GCRA rate classes + a failure-backoff table in one `anvil-cache` limiter; (identifier, IP) and identifier tiers; Turnstile/hCaptcha opt-in with a CSP relaxation |
| AUTH-10 | List/revoke sessions; idle/absolute timeouts; admin revoke | `browser_session.idle_expires_at` sliding, throttled `last_seen_at` writes; user and admin revoke endpoints |
| UI-02 | WCAG 2.2 AA, responsive, password flow without JS | axe tags incl. `wcag22aa`; manual checks for criteria axe cannot test (3.3.8 accessible authentication, 2.4.11 focus not obscured); JS used only for passkeys and form_post |
| UI-07 | Editable email templates per tenant; SMTP config + test send | `email_template` table, minijinja with `fuel` limit + autoescape, compile-on-save, synchronous test send via lettre |
| ADM-04 | Audit of security events and admin actions; queryable; streamed as JSON | Typed `AuditAction` enum defined up front; same-transaction writes; `tracing` target `audit` to stdout; cursor pagination on the UUIDv7 id |
| SEC-02 | Keys generated at first start, KEK-encrypted, rotated on schedule with overlap | Rotation state machine, `job_lease`, two-statement promotion (partial unique index), JWKS `Cache-Control` tied to the prepublish window |
| SEC-05 | Auth and token endpoints rate limited by default | Route-class layer on by default; `retain_recent()` housekeeping; metrics |
| OPS-04 | Migrations auto-run, tested N-1→N, never destructive without a flag | `Migrator::run_to` (sqlx 0.9.1) + fixtures; checksum and immutability check against the previous release tag; `destructive` description marker + `--allow-destructive-migrations` |
| OPS-06 | Correct behind reverse proxies | Right-to-left trusted-CIDR walk over `Forwarded` / `X-Forwarded-For`; issuer and cookie security derived from `public_url`, never from headers |
</phase_requirements>

## Standard Stack

### Core (Rust; additions to the Phase 1/2 workspace)
| Library | Version | Purpose | Notes (verified) |
|---------|---------|---------|------------------|
| webauthn-rs | 0.6.2 | Passkey registration/authentication | Features: `danger-allow-state-serialisation`, `conditional-ui`. Default feature `attestation` can stay (unused). Pulls `crypto-glue` → RustCrypto incl. `rsa 0.10.0-rc` (see Summary #1) |
| totp-rs | 6.0.0 | RFC 6238 TOTP | `default-features = false, features = ["std", "otpauth", "zeroize"]`. Do **not** enable `qr` (pulls `image`) or `gen_secret` (use our own `Rng` trait for secrets) |
| qrcodegen | 1.8.0 | SVG QR for the otpauth URI | Pure Rust, no deps; render an `<svg>` server-side, so CSP needs no `img-src data:` |
| jsonwebtoken | 12.0.0 | RS256/ES256 encode/decode; raw `crypto::sign/verify` for Ed25519 | `default-features = false, features = ["aws_lc_rs"]` → the aws-lc provider is selected automatically (`CryptoProvider::try_get_default()` is `Some` when only one backend feature is on). Call it at startup to fail fast |
| aws-lc-rs | 1.19.0 | Key generation: `EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)`, `Ed25519KeyPair::generate_pkcs8(rng)` (PKCS#8 v2) | ES256 in jsonwebtoken uses `*_FIXED` (raw r‖s, 64 bytes), which is correct for JWS |
| governor | 0.10.4 | GCRA keyed rate limiting | `RateLimiter::keyed(quota)` / `DefaultKeyedRateLimiter<K>`, `check_key(&k)` → `Err(NotUntil)` with `wait_time_from(clock.now())`. Call `retain_recent()` periodically. `FakeRelativeClock` for deterministic tests |
| moka | 0.12.16 | TTL map for failure-backoff state (in-process) | Behind the `Cache` trait; Redis implementation in 0.4 |
| ipnet | 2.12.2 | Trusted proxy CIDR parsing/matching | Write our own extractor (about 150 lines + proptest) |
| rust-embed | 8.14.0 | Embed `admin-ui/dist` | Use `#[allow_missing = true]` (placeholder when dist is absent) and the `mime-guess` + `interpolate-folder-path` features; **not** `compression` (Summary #7). `debug-embed` off → debug builds read from disk |
| minijinja | 3.1.0 | Email templates (tenant-editable) | Enable `fuel` to bound template execution; autoescape HTML templates |
| lettre | 0.11.24 | SMTP test send | Already in the stack |
| sqlx | 0.9.1 | `Migrator::run_to(target, conn)` exists, for upgrade tests; `Migrator::with_migrations(vec)` for guard tests | Verified in sqlx-core 0.9.1 source |

### Admin console (npm; verified against registry `latest` on 2026-11-25)
| Package | Version | Purpose | Notes |
|---------|---------|---------|-------|
| react / react-dom | 19.3.x | UI | |
| vite | 8.3.x | Build | Node `^20.19 \|\| >=22.12`. Set `base: '/console/'` |
| @vitejs/plugin-react | 6.3.x | | Peer `vite ^8` |
| typescript | **5.9.3 (pin)** | Types | Summary #8. TS 7 (native port) is incompatible with tools that use the TS JS API |
| @tanstack/react-router + @tanstack/router-plugin | 1.170.x / 1.169.x | File-based routing, `basepath: '/console'` | |
| @tanstack/react-query | 5.108.x | Server state | |
| @tanstack/react-table | **9.3.x** | Tables | v9 (Aug 2026) renamed `useReactTable` → `useTable`, requires a `features` option (`stockFeatures` for v8-like behavior), and moved state to a store. shadcn data-table examples may still show v8. Adapt or use the v9 `useLegacyTable` shim only temporarily |
| shadcn (CLI) | 4.23.x | Copies Radix-based components into `src/components/ui` | Tailwind v4 (`tailwindcss` + `@tailwindcss/vite` 4.3.x) |
| openapi-typescript | 7.13.0 | `paths` types from the OpenAPI 3.1 spec | Peer TS ^5 |
| openapi-fetch | 0.17.0 | Typed fetch client over those types | Optional `openapi-react-query` 0.5.4 for Query bindings |
| oidc-client-ts | 3.5.0 | Auth code + PKCE for the console (public client) | Handles state/nonce/PKCE/refresh. Prefer it over hand-rolling |
| @playwright/test | 1.65.x | e2e (console + login UI) | Chromium project needed for the CDP WebAuthn domain |
| @axe-core/playwright | 4.14.x | a11y audit | Node `>=22.12` → CI must use Node 22 LTS or newer |
| vitest | 5.1.x | Optional unit tests for the console | |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Own client-IP extractor | axum-client-ip 1.3.1 | Picks a single "rightmost" header value. It does not walk a chain of N trusted CIDRs, and the config shape differs from `ANVILID_TRUSTED_PROXIES` |
| tower_governor 0.8.0 | (own layer over governor) | tower_governor is coarse per-IP only; per-account backoff needs domain logic, and CLAUDE.md requires one limiter |
| totp-rs `qr` | qrcodegen SVG | `qr` drags in `image`; a base64 PNG would need `img-src data:` |
| rust-embed | memory-serve 2.4.0 (pre-compressed, ETag, SPA fallback built in) | Locked decision is rust-embed. memory-serve would remove about 80 lines of serving code. Mention it, don't switch |
| Hand-rolled WebAuthn JS | @simplewebauthn/browser 14.0.0 (vendored, built to one asset) | Modern browsers have `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()`. A small helper with a base64url fallback is enough (LOW confidence on exact browser coverage; test in Playwright) |

**Installation (illustrative):**
```toml
webauthn-rs = { version = "0.6.2", features = ["danger-allow-state-serialisation", "conditional-ui"] }
totp-rs     = { version = "6.0.0", default-features = false, features = ["std", "otpauth", "zeroize"] }
qrcodegen   = "1.8"
governor    = "0.10.4"
ipnet       = "2.12"
rust-embed  = { version = "8.14.0", features = ["mime-guess", "interpolate-folder-path"] }
minijinja   = { version = "3.1.0", features = ["loader", "fuel"] }
```
```bash
cd admin-ui && npm i react react-dom @tanstack/react-router @tanstack/react-query @tanstack/react-table openapi-fetch oidc-client-ts
npm i -D vite @vitejs/plugin-react typescript@5.9 @tanstack/router-plugin openapi-typescript tailwindcss @tailwindcss/vite vite-plugin-compression2
cd tests/e2e && npm i -D @playwright/test @axe-core/playwright
```
(`vite-plugin-compression2`: version not verified. Any plugin that emits `.br`/`.gz` sidecars works. A 20-line post-build Node script using `zlib.brotliCompressSync` also works and avoids the dependency.)

**cargo-deny change required (Summary #1):**
```toml
[[bans.deny]]
name = "rsa"
wrappers = ["crypto-glue"]   # verification-only use inside webauthn-rs; we never use rsa for private keys
```
Also expect `multiple-versions` warnings (argon2 0.5 vs 0.6, base64 0.21/0.23). Add `skip` entries with a comment.

## Architecture Patterns

### Where Phase 3 code lands
```
crates/
  anvil-jose/src/        es256.rs, ed25519.rs (own JWS header/JWK serde), jwk.rs (RFC 7638 for RSA/EC/OKP), alg.rs (allow-list incl. Ed25519)
  anvil-core/src/
    keys/rotation.rs     pure rotation planner: (keys, now, policy) -> Vec<KeyAction>
    flow/passkey.rs      passkey steps (registration in settings flow, login step, usernameless)
    flow/totp.rs         TOTP enroll/verify + recovery codes
    consent.rs           ConsentService
    token/introspect.rs, token/revoke.rs
    authorize/response_mode.rs   query | form_post response builder
    session.rs           idle/absolute policy, list/revoke
    audit/events.rs      AuditAction enum (ALL phase-3 variants added in wave 1)
    ratelimit.rs         LimitKey/RouteClass/Decision types (pure)
  anvil-cache/src/limiter/   governor GCRA + backoff store (moka); RateLimiter trait
  anvil-web/src/
    client_ip.rs         trusted-proxy extractor (one implementation)
    layers/ratelimit.rs  route-class layer
    handlers/{introspect,revoke,passkey,totp,consent,account_sessions,account_apps}.rs
    handlers/admin/{audit,sessions,email_templates,smtp}.rs
    console.rs           rust-embed + SPA fallback at /console/*
  anvil-mail/src/        tenant template resolution, test-send
  anvil-storage*/        migrations + repo methods + contract tests
  anvilid/src/jobs/      key_rotation.rs, limiter_housekeeping.rs, audit_retention.rs
admin-ui/                Vite project
themes/default/          templates: consent, passkey, totp, recovery, account/sessions, account/apps, form_post; assets/{webauthn,form_post}.js
tests/e2e/               Playwright (chromium project with the CDP fixture)
tests/upgrade/fixtures/v0.1/{sqlite,postgres}.sql
```

### Pattern 1: Passkey ceremonies with server-side state in `flow`
**What:** Every `start_*` result is serialized (`danger-allow-state-serialisation`) into the `flow.state` JSON of the current flow row. That row is bound to the flow cookie and CSRF token. `finish_*` loads it and **deletes or advances it in the same transaction**, so the challenge is single-use.
```rust
// Registration (settings flow, user already authenticated)
let (mut ccr, reg_state) = webauthn.start_passkey_registration(
    user.id,                         // user handle MUST be a Uuid: identify_discoverable_authentication parses it
    &user.email, &display_name,
    Some(existing_cred_ids),         // exclude_credentials → prevents re-registering the same authenticator
)?;
// Make it discoverable (usernameless). Library default is residentKey=discouraged.
if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
    sel.resident_key = Some(ResidentKeyRequirement::Required);
    sel.require_resident_key = true;
}
flow.state = FlowState::PasskeyRegistering { reg_state };   // persisted server-side only

// finish: MUST check the CredentialID is not registered to any account (library doc requirement)
let passkey = webauthn.finish_passkey_registration(&reg, &reg_state)?;

// Usernameless login (feature "conditional-ui")
let (mut rcr, disc_state) = webauthn.start_discoverable_authentication()?;
rcr.mediation = None;  // library forces Conditional; clear it for an explicit "Sign in with a passkey" button
// …on response:
let (user_id, cred_id) = webauthn.identify_discoverable_authentication(&resp)?;
let stored = storage.users().find_webauthn_credential(tenant, user_id, cred_id).await?; // tenant-scoped lookup
let res = webauthn.finish_discoverable_authentication_v2(&resp, disc_state, &stored.passkey)?; // _v2: v1 is deprecated
// Counter/backup-state persistence (CAS):
if res.needs_update() { let mut pk = stored.passkey.clone(); pk.update_credential(&res); /* save */ }
storage.users().advance_credential_counter(tenant, stored.id, u64::from(res.counter())).await?; // WHERE counter < ?
```
**Clone detection (verified in webauthn-rs-core 0.6.2 `core.rs:1184-1205`):** if either the presented or the stored counter is > 0 and `presented <= stored`, `finish_*` returns `Err(WebauthnError::CredentialPossibleCompromise)`. `require_valid_counter_value` is always true in the `webauthn-rs` wrapper. Map that error to an `AuditAction::PasskeyCloneSuspected` event plus a generic login failure. Optionally mark the credential `suspended`. Synced passkeys usually report counter 0 forever, so the check is a no-op for them (expected).

**Race:** two concurrent assertions with counter n+1 and n+2 can both pass the library check against stored n. The storage CAS (`UPDATE credential SET counter=? WHERE id=? AND counter < ?`) prevents the counter from going backwards. Treat 0 rows affected with a counter that is not newer as a failed login.

**rp_id/origin:** one `Webauthn` per tenant origin: `WebauthnBuilder::new(rp_id = issuer host, &origin)?.rp_name(tenant.display_name).build()`. Cache it per tenant. Path-based tenants share an rp_id (same host). Credential lookup is always tenant-scoped, so this is safe, but browsers may offer passkeys from other tenants in the account picker (document this). `http://localhost` works (origin scheme must match; localhost ports are handled).

### Pattern 2: TOTP with replay prevention
```rust
// Enrollment: secret from our Rng trait (20 bytes), never from totp-rs gen_secret
let totp = totp_rs::Builder::new()
    .with_secret(secret_bytes.to_vec())          // SHA1, 6 digits, 30 s, skew 1 = defaults (max authenticator-app compatibility)
    .with_account_name(sanitize_no_colon(&user.email))   // ':' rejected by totp-rs (InvalidAccountName)
    .with_issuer(Some(sanitize_no_colon(&tenant.display_name)))
    .build()?;                                   // asserts ≥128-bit secret, digits 6..=8
let uri = totp.to_url()?;                        // otpauth://totp/…  → SVG via qrcodegen; also show base32 for manual entry
// Pending secret lives in flow.state ENCRYPTED (AAD = "flow"+flow_id), until the user confirms one code.

// Verification:
let step = totp.check(code, now_unix_secs)       // Option<u64> = matched step (v6 API); comparison is constant-time
    .ok_or(CoreError::InvalidOtp)?;
// Atomic replay guard: accept only if step > last_step
let accepted = storage.users().advance_credential_counter(tenant, cred_id, step).await?; // WHERE counter IS NULL OR counter < ?
```
- totp-rs docs state explicitly: "This library does NOT handle [single use] … it is the caller's responsibility". That responsibility is the CAS above.
- The seed is stored AES-256-GCM encrypted with AAD `credential:{id}`. Generate the UUIDv7 before encrypting.
- 6 digits with skew 1 means 3 valid codes in 10⁶. **Rate-limit second-factor attempts per user** (auth class, key `mfa:{user_id}`) with backoff.

**Recovery codes:** 10 codes, each 16 base32 characters (80 bits) shown as `XXXX-XXXX-XXXX-XXXX`. Store `HMAC-SHA256(pepper, normalize(code))`, with `pepper = HKDF(KEK, info="anvil/recovery-code/v1")`. Use a table `recovery_code(tenant_id, user_id, code_hash PK, used_at)`. Consume with a single `UPDATE … SET used_at=? WHERE tenant_id=? AND user_id=? AND code_hash=? AND used_at IS NULL RETURNING`. Regenerating codes deletes the old set. Each use emits an audit event and a notification email.

### Pattern 3: `form_post` response mode
- The Form Post conformance plan (`oidcc-formpost-basic-certification-test-plan`, certification profile "Form Post OP") is **the full Basic OP module list with `ResponseMode=form_post`** (verified from conformance-suite source `OIDCCFormPostBasicTestPlan` / `AbstractFormPostTestPlan`). Every Basic test, error cases included (`oidcc-response-type-missing`, `oidcc-prompt-none-not-logged-in`, `oidcc-ensure-registered-redirect-uri`, code reuse, PKCE, refresh), must pass with form_post.
- One response builder in `anvil-core`: `AuthorizationResponse { redirect_uri, params: Vec<(k,v)> /* code|error, state, iss */, mode }`. The web layer renders `mode=Query` as a 303 redirect and `mode=FormPost` as an HTML page. Errors after redirect-URI validation use the requested mode. Invalid redirect URI → error page, never a post.
- Accept only `response_mode ∈ {query, form_post}`. Anything else → `invalid_request`, delivered via the default (query) mode. Discovery: `"response_modes_supported": ["query","form_post"]`.
- **Page:** `<form method="post" action="{{ redirect_uri }}">` with hidden inputs (minijinja autoescape), a visible `<noscript>` submit button, and `<script src="/ui/assets/form_post.<hash>.js">` that calls `document.forms[0].submit()`. No inline script, so the global `script-src 'self'` holds.
- **CSP pitfall:** if the global CSP sets `form-action 'self'`, browsers block the post to the RP. The form_post response needs a per-response CSP with `form-action <origin of redirect_uri>` (or the directive omitted). Also send `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- RP-side note for docs: the cross-site POST does not carry the RP's `SameSite=Lax` cookies.

### Pattern 4: Introspection (RFC 7662) and revocation (RFC 7009)
- Both endpoints authenticate the caller through the single `ClientAuthenticator`. Public clients (`none`) may **revoke** their own tokens (with `client_id`) but may **not introspect**.
- **Introspect** `POST /introspect` (form: `token`, optional `token_type_hint`). Look up by hint first, then fall back to the other type (RFC 7662 allows ignoring the hint):
  - Opaque access token → `access_token` by SHA-256 hash; check `expires_at`, `revoked_at`, and the family's `revoked_at`.
  - Refresh token → `refresh_token` by hash; check consumed, expiry and family.
  - JWT → verify with our own JWKS keys (allow-listed alg, `typ=at+jwt`, `iss`, `exp`), then check the family reference for revocation.
  - Anything invalid, unknown, expired, revoked, from another tenant, or **not visible to the caller** → `{"active": false}` with HTTP 200 and nothing else.
  - Active → `active, scope, client_id, sub, aud, iss, exp, iat, nbf?, jti?, token_type ("Bearer" / "refresh_token"), username?`. Headers: `Cache-Control: no-store`.
- **Revoke** `POST /revoke`: return 200 for unknown or invalid tokens (§2.2). An unsupported `token_type_hint` value → `unsupported_token_type`. Revoking a refresh token revokes its family. Revoking an opaque access token sets its `revoked_at` (and, recommended, revokes the family, as Hydra and Keycloak do). Revoking a JWT access token revokes its family (locked by §6.1).
- **JWT revocation needs a family pointer in the token.** Today §8.2 claims carry no family. Add a private claim (e.g. `fid`, a random UUID with no other meaning) or a server-side `jti → family` index. A private claim avoids storage per JWT. Phase 2 may already have chosen something: check its output. Client-credentials tokens: create a `token_family` with `user_id = NULL` so they are revocable too.
- Document that JWT revocation only affects introspection and our own UserInfo. Resource servers that validate locally see revocation only when the token expires (10 min).
- Discovery: `introspection_endpoint`, `revocation_endpoint`, `*_endpoint_auth_methods_supported`.

### Pattern 5: Multi-algorithm signing and rotation (SEC-02, OIDC-11)
- One key per (tenant, alg) per state; the partial unique index allows one `active` per (tenant, alg). Tenant setting `signing_algs` (default `["RS256"]`). Client `id_token_signed_response_alg` must be in the tenant's enabled set; the default is RS256. Access tokens use the tenant default alg.
- **JWKs:**
  - RSA `{kty:RSA,n,e,alg:RS256,use:sig,kid}`
  - EC `{kty:EC,crv:P-256,x,y,alg:ES256,use:sig,kid}`: x and y are the 32-byte halves of the uncompressed point (`0x04‖X‖Y`) from `EcdsaKeyPair::public_key()`
  - OKP `{kty:OKP,crv:Ed25519,x,alg:"Ed25519",use:sig,kid}`
  - `kid` = RFC 7638 over the required members only, lexicographic: RSA `{e,kty,n}`, EC `{crv,kty,x,y}`, OKP `{crv,kty,x}`. Implement it in anvil-jose and cross-check against the RFC 7638 §3.1 test vector.
- **Ed25519 JWS:** header `{"alg":"Ed25519","kid":…,"typ":…}` serialized by us. `signing_input = b64url(header) + "." + b64url(payload)`; signature = `jsonwebtoken::crypto::sign(signing_input, &EncodingKey::from_ed_der(pkcs8), Algorithm::EdDSA)` (returns the base64url string). Verification of our own Ed25519 tokens (introspection, userinfo) goes through anvil-jose, which maps `Ed25519` → `crypto::verify(…, Algorithm::EdDSA)`.
- **`at_hash` for Ed25519 uses SHA-512** (left 32 bytes). This follows the OpenID Connect issue resolution and the OIDF "Token Hash Algorithm Implementer's Guide" (MEDIUM confidence; `oidc-token-hash` uses the same mapping). ES256 and RS256 use SHA-256.
- **Interop:** RFC 9864 (Oct 2025) deprecates `EdDSA` in favor of `Ed25519`, but RP library support is uneven. jsonwebtoken itself cannot parse `"alg":"Ed25519"`. Keep Ed25519 opt-in per tenant/client, never the default, and document that RPs need RFC 9864 support.
- **Rotation planner (pure function in anvil-core), run hourly under `job_lease`:**
  1. No `active` key for an enabled alg → generate one and activate immediately (first start; nobody has cached a JWKS yet).
  2. `active.age ≥ rotation_period − prepublish` and no `next` → generate `next` (published, not signing).
  3. `next.created_at + prepublish ≤ now` and `active.age ≥ rotation_period` → **promote in one transaction with two statements in this order**: `active → retired` (`retired_at = now`, `expires_at = now + max_token_lifetime + skew`), then `next → active`. Postgres non-deferrable unique indexes are checked per row, so a single UPDATE that swaps both rows can fail.
  4. Delete `retired` keys with `expires_at < now`.
  - `prepublish ≥ jwks_max_age`. Serve `/jwks` with `Cache-Control: public, max-age=<jwks_max_age>` (suggest 3600 s with a 90-day rotation) plus a strong `ETag`.
  - `anvilid keys rotate` = create `next` now and let the job promote it. `--immediate` (compromise) promotes now and may drop the old key from JWKS. Audit both.
  - `max_token_lifetime` = max(ID token 1 h, access token 10 min, logout token 2 min). Refresh tokens are opaque and not signed.

### Pattern 6: One keyed limiter (AUTH-09, SEC-05)
```rust
// anvil-core (pure types)
pub enum RouteClass { Auth, Token, Admin, Default }
pub enum LimitKey { Ip(IpAddr), Identifier(TenantId, HashedIdent), IdentIp(TenantId, HashedIdent, IpAddr), Client(TenantId, ClientId), User(TenantId, UserId) }
pub enum Decision { Allow, Deny { retry_after: Duration }, RequireCaptcha }

// anvil-cache: the ONLY implementation
#[async_trait] pub trait RateLimiter: Send + Sync {
    async fn check(&self, class: RouteClass, key: &LimitKey) -> Decision;   // GCRA (governor) – request rate
    async fn record_failure(&self, key: &LimitKey) -> Backoff;              // progressive backoff state
    async fn record_success(&self, key: &LimitKey);                          // reset backoff
    async fn backoff(&self, key: &LimitKey) -> Option<Duration>;            // remaining lock window
}
```
- **Rate (GCRA):** one `DefaultKeyedRateLimiter<LimitKey>` per route class with a configurable `Quota` (e.g. auth 10/min burst 5 per IP; token 100/s per client + 50/s per IP; admin 20/s per token subject; default 50/s per IP). A tower layer applies the IP-keyed checks per route class. Handlers apply identifier- and client-keyed checks after parsing (the identifier is in the body).
- **Progressive backoff (brute force):** a moka TTL map `key → {failures, locked_until}`.
  - After `free_attempts` (5), `delay = min(base × 2^(failures − free), cap)` (1 s → 15 min cap). Reset on success. Entries expire after `cap × 2` of inactivity. No permanent locks.
  - Two tiers: **(identifier, IP)** strict; **identifier-only** loose (e.g. 50/h). When the loose tier trips, return `RequireCaptcha` if CAPTCHA is configured, otherwise a delay. Keying on the *identifier string* (normalized, HMAC-hashed) and not the user id means unknown accounts behave exactly like real ones (no enumeration), together with the Phase 2 dummy hash.
  - **Reject with "try again in N s"** (429 + `Retry-After` for API/token; a form message for the UI). Don't `sleep` in the handler: it holds the connection and amplifies DoS.
- **Housekeeping:** governor keyed state grows without bound unless `retain_recent()` (and optionally `shrink_to_fit()`) runs. Schedule it every 60 s per node (no `job_lease`: the state is local).
- **CAPTCHA (Turnstile/hCaptcha):** off by default, with tenant config `{provider, site_key, secret (KEK-encrypted)}`. Only shown on `RequireCaptcha`. Verify server-side by POST to the provider's siteverify (Turnstile: `https://challenges.cloudflare.com/turnstile/v0/siteverify`; hCaptcha: `https://api.hcaptcha.com/siteverify`, MEDIUM confidence). Fail closed. Enabling it **relaxes the login-page CSP** for the provider's script and frame origins. Document this, since it breaks "no external assets" by operator choice.
- Metrics: `anvil_rate_limited_total{class,key_kind}`, `anvil_auth_backoff_active`.
- Redis (0.4): the same trait, with GCRA as a Lua script. Don't design for it now beyond the trait boundary.

### Pattern 7: Trusted-proxy client IP (OPS-06)
```
peer = socket addr (ConnectInfo)
if peer ∉ trusted_cidrs → client_ip = peer; ignore all forwarding headers
else: chain = parse(all Forwarded headers' for= values) or, if absent, all X-Forwarded-For values (comma-joined across header lines, in order)
      walk chain right→left: skip entries ∈ trusted_cidrs; first entry ∉ trusted → client_ip
      if every entry is trusted → leftmost entry; if an entry is unparsable ("unknown", "_obf", garbage) → stop, client_ip = last trusted hop (peer side)
```
- **Pitfalls:**
  - `Forwarded` (RFC 7239): `for="[2001:db8::1]:4711"`, quoted values, IPv4 with port, case-insensitive keys, multiple elements per header and multiple headers.
  - XFF has no ports usually, but some proxies append them.
  - IPv4-mapped IPv6 `::ffff:a.b.c.d`: normalize before CIDR matching.
  - Never take the *leftmost* XFF entry: clients can spoof it.
  - If both headers are present, prefer `Forwarded` only if the configured proxies emit it. Make the header choice a config option (`trusted_proxy_header = forwarded|x-forwarded-for`, default x-forwarded-for) to avoid mixed-source spoofing.
- **Issuer, cookie `Secure` and HSTS come from `public_url`**, never from `X-Forwarded-Proto/Host`. Host-based tenant matching may read `X-Forwarded-Host` only when the peer is trusted.
- Default `ANVILID_TRUSTED_PROXIES` = none (loopback in dev mode) per §13.
- proptest: random chains with spoofed prefixes never yield an IP from the spoofed portion when the trusted hops are honest.

### Pattern 8: Consent (OIDC-13)
- `ConsentService::decide(user, client, requested_scopes, prompt)`:
  - `client.consent_mode == skip_first_party` → skip.
  - An active `consent_grant` with `scopes ⊇ requested` → skip.
  - Otherwise show the consent step (a flow kind `consent`, referencing `authorization_request`).
  - On approve, upsert the grant (union of scopes). On deny → `access_denied` via the response mode.
- User revocation (`/ui/account/apps`): set `revoked_at` and **revoke all token families for (user, client)**. Audit it.
- The **conformance test client** must be `skip_first_party`, or the conformance browser script must click "Allow". Otherwise enabling consent breaks Basic/Config/Form Post runs.

### Pattern 9: Sessions (AUTH-10)
- On each authenticated request: `if now > idle_expires_at || now > expires_at → invalid`. Slide `idle_expires_at` and `last_seen_at` **at most once per minute** per session. SQLite has a single writer, so a write on every request hurts throughput.
- User endpoints: `/ui/account/sessions` (list with user agent, IP, created and last-seen, a current-session marker; revoke one or all others). Admin: `GET/DELETE /api/admin/v1/tenants/{t}/users/{id}/sessions[/{sid}]`.
- Revoking a session deletes the row. Recommended: also revoke token families issued under that `sid` (link via `rp_session` / `authorization_code.browser_session_id`). Back-channel logout delivery is Phase 4. Leave a domain event for it, don't build a stub.

### Pattern 10: Audit (ADM-4)
- `AuditAction` enum in `anvil-core::audit` with **all Phase 3 variants defined in Wave 1**: login success/failure per method, passkey registered/removed/clone_suspected, totp enrolled/removed, recovery_code used/regenerated, consent granted/revoked, session revoked, token revoked, refresh reuse detected, key generated/activated/retired, rate-limit lockout, admin CRUD actions, smtp test send, template updated. Defining them up front avoids merge conflicts between parallel plans.
- Writes go through `AuditRepo` in the same transaction as the state change when one exists. A subscriber mirrors each event to stdout via `tracing::info!(target: "audit", …)` as JSON.
- API: `GET /api/admin/v1/tenants/{t}/audit-events?from&to&actor&action&outcome&target&cursor&limit`. The cursor is the last UUIDv7 id (time-ordered, stable). Index `(tenant_id, at DESC)` plus `(tenant_id, action, at)`.
- Never put secrets, codes or tokens in `details`. Use a typed details struct per action, not free-form maps.

### Pattern 11: Email templates + SMTP (UI-07)
- Table `email_template(tenant_id, kind, subject, body_html, body_text, updated_at)`. Fall back to the embedded defaults when no row exists.
- On save: compile with minijinja (syntax errors → 422 with line info), then render against a sample context. The environment has `set_fuel(Some(N))` and autoescape for `.html`.
- Variables are a fixed, documented context per `kind`. Templates can't access anything else; minijinja has no file or env access.
- SMTP: an installation-level config file is the default, with a per-tenant override row (password KEK-encrypted).
- `POST …/smtp/test {to}` sends **synchronously** (not via the outbox) and returns the SMTP error text on failure. It requires `admin:write`, is rate-limited (admin class) and audited. The SMTP host is admin-supplied and can probe internal networks. Accept this for admins, document it, and add a timeout.

### Pattern 12: Admin console embedding and auth
```rust
#[derive(rust_embed::Embed)]
#[folder = "$CARGO_MANIFEST_DIR/../../admin-ui/dist"]
#[allow_missing = true]
struct ConsoleAssets;

async fn console(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches("/console/");
    let (file, is_index) = match ConsoleAssets::get(path) {
        Some(f) if !path.is_empty() => (f, false),
        _ => match ConsoleAssets::get("index.html") {             // SPA fallback
            Some(f) => (f, true),
            None => return placeholder_page(),                     // dist missing (no Node) — explains how to build
        },
    };
    // pick "<path>.br" / ".gz" sidecar by Accept-Encoding; ETag = hex(file.metadata.sha256_hash())
    // hashed assets (/console/assets/*-[hash].js): Cache-Control: public, max-age=31536000, immutable
    // index.html: Cache-Control: no-cache; CSP: default-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'
}
// Return 404 (not index.html) for missing paths that look like assets (have an extension), so broken chunk loads fail loudly.
```
- Mount `/console/*` **outside** tenant resolution (installation-wide), next to the `system` tenant at `/t/system`. Same origin as the API means no CORS.
- **Built-in console client:** at startup, upsert a public client in the `system` tenant (`client_id = "anvil-console"`, auth method `none`, PKCE, redirect `{public_url}/console/callback`, post-logout `{public_url}/console/`). Derive it from `public_url` on every start so changing the public URL doesn't break login. This is product configuration like the `system` tenant, not a test hook. Phase 2 bootstrap may already create clients: reconcile with it.
- SPA auth: `oidc-client-ts` `UserManager({ authority: origin + '/t/system', client_id: 'anvil-console', redirect_uri, response_type: 'code', scope: 'openid admin:read admin:write' })`. Store in `sessionStorage`. Rely on refresh rotation (OIDC-5). Logout = revoke refresh token (`/t/system/revoke`) + local clear (RP-initiated logout is Phase 4).
- **Open dependency:** how a system-tenant *user* gets admin scopes through auth code (RBAC is 0.4). Phase 2 must define this (e.g. every active system-tenant user is an admin). Verify before planning the console.
- **OpenAPI → TS:** the Rust side writes the spec to a checked-in file (e.g. `docs/openapi/admin-v1.json`) via a test or `anvilid openapi` subcommand. CI already checks spec drift. `admin-ui` runs `openapi-typescript ../docs/openapi/admin-v1.json -o src/api/schema.d.ts`; `tsc --noEmit` fails on drift.
- **CI ordering:** (1) Rust: spec drift check (does not need dist thanks to `allow_missing`). (2) Node 22: `npm ci && npm run gen:api && npm run typecheck && npm run build` (with `.br/.gz` emit). (3) `cargo build --release` with dist present; release/CI also asserts `admin-ui/dist/index.html` exists (§10.4). (4) Playwright against the release binary. Don't run npm from `build.rs`.
- **CSP and component libraries:** React style props use CSSOM (allowed under strict `style-src`). Some Radix-adjacent packages inject `<style>` elements (e.g. scroll-lock, toasts), and those are blocked without `'unsafe-inline'` in `style-src`. Test under the real CSP in Playwright. If needed, allow `style-src 'self' 'unsafe-inline'` for `/console/*` only (scripts stay strict). MEDIUM confidence.
- **Console v1 pages (discretion):** Users (list/search/detail: sessions tab, credentials tab with "remove passkey/TOTP"), Clients (list/detail incl. token_format, consent_mode, signing alg), Sessions (tenant-wide list, revoke), Audit (filterable table, cursor paging), plus Email templates/SMTP (UI-07 says "admin can edit", so the console needs it, not just the API). The tenant switcher stays hidden (multi-tenant console is 0.4); target the `default` tenant.

### Pattern 13: Migrations: upgrade test and destructive guard (OPS-04)
- **Upgrade test (CI, both backends):**
  1. Fresh DB → `migrator.run_to(LAST_V0_1_VERSION, &mut conn)` (sqlx 0.9.1 `Migrator::run_to`).
  2. Load `tests/upgrade/fixtures/v0.1/{sqlite,postgres}.sql`: a tenant, clients (confidential, public), users with Argon2 password, a live refresh-token family, a signing key encrypted with a test KEK, sessions, an outbox row.
  3. `migrator.run(&mut conn)`.
  4. Assert through the **current storage traits**: users readable, password verifies, the refresh token rotates, the key decrypts and signs, the client has default `token_format=jwt` and `consent_mode` defaulted.
  5. Run the contract suite on the upgraded DB.
- **Immutability check:** CI fails if any migration file that exists at the previous release tag differs from it (`git diff --exit-code v0.1.0 -- 'crates/anvil-storage-*/migrations/'` on pre-existing files). sqlx also refuses edited applied migrations (checksum mismatch → `VersionMismatch`). Phase 3 must make sure 0.1 is tagged and its last migration version recorded.
- **Destructive guard:**
  - Convention: any migration whose description starts with `destructive_` (`20270101000000_destructive_drop_x.sql`) is destructive.
  - At startup, the storage crate computes pending migrations (`Migrator::iter()` minus applied rows in `_sqlx_migrations`). If any pending one is destructive and `--allow-destructive-migrations` / `ANVILID_ALLOW_DESTRUCTIVE_MIGRATIONS=true` isn't set → refuse with a clear message listing them.
  - A CI lint script rejects `DROP TABLE|DROP COLUMN|RENAME|ALTER COLUMN .* TYPE|DELETE FROM|TRUNCATE` in migrations without the prefix. An allow-annotation (`-- anvil:non-destructive-rebuild`) covers SQLite table rebuilds that copy all data.
  - Test the guard with `Migrator::with_migrations(vec![…])` built in **test code**. Phase 3 itself should need only additive migrations.
- **SQLite pitfalls:** `ALTER TABLE ADD COLUMN` can't add PK/UNIQUE or non-constant defaults; table rebuilds need `PRAGMA foreign_keys=OFF`, which is a no-op inside a transaction, so such a migration needs sqlx's `-- no-transaction` directive. Postgres: `ADD COLUMN … DEFAULT <const>` is metadata-only (fast).
- **Parallel-plan pitfall:** migration version collisions. Put all Phase 3 schema in one Wave 1 plan.

### Anti-Patterns to Avoid
- **Storing WebAuthn state in a cookie or hidden field.** Replay bypasses the authenticator (library docs). It goes in `flow.state` only.
- **Using deprecated `finish_discoverable_authentication`.** Use `_v2`.
- **Letting the authorize handler build form_post HTML with string concatenation.** Use the template with autoescape.
- **A second limiter for the token endpoint or CAPTCHA.** It must be the same trait.
- **Deriving `iss` or cookie security from forwarded headers.**
- **Sleeping in handlers for progressive delay.**
- **Returning `active:true` metadata for tokens the caller isn't entitled to see.**
- **Swapping active/next keys in one UPDATE** under a partial unique index.
- **Rendering the TOTP QR as a `data:` PNG.** It needs a CSP relaxation and the heavy `image` crate.
- **Running `npm` in `build.rs`.**

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| WebAuthn attestation/assertion verification (CBOR, COSE, flags, origin/rpIdHash, counters) | Own verifier | webauthn-rs 0.6.2 | Huge spec surface, backup flags, UV policy |
| HOTP/TOTP math, otpauth URI escaping | Own HMAC truncation | totp-rs 6 (`check` returns the step; constant-time compare) | RFC edge cases, URI encoding |
| GCRA rate math | Token buckets | governor | Lock-free and tested; has `FakeRelativeClock` |
| JWS signing primitives, RSA/EC key parsing | Own crypto | jsonwebtoken `crypto::sign/verify` + aws-lc-rs | Only the Ed25519 header/JWK *serialization* is ours |
| OIDC browser client for the console (PKCE, state, nonce, refresh) | Custom fetch logic | oidc-client-ts | Many subtle state bugs |
| OpenAPI client types | Hand-written TS interfaces | openapi-typescript + openapi-fetch | Drift fails the build (locked) |
| Accessible primitives (dialogs, menus, focus traps) | Custom components | shadcn/ui (Radix) | WCAG behaviors |
| a11y checks | Manual review only | @axe-core/playwright | Plus manual review of the criteria axe can't test |
| QR encoding | Own encoder | qrcodegen | |
| CIDR math | String prefix checks | ipnet | IPv6, mapped addresses |

**Key insight:** the security-critical *glue* is ours: state persistence, atomic counters, family revocation, IP-chain trust, guard rails. The cryptographic and protocol *primitives* are never ours.

## Common Pitfalls

### Pitfall 1: cargo-deny failure on adding webauthn-rs
**What goes wrong:** the CI deny check fails (banned `rsa`, duplicate argon2/base64).
**How to avoid:** add the `wrappers` exception and `skip` entries in the same PR as the dependency, and record the rationale in ARCHITECTURE.md §2.
**Warning signs:** `cargo deny check bans` reports `rsa` via `crypto-glue`.

### Pitfall 2: Passkeys are not discoverable
**What goes wrong:** usernameless login finds no credential, because the library requested `residentKey: discouraged`.
**How to avoid:** override `authenticator_selection.resident_key`. In e2e, assert `WebAuthn.getCredentials` shows `isResidentCredential: true`.

### Pitfall 3: Usernameless API missing at compile time
**What goes wrong:** `start_discoverable_authentication` is not found.
**How to avoid:** enable the `conditional-ui` feature. Clear the forced `mediation: Conditional` for a button-triggered flow.

### Pitfall 4: Ed25519 tokens unreadable or rejected
**What goes wrong:** `jsonwebtoken::encode` can't express `Ed25519`, and RPs without RFC 9864 support reject the tokens.
**How to avoid:** use our own JWS path. Keep Ed25519 opt-in. Interop-test with at least one RP library that supports `Ed25519` (e.g. a Python/Node JOSE library, LOW confidence about which versions) in an integration test using a JWKS fixture.

### Pitfall 5: Rotation breaks RPs
**What goes wrong:** a new kid signs before RPs have refreshed their cached JWKS.
**How to avoid:** prepublish ≥ JWKS `max-age`. Test with a fake clock: at activation time, the key has appeared in every JWKS response for at least `max-age`.

### Pitfall 6: Form Post plan fails on error paths
**What goes wrong:** errors are still delivered in the query string, or the CSP `form-action` blocks the post.
**How to avoid:** one response builder. Run the conformance form_post plan in CI from the moment form_post lands.

### Pitfall 7: Consent breaks existing conformance automation
**What goes wrong:** the browser script stalls on the new consent page.
**How to avoid:** configure the conformance client as first-party, or extend the browser config.

### Pitfall 8: Account-lockout DoS
**What goes wrong:** an attacker locks victims out by failing logins against their email from many IPs.
**How to avoid:** use the two tiers. The identifier-only tier escalates to CAPTCHA or short delays, never hard locks, and the cap is 15 min.

### Pitfall 9: Unbounded limiter memory
**What goes wrong:** the governor keyed map grows with every new IP.
**How to avoid:** run the `retain_recent()` job and give moka entries a TTL. Expose a key-count gauge.

### Pitfall 10: SQLite write amplification
**What goes wrong:** updating `last_seen_at` on every request serializes on the single writer.
**How to avoid:** throttle to once per minute per session.

### Pitfall 11: TOTP replay across nodes or concurrent requests
**What goes wrong:** the check and the update are separate statements.
**How to avoid:** a single conditional UPDATE, covered by a storage contract concurrency test (two parallel uses of the same step → exactly one accepted).

### Pitfall 12: Recovery code race
**What goes wrong:** a JSON list in `credential.data` is read-modify-written.
**How to avoid:** one row per code and a single-statement consume, with a concurrency test.

### Pitfall 13: Migration version collisions between parallel plans
**How to avoid:** a single schema plan in Wave 1. Later plans add no migrations unless they are sequenced.

### Pitfall 14: TypeScript 7 breaks codegen
**How to avoid:** pin `typescript@5.9` and commit `package-lock.json`.

### Pitfall 15: axe gives false confidence
**What goes wrong:** axe can't test 3.3.8 Accessible Authentication (paste allowed, `autocomplete="username"` / `"current-password"` / `"one-time-code"`, no cognitive tests), 2.4.11 Focus Not Obscured, or keyboard-only flows.
**How to avoid:** add Playwright keyboard-navigation tests and a short manual checklist in the PR template for login pages. Note that an interactive CAPTCHA conflicts with 3.3.8 unless an alternative exists. Turnstile's managed or non-interactive mode is preferable.

### Pitfall 16: Console 404s on deep links or stale chunks
**How to avoid:** SPA fallback only for extension-less paths. Serve `index.html` with `no-cache` and hashed assets as immutable.

## Code Examples

### Playwright virtual authenticator fixture (CDP WebAuthn domain, Chromium only)
```ts
// tests/e2e/fixtures/webauthn.ts — verified against devtools-protocol browser_protocol.json (WebAuthn domain)
import { test as base, CDPSession } from '@playwright/test';
export const test = base.extend<{ authenticator: { cdp: CDPSession; id: string } }>({
  authenticator: async ({ page }, use) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
                 hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
                 automaticPresenceSimulation: true },
    });
    await use({ cdp, id: authenticatorId });
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  },
});
// Clone-detection e2e: after one successful login, roll the counter back and expect rejection + audit event
//   const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId: id });
//   await cdp.send('WebAuthn.setCredentialProperties', { authenticatorId: id, credentialId: credentials[0].credentialId, signCount: 0 });
// Negative tests: WebAuthn.setResponseOverrideBits { isBogusSignature: true } / { isBadUV: true } → login must fail.
// Usernameless: assert credentials[0].isResidentCredential === true after registration.
```
Note: the virtual authenticator increments `signCount` per assertion, so the rollback test triggers webauthn-rs's `CredentialPossibleCompromise`.

### axe audit of login pages
```ts
import AxeBuilder from '@axe-core/playwright';
for (const path of ['/ui/login', '/ui/registration', '/ui/recovery', '/ui/consent?…', '/ui/login/totp', '/ui/account/sessions']) {
  await page.goto(path);
  const r = await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();
  expect(r.violations).toEqual([]);
}
// No-JS password flow: a separate project with `javaScriptEnabled: false` runs the full login → redirect.
```

### TOTP code generation in e2e (Node crypto, no extra deps)
```ts
import { createHmac } from 'node:crypto';
export function totp(base32: string, t = Date.now()): string {
  const key = base32Decode(base32);               // small helper in tests
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / 30)));
  const h = createHmac('sha1', key).update(ctr).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
// Replay test: submit the same code twice in one step → second attempt rejected.
```

### Introspection response shapes
```json
{"active": false}
{"active": true, "scope": "openid profile", "client_id": "app", "sub": "0193…", "aud": ["https://api.example"],
 "iss": "https://id.example.com", "exp": 1767225600, "iat": 1767225000, "token_type": "Bearer"}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `alg: EdDSA` (polymorphic) | `alg: Ed25519` (RFC 9864) | Oct 2025 | Our own JWS/JWK serialization; uneven RP support |
| webauthn-rs on OpenSSL | webauthn-rs 0.6 on RustCrypto via `crypto-glue` | 0.6 line | No OpenSSL (good), but `rsa` rc crate (deny exception) |
| totp-rs `TOTP::new(...)` + `check_current -> bool` | totp-rs 6 `Builder` → `Totp`; `check -> Option<u64>` step | 6.0.0 (2026-08) | Older examples won't compile; the step return enables replay guards |
| TanStack Table v8 `useReactTable` | v9 `useTable` + explicit `features` | Aug 2026 | shadcn examples may lag |
| TypeScript 5.x JS compiler | TS 7 native (`latest`) | Jul 2026 | Pin 5.9 for codegen tools |
| Conformance plan per response mode via variants | Dedicated `oidcc-formpost-basic-certification-test-plan` wrapping the Basic plan | current suite | Run as a separate CI job |

**Deprecated/outdated:**
- `Webauthn::finish_discoverable_authentication`: deprecated, use `_v2`.
- The research note's `totp-rs features = ["qr","gen_secret"]`: replace with `["std","otpauth","zeroize"]` + qrcodegen.

## Open Questions

1. **Audience of access tokens without resource indicators (OIDC-15 "audience-restricted").**
   - What we know: RFC 8707 support is Phase 4; RFC 9068 requires `aud`.
   - Unclear: the default `aud` value.
   - Recommendation: a per-client `access_token_audience` list, defaulting to the tenant issuer (which covers our UserInfo). Record it in ARCHITECTURE.md §8.2.
2. **Who may introspect?**
   - Recommendation: confidential clients with an admin-granted `introspection` capability (a client flag or the `introspect` scope), tenant-scoped. Tokens outside the caller's visibility return `active:false`.
3. **RFC 7009 when the token belongs to another client.**
   - §2.1 says such a request is refused with an error; §2.2 says invalid tokens get 200.
   - Recommendation: don't revoke, and return 200 (treat it as invalid for this caller, which avoids an oracle). Note the choice in docs.
4. **JWT family pointer claim name, and whether Phase 2 already embeds one.** Check Phase 2 output.
5. **Admin authorization for console users before RBAC (0.4).** Depends on the Phase 2 bootstrap model.
6. **`amr` values for passkeys** (RFC 8176: `hwk`/`swk`, `user`, `pin`, `mfa`). Low risk.
   - Recommendation: passkey with UV → `["hwk","user","mfa"]` when the authenticator is not backup-eligible, `["swk","user","mfa"]` when it is. TOTP → `["otp"]` plus `["pwd","otp","mfa"]` combined. LOW confidence on a community convention.
7. **Where recovery codes and counters live:** schema changes vs §6.1 (Summary #4/#5) need sign-off.
8. **0.1 release tag and fixture capture.** The upgrade test needs Phase 2 to tag `v0.1.0` and record its last migration version. If Phase 2 doesn't, Phase 3 Wave 1 must.
9. **Conformance local-run acceptance for certification:** unconfirmed (carried from research/03). Not blocking.

## Suggested Plan Decomposition (waves)

Waves are built so that plans within a wave touch disjoint crates or modules. Shared touch points (router registration, discovery metadata, the OpenAPI path list) are one-line additions. Expect trivial merges.

**Wave 1: foundations (sequential, 2 plans in parallel)**
- **03-01 Schema + storage + audit types.** All migrations, both backends:
  - `credential.counter`, `recovery_code`, `consent_grant`, `audit_event`, `email_template`, `smtp_settings`, `captcha_settings`
  - client `token_format` / `consent_mode` / `id_token_signed_response_alg` / introspection flag
  - `browser_session.idle_expires_at`, `signing_key.alg`, `access_token` if missing
  - Repo methods: credential CAS, recovery consume, consent, audit query, session list/revoke, opaque token lookup, family revoke by (user, client) / sid
  - Contract tests incl. concurrency (TOTP step, recovery code, counter)
  - The `AuditAction` enum with every Phase 3 variant, and `AuditService`
- **03-02 Migration safety.** Destructive guard + flag, CI lint script, immutability check against the previous tag, upgrade-test harness (`run_to` + fixtures v0.1 for both backends), cargo-deny exception for webauthn-rs. Disjoint: `anvilid` CLI flag, `tests/upgrade`, CI yaml, `deny.toml`.

**Wave 2: features (parallel, disjoint)**
- **03-03 JOSE + keys:** anvil-jose ES256/Ed25519, JWK/thumbprint, Ed25519 JWS, `at_hash` per alg; KeyService multi-alg; rotation planner + job + `keys rotate`; JWKS cache headers; discovery alg list. (anvil-jose, anvil-core/keys, anvilid/jobs)
- **03-04 Limiter + client IP + CAPTCHA:** anvil-cache limiter, route-class layer, client_ip extractor, backoff in login/MFA/token handlers, CAPTCHA verify, metrics, housekeeping job. (anvil-cache, anvil-web/layers, client_ip.rs)
- **03-05 Passkeys:** settings-flow registration, login step, usernameless, passkey management (list/remove) in a minimal `/ui/account/security`, `webauthn.js`, templates, audit. (anvil-core/flow/passkey, handlers/passkey, themes)
- **03-06 TOTP + recovery codes:** enroll/verify/remove, QR SVG, second-factor step in the login flow, recovery code generation and consumption, per-user MFA rate limit (uses the 03-04 trait, so depends on 03-04's trait file; land the trait first or put 03-06 at the start of Wave 3).
- **03-07 Token lifecycle:** opaque access tokens per client, JWT family claim, `/introspect`, `/revoke`, discovery entries, security negative tests. (anvil-core/token, handlers/introspect+revoke)
- **03-08 Authorize: form_post + consent:** response builder, form_post page + JS + per-response CSP, consent step + ConsentService, `/ui/account/apps` with revoke → family revocation, conformance client config. (anvil-core/authorize, consent.rs)
- **03-09 Sessions:** idle/absolute enforcement, throttled touch, `/ui/account/sessions`, admin session API. (anvil-core/session, handlers/account_sessions, handlers/admin/sessions)
- **03-10 Mail templates + SMTP test + audit API:** template CRUD with compile check, SMTP settings, test send, audit-events query API + stdout mirror. (anvil-mail, handlers/admin/{email_templates,smtp,audit})
- **03-11 Admin console scaffold:** Vite/TS/Router/Query/shadcn/Table project, openapi codegen, oidc-client-ts auth, rust-embed serving + SPA fallback + placeholder, built-in console client upsert, CI Node job, Users and Clients pages (APIs exist from Phase 2). (admin-ui/, anvil-web/console.rs)

**Wave 3: integration and verification**
- **03-12 Console pages:** Sessions, Audit, Email templates/SMTP, credential removal (needs 03-09/03-10 APIs).
- **03-13 E2E + a11y:** Playwright fixtures (CDP authenticator, axe, TOTP helper, no-JS project); passkey (incl. usernameless, clone rollback, bogus signature), TOTP (incl. replay), recovery code, consent remember/revoke, session revoke, console smoke; fix a11y findings in templates.
- **03-14 Conformance + release gate:** add the `oidcc-formpost-basic-certification-test-plan` CI job; re-run Basic/Config with consent on; run the upgrade test on both backends; brute-force/rate-limit integration tests behind a simulated trusted proxy; update ARCHITECTURE.md for the divergences found here.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust: `cargo test` (or `cargo nextest` if Phase 1 adopted it) with proptest, insta, testcontainers; Node: Playwright 1.65 + @axe-core/playwright 4.14; optional vitest 5 for admin-ui; OpenID conformance suite (Docker) |
| Config file | Workspace from Phase 1; `tests/e2e/playwright.config.ts` (exists from Phase 2 if Phase 2 added e2e, else Wave 0); `admin-ui/vite.config.ts` (new) |
| Quick run command | `cargo test -p <crate-touched>` (e.g. `cargo test -p anvil-jose`, `cargo test -p anvil-cache`) |
| Full suite command | `cargo test --workspace` (SQLite + Postgres contract) && `cd admin-ui && npm run typecheck && npm run build` && `cd tests/e2e && npx playwright test` && conformance script (Phase 1 runner) for basic, config, formpost |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OIDC-10 | Introspect: active/inactive, other-tenant → inactive, public client rejected; revoke: unknown token 200, refresh revoke kills family, JWT revoke → introspect inactive, bad hint → `unsupported_token_type` | integration + security | `cargo test -p anvil-web --test security_introspect_revoke` | ❌ Wave 0 |
| OIDC-11 | ES256/Ed25519 sign + verify round trip; JWK thumbprint vectors (RFC 7638 §3.1); `alg` header is `Ed25519`; `at_hash` SHA-512 for Ed25519; alg not enabled → client registration rejected | unit | `cargo test -p anvil-jose` | ❌ Wave 0 |
| SEC-02 | Rotation planner states over a fake clock; prepublish ≥ max-age; two-step promotion under the unique index (contract test, both DBs); retired key stays until expiry; lease prevents double-run | unit + contract | `cargo test -p anvil-core keys::rotation` / `cargo test -p anvil-storage-postgres contract::keys` | ❌ Wave 0 |
| OIDC-13 | Consent shown once, remembered for a scope subset, re-shown for new scopes, deny → `access_denied`, revoke → families revoked, first-party skip | integration + e2e | `cargo test -p anvil-web --test consent` ; `npx playwright test consent.spec.ts` | ❌ Wave 0 |
| OIDC-15 | Opaque client gets a non-JWT token, stored hashed, works at UserInfo/introspect; JWT has `typ=at+jwt` and `aud` | integration | `cargo test -p anvil-web --test access_token_format` | ❌ Wave 0 |
| OIDC-25 | form_post page: autoescaped hidden fields, iss/state, per-response CSP form-action, no inline script; errors via form_post; invalid redirect → error page; unknown response_mode rejected | integration + conformance | `cargo test -p anvil-web --test response_mode` ; conformance `oidcc-formpost-basic-certification-test-plan` | ❌ Wave 0 |
| AUTH-04 | Register/login/usernameless; challenge single-use (replayed finish rejected); state never in cookie; clone rollback rejected + audited; bogus signature/bad UV rejected; cred ID registered to another user rejected | e2e (CDP) + integration | `npx playwright test passkey.spec.ts --project=chromium` | ❌ Wave 0 |
| AUTH-05 | Enroll requires a valid code; replay in the same step rejected (concurrency contract test); skew window; recovery code single-use (concurrency); seed encrypted at rest; MFA attempts throttled | unit + contract + e2e | `cargo test -p anvil-storage contract::credentials` ; `npx playwright test totp.spec.ts` | ❌ Wave 0 |
| AUTH-09 / SEC-05 | Nth failed login → Retry-After with growing delay; resets on success; unknown user identical behavior; per-IP limit; token endpoint per-client limit; CAPTCHA required on the loose tier when configured (siteverify mocked with wiremock in tests) | integration (FakeRelativeClock) | `cargo test -p anvil-cache limiter` ; `cargo test -p anvil-web --test security_bruteforce` | ❌ Wave 0 |
| OPS-06 | Spoofed XFF from an untrusted peer ignored; chain walk with trusted hops; Forwarded quoted IPv6; mapped IPv4; garbage stops the walk; issuer unaffected by X-Forwarded-Host | unit (proptest) + integration | `cargo test -p anvil-web client_ip` | ❌ Wave 0 |
| AUTH-10 | Idle expiry, absolute expiry, touch throttling, user revoke (other session), admin revoke, revoked session cookie rejected | integration | `cargo test -p anvil-web --test sessions` | ❌ Wave 0 |
| UI-02 | axe clean (wcag22aa tags) on all login/MFA/consent/account pages; no-JS password login completes; keyboard-only login | e2e | `npx playwright test a11y.spec.ts nojs.spec.ts` | ❌ Wave 0 |
| UI-07 | Invalid template → 422; fuel limit stops runaway loops; autoescape; tenant override used by the outbox; test send success/failure surfaced (SMTP sink container or a local SMTP mock in tests) | integration | `cargo test -p anvil-mail` ; `cargo test -p anvil-web --test admin_email` | ❌ Wave 0 |
| ADM-04 | Each Phase 3 action emits exactly one typed event; written in the same tx (rollback → no event); query filters + cursor; stdout mirror contains no secrets (insta snapshot) | integration | `cargo test -p anvil-web --test audit` | ❌ Wave 0 |
| OPS-04 | 0.1 fixture → upgrade → contract suite (both DBs); destructive pending migration refused without the flag; lint catches unmarked DROP; previous-tag files unchanged | integration + CI script | `cargo test -p anvilid --test upgrade_from_v0_1` ; `scripts/check-migrations.sh` | ❌ Wave 0 |
| ADM-02 (console v1 part) | Console login via PKCE, users/clients/sessions/audit pages render, revoke session works; axe on console | e2e | `npx playwright test console.spec.ts` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p <touched crate>` (< 30 s), plus `npm run typecheck` when admin-ui changes
- **Per wave merge:** `cargo test --workspace` (SQLite + Postgres) + Playwright subset for the touched flows
- **Phase gate:** full suite + conformance Basic, Config **and Form Post** + upgrade test + axe clean, before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/e2e/fixtures/webauthn.ts`: CDP virtual authenticator fixture (AUTH-04)
- [ ] `tests/e2e/fixtures/axe.ts` + a no-JS Playwright project (UI-02)
- [ ] `tests/e2e/helpers/totp.ts`: RFC 6238 generator (AUTH-05)
- [ ] `tests/e2e/global-setup.ts`: start the release binary with a temp data dir, obtain the setup URL via `anvilid admin setup-url` (no test hooks in production code)
- [ ] `tests/upgrade/fixtures/v0.1/{sqlite,postgres}.sql` + harness (OPS-04)
- [ ] `scripts/check-migrations.sh` (lint + previous-tag immutability)
- [ ] Conformance job config for `oidcc-formpost-basic-certification-test-plan` (reuse the Phase 1/2 runner; test client = first-party)
- [ ] Node 22 LTS setup in CI (required by Vite 8 and @axe-core/playwright 4.14)
- [ ] An SMTP sink for tests (testcontainers Mailpit or similar; version not verified)

## Sources

### Primary (HIGH confidence)
- Crate sources downloaded from crates.io and read: webauthn-rs 0.6.2 (`lib.rs` registration/discoverable code, `interface.rs` `update_credential`, `private.rs`), webauthn-rs-core 0.6.2 (`core.rs` counter check lines 1184–1205, resident key handling, `Cargo.toml` deps), webauthn-rs-proto 0.6.2 (`AuthenticatorSelectionCriteria`, `RequestChallengeResponse.mediation`), totp-rs 6.0.0 (`lib.rs` `check`, `builder.rs`, `rfc.rs`, `Cargo.toml` features), jsonwebtoken 12.0.0 (`algorithms.rs`, `header.rs`, `jwk.rs` thumbprint, `crypto/mod.rs` sign/verify/provider), governor 0.10.4 (`state/keyed.rs`, `clock.rs`), rust-embed 8.14.0 (features, README), sqlx-core 0.9.1 (`migrate/migrator.rs` `run_to`, `with_migrations`)
- crates.io API: crypto-glue 0.2.2 dependency list; qrcodegen-image 1.5.0 deps (`image`); minijinja 3.1.0 features (`fuel`); latest versions of axum-client-ip, ipnet, moka, redis, memory-serve
- docs.rs: webauthn-rs 0.6.2 `Webauthn`, `WebauthnBuilder`, feature list; webauthn-rs-core `AuthenticationResult`; aws-lc-rs 1.19.0 `Ed25519KeyPair`, `EcdsaKeyPair`
- OpenID conformance-suite source (gitlab.com/openid/conformance-suite, master): `OIDCCFormPostBasicTestPlan.java`, `AbstractFormPostTestPlan.java`, `OIDCCBasicTestPlan.java`
- Chrome DevTools Protocol `browser_protocol.json` (WebAuthn domain: `addVirtualAuthenticator`, `setCredentialProperties` with `signCount`, `setResponseOverrideBits`)
- npm registry `latest` metadata for all frontend packages listed (versions, engines, peerDependencies)
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html): Ed25519 fully-specified alg; `EdDSA` deprecated

### Secondary (MEDIUM confidence)
- [OpenID Connect issue 1125: *_hash algorithm for EdDSA](https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens), [self-issued.info](https://self-issued.info/?m=202609) (Token Hash Algorithm Implementer's Guide → SHA-512 for Ed25519), [oidc-token-hash](https://npmjs.com/package/oidc-token-hash)
- [TanStack Table v9 migration guide](https://tanstack.com/table/latest/docs/framework/react/guide/migrating)
- [OpenID Form Post certification announcement](https://openid.net/openid-certification-now-available-for-form-post-response-mode-implementations/), [OP submission](https://openid.net/certification/op_submission/)
- [Cloudflare Turnstile server-side validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
- RFC 7662, RFC 7009, RFC 7239, RFC 7638, RFC 9068, RFC 8176, OAuth 2.0 Form Post Response Mode 1.0 (from training knowledge; well-established specs)

### Tertiary (LOW confidence, validate)
- hCaptcha siteverify URL; `vite-plugin-compression2` and Mailpit versions; browser coverage of `PublicKeyCredential.parseCreationOptionsFromJSON`; which RP libraries accept `alg: Ed25519`; `amr` conventions for passkeys; Radix-adjacent packages injecting `<style>` under strict CSP

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH (Rust crates read from source); MEDIUM (npm: registry metadata, but not exercised)
- Architecture: HIGH for the patterns that follow locked docs; MEDIUM for the open questions on audience, introspection policy and console admin authz
- Pitfalls: HIGH for the dependency/API facts (cargo-deny/rsa, Ed25519 alg, resident key, conditional-ui, TS 7 peer); MEDIUM for the CSP/console and interop items

**Research date:** 2026-11-25
**Valid until:** about 2026-12-25 for the npm tooling (fast-moving); about 2027-02 for the Rust crates and specs
