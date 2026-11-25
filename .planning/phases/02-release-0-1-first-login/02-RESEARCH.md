# Phase 2: Release 0.1 "First login" - Research

**Researched:** 2026-11-25
**Domain:** OAuth 2.1 / OpenID Connect provider (Rust: axum 0.8, aws-lc-rs, jsonwebtoken 12, sqlx 0.9), server-rendered login flows, management API, OpenID conformance (Basic OP + Config OP)
**Confidence:** HIGH for the conformance requirements (read from the suite source, commit `246b2c1`, 2026-11-24) and the crate APIs (read from the published crate sources, plus a compiled probe). MEDIUM for the design recommendations.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
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

### Deferred Ideas (OUT OF SCOPE)
- Passkeys, TOTP, introspection/revocation, consent screen, form_post, ES256/Ed25519, rate limiting, audit log UI — Phase 3
- Admin console UI — Phase 3+
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| OIDC-01 | Auth code + PKCE; only S256 accepted | §Conformance: the Basic OP tests send **no PKCE** (see Conflict C1). PKCE verification code is under Code Examples. RFC 9700 §2.1.1 wording is quoted under Pitfalls |
| OIDC-02 | Exact redirect matching, loopback port flexibility, error page and never a redirect | `oidcc-ensure-registered-redirect-uri` expects an error page, and the browser config takes an automatic screenshot. Matcher code is under Code Examples |
| OIDC-03 | Codes single-use, 60 s or less, bound; reuse revokes tokens | `oidcc-codereuse` and `oidcc-codereuse-30seconds`: the original access token must stop working at UserInfo (WARNING otherwise). JWT access tokens therefore need a family check at UserInfo |
| OIDC-04 | client_secret_basic/post, private_key_jwt (aud = issuer, jti), none | Basic OP uses basic + post. The private_key_jwt rules come from RFC 10070, which I verified. A gap in jsonwebtoken's `aud` validation is under Pitfalls |
| OIDC-05 | Refresh rotation and family revocation on reuse | `oidcc-refresh-token` flow analysed: it passes with rotation. A refreshed ID token must keep `auth_time`, `azp`, `iss`, `sub` and `aud` (`CompareIdTokenClaims`), so token_family needs auth context (Gap G2) |
| OIDC-06 | Client credentials | Not covered by the conformance suite. Covered by our own tests (public clients rejected, `openid` scope rejected, no refresh token) |
| OIDC-07 | ID token signed with active key, kid, nonce, at_hash, auth_time, acr/amr | `PerformStandardIdTokenChecks` conditions listed. Signing path verified by compiling a probe |
| OIDC-08 | Discovery + RFC 8414 + JWKS with overlap | Config OP checks listed. The schema allow-list (unknown fields give a WARNING) and RFC 8414 path insertion (Conflict C4) are covered |
| OIDC-09 | UserInfo with scope claims | The scope tests return a WARNING if claims are missing, so the conformance user needs a full profile. GET, POST header and POST body must all work |
| OIDC-24 | RFC 9207 `iss` | `ValidateIssIfPresentInAuthorizationResponse`. openid-client (oauth4webapi) enforces `iss` when the metadata flag is set, which I confirmed in its source |
| AUTH-01 | Password login, Argon2id, policy, breach check | OWASP parameters match argon2 0.6 defaults (19 MiB, t=2, p=1). Patterns for the bounded pool, dummy hash and HIBP range API are covered |
| AUTH-02 | Self-registration (disable/invite-only), email verification | Flow-engine design. Verification is not required to log in by default (needed for zero-config) |
| AUTH-03 | Recovery without account enumeration | Token design, constant response, and confirming with POST so link scanners don't consume tokens |
| UI-01 | Pages served with no external assets | Embedded themes, strict CSP, a test that scans rendered HTML |
| ADM-01 | OpenAPI 3.1 management API with OAuth admin scopes | utoipa 6.0.0 (defaults to OpenAPI 3.1) + utoipa-axum 0.3.0 (axum 0.8). Drift check via a committed spec file |
| ADM-03 | One-time setup URL, no default credentials | Bootstrap design. The script automation path is covered (Open Question Q2) |
| OPS-01 | Static binary / image under 50 MB | Distroless/scratch image. Default listen address inside the container (Pitfall P9). Size gate in CI |
| OPS-02 | SQLite default, Postgres | The Phase 1 storage pattern extended to all 0.1 aggregates. Contract suite on both |
| OPS-05 | Zero config; only public URL in prod | Dev-mode detection from `public_url` scheme and host |
| SEC-01 | RFC 9700 / OAuth 2.1 defaults | Checklist mapped to tests (§RFC 9700 checklist) |
| SEC-04 | CSRF, hardened cookies, strict CSP | Synchronizer token + Fetch Metadata (Go `CrossOriginProtection` semantics). Cookie matrix |
| SEC-06 | No test-only behavior in release | Dependency-graph and grep gates (§Validation) |
| SEC-07 | Dependency audit + fuzz JWT and authorize parsers | cargo-fuzz 0.13.2 / libfuzzer-sys 0.4.13 targets. Nightly CI |
| QUAL-01 | Negative test per control | Test map in §Validation Architecture |
| QUAL-02 | Same suite on SQLite and Postgres | Backend-selecting test harness. Dev-dependency rule (Conflict C6) |
| QUAL-04 | Zero-config docker run → login at most 2 min | Node sample RP (openid-client 6.9.1) + Playwright 1.65 script, described step by step |
</phase_requirements>

## Summary

Phase 2 builds a complete OpenID Provider on the Phase 1 skeleton. Most of the domain is well understood. The risk is in details that the **OpenID conformance suite checks mechanically**. I read the current Basic and Config test plans from the suite source (`OIDCCBasicTestPlan.java`, `OIDCCConfigTestPlan.java`) and the conditions they call. Several of their requirements are not obvious from the requirements list:

1. **The suite does not send PKCE** in any Basic OP module except `oidcc-ensure-request-with-valid-pkce-succeeds`. A server that requires PKCE from every client fails Basic OP. This conflicts with the locked control "PKCE required for every authorization code request" (Conflict C1).
2. **Basic OP requires `prompt=none`, `prompt=login`, `max_age` and `id_token_hint` behaviour plus SSO session reuse.** These are OIDC-14 features, which the roadmap maps to Phase 4.
3. **Config OP fails if any `*_endpoint` is not HTTPS**, so the CI run needs TLS in front of AnvilID.
4. **Unknown metadata fields and missing claims produce WARNINGs**, and `run-test-plan.py` fails CI on unexpected warnings and skips unless they are listed in expected-failures/expected-skips files.

On the crypto side, I proved one integration trap by compiling a probe: **aws-lc-rs exports RSA private keys only as PKCS#8, but jsonwebtoken 12's aws-lc backend parses RSA `EncodingKey` bytes as PKCS#1** (`RsaKeyPair::from_der`). Passing PKCS#8 to `EncodingKey::from_rsa_der` compiles and then fails at sign time with "Signing failed: signature error". Wrapping the PKCS#8 DER in a `PRIVATE KEY` PEM and calling `EncodingKey::from_rsa_pem` works. `Jwk::from_encoding_key` and `Jwk::thumbprint(SHA256)` then produce correct `n`/`e` and an RFC 7638 `kid`, and an HS256 token presented to RS256 validation is rejected with `InvalidAlgorithm`.

The prior stack research (docs/research/04) has two manifest errors. **minijinja 3.1 has no `loader` feature** (the loader is always on), and **its `serde` support is opt-in**. **lettre needs a root-certificate feature** (`webpki-roots`) when used with `rustls` + `aws-lc-rs`, because `rustls-tls` pulls in `ring`.

**Primary recommendation:** First define the domain types, ports (storage traits) and CoreError in one small wave-1 plan, alongside independent jose/web-shell/infra plans. Then build storage, core services and mail in parallel, then HTTP surfaces, then binary wiring, then the conformance and e2e gates. Before planning, get user decisions on C1 (PKCE for conformance clients) and C2 (pull minimal prompt/max_age into 0.1).

## Conflicts with locked docs (raise before planning, per CLAUDE.md)

| # | Conflict | Evidence | Recommendation |
|---|----------|----------|----------------|
| **C1** | §11 / PRD OIDC-1: "PKCE required for every authorization code request". The Basic OP plan sends **no `code_challenge`** in about 35 of its 36 modules | `AbstractOIDCCServerTest.CreateAuthorizationRequestSteps` adds only state, nonce and response_type. Only `OIDCCEnsureRequestWithValidPkceSucceeds` adds PKCE. No `usePkce` variant exists in the OIDCC plans (only in `AbstractOIDCCServerSecurityProfileTest`, which is FAPI) | Add a per-client `require_pkce` flag: **default true**, and it can be set to false **only for confidential clients**. When false, `nonce` is required for `openid` requests. This matches RFC 9700 §2.1.1: public clients MUST use PKCE; for confidential clients PKCE is RECOMMENDED and "confidential OpenID Connect clients MAY use the nonce parameter". `plain` is always rejected, the downgrade defence (§4.8.2) still applies, and if a challenge is present it is always enforced. Conformance clients are created with `require_pkce=false`. **Needs user sign-off** because it changes the wording of OIDC-1 and §11 |
| **C2** | OIDC-14 (`prompt`, `max_age`, `login_hint`, `acr_values`) is mapped to Phase 4, but Basic OP needs it now | Modules `oidcc-prompt-none-not-logged-in` (error must be one of `login_required`, `interaction_required`, `account_selection_required`, `consent_required`), `oidcc-prompt-none-logged-in`, `oidcc-prompt-login` (a second login page is required), `oidcc-max-age-1` (re-login is required and `auth_time` must be later), `oidcc-max-age-10000`, `oidcc-id-token-hint` (`prompt=none` + hint must succeed silently) | Implement in 0.1: `prompt=none`, `prompt=login`, `max_age`, `id_token_hint` (with `prompt=none`), SSO session reuse, and accept-and-ignore for `display`, `ui_locales`, `claims_locales`, `login_hint` (prefill only) and `acr_values`. Leave `consent`, `select_account` and `create` to Phase 4. Advertise `prompt_values_supported: ["none","login"]` |
| **C3** | §4: `anvil-core` depends only on `anvil-jose` and pure libraries, while core services hold storage traits that §7.1 places in `anvil-storage`, which depends on `anvil-core` for domain types. That is a dependency cycle | ARCHITECTURE.md §4, §5, §7.1 | Check how Phase 1 Spike A resolved it. If unresolved, recommend: **ports (repository traits, `StorageError`) and domain types live in `anvil-core::ports` / `anvil-core::domain`**, and `anvil-storage` holds the generic contract suite plus shared helpers. The dependency checker doesn't change. Update the ARCHITECTURE.md §7.1 wording |
| **C4** | §10.1 lists well-known paths relative to the tenant base. RFC 8414 §3.1 puts AS metadata at `https://host/.well-known/oauth-authorization-server/t/acme` (path **insertion**), while OIDC Discovery **appends** (`/t/acme/.well-known/openid-configuration`) | RFC 8414 §3.1. MCP clients try both | Serve OIDC at `{issuer}/.well-known/openid-configuration` and RFC 8414 at `/.well-known/oauth-authorization-server{base_path}`. The tenant-resolution layer must route `/.well-known/*/t/{slug}` before `/t/{slug}` prefix matching |
| **C5** | Config OP: `CheckDiscEndpointAllEndpointsAreHttps` (FAILURE) applies to every `*_endpoint` key, and `CheckDiscEndpointIssuer` requires issuer to equal the discovery URL prefix | Suite source | In CI, run AnvilID behind a TLS terminator (Caddy or nginx sidecar with a cert generated at CI time, never committed) with `ANVILID_PUBLIC_URL=https://<op-host>:<port>`. The suite trusts any cert: `AbstractCondition` uses a trust-all `X509TrustManager` + `NoopHostnameVerifier`, and the suite's own CI uses a self-signed `local-provider-oidcc.crt`. Trusted-proxy support (Phase 3) is **not** needed because the issuer comes from `public_url`, never from request headers |
| **C6** | §16 puts HTTP integration and security tests in `anvil-web/tests`, but `anvil-web` may not import concrete storage crates, and QUAL-02 needs those tests on both backends | §4, §16 | The Phase 1 dependency checker should ignore `kind = "dev"` dependencies, so `anvil-web/tests` can dev-depend on both storage crates and pick one via `ANVILID_TEST_DB=sqlite\|postgres`. Alternative: move these tests to `crates/anvilid/tests` |

## Gaps in the §6.1 data model for 0.1

| # | Gap | Why | Fix |
|---|-----|-----|-----|
| G1 | `client` needs `require_pkce` (C1) and `default_audience`/AT audience policy | C1. RFC 9068 requires `aud` and resource indicators arrive in Phase 4 | Add the columns |
| G2 | `token_family` needs `auth_time`, `acr`, `amr`, `browser_session_id`/`sid` | A refreshed ID token must repeat `auth_time` (`CompareIdTokenClaims` FAILURE if it differs) | Add the columns. Fill them from the code at exchange time |
| G3 | Every code exchange must create a `token_family`, even when no refresh token is issued | Code reuse must revoke the access token issued from it. JWT access tokens aren't stored, so revocation happens through the family | Always create the family. Put the family id in the AT (private claim) and have UserInfo check `token_family.revoked_at` |
| G4 | `user` needs standard-claim storage (profile and address) | Scope tests WARN (and so fail CI) on missing claims | Store OIDC standard claims in `attributes` JSON with a typed accessor. `updated_at` comes from the column, as a number |
| G5 | `admin_setup_token` → admin user + **management API credential** | Without a console there is no other way to get admin API tokens in 0.1 | See Q2 |
| G6 | Verification and recovery tokens | Not in §6.1 | Store them as `flow` rows (kind `verification`/`recovery`) with `token_hash`, or add a `self_service_token` table (hash PK, kind, user_id, expires_at, consumed_at), consumed atomically like codes |

## Standard Stack

All versions were checked on crates.io / npm on 2026-11-25.

### Core
| Library | Version | Purpose | Notes (verified) |
|---------|---------|---------|------------------|
| axum | 0.8.9 | HTTP | |
| axum-extra | 0.12.6 | cookies (`cookie` 0.18), typed headers | |
| tower-http | 0.7.1 | CORS, headers, body limit, trace | Compatible with axum 0.8 (http 1, tower-layer 0.3). axum optionally pins tower-http 0.6, so expect a cargo-deny duplicate warning if both appear. Using 0.6.x avoids it |
| aws-lc-rs | 1.19.0 | RSA keygen (`rsa::KeyPair::generate(KeySize::Rsa2048)`), PKCS#8 export (`AsDer<Pkcs8V1Der>`), HKDF, `aead::RandomizedNonceKey` (AES-256-GCM, internal nonces), `rand`, `digest` (SHA-256) | **No PKCS#1 private export exists** (verified in source) |
| jsonwebtoken | 12.0.0 (2026-11-13) | JWS encode/decode, `jwk::Jwk::from_encoding_key`, `Jwk::thumbprint(ThumbprintHash::SHA256)`, `DecodingKey::from_jwk` | Features: `default-features = false, features = ["aws_lc_rs", "use_pem"]`. **`use_pem` is required** for the PKCS#8 path. With exactly one backend feature, no `install_default()` is needed. Call `CryptoProvider::try_get_default()` at startup to fail fast. 12.0 rejects unknown `crit` |
| argon2 | 0.6.0 | Argon2id | `Params::DEFAULT` = m 19456 KiB, t 2, p 1, which matches OWASP exactly. `Params::new(m,t,p,None)`. Use `hash_password_with_salt` with a salt from aws-lc-rs, so `getrandom` is not a second RNG |
| minijinja | 3.1.0 | Templates | `features = ["serde"]` (**serde is off by default in 3.x**). There is **no `loader` feature**: `set_loader`/`path_loader` are always available. Auto-escapes `.html`, `.htm` and `.xml` (and `.html.j2`) |
| lettre | 0.11.24 | SMTP | `default-features = false, features = ["tokio1-rustls", "aws-lc-rs", "webpki-roots", "smtp-transport", "builder", "hostname", "pool"]`. Don't use `rustls-tls`, because it enables `ring` |
| utoipa | 6.0.0 | OpenAPI | Serializes **OpenAPI 3.1 by default** (`OpenApiVersion::Version31`; 3.2 is opt-in). Features `["axum_extras", "uuid", "time"]`. MSRV 1.88 |
| utoipa-axum | 0.3.0 | `OpenApiRouter` + `routes!` | Depends on utoipa 6.0.0 and axum 0.8.4+ |
| sqlx | 0.9.1 | Storage | Phase 1 owns the setup |
| subtle | 2.6.1 | Constant-time compare of secret hashes | Or `aws_lc_rs::constant_time::verify_slices_are_equal` |
| secrecy / zeroize | 0.10.3 / 1.9.2 | Secret hygiene | |
| figment, clap 4, time 0.3.55, uuid 1.29 (v7), url 2.5.9, base64 0.23.1 | | config, CLI, time, ids | |

### Supporting
| Library | Version | Purpose | When |
|---------|---------|---------|------|
| reqwest | 0.13.5 (rustls) | HIBP range API | Fixed host only. jwks_uri (and its SSRF guard) is deferred, see Pitfall P14 |
| rust-embed | 8.14.0 | Embedding `themes/default` | |
| proptest 1.12, insta 1.49, wiremock 0.6.5, testcontainers 0.28 / -modules 0.15, axum-test 21.1 or `tower::ServiceExt::oneshot` | | tests | dev only |
| cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, arbitrary 1.5 | | SEC-07 fuzzing (`fuzz/` crate, nightly) | |
| openid-client (npm) | 6.9.1 | Sample RP in `examples/` | Certified-grade RP by the node-oidc-provider author. Enforces RFC 9207 `iss` when `authorization_response_iss_parameter_supported` is true (verified in oauth4webapi 3.8.9 source) |
| express | 5.3.0 | Sample RP server | |
| @playwright/test | 1.65.1 (node ≥20) | e2e + QUAL-04 script | |
| Mailpit (container) | latest | SMTP sink for e2e registration/recovery | Test infrastructure only. Messages are read through its HTTP API |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Node sample RP | Rust RP with `openidconnect` 4.1 | It would live in the workspace and pull RustCrypto `rsa` (banned by cargo-deny). Node pairs naturally with Playwright and openid-client is the reference RP |
| Signing via jsonwebtoken with a PEM-wrapped PKCS#8 | Direct aws-lc-rs signing in `anvil-jose` | Both work. The PEM path keeps jsonwebtoken as the single JWS implementation (§2), and the conversion is done once at key load |
| HtmlUnit browser config for conformance | Separate Selenium | The suite has HtmlUnit built in. Our pages are JS-free, so it works |

**Installation (workspace excerpt):**
```toml
jsonwebtoken = { version = "12.0.0", default-features = false, features = ["aws_lc_rs", "use_pem"] }
aws-lc-rs    = "1.19"
argon2       = { version = "0.6.0", default-features = false, features = ["alloc", "password-hash"] }
minijinja    = { version = "3.1.0", features = ["serde"] }
lettre       = { version = "0.11.24", default-features = false, features = ["tokio1-rustls", "aws-lc-rs", "webpki-roots", "smtp-transport", "builder", "hostname", "pool"] }
utoipa       = { version = "6.0.0", features = ["axum_extras", "uuid", "time"] }
utoipa-axum  = "0.3.0"
```

## OpenID Conformance: exact requirements for Basic OP + Config OP

Source: `gitlab.com/openid/conformance-suite` @ `246b2c14` (2026-11-24).

### Basic OP (`oidcc-basic-certification-test-plan`)
The plan runs with variants `response_type=code`, `client_auth_type=client_secret_basic` and `response_mode=default`. `oidcc-server-client-secret-post` runs with `client_secret_post`. With `client_registration=static_client`, the config needs `client`, `client2` and `client_secret_post` sections (client_id + client_secret each). Every client needs the exact redirect URI `{suite_base}/test/a/{alias}/callback`.

| Module | What AnvilID must do | Severity if wrong |
|---|---|---|
| oidcc-server | Happy path: code → token (basic auth), ID token checks (below), `state` echoed, UserInfo | FAILURE |
| oidcc-response-type-missing | Missing `response_type` with a valid client and redirect → **redirect** with `invalid_request` or `unsupported_response_type` (+ `iss`). An error page would need a screenshot | FAILURE |
| oidcc-idtoken-signature | RS256, `kid` present, verifiable via JWKS | FAILURE |
| oidcc-idtoken-unsigned | **Skipped** if `none` is not in `id_token_signing_alg_values_supported` (acceptable for certification) | add to expected-skips |
| oidcc-userinfo-get / -post-header / -post-body | Bearer in header (GET and POST). Body-form token: WARNING if unsupported, so **support it** (RFC 6750 §2.2). Never accept tokens in the query string | FAILURE / WARNING |
| oidcc-ensure-request-without-nonce-succeeds-for-code-flow | `nonce` is optional for code flow. **With C1, a client with `require_pkce=false` must still allow this**: the request has neither nonce nor PKCE. Decision: when PKCE isn't required, accept missing nonce for confidential clients (the code is bound to the client secret), or list this as an expected failure. Recommend accepting, because OIDC Core makes nonce optional for code flow | FAILURE |
| oidcc-scope-profile / email / address / phone / all | Claims for the scope present in UserInfo (`VerifyScopesReturnedInUserInfoClaims` WARNING). Types validated (`ValidateUserInfoStandardClaims` FAILURE): `email_verified` boolean, `address` object, `updated_at` number. `sub` equals the ID token `sub` | WARNING / FAILURE |
| oidcc-ensure-other-scope-order-succeeds | Scope order independent | FAILURE |
| oidcc-display-page / -popup | `display` must not cause an error | FAILURE |
| oidcc-prompt-login | A second login page is shown even with a session. `auth_time` later | FAILURE |
| oidcc-prompt-none-not-logged-in | Redirect error `login_required` (one of 4 permitted). Long `state` preserved | FAILURE |
| oidcc-prompt-none-logged-in | Silent success with the session. `sub` and `auth_time` consistent | FAILURE |
| oidcc-max-age-1 | After 1 s, `max_age=1` forces re-login. `auth_time` present and later | FAILURE |
| oidcc-max-age-10000 | Session reused. `auth_time` present | FAILURE |
| oidcc-unknown-parameter | Ignore unknown parameters | FAILURE |
| oidcc-id-token-hint | `prompt=none` + `id_token_hint` (our own ID token) → silent success. Validate the hint signature with our keys and `iss`, **ignore `exp`**, and check that `sub` matches the session | FAILURE |
| oidcc-login-hint / ui-locales / claims-locales | Must not error | FAILURE |
| oidcc-ensure-request-with-acr-values-succeeds | Succeeds. ID token `acr` should be one of the requested values (WARNING otherwise), so advertise `acr_values_supported` and echo a satisfied value | WARNING |
| oidcc-codereuse | Second use → `invalid_grant` | WARNING |
| oidcc-codereuse-30seconds | `invalid_grant`, **and the AT from the first exchange must be rejected by UserInfo** (4xx), otherwise WARNING. Needs G3 | WARNING |
| oidcc-ensure-registered-redirect-uri | Error page (no redirect). Browser config waits for a stable string and uploads a screenshot. Result REVIEW is allowed by the runner | FAILURE |
| oidcc-ensure-post-request-succeeds | `POST /authorize` (form) works like GET | WARNING |
| oidcc-server-client-secret-post | Happy path with `client_secret_post` | FAILURE |
| oidcc-request-uri-unsigned-…, oidcc-unsigned-request-object-…, oidcc-ensure-request-object-with-redirect-uri | **Skipped** when `none` is not in `request_object_signing_alg_values_supported` (`skipTestIfNoneUnsupported`). Don't advertise it. If `request`/`request_uri` is sent anyway, return `request_not_supported` / `request_uri_not_supported` | expected-skips |
| oidcc-claims-essential | `claims={"userinfo":{"name":{"essential":true}}}` with scope `openid` only: success, `name` in UserInfo (WARNING if missing) and **not** in the ID token (WARNING if present) | WARNING. **Implement minimal `claims` parameter support** |
| oidcc-refresh-token | Skipped if no refresh token is issued. Otherwise: refresh works with `Cache-Control: no-store`, new ID token `iss/sub/aud/azp/auth_time` equal to the original, **client 2's RT presented by client 1 → error**. If `offline_access` is in `scopes_supported`, the suite adds `prompt=consent`, so **do not advertise `offline_access` in 0.1** (no consent UI). Issue RTs to clients whose `grant_types` include `refresh_token` | FAILURE |
| oidcc-ensure-request-with-valid-pkce-succeeds | Valid S256 PKCE works | FAILURE |

**ID token checks run on every flow** (`PerformStandardIdTokenChecks`, all FAILURE): `iss` equals the discovery issuer, `aud` contains client_id, `exp` present and in the future (seconds, not ms), `iat` within 5 minutes and not in the future, `auth_time` sane if present, `acr` non-empty if present, `nonce` equals the sent value, signature valid, `sub` present, `updated_at` a number if present.

**Token endpoint** (FAILURE): HTTP 200, `application/json`, **`Cache-Control: no-store`**, `token_type` Bearer, AT entropy of at least 128 bits, `expires_in` present (WARNING), RT charset per RFC 6749 A.17.

### Config OP (`oidcc-config-certification-test-plan`)
Single module, `oidcc-discovery-endpoint-verification`, with `server_metadata=discovery`:
- 200 + JSON content type. `issuer` equals the discovery URL minus `/.well-known/openid-configuration`, **exact string, no trailing slash** (FAILURE).
- Validated against the suite schema `json-schemas/rfc8414/oauth_authorization_server_metadata.json` (`additionalProperties: false`). **Any field outside its 106-property list raises a WARNING** (`CheckForUnexpectedParametersInServerMetadata`). All fields we plan to publish are in the list, including `authorization_response_iss_parameter_supported`, `code_challenge_methods_supported`, `prompt_values_supported` and `claims_parameter_supported`.
- `response_types_supported` contains at least one OIDC type (`code`). `grant_types_supported` is a non-empty array if present. `id_token_signing_alg_values_supported` contains RS256. `subject_types_supported` is present. `scopes_supported` contains `openid`. `userinfo_endpoint` present (WARNING if absent). `jwks_uri` fetchable, keys valid with distinct `kid`s. `code_challenge_methods_supported` is an array. **All `*_endpoint` HTTPS** (C5). Locale syntax is valid if present.

**Recommended 0.1 discovery document** (same JSON at both well-known paths):
```json
{
  "issuer": "https://op.example",
  "authorization_endpoint": "https://op.example/authorize",
  "token_endpoint": "https://op.example/token",
  "userinfo_endpoint": "https://op.example/userinfo",
  "jwks_uri": "https://op.example/jwks",
  "scopes_supported": ["openid", "profile", "email", "address", "phone"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true,
  "prompt_values_supported": ["none", "login"],
  "acr_values_supported": ["<single 0.1 password-level value>"],
  "claims_parameter_supported": true,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "claims_supported": ["sub","iss","aud","exp","iat","auth_time","nonce","acr","amr","azp","sid","name","given_name","family_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at","email","email_verified","address","phone_number","phone_number_verified"]
}
```
`request_uri_parameter_supported` **defaults to true when omitted** (OIDC Discovery §3), so set it to false explicitly. Don't list `offline_access` or `none`. If `private_key_jwt` verification only supports RS256 in 0.1, list only `RS256` in `token_endpoint_auth_signing_alg_values_supported` (verifying ES256/PS256 client assertions is cheap with jsonwebtoken, and the Phase 3 deferral of ES256 concerns **signing**).

### Driving the suite headlessly (Phase 2 additions to the Phase 1 pipeline)
- The config JSON has a `browser` array (HtmlUnit, JS errors ignored) with `match` URL globs and `commands`: `["text","id","identifier","<user>","optional"]`, `["click","id","login-submit"]`, `["wait","id","submission_complete",10]`, and `["wait","xpath","//*",10,"<stable error text>","update-image-placeholder"]` for error-page modules. Per-module `override` blocks for `oidcc-prompt-login`, `oidcc-max-age-1` (`update-image-placeholder-optional` on the second login page) and `oidcc-ensure-registered-redirect-uri` (error page). The model is `.gitlab-ci/local-provider-oidcc-conformance-config.json` in the suite repo.
- **Stable selectors are part of the contract.** The login page needs fixed `id`/`name` attributes (`identifier`, `password`, `login-submit`), and the redirect-URI error page needs a fixed text marker. Snapshot-test them so a template change can't silently break conformance.
- `run-test-plan.py --expected-skips-file tests/conformance/expected-skips.json --expected-failures-file tests/conformance/expected-failures.json oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] config.json oidcc-config-certification-test-plan config.json`. Unexpected skips, warnings and failures all fail the run. Expected skips: `oidcc-idtoken-unsigned`, the 3 request-object/request-uri modules. Anything else should pass without an entry.
- Per-run setup script: start the binary behind TLS, run bootstrap (Q2), create 3 confidential clients (`require_pkce=false`, exact suite callback, `grant_types` including refresh_token) and a user with **every standard claim filled**, then write the config JSON with the generated secrets to a temp file. Nothing is committed.

## Architecture Patterns

### Recommended module layout (within the §4 crates)
```
crates/anvil-core/src/
  domain/        # TenantId, Tenant, User, Client, Credential, Scope, Claims, SessionInfo...
  ports/         # Storage + repo traits, StorageError, Clock, Rng, PasswordHasher, Mailer-outbox (C3)
  error.rs       # CoreError -> OAuthError / HTTP status / FlowMessage (single mapping)
  oauth/         # authorize_request.rs (parse+validate), redirect.rs, pkce.rs, scope.rs, claims_request.rs
  service/       # authorize.rs, token.rs, client_auth.rs, key.rs, session.rs, user.rs, client.rs, tenant.rs, bootstrap.rs
  flow/          # engine.rs, login.rs, registration.rs, verification.rs, recovery.rs, form.rs (FormDescription)
crates/anvil-jose/src/  keys.rs (gen, PKCS#8, KEK envelope), jwk.rs (JWKS, kid), sign.rs, verify.rs (allow-lists, client assertions), hash.rs (at_hash)
crates/anvil-web/src/
  state.rs       # AppState (Arc<dyn Storage>, services, config, templates)
  layers/        # tenant resolution, security headers, request id, fetch-metadata CSRF
  protocol/      # discovery, jwks, authorize, token, userinfo (each exposes routes())
  ui/            # login, registration, verification, recovery, setup, error pages
  admin/         # /api/admin/v1 (utoipa-axum OpenApiRouter), bearer auth extractor
  render.rs      # minijinja env: theme dir loader -> embedded fallback
  cookies.rs     # cookie policy (prod vs dev)
crates/anvil-mail/src/  outbox worker, templates, MailTransport trait, SMTP impl
crates/anvilid/src/     config (figment), cli (serve/migrate/config/admin setup-url), bootstrap, jobs
themes/default/         *.html templates + css (hashed asset names)
examples/node-rp/       express + openid-client sample
tests/conformance/      config template, expected-*.json, setup script
tests/e2e/              Playwright specs (+ qual04 zero-config script)
fuzz/                   cargo-fuzz targets
```

### Pattern 1: Authorization request pipeline (order matters)
1. Resolve tenant → issuer (one function, C4).
2. Parse params from query (GET) or form (POST). Reject duplicate parameters with `invalid_request`.
3. Look up the client. **If the client is unknown, or `redirect_uri` doesn't match exactly, render the error page and never redirect.** Steps 3–4 run before anything that could redirect.
4. Redirect URI match: exact string; loopback exception (`http://127.0.0.1:{any}`, `http://[::1]:{any}`) only for clients registered as native with a loopback URI. `localhost` gets no port flexibility (RFC 8252 §8.3 recommends IP literals). Registration-time validation: no fragments, no wildcards, `http` only for loopback.
5. From here on, errors redirect with `error`, `error_description`, `state` and **`iss`** (RFC 9207 includes error responses).
6. `response_type` must be `code` (missing → `invalid_request`, others → `unsupported_response_type`). `request`/`request_uri` → `request_not_supported`/`request_uri_not_supported`.
7. PKCE: `code_challenge_method` must be `S256` (missing method with a challenge → `invalid_request`; `plain` → `invalid_request`). Challenge must be a 43-char base64url string. Required unless the client has `require_pkce=false` (C1).
8. Scope: must be in the client's allowed scopes. Unknown scopes are rejected (`invalid_scope`) or dropped (decide once, test it).
9. Persist an `authorization_request` row (expires about 15 min). Then decide with the session (prompt, max_age, id_token_hint): issue a code now, or start a login flow bound to the request id.

### Pattern 2: Flow engine (pure transitions + one renderer)
- `fn transition(state: FlowState, input: FlowInput, ctx: &Ctx) -> (FlowState, Vec<Effect>)`. Effects (`VerifyPassword`, `CreateSession`, `EnqueueEmail`, `CompleteAuthorization`) are executed by the service layer through ports, so the pure part is exhaustively unit-testable.
- Each step yields a `FormDescription { action, method, fields: [{name, kind, value, required, autocomplete, messages}], messages, csrf_token }`. The handler renders `templates/{flow}.html` with it. On validation error, re-render the same form with field messages and previous non-secret values (never echo passwords), with HTTP 400 (or 200; pick one consistently) and **no redirect**.
- On success the handler responds **303 See Other** (RFC 9700 §4.12: never 307 after a credential POST) to the authorize continuation (`/authorize/continue?request={id}`) or the next step.
- The flow row stores `csrf_hash` and a hash of the flow-cookie value. Both are checked on every POST (synchronizer token), and the flow expires after 15 min.

### Pattern 3: CSRF = synchronizer token + Fetch Metadata (Go 1.25 `CrossOriginProtection` semantics)
For unsafe methods (GET/HEAD/OPTIONS are exempt):
1. If `Sec-Fetch-Site` is present: allow only `same-origin` or `none`; otherwise reject with 403.
2. Else if `Origin` is present: require `Origin` == this server's public origin (scheme+host+port from `public_url` or the tenant host); otherwise reject.
3. Else (neither header): allow (non-browser or old browser). The synchronizer token still applies.
4. Then require the form `csrf_token` to match the flow's `csrf_hash` (constant-time).
This matters for conformance because HtmlUnit may omit Fetch Metadata headers, and rule 3 keeps it working. **Exempt from the browser CSRF layer:** `/token` and `/api/admin/*` (client-authenticated, no cookies), and `POST /authorize` (an OAuth front-channel request that is cross-site by design; `oidcc-ensure-post-request-succeeds`).

### Pattern 4: Cookie policy
| Cookie | Prod (https public_url) | Dev (http://localhost or 127.0.0.1) |
|---|---|---|
| session | `__Host-anvil_session`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain | `anvil_session`, HttpOnly, SameSite=Lax (no Secure, no prefix). Warning logged once and dev banner shown |
| flow | `__Host-anvil_flow`, Secure, HttpOnly, SameSite=**Strict**, Path=/ | `anvil_flow`, HttpOnly, SameSite=Strict |
- Path tenants share a host, so `__Host-` cookies must be keyed by tenant in the **name** (for example `__Host-anvil_session_{tenant_short_id}`) or store per-tenant entries server-side. `__Host-` forbids a Path other than `/`.
- A SameSite=Strict flow cookie is **not sent** on the cross-site navigation from an email link. Verification and recovery links must therefore carry a self-contained token and must not depend on the flow cookie.
- The session cookie value is 256-bit random. Store only its SHA-256 (§6.2). Rotate it on login (session fixation).

### Pattern 5: Bounded Argon2 pool + timing equalization
```rust
// anvil-web (or anvilid) implementation of anvil_core::ports::PasswordHasher
pub struct Argon2Pool { sem: Arc<tokio::sync::Semaphore>, params: argon2::Params, dummy_phc: String }
impl Argon2Pool {
    pub async fn verify(&self, phc: Option<&str>, password: SecretString) -> Result<bool, CoreError> {
        let permit = tokio::time::timeout(Duration::from_secs(5), self.sem.clone().acquire_owned())
            .await.map_err(|_| CoreError::Overloaded)?.map_err(|_| CoreError::Overloaded)?;
        let target = phc.map(str::to_owned).unwrap_or_else(|| self.dummy_phc.clone()); // unknown user => dummy hash
        let known = phc.is_some();
        tokio::task::spawn_blocking(move || {
            let _p = permit;
            let parsed = argon2::PasswordHash::new(&target).ok();
            let ok = parsed.map(|h| argon2::Argon2::default()
                .verify_password(password.expose_secret().as_bytes(), &h).is_ok()).unwrap_or(false);
            known && ok
        }).await.map_err(|_| CoreError::Internal)
    }
}
```
- Permits = `std::thread::available_parallelism()` (each verify uses about 19 MiB, so N×19 MiB is the peak). Saturation returns 503 / a "try again" flow message, never a fallback.
- `dummy_phc` is generated at startup with the **same params** from a random password. Rehash on successful login if the stored params differ from current (`needs_rehash`).
- Users without a password credential and blocked users also go through the dummy path, with the same response and message as a wrong password.
- Password policy: minimum 8 characters (NIST SP 800-63B), maximum length (for example 1024 characters) to bound hashing cost, no composition rules, optional breach check.

### Pattern 6: Breach check (HIBP k-anonymity, AUTH-01)
`GET https://api.pwnedpasswords.com/range/{first5 SHA-1 hex}` with header `Add-Padding: true` (pads to 800–1000 entries; drop count-0 lines). No API key, no rate limit (verified on the HIBP API v3 page). Use SHA-1 via `aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY`. Config: `password.breach_check = "hibp" | "off"` (air-gapped) plus `password.breach_check_url` (base URL; tests point it at wiremock, which is configuration and not a test hook). Fail-open with a warning log on network error or timeout (2 s), and document it.

### Pattern 7: Email verification and recovery without enumeration (AUTH-02/03)
- **Recovery request:** always render the same "If an account exists for that address, we've sent instructions" page with the same status, whether or not the user exists. Delivery is asynchronous through the outbox, so the request path does the same work (indexed lookup, at most one row insert) and the response time doesn't depend on SMTP. Optionally (default off) send a "no account exists" notice to unknown addresses.
- **Token:** 256-bit random, base64url, SHA-256 stored, single-use (atomic `UPDATE … WHERE consumed_at IS NULL AND expires_at > ? RETURNING`). Recovery expires after 1 h and verification after 24 h. Bound to user_id and the email address it was sent to (invalid if the email changed).
- **Link scanners:** `GET /ui/recovery?token=…` shows a page with a button that POSTs the token. **Consume only on POST.** Otherwise mail security scanners that prefetch links burn the single-use token.
- Pages carrying tokens send `Referrer-Policy: no-referrer` and no third-party assets.
- After a successful recovery: set the new password, mark the email verified (the user just proved control of it), **revoke all browser sessions and token families for the user**, then send a "your password was changed" notice.
- **Verification is not required to log in** by default (tenant setting `require_verified_email`, default false). The `email_verified` claim reflects the actual state. Zero-config and QUAL-04 work without SMTP.
- **Registration enumeration** (optional hardening, not required by AUTH-02): show "check your email" and email the existing user, instead of saying "email already taken". Recommend implementing the clean `Conflict` path first and leaving this as a tenant option.

### Pattern 8: Outbox + transport
- `email_outbox` row inserted in the same transaction as the domain change. The worker (anvilid background job, `job_lease`-guarded) claims due rows (Postgres `FOR UPDATE SKIP LOCKED`, SQLite single writer), renders the template with minijinja (`emails/*.txt` + `.html`), sends via `trait MailTransport { async fn send(&self, msg: OutgoingMail) -> Result<(), MailError> }`, and on failure records `attempts` + `next_attempt_at` (exponential backoff) and `last_error`.
- Production impl: `lettre::AsyncSmtpTransport<Tokio1Executor>::from_url(smtp_url)?.build()`.
- **No SMTP configured** (zero-config): the worker is not started, startup logs a warning, and rows stay pending (they expire). Never log message bodies or links (they contain tokens).
- Tests: `CapturingTransport` (a `Mutex<Vec<OutgoingMail>>`) lives in **test code only**, for example `anvil-mail/tests/support` or a dev-dependency test-support crate that is never a normal dependency. Playwright e2e uses a Mailpit container through real SMTP.

### Pattern 9: Management API (ADM-01)
- `OpenApiRouter::new().routes(routes!(list_users, create_user)).…split_for_parts()` gives `(Router, OpenApi)`. Serve the spec at `/api/admin/v1/openapi.json`. Add a `SecurityScheme::OAuth2` (clientCredentials flow, token URL = system tenant token endpoint, scopes listed).
- Auth extractor: Bearer JWT, verified locally with `KeyService` (system tenant keys). `typ` must be `at+jwt`, `iss` must be the system issuer, `aud` must be the management API identifier, `exp` must be valid, and the family must not be revoked. Required scope is checked per route (`admin:read`, `admin:write`, `admin:{resource}:write`). Errors return `WWW-Authenticate: Bearer error="invalid_token"` (401) or `insufficient_scope` (403).
- 0.1 resources: `tenants` (system-only), `tenants/{tenant}/clients` (secret returned **once** on create and on rotate), `tenants/{tenant}/users` (create with password or invite, update claims, block, delete). Pagination (cursor on UUIDv7), RFC 9457 problem+json errors.
- **OpenAPI drift check:** a test (or `anvilid openapi` hidden subcommand / xtask) writes the generated JSON. CI diffs it against the committed `docs/openapi/admin-v1.json` (an insta snapshot works too) and fails on difference.

### Pattern 10: Bootstrap (ADM-03, OPS-05)
- `serve` with an empty database, in one transaction: create tenants `system` and `default`, generate KEK if absent (`anvilid-data/kek`, 0600, warn "back this up"), generate one active RS256 key per tenant (encrypted), create `admin_setup_token` (1 h), and print `Setup URL: {public_url}/setup?token=…` as a **stable log line** (scripts grep for it).
- `/setup` (installation-level route): GET validates the token without consuming it. POST (CSRF-protected) atomically consumes the token, creates the first admin user in `system`, and (Q2) shows a one-time management API client credential.
- `anvilid admin setup-url`: issues a new token. With SQLite, the **single-instance lock should be a separate `serve.lock` file**, so admin CLI commands can open the WAL database while `serve` runs (Pitfall P10).

### Anti-Patterns to Avoid
- **Building the issuer string with `url::Url` serialization.** `Url::parse("https://h")` serializes as `https://h/`, and the trailing slash breaks `CheckDiscEndpointIssuer` and every `iss` comparison. Build the issuer string explicitly (strip trailing `/` from `public_url`, append the base path).
- **Using `Validation::set_audience` alone for client assertions.** It accepts any `aud` array that *contains* the issuer, but RFC 10070 requires the issuer as the **sole** value.
- **Check-then-insert** for users, codes, jti or setup tokens. Use the atomic contracts from §7.1.
- **Business logic in handlers** (for example computing at_hash or deciding on prompt in axum code).
- **Logging** tokens, codes, secrets, setup URLs at debug level, or email bodies. The setup URL is printed once deliberately, at info level, on first start only.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWS sign/verify, JWK n/e, RFC 7638 thumbprint | Custom base64/JSON canonicalization | jsonwebtoken 12 (`encode`, `decode`, `Jwk::from_encoding_key`, `Jwk::thumbprint`) | The canonical member order (`e`,`kty`,`n`) and base64url details are easy to get wrong. Verified in the probe |
| RSA keygen, AES-GCM, HKDF, CSPRNG, SHA-256 | Anything | aws-lc-rs (`rsa::KeyPair::generate`, `aead::RandomizedNonceKey`, `hkdf::Salt`, `rand::fill`, `digest`) | Single backend (§2). `RandomizedNonceKey` removes nonce management |
| Argon2id | | argon2 0.6 | |
| Constant-time compare | `==` on hashes | `subtle::ConstantTimeEq` | |
| OpenAPI generation | Hand-written spec | utoipa + utoipa-axum | Drift-free |
| SMTP | | lettre | |
| Sample RP | Hand-rolled OAuth client | openid-client 6.9 | The sample also acts as an independent validator (it enforces `iss`, `nonce`, PKCE and ID token checks) |
| Conformance browser automation | Custom Selenium | Suite's built-in `browser` config | |
| Template escaping | Manual | minijinja auto-escape by `.html` extension | |

**Key insight:** in this phase the dangerous bugs are semantic (wrong audience rule, trailing slash, PKCE downgrade, 307 vs 303, Strict cookies on email links), not algorithmic. Spend the effort on negative tests and conformance, not on primitives.

## Common Pitfalls

### P1: PKCS#8 vs PKCS#1 when bridging aws-lc-rs → jsonwebtoken (verified by probe)
**What goes wrong:** `EncodingKey::from_rsa_der(pkcs8)` constructs fine, but `encode` fails with "Signing failed: signature error".
**Why:** the jsonwebtoken aws-lc backend calls `RsaKeyPair::from_der`, which parses an RFC 8017 `RSAPrivateKey` (PKCS#1). aws-lc-rs only exports PKCS#8.
**How to avoid:** store PKCS#8 (encrypted). At load time wrap it as `-----BEGIN PRIVATE KEY-----` PEM and call `EncodingKey::from_rsa_pem` (needs `use_pem`). Unit test: generate → sign → verify via the JWKS-derived `DecodingKey`.

### P2: Requiring PKCE breaks Basic OP (C1)
**Warning sign:** every conformance module fails at the authorization endpoint with `invalid_request`.

### P3: Unexpected WARNINGs or SKIPs fail CI even though certification would accept them
Keep `expected-skips.json` minimal and reviewed. Avoid warnings by: supporting the UserInfo body token, minimal `claims` parameter support, a full-profile test user, `acr` echo, AT revocation on code reuse, and publishing no non-schema metadata fields.

### P4: Refreshed ID token differs from the original
`auth_time` must be the original authentication time. `azp` must be present in both or neither. Omit `nonce` from refreshed ID tokens. Needs G2.

### P5: Code reuse doesn't kill the JWT access token
Needs G3: a family id in the AT, and a UserInfo family check.

### P6: Client-assertion audience
Enforce `aud` == issuer as a single string, or as a one-element array equal to the issuer. Also `iss == sub == client_id`, `exp` present with `exp - now ≤ 5 min` (and `exp > now - leeway`), `jti` present, then `record_jti(tenant, sha256(client_id‖jti), exp)` insert-or-fail. Alg must be in the key's allow-list and never `HS*`/`none` (jsonwebtoken rejects mixing families: `InvalidAlgorithm`, verified). `typ: client-authentication+jwt` is recommended, and **untyped assertions must still be accepted** (RFC 10070). Accept a missing `kid` only if exactly one key in the client's JWKS fits the alg.

### P7: client_secret_basic decoding
RFC 6749 §2.3.1 form-urlencodes client_id and secret **before** base64. URL-decode both after base64 decoding. Reject requests that use more than one auth method (header + body) with `invalid_client`. Return 401 with `WWW-Authenticate: Basic` when the header was used. Compare `sha256(secret)` to the stored hash in constant time.

### P8: Refresh races
Strict rotation means two concurrent refreshes with the same RT (SPA tabs, retries) trigger reuse detection and revoke the family. This is required by the architecture. Document it for client developers. Also: verify the client binding **before** consuming. A wrong client presenting someone's RT gets `invalid_grant` without consuming it or revoking the family, so it cannot be used to log users out. Scope on refresh may only narrow. The child expires at `min(now + 14 d, family.created_at + 30 d)`.

### P9: Zero-config container is unreachable
The binary default is `127.0.0.1:8080`, which isn't reachable through `-p 8080:8080`. The image must set `ENV ANVILID_LISTEN=0.0.0.0:8080` (the default stays loopback for the bare binary) and use a writable `WORKDIR` (for example `/data` on distroless `nonroot`) for `./anvilid-data`. The dev-mode `public_url` stays `http://localhost:8080`.

### P10: SQLite exclusive lock blocks `anvilid admin setup-url`
If the lock is taken on the database file itself, CLI admin commands can't run while serving. Use a separate `serve.lock`.

### P11: Issuer trailing slash and the well-known path for path tenants
See the Anti-Patterns list and C4. Add tests for the default tenant (`https://h`) and a path tenant (`https://h/t/acme`): discovery is fetched from both paths and `issuer` matches exactly.

### P12: 307 after POST, and open redirects
Always respond 303 after form POSTs. Never redirect to a URI that hasn't passed the exact match. That includes error responses for an unknown `client_id`.

### P13: The `__Host-` prefix and dev mode
Browsers reject `__Host-` cookies without `Secure`. Dev mode on http must use unprefixed names. Detect dev mode from `public_url` (scheme `http` and host `localhost`, `127.0.0.1` or `[::1]`), never from request headers. Over plain http on any other host, refuse to start unless an explicit `--insecure-dev` style flag is set.

### P14: jwks_uri means SSRF
§11 requires a guarded HTTP client for any client-supplied URL. Recommend **inline `jwks` only** for private_key_jwt in 0.1, and reject `jwks_uri` at client registration with an explicit "not supported in this release" validation error (no stub). Ship `jwks_uri` with the SSRF guard in a later phase.

### P15: Email links and SameSite=Strict
See Pattern 4.

### P16: minijinja 3 manifest errors from docs/research/04
`features = ["loader"]` fails to resolve. Without `serde`, `Value::from_serialize` and `context!` with structs aren't available.

### P17: The `prompt=none` hint path
Validate `id_token_hint` with our own keys including retired ones, and ignore `exp` (Core lets OPs accept expired hints). If its `sub` doesn't match the session user, return `login_required`. Never log the hint.

### P18: UserInfo token confusion
Reject ID tokens presented as access tokens (`typ` must be `at+jwt`), tokens from another tenant (`iss`), tokens without the `openid` scope (403 `insufficient_scope`), client-credentials tokens (no user `sub`), tokens in the query string, and revoked families. Set CORS on `/token`, `/userinfo`, `/jwks` and discovery only, never on `/authorize`.

## Code Examples

### RS256 key → signer → JWKS entry with RFC 7638 kid (verified by compiling against aws-lc-rs 1.19 + jsonwebtoken 12.0)
```rust
use aws_lc_rs::{encoding::AsDer, rsa::{KeyPair, KeySize}};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::{Jwk, ThumbprintHash, PublicKeyUse}};

let kp = KeyPair::generate(KeySize::Rsa2048)?;
let pkcs8 = kp.as_der()?;                       // PKCS#8 v1 DER; encrypt with KEK before storing
let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
for line in b64.as_bytes().chunks(64) { pem.push_str(std::str::from_utf8(line)?); pem.push('\n'); }
pem.push_str("-----END PRIVATE KEY-----\n");
let enc = EncodingKey::from_rsa_pem(pem.as_bytes())?;       // NOT from_rsa_der(pkcs8): that fails at sign time

let mut jwk = Jwk::from_encoding_key(&enc, Algorithm::RS256)?; // n, e, alg
let kid = jwk.thumbprint(ThumbprintHash::SHA256)?;           // RFC 7638, base64url
jwk.common.key_id = Some(kid.clone());
jwk.common.public_key_use = Some(PublicKeyUse::Signature);

let mut header = Header::new(Algorithm::RS256);
header.kid = Some(kid);
let id_token = encode(&header, &claims, &enc)?;
// For access tokens: header.typ = Some("at+jwt".into());
```

### KEK envelope (AES-256-GCM with HKDF-derived key, AAD = table + row id)
```rust
use aws_lc_rs::{aead::{Aad, RandomizedNonceKey, AES_256_GCM}, hkdf};
struct Len32; impl hkdf::KeyType for Len32 { fn len(&self) -> usize { 32 } }
fn data_key(kek: &[u8], purpose: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"anvilid/v1").extract(kek);
    let mut out = [0u8; 32];
    prk.expand(&[purpose], Len32).expect("len").fill(&mut out).expect("fill");
    out
}
let key = RandomizedNonceKey::new(&AES_256_GCM, &data_key(kek, b"signing_key"))?;
let mut buf = pkcs8.as_ref().to_vec();
let nonce = key.seal_in_place_append_tag(Aad::from(format!("signing_key:{row_id}").as_bytes()), &mut buf)?;
// store nonce || buf ; open with key.open_in_place(nonce, aad, &mut stored)
```

### at_hash
```rust
let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, access_token.as_bytes());
let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&d.as_ref()[..16]);
```

### PKCE S256 verification (pure, in anvil-core)
```rust
fn verify_s256(verifier: &str, challenge: &str) -> Result<(), CoreError> {
    // RFC 7636 §4.1: 43..=128 chars of [A-Z a-z 0-9 - . _ ~]
    let ok_len = (43..=128).contains(&verifier.len());
    let ok_chars = verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if !(ok_len && ok_chars) { return Err(CoreError::InvalidGrant("invalid code_verifier")); }
    let computed = b64url(sha256(verifier.as_bytes()));   // via a Crypto port or anvil-jose helper
    if computed.as_bytes().ct_eq(challenge.as_bytes()).into() { Ok(()) } else { Err(CoreError::InvalidGrant("PKCE mismatch")) }
}
// Downgrade (RFC 9700 §4.8.2): code had no challenge AND request has code_verifier -> invalid_grant.
// Code had a challenge AND request lacks code_verifier -> invalid_grant.
```

### Redirect URI matching
```rust
fn redirect_matches(registered: &[String], requested: &str, native: bool) -> bool {
    if registered.iter().any(|r| r == requested) { return true; }     // exact string
    if !native { return false; }
    let Ok(req) = url::Url::parse(requested) else { return false };
    let is_loopback = |u: &url::Url| u.scheme() == "http"
        && (matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback()));
    is_loopback(&req) && registered.iter().filter_map(|r| url::Url::parse(r).ok()).any(|r|
        is_loopback(&r) && r.host() == req.host() && r.path() == req.path() && r.query() == req.query())
}
```

### Conformance browser config skeleton (generated per run; selectors are a contract)
```json
{
  "alias": "anvilid",
  "server": { "discoveryUrl": "https://anvilid-op:8443/.well-known/openid-configuration" },
  "client":  { "client_id": "<gen>", "client_secret": "<gen>" },
  "client2": { "client_id": "<gen>", "client_secret": "<gen>" },
  "client_secret_post": { "client_id": "<gen>", "client_secret": "<gen>" },
  "browser": [{
    "match": "https://anvilid-op:8443/authorize*",
    "tasks": [
      { "task": "Login", "optional": true, "match": "https://anvilid-op:8443/ui/login*",
        "commands": [["text","id","identifier","<user>","optional"],["text","id","password","<pw>","optional"],["click","id","login-submit"]] },
      { "task": "Verify Complete", "match": "*/test/*/callback*", "commands": [["wait","id","submission_complete",10]] }
    ]
  }],
  "override": {
    "oidcc-ensure-registered-redirect-uri": { "browser": [{ "match": "https://anvilid-op:8443/authorize*",
      "tasks": [{ "task": "Expect error page", "match": "https://anvilid-op:8443/authorize*",
        "commands": [["wait","xpath","//*",10,"<stable redirect-uri error text>","update-image-placeholder"]] }] }] }
  }
}
```
(Add `oidcc-prompt-login` and `oidcc-max-age-1` overrides with `update-image-placeholder-optional` on the second login page, as in the suite's own example.)

### Sample RP core (examples/node-rp, openid-client 6.9.1)
```js
import * as client from 'openid-client';
const config = await client.discovery(new URL(process.env.ISSUER), process.env.CLIENT_ID, process.env.CLIENT_SECRET);
if (new URL(process.env.ISSUER).hostname === 'localhost') client.allowInsecureRequests(config); // dev mode only
// /login: verifier = client.randomPKCECodeVerifier(); challenge = await client.calculatePKCECodeChallenge(verifier);
//         nonce/state random; redirect to client.buildAuthorizationUrl(config, {redirect_uri, scope:'openid profile email', code_challenge, code_challenge_method:'S256', state, nonce})
// /callback: tokens = await client.authorizationCodeGrant(config, new URL(req.url, base), {pkceCodeVerifier, expectedState, expectedNonce})
//            info = await client.fetchUserInfo(config, tokens.access_token, tokens.claims().sub)
// /refresh: refreshed = await client.refreshTokenGrant(config, refresh_token)   // rotation: store the new RT
```

## RFC 9700 / OAuth 2.1 checklist → 0.1 tests (SEC-01, QUAL-01)

| Control (source) | Test (file under `anvil-web/tests/security_*.rs` unless noted) |
|---|---|
| Exact redirect match; no redirect on mismatch (9700 §4.1, §4.11) | `security_redirect`: unregistered URI, appended path, added query, different case or port (non-native), fragment → error page, **no Location header** |
| Loopback port flexibility only for native (RFC 8252 §7.3) | native client with any port → ok. Web client with a different port → error page. `localhost` (not an IP) → no flexibility |
| PKCE required, S256 only (OIDC-1; 9700 §2.1.1) | missing challenge (require_pkce=true) → `invalid_request` redirect. `plain` → `invalid_request`. Wrong verifier → `invalid_grant`. Malformed verifier → `invalid_grant` |
| PKCE downgrade (9700 §4.8.2) | code issued without challenge + verifier sent → `invalid_grant`. Code with challenge + no verifier → `invalid_grant` |
| require_pkce=false only for confidential clients (C1) | management API rejects `require_pkce=false` for public clients (422) |
| Code single-use, 60 s, bound (6749 §4.1.2) | reuse → `invalid_grant` + family revoked (UserInfo with the first AT → 401). Expired (clock fake) → `invalid_grant`. Other client → `invalid_grant`. `redirect_uri` mismatch at token → `invalid_grant`. Concurrency: contract suite (N parallel → 1 winner) |
| Refresh rotation + reuse revokes family (9700 §2.2.2) | reuse old RT → `invalid_grant`, then the new RT also fails. Wrong client → `invalid_grant`, no revocation. Scope widening → `invalid_scope`. Idle/absolute expiry |
| No implicit / hybrid / ROPC (9700 §2.1.2, §2.4) | `response_type=token`, `id_token`, `code id_token` → `unsupported_response_type`. `grant_type=password` → `unsupported_grant_type` |
| Client authentication (OIDC-4; 9700 §2.5) | bad secret → 401 `invalid_client`. Two methods → `invalid_client`. Public client on client_credentials → `unauthorized_client`. URL-encoded basic credentials decode correctly (positive) |
| private_key_jwt (RFC 10070, 7523) | aud = token endpoint URL → reject. aud = [issuer, other] → reject. Replayed jti → reject. exp > 5 min → reject. Expired → reject. iss ≠ sub → reject. HS256 / none alg → reject. Unknown kid → reject. Signed by an unregistered key → reject. Untyped but valid → **accept** |
| `iss` in authorization responses incl. errors (RFC 9207) | success and error redirects contain `iss` equal to the tenant issuer |
| ID token correctness (Core §2, §3.1.3.7) | unit tests on claims (nonce, at_hash, auth_time, acr, amr, azp, sid, kid) + conformance |
| Tokens not accepted in query (9700 §2.3; RFC 6750) | `GET /userinfo?access_token=` → 401 |
| AT/ID token confusion (RFC 9068 `typ`) | ID token as bearer at UserInfo → 401. AT from another tenant → 401 |
| 303 not 307 after POST (9700 §4.12) | login/registration/recovery POST success → status 303 |
| Clickjacking (9700 §4.16) | every UI response has CSP `frame-ancestors 'none'` |
| Referer leakage (9700 §4.2) | auth/UI pages have `Referrer-Policy: no-referrer`, and no external assets (HTML scan) |
| CSRF (SEC-04) | missing/wrong csrf_token → 403. `Sec-Fetch-Site: cross-site` → 403. Foreign `Origin` → 403. Valid token + no fetch headers → ok |
| Cookies (SEC-04) | prod: `__Host-`, Secure, HttpOnly, SameSite as specified. Dev: no prefix/Secure + warning |
| CSP strict (SEC-04) | `script-src 'self'`, no `unsafe-inline` on all UI responses |
| Secrets hashed (§6.2) | storage contract: code/RT/session/secret/setup token never stored in plaintext (row inspection test) |
| Cross-tenant isolation (§6) | client of tenant A at tenant B's `/token` → `invalid_client`. Tenant-A AT at tenant-B UserInfo → 401. Admin API path tenant mismatch → 404 |
| Account enumeration (AUTH-03) | recovery for existing vs unknown email → identical status and body. Login unknown user vs wrong password → identical message (dummy hash executed: assert the hasher was called) |
| Setup token single-use (ADM-03) | second POST with the same token → rejected. Expired → rejected. No default credentials: a fresh DB has zero users |
| Admin scopes (ADM-01) | no token → 401. Token without `admin:write` on POST → 403. Non-system-tenant token → 401. ID token as bearer → 401 |
| Cache headers (6749 §5.1) | token responses `Cache-Control: no-store` |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| private_key_jwt `aud` = token endpoint URL (or any value including issuer) | `aud` must be the issuer, as the sole value | RFC 10070, Nov 2026 | Reject token-endpoint audiences |
| jsonwebtoken ring-only | Pluggable `aws_lc_rs` / `rust_crypto` providers | jsonwebtoken 10.0 (2025-09) | Select via feature. `try_get_default()` added in 12.0 |
| utoipa 5 (OpenAPI 3.1) | utoipa 6: 3.1 default, 3.2 opt-in | 2026-09-23 | Keep 3.1 per ADM-01 |
| minijinja 2 (serde built in) | minijinja 3: serde opt-in | 3.0 | Enable `serde` |
| Implicit/hybrid in certification | Basic + Config without implicit is still certifiable | | Implicit OP / Hybrid OP plans are simply not run |

**Deprecated/outdated:** `EdDSA` alg name (RFC 9864). Not relevant in 0.1 (RS256 only).

## Suggested plan decomposition (waves maximize parallelism; disjoint files per wave)

| Wave | Plan | Scope | Files / crates | Depends on |
|---|---|---|---|---|
| 1 | **02-01 Domain, ports, errors** | Domain types, storage port traits for all 0.1 aggregates (signatures only), Clock/Rng/PasswordHasher ports, CoreError + OAuth mapping table, FormDescription type. Resolves C3 | `anvil-core/src/{domain,ports,error.rs,flow/form.rs}` | Phase 1 |
| 1 | **02-02 anvil-jose** | Keygen, KEK envelope, PKCS#8 → EncodingKey, JWKS/kid, signer (ID/AT), verifier with allow-lists, client-assertion verification (RFC 10070), at_hash, id_token_hint validation. JWT fuzz target | `anvil-jose/**`, `fuzz/fuzz_targets/jwt_*` | Phase 1 |
| 1 | **02-03 Web shell + theme** | AppState skeleton, security-header layer, Fetch-Metadata CSRF layer, cookie policy, minijinja env (theme dir → embedded), asset embedding with hashed names, error page, base layout/CSS (no JS) | `anvil-web/src/{state,layers,render,cookies}.rs`, `themes/default/**` | Phase 1 |
| 1 | **02-04 Delivery infra** | Container image (distroless/scratch, `ANVILID_LISTEN=0.0.0.0:8080`, WORKDIR, size gate under 50 MB), `examples/node-rp`, Playwright project skeleton, conformance config template + expected-skips + TLS sidecar compose, nightly fuzz workflow | `Dockerfile`, `examples/**`, `tests/e2e/**` (skeleton), `tests/conformance/**`, `.github/workflows/{fuzz,conformance}.yml` | Phase 1 |
| 2 | **02-05 SQLite storage + contract suite** | Migrations for all 0.1 tables (G1–G6), all repos, atomic contracts (code, refresh, jti, setup/recovery tokens, user unique), contract tests incl. concurrency | `anvil-storage/src/contract/**`, `anvil-storage-sqlite/**` | 02-01 |
| 2 | **02-06 Postgres storage** | Same migrations and repos for Postgres. Plugged into the contract suite once 02-05 lands (coordinate: 02-05 owns `contract/`, 02-06 owns only its crate and its instantiation file) | `anvil-storage-postgres/**` | 02-01 |
| 2 | **02-07 OAuth core services** | Authorize request parsing/validation (+ fuzz target), redirect matcher, PKCE, scope/claims-request, AuthorizeService (prompt/max_age/hint decisions), TokenService (code, refresh, client_credentials), ClientAuthenticator, KeyService, claims assembly by scope. Unit tests with in-test fakes | `anvil-core/src/{oauth,service/{authorize,token,client_auth,key}}.rs`, `fuzz/fuzz_targets/authorize_*` | 02-01, 02-02 |
| 2 | **02-08 Flows + sessions + users** | FlowEngine (login, registration, verification, recovery), SessionService, UserService/ClientService/TenantService validation, bootstrap service (tenants, keys, setup token), password policy, HIBP check port | `anvil-core/src/{flow/*,service/{session,user,client,tenant,bootstrap}}.rs` | 02-01 |
| 2 | **02-09 anvil-mail** | Templates, MailTransport trait, lettre SMTP impl, outbox worker logic, CapturingTransport in tests | `anvil-mail/**` | 02-01 |
| 3 | **02-10 Protocol endpoints** | discovery (both paths, C4), jwks, authorize (GET/POST, continue), token, userinfo (header/body), CORS, tenant-resolution layer. Security negative tests for protocol controls | `anvil-web/src/protocol/**`, `anvil-web/src/layers/tenant.rs`, `anvil-web/tests/security_{redirect,pkce,code,refresh,client_auth,jwt,userinfo}.rs` | 02-03, 02-05, 02-07 |
| 3 | **02-11 UI flows** | `/ui/login`, registration, verification, recovery, `/setup`. Argon2 pool impl, HIBP reqwest impl. CSRF/cookie/CSP/enumeration tests, stable selectors snapshot | `anvil-web/src/ui/**`, `anvil-web/src/crypto/argon.rs`, `anvil-web/tests/security_{csrf,cookies,csp,enumeration,setup}.rs` | 02-03, 02-05, 02-08 |
| 3 | **02-12 Management API** | utoipa-axum routers (tenants, clients, users), admin bearer extractor + scopes, problem+json, committed OpenAPI + drift test | `anvil-web/src/admin/**`, `docs/openapi/admin-v1.json`, `anvil-web/tests/{admin_*,security_admin}.rs` | 02-03, 02-05, 02-07 |
| 4 | **02-13 Binary wiring** | figment config + `config show/validate`, clap CLI (`serve`, `migrate`, `admin setup-url`), dev-mode detection, data dir/KEK/serve.lock, router assembly, background jobs (outbox, cleanup), stable setup-URL log line, Postgres selection | `anvilid/**` | 02-06, 02-09, 02-10, 02-11, 02-12 |
| 5 | **02-14 Conformance gate** | Setup script (bootstrap → API → clients/user → config), Basic + Config plans green in CI, fixes | `tests/conformance/**`, CI workflow | 02-13, 02-04 |
| 5 | **02-15 E2E + QUAL-04 + both backends** | Playwright specs (register → verify via Mailpit → login → recover), zero-config `docker run` ≤ 120 s script with the sample app (SQLite + Postgres compose variants), SEC-06 release-graph gate | `tests/e2e/**`, `scripts/qual04.*`, CI workflow | 02-13, 02-04 |

Router assembly is the shared-file hazard. Each wave-3 plan exposes `pub fn routes() -> Router<AppState>` from its own module, and only 02-13 assembles them. Migrations are a second hazard: 02-05 and 02-06 each own their own `migrations/{sqlite,postgres}/` directory, so they never touch the same files.

## Open Questions

1. **Q1: C1 PKCE exemption.** What we know: Basic OP cannot pass with PKCE mandatory for all clients, and RFC 9700 permits nonce for confidential OIDC clients. What's unclear: whether the user accepts a per-client `require_pkce=false` (confidential only). Recommendation: accept it, default true, and document that conformance clients use it.
2. **Q2: How the first admin gets management API credentials in 0.1** (no console). Recommendation: the `/setup` POST creates the admin user **and** a system-tenant confidential client (`client_credentials`, `admin:*` scopes) whose secret is shown once on the success page (ids `mgmt-client-id`, `mgmt-client-secret` for scripting). Alternative: a seeded public console client plus auth code, which is harder to script. The QUAL-04 and conformance scripts drive `/setup` with Playwright, or with curl and a cookie jar (GET the page, extract `csrf_token`, POST).
3. **Q3: C2 scope pull-in** of minimal prompt/max_age/id_token_hint from OIDC-14 into 0.1. This is needed for Basic OP. Update the REQUIREMENTS traceability note.
4. **Q4: C3 location of the ports.** Depends on the Phase 1 Spike A outcome.
5. **Q5: The `acr` value string** for single-factor password (for example `urn:anvilid:acr:pwd`, or a numeric LoA). It must be stable because RPs will pin it. Recommendation: one constant, `amr = ["pwd"]` (RFC 8176).
6. **Q6: Access-token audience without RFC 8707** (Phase 4). Recommendation: tenant tokens use `aud = [issuer]` (the OP is the RS for UserInfo) unless the client has `default_audience`. System-tenant admin clients use the management API identifier `{public_url}/api/admin/v1`.
7. **Q7: TLS terminator for conformance CI** (Caddy vs nginx vs built-in rustls listener). It depends on what Phase 1's pipeline already does. Built-in TLS would expand 0.1 scope, so prefer a sidecar.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (+ tokio::test), proptest 1.12, insta 1.49, testcontainers 0.28 (Postgres), wiremock 0.6.5 (HIBP), cargo-fuzz 0.13.2. Playwright 1.65.1 (Node ≥20) for e2e/QUAL-04. OpenID conformance suite (Docker) via `run-test-plan.py` |
| Config file | Phase 1 provides the workspace runner (`just`/`make`/`xtask`, whichever was chosen). New: `tests/e2e/playwright.config.ts`, `tests/conformance/{config.template.json,expected-skips.json,expected-failures.json}`, `fuzz/Cargo.toml` |
| Quick run command | `cargo test -p anvil-core -p anvil-jose` (pure, under 30 s) and `ANVILID_TEST_DB=sqlite cargo test -p anvil-web --test 'security_*'` |
| Full suite command | `cargo test --workspace` with `ANVILID_TEST_DB=sqlite` then `ANVILID_TEST_DB=postgres` (CI matrix), plus `npx playwright test` (e2e), the conformance workflow, and `scripts/qual04` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OIDC-01 | S256 only, PKCE enforced per policy, downgrade | unit + integration | `cargo test -p anvil-core pkce` ; `cargo test -p anvil-web --test security_pkce` | ❌ Wave 0 |
| OIDC-02 | exact match, loopback, error page | unit (proptest) + integration | `cargo test -p anvil-core redirect` ; `--test security_redirect` | ❌ |
| OIDC-03 | single use, expiry, binding, reuse revokes | contract + integration | `cargo test -p anvil-storage-sqlite contract` (and postgres) ; `--test security_code` | ❌ (contract partially from Phase 1) |
| OIDC-04 | 4 auth methods, private_key_jwt rules, constant time | unit + integration | `cargo test -p anvil-jose client_assertion` ; `--test security_client_auth` | ❌ |
| OIDC-05 | rotation, reuse revokes family, client binding | contract (concurrency) + integration | `--test security_refresh` | ❌ |
| OIDC-06 | client_credentials | integration | `cargo test -p anvil-web --test token_client_credentials` | ❌ |
| OIDC-07 | ID token claims and signature | unit + conformance | `cargo test -p anvil-core id_token` ; conformance Basic | ❌ |
| OIDC-08 | discovery (both paths), JWKS next/active/retired | integration + conformance Config | `--test discovery` | ❌ |
| OIDC-09 | UserInfo scope claims, GET/POST/body | integration + conformance | `--test userinfo` | ❌ |
| OIDC-24 | `iss` on success and error | integration | `--test security_iss` | ❌ |
| AUTH-01 | Argon2id, dummy hash, policy, HIBP (wiremock) | unit + integration | `cargo test -p anvil-web argon` ; `--test security_enumeration` | ❌ |
| AUTH-02 | register, disable/invite-only, verify email | integration (capturing transport) + e2e (Mailpit) | `--test flow_registration` ; `npx playwright test registration` | ❌ |
| AUTH-03 | recovery, non-enumeration, POST-consume, sessions revoked | integration + e2e | `--test flow_recovery` ; `npx playwright test recovery` | ❌ |
| UI-01 | no external assets, strict CSP | integration (HTML scan) | `--test security_csp` | ❌ |
| ADM-01 | OpenAPI 3.1, scopes, CRUD, drift | integration + snapshot | `cargo test -p anvil-web --test admin_api` ; `--test openapi_drift` | ❌ |
| ADM-03 | setup URL one-time, no default creds | integration + e2e | `--test security_setup` ; QUAL-04 script | ❌ |
| OPS-01 | image under 50 MB, static binary | CI check | `docker image inspect -f '{{.Size}}' anvilid:ci` compared against 52428800 | ❌ |
| OPS-02 | SQLite + Postgres | contract + full suite matrix | CI matrix `ANVILID_TEST_DB` | partial (Phase 1) |
| OPS-05 | zero config start | integration (spawn binary in tempdir) | `cargo test -p anvilid --test zero_config` | ❌ |
| SEC-01 | RFC 9700 checklist | integration | `cargo test -p anvil-web --test 'security_*'` | ❌ |
| SEC-04 | CSRF, cookies, CSP | integration | `--test security_csrf --test security_cookies --test security_csp` | ❌ |
| SEC-06 | no test-only code in release | CI script | `cargo tree -p anvilid -e normal --prefix none` must not contain `wiremock\|testcontainers\|axum-test\|proptest\|anvil-test-support`, plus a grep gate rejecting `cfg(feature = "test` / `cfg(any(test` outside `#[cfg(test)] mod` and `tests/` | ❌ |
| SEC-07 | audit + fuzz | CI | `cargo deny check` (Phase 1) ; nightly `cargo +nightly fuzz run jwt_decode -- -max_total_time=300` and `authorize_parse` ; PR smoke `-runs=10000` | ❌ |
| QUAL-01 | negative test per control | meta | each row of the RFC 9700 table has a named test. CI fails if a `security_*` file is missing (list check) | ❌ |
| QUAL-02 | both backends | CI matrix | `ANVILID_TEST_DB=postgres cargo test --workspace` | ❌ |
| QUAL-04 | `docker run` → sample login ≤ 120 s | e2e script | `scripts/qual04.sh` (docker run → grep setup URL → Playwright setup → admin API creates client → start `examples/node-rp` → Playwright register+login+refresh+userinfo → assert elapsed) | ❌ |

### How each success criterion is verified automatically
1. **Sample app login + refresh + UserInfo on both backends:** `scripts/qual04.sh` runs twice in CI (SQLite default image, and Compose with Postgres + `ANVILID_DATABASE_URL`). The Playwright spec asserts the app page shows `sub`/email from UserInfo and that a refresh produced a new token (and the old RT fails, an optional extra check through the app's debug route).
2. **Basic OP + Config OP:** conformance workflow on main (and PRs touching protocol code). Exit code from `run-test-plan.py` with the reviewed expected-skips file.
3. **≤ 2 min zero-config, setup URL, no default credentials:** the same `qual04` script measures wall time from `docker run` to the app's logged-in page and fails above 120 s. `security_setup` asserts a fresh DB has zero users and that the setup token is single-use.
4. **§11 negative tests on both backends:** `cargo test -p anvil-web --test 'security_*'` in the `ANVILID_TEST_DB` matrix.
5. **Self-service through built-in pages + management API:** Playwright specs (registration → Mailpit verification → login → recovery) + `admin_api` integration tests + `openapi_drift`.

### Sampling Rate
- **Per task commit:** `cargo test -p <crate touched>` (SQLite) + `cargo clippy -p <crate> -D warnings`
- **Per wave merge:** `cargo test --workspace` on SQLite and Postgres
- **Phase gate:** full matrix + Playwright + conformance Basic/Config + qual04 (both backends) green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `anvil-web/tests/support/mod.rs`: router builder selecting the backend via `ANVILID_TEST_DB`, fake clock, capturing mail transport, helpers for creating tenant/client/user and completing an auth-code flow without a browser (form POST with CSRF extraction)
- [ ] Dependency-rule checker update: ignore dev-dependencies (C6)
- [ ] `tests/e2e/` Playwright project + Mailpit service in CI
- [ ] `tests/conformance/` config template, expected-skips, setup script, TLS sidecar
- [ ] `fuzz/` crate with `jwt_decode`, `client_assertion`, `authorize_parse`, `redirect_match` targets
- [ ] `scripts/qual04.sh` + `examples/node-rp`

## Sources

### Primary (HIGH confidence)
- OpenID conformance suite source, commit 246b2c14 (2026-11-24): `OIDCCBasicTestPlan.java`, `OIDCCConfigTestPlan.java`, `AbstractOIDCCServerTest.java`, `OIDCCRefreshToken.java`, `OIDCCDiscoveryEndpointVerification.java`, `PerformStandardIdTokenChecks.java`, `ValidateIdToken.java`, `CompareIdTokenClaims.java`, `CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface.java`, `CheckDiscEndpointAllEndpointsAreHttps.java`, `CheckForUnexpectedParametersInServerMetadata.java`, `json-schemas/rfc8414/oauth_authorization_server_metadata.json`, `AbstractCondition.java` (trust-all TLS), `BrowserControl.java`, `scripts/run-test-plan.py`, `.gitlab-ci/local-provider-oidcc-conformance-config.json`, `.gitlab-ci/expected-*-oidcc.json`. https://gitlab.com/openid/conformance-suite
- jsonwebtoken 12.0.0 crate source (`jwk.rs`, `encoding.rs`, `crypto/aws_lc/{mod,rsa}.rs`, `crypto/mod.rs`, Cargo features) and CHANGELOG: https://github.com/Keats/jsonwebtoken/blob/master/CHANGELOG.md
- aws-lc-rs 1.19.0 crate source (`rsa/key.rs`, `rsa/encoding.rs`, `aead/rand_nonce.rs`, `hkdf.rs`, `constant_time.rs`)
- Compiled probe (aws-lc-rs 1.19 + jsonwebtoken 12.0, rustc 1.94.1): PKCS#8-DER signing fails; PEM path, JWK, thumbprint, verify and alg-confusion rejection confirmed
- argon2 0.6.0 source (`params.rs` defaults, features); minijinja 3.1.0 source (features, loader, auto-escape); lettre 0.11.24 Cargo features; utoipa 6.0.0 source + CHANGELOG; utoipa-axum 0.3.0 source
- crates.io / npm registry version queries (2026-11-25)
- RFC 9700 §2.1.1, §2.2.2, §4.8.2: https://www.rfc-editor.org/rfc/rfc9700.html
- RFC 10070 (Nov 2026, PS): https://www.rfc-editor.org/info/rfc10070
- OWASP Password Storage Cheat Sheet (Argon2id parameters): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- HIBP API v3 (Pwned Passwords range, Add-Padding, no key, no rate limit): https://haveibeenpwned.com/API/v3
- openid-client 6.9.1 type declarations; oauth4webapi 3.8.9 source (RFC 9207 `iss` enforcement)

### Secondary (MEDIUM confidence)
- Go `net/http.CrossOriginProtection` docs (partial read: safe methods exempt; requests with neither Sec-Fetch-Site nor Origin are allowed): https://pkg.go.dev/net/http#CrossOriginProtection
- OIDC Core 1.0 §3.1.2.1, §12.2 and Discovery §3 defaults (`request_uri_parameter_supported` default true), RFC 9207, RFC 8414 §3.1, RFC 8252 §7.3/§8.3, RFC 6749 §2.3.1: from training knowledge, consistent with the suite behaviour observed. Re-read the exact text when writing user docs

### Tertiary (LOW confidence)
- HtmlUnit's handling of `Sec-Fetch-*`/`Origin` headers was not verified. The CSRF design tolerates both cases
- Current distroless static image tag (debian12 vs debian13): verify when writing the Dockerfile

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions and features were read from published crates, and the critical integration was compiled.
- Conformance requirements: HIGH. Read from the current suite source.
- Architecture/design patterns: MEDIUM. These are well-established practices, but some choices (C1–C6, Q2, Q5, Q6) need user and planner confirmation.
- Pitfalls: HIGH for P1–P7, P11, P16 (verified). MEDIUM for the rest.

**Research date:** 2026-11-25
**Valid until:** about 2026-12-25 (the conformance suite changes weekly; re-check the Basic plan module list right before the conformance plan executes)
