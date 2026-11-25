# Phase 4: Release 0.3 "Real-world logins" - Research

**Researched:** 2026-11-25
**Domain:** OIDC logout profiles, upstream federation (social/OIDC/OAuth2), account linking, passwordless email, MFA policy and step-up, RFC 8707, theming, i18n, on the existing AnvilID 0.2 codebase
**Confidence:** HIGH for the codebase and the conformance suite (read from source at the pinned tag); HIGH/MEDIUM for specs; MEDIUM/LOW for provider quirks that only real providers can confirm (flagged)

## Summary

Phase 4 adds eleven requirements to a 0.2 codebase whose patterns are set: pure `anvil-core` with intent-method storage ports, two sqlx backends with one shared contract suite, a flow engine that plans effects in pure transitions, one keyed rate limiter, KEK sealing for secrets, minijinja templates under a strict CSP, and an OpenAPI-driven React console. Nothing in this phase needs a new architectural idea. A few current facts do force specific designs, and the planner must account for each:

1. **No SSRF-guarded HTTP client exists yet.** `adapters/captcha.rs` has a fixed-endpoint, no-redirect reqwest client, but it does no DNS-level private-range blocking. Back-channel logout (client-supplied URL) and generic OIDC discovery/JWKS (admin-supplied URL) both need one guarded client. Build it first; it is a shared dependency.
2. **The flow cookie is `SameSite=Strict`, and the browser does not send it on any upstream-IdP callback.** That covers Google/GitHub/Microsoft GET redirects and Apple's `form_post` cross-site POST. Magic-link clicks from webmail are affected too. The upstream callback therefore needs its own `SameSite=Lax` binding cookie plus a server-side transaction keyed by `state`. Apple's POST callback needs a POST→303→GET hop.
3. **SQLite CHECK constraints guard several enum columns.** Adding a value means a table rebuild: `flow.kind` needs `logout`, `self_service_token.kind` needs `email_change`, and `email_template.kind` needs the new email kinds. The 0.2 rebuild pattern exists (0003, in-transaction because there are no inbound FKs). Next migration numbers: **SQLite `0005`, Postgres `0004`**.
4. **The conformance back-channel callback is unreachable with default settings.** It lives at `https://localhost.emobix.co.uk:8443/test/a/anvilid/backchannel_logout`. That name resolves to 127.0.0.1, which the SSRF guard blocks. The host is served by the suite's nginx with a self-signed `CN=localhost` cert, so it fails rustls hostname checks. Two legitimate operator settings fix this: a CIDR allow-list and an extra CA file. The harness then mounts its own CA-signed cert into nginx. No test hooks needed.
5. **Rust OIDC client crates are not usable.** `openidconnect 4.1` and `oauth2 5.0` both depend on `chrono` (banned). `openidconnect` also depends on RustCrypto `rsa` (banned outside the crypto-glue wrapper). The upstream RP must be built on reqwest plus `anvil-jose::verify_jwt`. This is less work than it sounds, because anvil-jose already verifies RS256/PS256/ES256/Ed25519 against a JWKS with an alg allow-list.
6. **i18n touches every template and four `message_text` functions in core.** These are `flow/engine.rs`, `service/session.rs`, `service/account.rs` and `ui/consent.rs`. Do it early (one wave after the foundation) so every new Phase 4 page is born localized. Fluent message IDs cannot contain `.`, so existing keys like `login.invalid_credentials` need a deterministic mapping.

**Primary recommendation:**
- Start with three foundation plans:
  - core model + ports + contract suite,
  - guarded outbound HTTP client + config keys,
  - conformance harness extension.
- Then put both backends and the i18n refactor in parallel.
- Then run four parallel tracks: logout, resource indicators, upstream adapters, and account/theming backend.
- Serialize the login-engine chain (MFA/OIDC-14 → upstream login → email OTP), because those plans all edit `flow/login.rs`, `service/flow.rs`, `ui/login.rs` and `templates/login.html`.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
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

### Deferred Ideas (OUT OF SCOPE)
- Organizations and per-org SSO (Phase 6), SAML (Phase 6, experimental), front-channel logout (P2), SMS OTP (2.0)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| OIDC-12 | RP-initiated logout + back-channel logout notifications | §Logout (suite modules read from source at release-v5.3.5, discovery fields, logout token claims, delivery job, harness changes for the callback) |
| OIDC-14 | `prompt` (none/login/consent/select_account/create), `max_age`, `login_hint`, `acr_values` | §OIDC-14 + MFA (current subset in `oauth/decision.rs` and `authorize_request.rs`; `create` per tenant registration mode; step-up semantics) |
| OIDC-16 | Resource indicators (RFC 8707) | §Resource indicators (parse/validate, code/family/AT columns, downscoping, aud arrays, introspection, UserInfo audience rule, MCP readiness) |
| AUTH-06 | Email OTP / magic link | §Passwordless email (state in flow row via `swap_state`, HMAC-peppered code, POST-only consumption, browser binding, enumeration safety) |
| AUTH-07 | Google, Apple, Microsoft, GitHub, generic OIDC/OAuth2 | §Upstream providers (per-provider endpoints/claims/quirks, hand-rolled RP on reqwest + anvil-jose, mocks) |
| AUTH-08 | MFA policy off/optional/required per tenant/client; step-up via acr_values | §OIDC-14 + MFA (pure `mfa_requirement` fn, in-flow enrolment, session upgrade intent) |
| AUTH-11 | Link only on verified email or explicit confirmation | §Account linking (threat model, state machine, per-provider email trust) |
| AUTH-13 | Account page: profile, email (re-verified), password, passkeys, MFA, sessions, connected apps | §Account page (what exists in 0.2; new profile/email/password/linked-identities pages; `complete_email_change` intent) |
| UI-03 | Theming live from console, per-tenant/org/client | §Theming (token model, CSS variables already in anvil.css, generated same-origin stylesheet, CSS validator, logo upload, preview endpoint) |
| UI-04 | Translated pages, language from ui_locales/browser | §i18n (fluent-bundle 0.16 concurrent + fluent-langneg 0.14, key mapping, minijinja `t()` function, RTL `dir`) |
| SEC-03 | Upstream IdP secrets encrypted | §Upstream providers / Data model (KEK purpose `anvilid/connection-secret/v1`, AAD tenant‖connection id, write-only API) |
</phase_requirements>

## Standard Stack

All core crates are already in the workspace. **Phase 4 adds only Fluent crates.** Everything else reuses existing dependencies.

### Core (already present, reused)
| Library | Version (lock) | Purpose in Phase 4 | Notes |
|---------|---------|---------|--------------|
| reqwest | 0.13.5 (rustls/aws-lc-rs) | Guarded outbound client: upstream discovery/JWKS/token/userinfo, GitHub API, back-channel POSTs | Use `dns_resolver(...)`, `redirect(Policy::none())`, `no_proxy()`, `tls_certs_merge(...)` (`add_root_certificate` is deprecated in 0.13), `timeout`/`connect_timeout` |
| ipnet | 2.12 | CIDR allow-list parsing, private-range checks | Already used for trusted proxies |
| anvil-jose | in-repo | `verify_jwt(token, &Jwks, &[Alg])` for upstream ID tokens; `SigningKey::from_pkcs8(kid, ES256, pkcs8).sign_jwt(...)` for the Apple client secret; `sign_jwt(Some("logout+jwt"), …)` for logout tokens; `Kek::seal/open` | No new crypto code |
| moka | 0.12 | JWKS / discovery caches (per node), keyed by URL | Already a dependency |
| minijinja | 3.1 | Register `t(key, **args)` for i18n; theme CSS rendered by Rust, not templates | |
| rust-embed | 8.14 | Embed `.ftl` catalogs | |
| wiremock | 0.6.5 (dev) | Provider mocks in `anvil-web/tests` | Already a dev-dependency |
| governor via `anvil-cache` limiter | — | New route classes or keys for email-code sends, upstream starts/callbacks | One limiter, no second implementation |

### Supporting (new)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| fluent-bundle | 0.16.0 (Apache-2.0 OR MIT) | Message formatting, plurals, `concurrent::FluentBundle` (Sync) | Server-rendered pages |
| fluent-langneg | 0.14.2 | `negotiate_languages` + `accepted_languages::parse` (Accept-Language) | Locale selection |
| unic-langid | 0.9.6 | `LanguageIdentifier` (pulled in by fluent anyway) | Parsing `ui_locales` tags |

Add them to the root `[workspace.dependencies]` in the foundation plan so that later plans never edit `Cargo.toml`/`Cargo.lock` concurrently. Then run `cargo deny check`, since transitive crates such as `intl_pluralrules`, `self_cell` and `rustc-hash` must pass the license and ban policy.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled upstream RP | `openidconnect` 4.1 / `oauth2` 5.0 | **Rejected.** Both depend on `chrono` (banned); `openidconnect` also needs `rsa`, `p256` and `ed25519-dalek` (a second crypto stack, and `rsa` is banned outside crypto-glue). Verified via the crates.io dependency API on 2026-11-25 |
| fluent-bundle directly | `fluent-templates` 0.15.1 | No minijinja integration (only handlebars/tera); its `static_loader!` adds macro dependencies. Direct fluent-bundle + rust-embed is ~150 lines and keeps the theme-dir override path |
| Fluent | JSON catalogs | JSON has no plural or gender rules, and contributors would have to invent them. Fluent is the stated community-contribution format |
| Hand-written CSS validator + CSP | `cssparser` 0.38 / lightningcss | cssparser is MPL-2.0 (would need a deny.toml per-crate exception) and the CSP already blocks external loads. A conservative token-level validator is enough (see Theming) |
| Node mock IdP for provider e2e | Running real providers in CI | Excluded by the locked decision |

**Installation (foundation plan):**
```toml
# Cargo.toml [workspace.dependencies] — Phase 4 (release 0.3)
fluent-bundle = "0.16.0"
fluent-langneg = "0.14.2"
unic-langid = "0.9.6"
```

## Architecture Patterns

### Recommended module layout (new files; keeps parallel plans disjoint)
```
crates/anvil-core/src/
  model/connection.rs        Connection, ConnectionConfig (tagged: Social{provider}, Oidc, OAuth2), IdentityLink
  model/branding.rs          ThemeTokens, Branding, BrandingScope
  model/logout.rs            RpSession, LogoutDelivery
  oauth/logout.rs            pure: end-session request validation, logout_token claims
  oauth/resource.rs          pure: RFC 8707 parse/validate/downscope
  policy/mfa.rs              pure: MfaPolicy resolution + mfa_requirement()   (or policy.rs → policy/ module)
  upstream/                  pure: provider presets, claim normalisation, id_token claim checks,
    mod.rs, providers.rs,       MS issuer template, Apple client-secret claims, link decision
    linking.rs, claims.rs
  flow/upstream.rs           login-flow sub-steps for upstream (pending link, callback stash)
  flow/email_code.rs         login-flow sub-steps for email OTP / magic link
  flow/logout.rs             FlowKind::Logout confirmation state
  service/connection.rs      admin CRUD + sealing secrets
  service/upstream.rs        start/callback orchestration through the UpstreamClient port
  service/logout.rs          RP-initiated logout + delivery planning
  service/branding.rs        theme CRUD, CSS generation inputs, preview tokens
crates/anvil-web/src/
  adapters/outbound.rs       THE guarded client (SSRF resolver, scheme/host rules, size/time limits)
  adapters/upstream/         UpstreamClient port impl: oidc.rs (discovery+JWKS cache), github.rs, apple.rs
  adapters/backchannel.rs    POST logout_token (uses outbound.rs)
  i18n.rs                    Fluent loader, negotiation, minijinja `t` registration
  theme.rs                   CSS variable stylesheet + custom CSS + logo routes, cache
  protocol/logout.rs         GET/POST /logout (end_session_endpoint)
  ui/upstream.rs, ui/email_code.rs, ui/logout.rs, ui/account_profile.rs, ui/account_linked.rs, ui/preview.rs
  admin/connections.rs, admin/branding.rs
themes/default/
  locales/en/main.ftl, locales/de/main.ftl
  templates/logout_confirm.html, logged_out.html, upstream_link.html, email_code.html,
            magic_link.html, account_profile.html, account_linked.html, select_account.html,
            preview.html
admin-ui/src/routes/connections/, admin-ui/src/routes/branding/
tests/e2e/lib/mock-idp.ts     zero-dependency Node mock (node:http + node:crypto)
```

### Pattern 1: Guarded outbound client (single implementation)
**What:** One builder in `adapters/outbound.rs` that every server-side fetch uses: upstream IdPs, JWKS, GitHub API, back-channel logout, and (recommended) the existing CAPTCHA and HIBP clients.
**Rules (ARCHITECTURE §11 SSRF row):**
- https only. Plain http is allowed only to an allow-listed destination, and only in dev mode or with `insecure_http`.
- The URL must have no userinfo.
- Resolve DNS through a custom `reqwest::dns::Resolve` that **drops any address outside the allow policy** and errors if none remain.
- **Pre-check IP-literal hosts.** reqwest does not call the resolver for IP literals, so the URL must be validated before the request.
- `redirect(Policy::none())`, plus `no_proxy()`. With a proxy, DNS happens at the proxy, which bypasses the guard.
- Connect timeout 5 s, total 10 s, body capped by streaming (`chunk()` loop as in `captcha.rs`) at 1 MiB (JWKS/discovery) or 64 KiB (token responses).
- Blocked ranges: 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4, 255.255.255.255; ::/128, ::1, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32. Also check the **embedded IPv4 inside IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96) and 6to4 (2002::/16)** addresses.
- New config keys:
  - `outbound_allow_cidrs`: CIDRs exempt from the private-range block. Default empty; in dev mode loopback is allowed by default, mirroring the 0.2 trusted-proxies precedent.
  - `outbound_ca_file`: a PEM bundle merged into the roots via `tls_certs_merge`. This has real production use (corporate CAs, internal RPs) and is what the conformance harness needs.
**Example:**
```rust
// Source: pattern; reqwest 0.13 docs (ClientBuilder::dns_resolver, Resolve trait). Sketch.
struct GuardedResolver { policy: Arc<OutboundPolicy> }
impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?
                .filter(|a| policy.allows(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("destination not allowed".into()); // never echo resolved IPs to users
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
// builder: .dns_resolver(Arc::new(GuardedResolver{..})).redirect(Policy::none()).no_proxy()
//          .https_only(!allow_http).connect_timeout(5s).timeout(10s).tls_certs_merge(extra_cas)
```

### Pattern 2: Upstream transaction bound to the browser by a Lax cookie
**What:**
1. A POST `/ui/login/upstream/{slug}` (CSRF-protected, same-site, so the Strict flow cookie is present) creates the pending upstream state *inside the login flow's state*:
   - `state_secret_hash`
   - `nonce`
   - sealed PKCE verifier
   - `connection_id`
   - `binding_hash`
2. It sets a short-lived `__Host-anvil_upstream_{t}` cookie (`SameSite=Lax`, 10 min) holding the binding secret.
3. It 303-redirects to the provider. `state` = `{flow_id}.{random}`.

The callback is `GET /ui/login/upstream/{slug}/callback`, or `POST` for Apple `form_post`. The POST stores the posted `code`/`id_token`/`user` into the flow via `swap_state` and answers **303 to the GET callback**: Lax cookies are sent on cross-site top-level GET navigations, never on cross-site POSTs. The GET then:
- verifies the Lax cookie against `binding_hash`,
- checks `state` and `connection` match,
- exchanges the code and validates the ID token,
- runs the link decision.

**Why:** No IdP callback can carry the Strict flow cookie (cookies.rs: flow = Strict, session = Lax).
**Also:** exempt the callback route from the Fetch-Metadata CSRF layer, as `POST /authorize` already is. Apple's POST arrives with `Sec-Fetch-Site: cross-site`. Its protection is `state` + binding cookie + nonce.

### Pattern 3: Session-revoking intents enqueue back-channel deliveries in the same transaction
**What:** A `logout_delivery` row per (revoked session × RP that has a `backchannel_logout_uri` and an `rp_session` row). It is inserted inside every intent that revokes a browser session:
- `SessionRepo::revoke`, `revoke_with_families`, `revoke_all_for_user`
- `UserRepo::complete_recovery`, `UserRepo::delete`
- the new logout intent

The worker claims rows like the outbox (lease, `FOR UPDATE SKIP LOCKED` on Postgres) and **signs the logout token at send time** (fresh iat/exp/jti, so retries after the 2-minute expiry still work).
**Why:** One implementation, and no revocation path can forget to notify RPs. The contract suite proves it on both backends.
**rp_session:** insert inside `GrantRepo::create_code` (the code already carries `session_id` and `client_id`), so `service/authorize.rs` does not need to change for logout. Use upsert/ignore on the PK `(tenant_id, session_id, client_id)`.

### Pattern 4: Flow-row state for short-lived secrets (email OTP, magic link, upstream pending, logout confirm)
**What:**
- Store hashes and counters in the typed flow state.
- Consume with `FlowRepo::swap_state` (CAS), exactly like the 0.2 passkey challenge and TOTP enrolment.
- The email code hash = HMAC-SHA256 under `Kek::derive_key("anvilid/email-otp/v1")` over `flow_id ‖ code`. A plain hash of 6 digits is brute-forceable offline.
- The magic-link token is 256-bit; store its SHA-256.

**Why:** No new tables and no new atomic SQL. Expiry, cookie binding and CSRF come for free. Flow TTL is 15 min; set the OTP TTL to 10 min within it.

### Pattern 5: Pure policy functions, effects in services
Follow the 0.2 style:
- `mfa_requirement(policy, request_acr, session, user_factors) -> MfaRequirement`
- `link_decision(upstream_identity, existing_link, email_match, tenant_policy, connection_trust) -> LinkDecision`
- `validate_end_session(params, verified_hint, client) -> EndSessionDecision`
- `downscope(granted, requested) -> Result<Vec<Resource>, invalid_target>`

Each one gets exhaustive unit tests and proptests in core. The services only orchestrate ports.

### Anti-Patterns to Avoid
- **Linking by email on every login.** Links are keyed by `(connection_id, subject)` only. Email is consulted only when no link exists, and only under the linking rules.
- **Deriving `sid` per RP.** 0.2 ID tokens already carry `sid = browser_session.id` (`service/token.rs:287`). The suite checks `logout_token.sid == id_token.sid`. Keep it. The `rp_session` table records *which* clients to notify, so a separate `sid` column (in ARCHITECTURE §6.1) is redundant. Raise the doc divergence.
- **Following redirects or honouring proxies in the outbound client** (both bypass the SSRF guard).
- **Putting provider secrets or real issuer hosts into CI.** Mocks only (locked decision).
- **Serving theme CSS inline.** The CSP has no `unsafe-inline` for styles. Generate a stylesheet served at a hashed same-origin URL.
- **Second CSRF mechanism for logout confirmation.** Use a `FlowKind::Logout` flow (cookie + synchronizer token), not an ad-hoc HMAC.
- **Adding admin API routes in several parallel plans.** Each one regenerates `docs/openapi/admin-v1.json` and `admin-ui/src/api/schema.d.ts`, which guarantees merge conflicts. Put at most one OpenAPI-changing plan in any wave.

## Logout (OIDC-12): exact conformance requirements

Read from the suite source at the pinned tag `release-v5.3.5` (local `./suite` git object store). Confidence: HIGH.

### Plans and module lists
| Plan (testPlanName) | Fixed variants | Modules |
|---|---|---|
| `oidcc-rp-initiated-logout-certification-test-plan` | server_metadata=discovery, client_auth_type=client_secret_basic, response_mode=default | `oidcc-rp-initiated-logout-discovery-endpoint-verification`, `oidcc-rp-initiated-logout`, `-bad-post-logout-redirect-uri`, `-modified-id-token-hint`, `-no-id-token-hint`, `-no-params`, `-no-post-logout-redirect-uri`, `-no-state`, `-only-state`, `-query-added-to-post-logout-redirect-uri`, `-bad-id-token-hint` |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | same | `oidcc-backchannel-logout-discovery-endpoint-verification`, `oidcc-backchannel-rp-initiated-logout` |

Non-fixed variants still have to be passed on the command line, as the suite's own CI does with `[response_type=code\ id_token][client_registration=dynamic_client]`. For AnvilID: `…-test-plan[response_type=code][client_registration=static_client]` (MEDIUM: `run-test-plan.py` reports a missing variant immediately; verify on the first run).

### What each module requires of the OP
- **Every module:**
  - Normal code flow with a 128-character `state`.
  - End-session redirect with `id_token_hint`, `post_logout_redirect_uri = {base}/post_logout_redirect` and a random `state` (VSCHAR, `~` for `+`, `;` and space).
  - Then a second authorization with **`prompt=none`, which must fail** with `login_required` or another interaction error (proves the session ended).
- `oidcc-rp-initiated-logout`, `-no-state`:
  - Redirect to the post-logout URI with exactly `state` (or no params when no state was sent).
  - Any extra query param → WARNING. Warnings fail `run-test-plan.py` unless listed, so **add nothing else** to the redirect.
- `-bad-post-logout-redirect-uri` and `-query-added-…`:
  - Must **not** redirect; show an error page (placeholder screenshot → REVIEW).
  - Exact string match against registered `post_logout_redirect_uris`; `?foo=bar` appended must not match.
- `-modified-id-token-hint` (`alg:none`) and `-bad-id-token-hint` (signed by the suite with a key derived from the client secret): must not redirect; error page "invalid id_token_hint".
- `-no-id-token-hint`: `post_logout_redirect_uri` without `id_token_hint` (and no `client_id`) → no redirect; error page.
- `-no-params`, `-no-post-logout-redirect-uri`, `-only-state`:
  - Must log the user out and show a "you are signed out" page.
  - A confirmation page first is allowed. The suite's own CI config for node-oidc-provider clicks a confirm button, then waits for the success page.
- Back-channel:
  - Discovery must have `backchannel_logout_supported: true`, `backchannel_logout_session_supported: true` and an https `end_session_endpoint`. `CheckDiscEndpointAllEndpointsAreHttps` covers every advertised endpoint.
  - The OP must POST `application/x-www-form-urlencoded` with **only** `logout_token` (extra params → WARNING) to `{base}/backchannel_logout`.
  - **And** redirect to post_logout with `state`. Either order is fine; the module waits for both.
  - TLS 1.3 (rustls default) avoids the BCP195 warnings.
- Logout token checks (`ValidateLogoutTokenClaims`, `CheckLogoutTokenNoNonce`, `CheckLogoutTokenHasSubOrSid`, `CheckIdTokenSidMatchesLogoutToken`, `CheckIdTokenSubMatchesLogoutToken`, `ValidateLogoutTokenSignature`):

  | Claim / property | Requirement |
  |---|---|
  | `iss` | == issuer |
  | `aud` | contains client_id |
  | `iat` | within 5 min skew, not more than 1 day old |
  | `jti` | present |
  | `events` | exactly `{"http://schemas.openid.net/event/backchannel-logout":{}}` |
  | `nonce` | absent |
  | `sub` and/or `sid` | present, equal to the ID token's |
  | signature | verifies against the published JWKS |

### Spec rules that go beyond the suite (verified, openid.net)
- **Back-Channel Logout 1.0** (Final incl. errata, 2023-12-15):
  - `exp` is **REQUIRED**. ARCHITECTURE §8.2 already says 2 min.
  - `typ: logout+jwt` is RECOMMENDED. Use it.
  - Success is 200, and **204 must also be accepted**. 400 = RP rejected: do not retry.
  - Retransmit only on likely-recoverable failures (network, 5xx, timeout).
  - `backchannel_logout_uri` must be absolute with no fragment; a query is allowed and must be preserved.
  - Client metadata: `backchannel_logout_session_required`.
- **RP-Initiated Logout 1.0** (Final 2022-09-12):
  - GET **and POST** support required.
  - Params: `id_token_hint`, `logout_hint`, `client_id`, `post_logout_redirect_uri`, `state`, `ui_locales`.
  - The OP SHOULD accept expired ID tokens it issued: use `ExpiryCheck::Ignore`, already used for `id_token_hint`.
  - If both `client_id` and `id_token_hint` are present they must match `aud`.
  - The OP MUST ask for confirmation when there is no valid hint or the hint does not belong to the current session/user.
  - Redirect only to an exact registered URI.
  - On any validation error, do not redirect.
  - A logout for a user who is not logged in is not an error (idempotent).
  - `ui_locales` selects the page language. Unknown locales are not an error.

### Recommended end-session decision table (pure fn in `oauth/logout.rs`)
| Input | Behaviour |
|---|---|
| Valid hint (sig over enabled algs, iss, aud = a known client, `client_id` matches if given), session matches hint `sub`/`sid` or there is no session | Log out immediately (revoke session + families, enqueue back-channel); redirect to `post_logout_redirect_uri` (+`state`) if given and registered for that client, else signed-out page |
| Hint invalid (bad signature, `alg:none`, unknown client, client_id mismatch) | Error page `logout.invalid_id_token_hint`; **no logout, no redirect** |
| `post_logout_redirect_uri` not registered for the client (incl. query added) | Error page `logout.redirect_uri_not_registered`; no redirect |
| `post_logout_redirect_uri` without hint and without `client_id` | Error page `logout.id_token_hint_required` |
| `client_id` + registered `post_logout_redirect_uri`, no hint | Confirmation page (`FlowKind::Logout`); after POST: log out, redirect with `state` |
| No params / only `state` / hint for another session | Confirmation page; after POST: signed-out page |

### Endpoint and CSRF details
- `/logout` GET and POST at the tenant base; advertise `end_session_endpoint = {issuer}/logout`.
- **Exempt `POST /logout` from the Fetch-Metadata layer.** RPs submit it cross-site, as with `POST /authorize`. The confirmation POST (`/ui/logout`) stays protected by flow cookie + CSRF.
- Do not advertise front-channel or session-management fields (default false; out of scope).
- Delivery timing: the spec text says the redirect happens after RPs are notified. Recommend:
  - enqueue in the same transaction as the revocation,
  - wake the worker in-process (`tokio::sync::Notify`) so the first attempt happens within milliseconds,
  - do not block the redirect.
  - A bounded inline wait is optional (see Open Questions).

### Conformance harness changes (tests/conformance)
1. Add selections to `run.sh`: `logout` (RP-initiated) and `backchannel`, plus `all` once green. Plans: `oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` and `oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]`.
2. Update `setup.sh`: the `client` gets `post_logout_redirect_uris: ["https://localhost.emobix.co.uk:8443/test/a/anvilid/post_logout_redirect"]` and `backchannel_logout_uri: "https://localhost.emobix.co.uk:8443/test/a/anvilid/backchannel_logout"`, `backchannel_logout_session_required: true`.
3. **Make the callback reachable:**
   - Generate a throwaway CA + leaf cert (SAN `localhost.emobix.co.uk`) in `$RESULTS_DIR/tmp`.
   - In `compose.override.yml`, mount it into the nginx service over `/etc/ssl/certs/nginx-selfsigned.crt` and `/etc/ssl/private/nginx-selfsigned.key` (paths from the suite's `nginx/Dockerfile` at the tag).
   - Start anvilid with `ANVILID_OUTBOUND_CA_FILE=<ca.pem>` and `ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32`.
   - Use a CA + leaf, not a self-signed leaf: webpki rejects a CA certificate used as an end-entity.
   - The suite's HtmlUnit trusts every certificate, so replacing nginx's cert does not affect it.
4. Add browser config overrides in `config.template.json`:
   - A `@BASE_URL@/logout*` block with a "Confirm" task (click `#logout-confirm-submit`, optional) and a "Verify Complete" task matching `*/test/*/post*`.
   - Per-module overrides for the 8 placeholder modules, waiting for the exact error and signed-out sentences with `update-image-placeholder`.
   - These ids and sentences become part of the theme contract in `themes/default/README.md`, like the 0.1 redirect-URI sentence.
5. `expected-failures.json` stays `[]`; no new skips expected.

## Upstream providers (AUTH-07, SEC-03)

### Provider matrix
| Provider | Protocol | Endpoints (defaults; overridable per connection) | Subject | Email trust | PKCE | Quirks (confidence) |
|---|---|---|---|---|---|---|
| Google | OIDC | discovery `https://accounts.google.com/.well-known/openid-configuration` | `sub` | `email_verified` claim trusted | yes | ID-token `iss` may be `https://accounts.google.com` **or** `accounts.google.com`; accept both for this preset only (HIGH). Optional `hd` (Workspace domain) allow-list |
| Microsoft (Entra) | OIDC | `https://login.microsoftonline.com/{common\|organizations\|consumers\|<tenant>}/v2.0/.well-known/openid-configuration` | `sub` (per-app pairwise, stable); store `tid`+`oid` in link metadata | **Not trusted by default.** The `email` claim can be unverified (nOAuth); new multi-tenant apps drop unverified-domain emails since June 2023; `xms_edov` exists but its status is uncertain (MEDIUM). Never auto-link; require explicit confirmation | yes | Multi-tenant metadata `issuer` is the template `https://login.microsoftonline.com/{tenantid}/v2.0`: replace `{tenantid}` with the token's `tid`, then compare exactly (Microsoft guidance, MEDIUM-HIGH). Optional allowed-tenant list. Consumers tid `9188040d-6c67-4c5b-b112-36a304b66dad` |
| Apple | OIDC-ish (no discovery use needed) | authorize `https://appleid.apple.com/auth/authorize`, token `https://appleid.apple.com/auth/token`, JWKS `https://appleid.apple.com/auth/keys`, iss `https://appleid.apple.com` | `sub` | `email_verified` trusted (may be boolean **or string** `"true"`; normalise). `is_private_email` relay addresses are fine (link by sub) | **not documented. Treat as unsupported; rely on nonce + confidential client** (LOW; verify in the manual checklist) | Requesting `name`/`email` scope **requires `response_mode=form_post`** (HIGH, Apple docs). `user` JSON (`{name:{firstName,lastName},email}`) only on the **first** authorization; sanitise and persist then (HIGH). Client secret = ES256 JWT: header `kid`=Key ID; claims `iss`=Team ID, `iat`, `exp` ≤ 6 months (mint fresh, 5 min), `aud`=`https://appleid.apple.com`, `sub`=Services ID (MEDIUM: Apple page body not retrievable; matches long-standing docs) |
| GitHub | OAuth2 (no OIDC) | authorize `https://github.com/login/oauth/authorize`, token `https://github.com/login/oauth/access_token` (send `Accept: application/json`), API `https://api.github.com` (`/user`, `/user/emails`); base URLs overridable for GitHub Enterprise Server | numeric `id` as string (never `login`, which can change) | Only `/user/emails` entry with `primary && verified` (locked); needs scope `user:email` (+`read:user`) | **yes (S256, since 2025-07-14 changelog; not required)** (HIGH) | API requires `User-Agent`; send `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28`. No verified primary email → cannot link or JIT-create; error page |
| Generic OIDC | OIDC | admin enters issuer; discovery fetched through the guarded client; `issuer` in the document must equal the configured issuer exactly | `sub` | Admin flag `trust_email_verified` (**default false**) | configurable, default on | Alg allow-list = discovery `id_token_signing_alg_values_supported` ∩ {RS256, PS256, ES256, Ed25519}. `EdDSA`-named keys are unsupported by anvil-jose by design; document it. Optional UserInfo fetch when the ID token lacks email. Check RFC 9207 `iss` on the callback when the provider advertises `authorization_response_iss_parameter_supported` |
| Generic OAuth2 | OAuth2 | admin enters authorize/token/userinfo URLs + JSON-pointer mapping (subject required; email, email_verified, name optional) | mapped | Never trusted unless the admin maps `email_verified` **and** enables trust | configurable | Userinfo with Bearer |

### ID-token validation (upstream, pure + adapter)
Validation order:
1. `verify_jwt(token, jwks, allowed_algs)`. The allow-list is checked before crypto; `none`/HMAC never pass.
2. `iss`: exact, with the Google and Microsoft preset rules above.
3. `aud` contains `client_id`. If multiple audiences, `azp == client_id`.
4. `exp > now - 60s`; `iat <= now + 60s`.
5. `nonce` == the flow nonce (required whenever one was sent).

JWKS handling:
- Cached in moka by URI. TTL = `Cache-Control: max-age` clamped to [5 min, 24 h].
- On unknown `kid`, refresh at most once per minute per URI.
- A failed fetch fails closed.
- `Jwks::parse` rejects sets containing private members; that is acceptable for upstreams.

### SEC-03: secret storage
- `connection.secret_enc` = `Kek::seal("anvilid/connection-secret/v1", tenant_id ‖ connection_id, secret)`. The secret is the client secret, or the Apple `.p8` PEM.
- Write-only in the admin API (view shows `secret_configured: true`), as with the 0.2 CAPTCHA and SMTP secrets.
- Add a `plaintext.rs` storage test proving the secret never hits disk in clear (the existing pattern in both backends' `tests/plaintext.rs`).

### Mock IdPs (discretion, recommended)
- **Rust integration tests (`anvil-web/tests/upstream_*.rs`):**
  - One wiremock `MockServer` per provider serving discovery/JWKS/token/userinfo/emails, with ID tokens signed by test keys (anvil-jose test key helpers or keys generated in the test).
  - Connections point at the mock via the per-connection endpoint/base-URL overrides. These are a real feature (Entra national clouds, GitHub Enterprise), not a test hook.
  - The outbound policy for tests allows loopback (dev-mode default or explicit `outbound_allow_cidrs`).
  - Quirk tests:
    - Google `iss` without scheme;
    - Microsoft `{tenantid}` substitution, plus a wrong-`tid` rejection;
    - Apple string `email_verified`, `form_post` callback, user JSON only first time;
    - GitHub unverified/non-primary emails ignored;
    - generic issuer mismatch, wrong nonce, wrong aud, expired token, unknown kid refresh, `alg:none`, HS256-with-public-key confusion — all rejected.
- **Playwright e2e:**
  - (a) **AnvilID as generic OIDC upstream**: a second tenant (`/t/upstream`) of the same instance, provisioned via the admin API. No extra process; covers the full browser redirect path.
  - (b) **`tests/e2e/lib/mock-idp.ts`**: a zero-dependency Node mock (`node:http`, `node:crypto` signs RS256/ES256 with `dsaEncoding: 'ieee-p1363'`). It serves an Apple-like `form_post` endpoint and a GitHub-like OAuth2 API.
  - **Bind the mock to `127.0.0.1` while AnvilID runs on `localhost`.** They are different sites, so Chromium applies real SameSite behaviour. This is what proves the Lax-binding design. If both are on `localhost` the cookie bug is invisible.
- **Manual real-provider checklist** (`docs/social-login-checklist.md`, owner-run before release): for each provider —
  - app registration fields,
  - redirect URI `{issuer}/ui/login/upstream/{slug}/callback`,
  - first login (JIT),
  - second login (link),
  - Apple first vs second login (name only first),
  - Microsoft personal + work accounts,
  - GitHub with private email,
  - account linking confirm path,
  - secret rotation.

  Update ROADMAP success criterion 2 and ARCHITECTURE M3 exit criteria to say "manual checklist", replacing "staging environment". Doc divergence to raise; the STATE.md blocker is resolved by the user decision.

## Account linking (AUTH-11)

### Threat model
| Threat | Mitigation |
|---|---|
| **Pre-account takeover**: attacker registers a local account with the victim's email (unverified) + password; victim later uses Google | Auto-link only to a local account with `email_verified = true`. If the local account is unverified, never link: tell the user to sign in or reset the password. Recovery goes to the victim's inbox, and `complete_recovery` revokes sessions and replaces the password, so the attacker loses access |
| **Unverified upstream email** | Never auto-link and never JIT-create with `email_verified=true`. JIT-created users get `email_verified = upstream_verified && connection_trusted` |
| **Email change at the IdP** | Links keyed by `(tenant, connection, subject)`. Email is never re-matched on later logins. Store `email_at_link` for audit only. Don't overwrite the local email from upstream |
| **Malicious or misconfigured generic IdP asserting arbitrary verified emails** | `trust_email_verified` default false for generic OIDC/OAuth2, true for Google/Apple/GitHub presets, false for Microsoft |
| **nOAuth (Microsoft mutable `email`)** | Microsoft email untrusted; link by `sub` |
| **Login CSRF / code injection / mix-up** | `state` bound to browser (Lax cookie) and connection; `nonce`; PKCE where supported; per-connection callback path; RFC 9207 `iss` check when advertised |
| **Account enumeration through the link page** | The "sign in to connect" page never shows whether an account exists unless the upstream email is verified *and* trusted (the user proved control of the address) |
| **Locking yourself out by unlinking** | Refuse to unlink the last sign-in method (no password, no passkey, no other link, and email OTP disabled) |

### State machine (pure `link_decision`)
```
callback validated ─► link exists? ── yes ─► user active? ─► SignIn(user) ─► MFA policy
                          │ no
                          ▼
     upstream email verified && connection trusted && local user with same email && local email_verified
       && tenant.auto_link ── yes ─► CreateLink + SignIn (audit identity_linked{mode:auto})
                          │ no
                          ▼
     local user with same email exists? ── yes ─► PendingLink (store upstream identity sealed in flow
                          │                         state; user signs in by password/passkey (+2FA);
                          │                         on success for ANY account they prove → CreateLink;
                          │                         audit identity_linked{mode:confirmed})
                          │ no
                          ▼
     registration open? ── yes ─► JIT CreateUser(+link, email_verified per rule, Apple name from user JSON)
                          │ no
                          ▼
                       Error page "no account" (no detail)
```
- Linking from the account page ("Connect Google") uses a settings flow (re-auth within 15 min, as in 0.2). The start/callback reuses the same service with `purpose = Link{user_id}`.
- Tenant settings: `auto_link: bool` (default **true**, safe given the verified+trusted gate) and `upstream_registration: bool` (default follows `registration`).

## Passwordless email (AUTH-06)

Best-practice rules (OWASP authentication guidance, NIST SP 800-63B-4 context):
- **Email is not a phishing-resistant or NIST out-of-band authenticator** (800-63B-4 excludes email for OOB). Email OTP is a single-factor convenience method. It **never satisfies MFA**: amr gets no `mfa` and acr stays at the single-factor level.
- **Code:** 6 digits from the KEK RNG (`random_bytes`); TTL 10 min; max 5 wrong attempts per code, after which the code is invalidated (counter in flow state, CAS); max 3 sends per flow; HMAC-peppered hash at rest.
- **Link:** 256-bit token, SHA-256 at rest, same TTL. The email carries **both** the code and the link.
- **Link scanners:** GET `/ui/login/email-link?flow=…&token=…` renders a "Continue signing in" button only. Only the POST consumes (CAS). Scanners that prefetch GET consume nothing.
- **Cross-device / login CSRF:**
  - The link is bound to the initiating browser through the flow (cookie + CSRF on the POST).
  - Opened in a different browser, the POST fails the binding. Show "Open the link in the browser where you started, or type the code" and never sign in that other browser. This also blocks "log the victim into the attacker's account".
  - Strict cookies are absent on the GET from webmail but present on the same-site POST from our page, so the design works.
- **Enumeration:** always render "If an account exists for that address, we sent a code". Unknown, blocked, or no-email accounts get the same page and the same timing class (sending is async via the outbox).
- **Rate limits (one limiter):**
  - auth-class per IP on send and verify;
  - the loose identifier tier per email for sends (anti mail-bombing);
  - the per-user second-factor-style key for verify attempts (KEK-sealed token as in 0.2 `factor_token`).
- **Tenant settings:** `email_otp: bool`, `magic_link: bool` (default false; require SMTP).
- **New `EmailKind::LoginCode`**, with variables `code`, `link`, `tenant_name`, `expires_minutes`. Sealed payload as in 0.2. Requires the `email_template.kind` CHECK rebuild in SQLite.
- **amr/acr:** amr `["otp"]` (RFC 8176 "otp"; flag as discretion), acr single-factor. A following TOTP/passkey upgrades to MFA.

## OIDC-14 completion + MFA policy (AUTH-08)

### Current state (0.2)
- `authorize_request.rs` accepts `prompt` ∈ {none, login, consent, select_account} and rejects `none` combined with anything else.
- `decision.rs` implements `prompt=login`, `max_age` and `id_token_hint` sub match.
- `login_hint`, `acr_values` and `ui_locales` are parsed and stored in `AuthorizationParams`, but ignored.
- Discovery: `prompt_values_supported: ["none","login"]`, `acr_values_supported: [ACR_PWD]` (both stale: consent already works).

### Additions
- **`prompt=consent`:** already implemented. Advertise it.
- **`prompt=select_account`:** AnvilID has one session per browser.
  - Render an account chooser: "Continue as alice@… / Use another account".
  - "Use another account" runs the login flow. Signing in as a *different* user **revokes the previous browser session** (and triggers back-channel logout through Pattern 3).
  - `select_account` + `none` is already rejected in validation.
- **`prompt=create`** (Initiating User Registration 1.0, Final 2022-12-02):
  - Start the registration flow, then resume the authorization.
  - Advertise `create` in `prompt_values_supported` **only for tenants with `registration = open`** (discovery is per tenant).
  - A tenant without it answers `invalid_request` ("unsupported prompt value"), as the spec prescribes for unsupported values.
  - Don't combine `create` with others (spec recommendation): reject `create` + `none`.
- **`login_hint`:** prefill the identifier field when it normalises as an email. Otherwise ignore it and never echo it unescaped. It also prefills the email-code form.
- **`acr_values` (voluntary) and `claims.id_token.acr` (essential):**
  - Publish `acr_values_supported: [urn:anvilid:acr:pwd, urn:anvilid:acr:mfa]`.
  - Requested MFA and the session is single-factor → **step-up**: the login flow starts directly at the SecondFactor step for the session's user (no password re-entry), or a passkey assertion.
  - On success the session is upgraded in place by a new intent `SessionRepo::upgrade_auth(tenant, session_id, acr, amr, auth_time, now)`. auth_time = now; amr = union (e.g. `["pwd","otp","mfa"]`).
  - The user has no second factor and policy is not `required`: voluntary → issue at the lower acr (the ID token `acr` tells the truth). Essential → error.
  - Error code: OpenID's `unmet_authentication_requirements` (Unmet Authentication Requirements spec; MEDIUM, verify status) or `access_denied` if unsure.
- **`max_age`:** unchanged; it already works with the step-up resume because `auth_time` updates.

### MFA policy (pure)
```rust
// anvil-core/src/policy/mfa.rs — sketch
pub enum MfaPolicy { Off, Optional, Required }           // tenant setting; client: Option<MfaPolicy> (None = inherit)
pub enum MfaRequirement { None, SecondFactor, Enroll, Unmet }
pub fn effective_policy(tenant: MfaPolicy, client: Option<MfaPolicy>) -> MfaPolicy { client.unwrap_or(tenant) } // org slot later
pub fn mfa_requirement(policy: MfaPolicy, wants_mfa: AcrRequest /*None|Voluntary|Essential*/,
                       session_is_mfa: bool, user_has_factor: bool) -> MfaRequirement { /* table below */ }
```
| policy | request asks MFA | user has factor | result |
|---|---|---|---|
| Off | no | any | None (0.2 users with TOTP: **not** prompted under Off) |
| Optional (default, = 0.2 behaviour) | no | yes | SecondFactor |
| Optional | no | no | None |
| Required | any | yes | SecondFactor |
| Required | any | no | **Enroll** (in-flow TOTP or passkey enrolment, reusing AccountService enrolment pieces; then sign in with MFA) |
| any | voluntary | no (and not Required) | None (lower acr issued) |
| any | essential | no (and not Required) | Unmet |

Passkey sign-in already counts as MFA. Upstream (social) sign-in is single-factor, so the Required policy adds the local second factor after the upstream login. **Precedence (discretion): most-specific explicit setting wins** (client > org (Phase 6) > tenant). Document that a client override can relax a tenant default, and audit policy changes.

## Resource indicators (OIDC-16, RFC 8707)

**Parsing:**
- `resource` may repeat (an exception to the "repeated parameter → invalid_request" rule in both `/authorize` and `/token`).
- Each value must be an absolute URI with no fragment; reject a query (SHOULD NOT; be strict).
- Each value must exactly match an entry in `client.allowed_resources`. Otherwise `invalid_target`, delivered via the redirect at `/authorize` and as JSON 400 at `/token`.
- New `CoreError::InvalidTarget` maps once in the single error mapping.

**Storage:**
- `AuthorizationParams.resource: Vec<String>` (serde default, so no migration because params are JSON).
- New JSON `resource` column (default `[]`) on `authorization_code`, `token_family` and `access_token` (opaque).
- ARCHITECTURE §6.1 already anticipates `resource` on these.

**Token endpoint:**
- *code grant*: optional `resource` ⊆ code's resources (downscoping); if absent, use all granted.
- *refresh*: optional `resource` ⊆ family's resources. The refresh token keeps the full grant.
- *client_credentials*: `resource` ⊆ allowed.

**Access tokens:**
- JWT `aud` = the selected resource(s). One value is serialised as a string, several as an array.
- With no resource, `aud` = client_id (0.2 behaviour, locked).
- The ID token `aud` is always client_id.
- Opaque tokens store resources for introspection.

**Introspection** returns `aud` (string or array) for both formats.

**UserInfo audience rule (recommended; see Open Questions):** accept an access token at `/userinfo` only if its `aud` contains the client_id (no resource requested) or `{issuer}/userinfo`. This keeps a token minted for an API from being replayed to UserInfo by that API.

**Consent:** show the requested resources. Merging grants by resource can wait for Phase 5. Keep `consent_grant` scope-only, and note the gap.

**MCP readiness (AGT-01, Phase 5):**
- MCP clients send `resource` (the canonical MCP server URI) in both the authorization and token requests and expect `aud` to contain it.
- The design above satisfies that. Phase 5 adds CIMD and dynamic `allowed_resources` policy.
- Multiple audiences enable token replay among them (RFC 8707 §3). Document that one resource per token is preferable; the AS may refuse multiple with `invalid_target` if the planner chooses (recommend allowing them, documented).

## Account page (AUTH-13)

**Exists (0.2):**
- `/ui/account/security`: passkeys, TOTP, recovery codes.
- `/ui/account/sessions`: list and revoke.
- `/ui/account/apps`: consents and revoke.
- Settings flows bound to the owner; credential changes need re-auth within 15 min.

**Missing (add):**
- **Profile** (`/ui/account/profile`): edit `name`, `given_name`, `family_name`, `locale` (feeds i18n for account pages) via `UserUpdate`. Audit the change.
- **Email change:**
  1. Re-auth required.
  2. Send a link to the **new** address. New `SelfServiceKind::EmailChange` token with `email = new`; SQLite rebuild of `self_service_token`.
  3. Send a notice to the **old** address: new `EmailKind::EmailChanged`, plus `EmailKind::EmailChange` for the verification mail.
  4. New intent `UserRepo::complete_email_change(tenant, token_hash, now) -> Result<Option<User>, StorageError>`. It consumes atomically and sets `email = token.email, email_verified = true`.
  5. `Conflict` if the address was taken in the meantime (unique index). Consumed on POST only.
  6. Identity links are unaffected.
- **Password change:** re-auth, policy + breach check, `set_password`. Then revoke other sessions (optional checkbox, default on) and enqueue the `password_changed` notice (exists). Users without a password (social-only) can set one.
- **Linked identities** (`/ui/account/linked`): list links (provider, email_at_link, created), connect (settings-flow start), unlink (last-method guard).
- **Account nav:** a shared `account_base.html` nav listing all pages; all labels localized.

## Theming (UI-03)

**Facts:**
- `anvil.css` already uses 17 `--anvil-*` custom properties (bg, surface, text, muted, primary, primary-text, border, input-border, focus, radius, font, danger*, warning*, code-bg) with a dark scheme.
- The page CSP is `default-src 'none'; style-src 'self'; img-src 'self'`. That means **no inline styles, no external images or fonts, and no `font-src` at all**.

**Model:**
- `ThemeTokens { logo: Option<AssetRef>, colors: {primary, primary_text, bg, surface, text, muted, border, focus, danger}, colors_dark: Option<…>, font_family: Option<String>, radius_px: Option<u8> }`.
- `custom_css: Option<String>`.
- Scopes: tenant (`scope_key=''`), client (`scope_key=client_id`), and later org (`org:{id}`).
- **Merge per token:** client > org > tenant > built-in default.

**Validation (in core, pure):**
- Colors only `#rgb|#rrggbb|#rrggbbaa`.
- Radius 0–32 px.
- Font family matches `^[A-Za-z0-9 ,'"-]{1,200}$` (system font stacks only; font file upload deferred because it would need `font-src 'self'`).
- Contrast check (WCAG relative luminance) for text/bg and primary_text/primary. Return **warnings** below 4.5:1 so the console shows them; refuse below 3:1 to protect the UI-02 AA commitment.
- With custom light colors and no `colors_dark`, emit `color-scheme: light` so the dark scheme does not override the brand.

**Custom CSS validator:**
- ≤ 32 KiB UTF-8; no control characters or NUL.
- Reject `@import`, `@font-face`, `@namespace`, `url(`, `image-set(`, `expression(`, `-moz-binding`, `behavior:`, `javascript:`, any backslash (escape obfuscation), `<`.
- Balanced braces and comments.
- Return a line number for errors (as the 0.2 email-template validator does).
- The CSP stays the real control: even a validator bypass cannot load external resources or run script.
- Threat note: the only author is a tenant admin, who already controls their users' experience. The validator mainly blocks accidental tracking pixels and makes cross-tenant mistakes impossible, because CSS is served per tenant only.

**Logo:**
- PNG/JPEG/WebP only (magic-byte sniff), ≤ 256 KiB, stored as a BLOB.
- Served at `/assets/branding/{sha256}.{ext}` with `immutable` caching, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`.
- **No SVG in 0.3.** Direct navigation to an SVG would execute script in our origin. If it is ever needed, serve it with `sandbox` CSP.

**Rendering:**
- `GET /assets/theme/{hash}.css`, where `hash` = SHA-256 of the merged tokens + custom CSS. Generated in Rust: `:root{--anvil-primary:#…;…}` followed by the custom CSS; values are already validated, so no escaping problem. moka-cached; `immutable`.
- `base.html` gains `<link rel="stylesheet" href="{{ page.theme_css }}">` after `anvil.css`, plus an optional `<img src="{{ page.logo_url }}" alt="{{ page.tenant_name }}">`.
- The client comes from the flow's authorization request when there is one.

**Live preview:**
1. The console (installation-level, same origin as `/t/{slug}/…`) PUTs a draft: `POST /api/admin/v1/tenants/{slug}/branding/preview` with the draft body.
2. The server stores the draft with a random preview token (hash + 15 min expiry) and returns `preview_url = /t/{slug}/ui/preview?token=…`.
3. The console shows it in an `<iframe>` and re-POSTs on a 300 ms debounce.
4. The preview page renders static sample login/consent markup with the draft CSS. Only that route sends `frame-ancestors 'self'` and `X-Frame-Options: SAMEORIGIN`; every other page keeps `'none'`/`DENY`.
5. "Publish" copies the draft to live (`PUT …/branding`).

The console CSP (`default-src 'self'`) allows same-origin frames. Host-based tenants are previewed through the path form on the public URL (verify tenant resolution allows `/t/{slug}` for host-mapped tenants; see Open Questions).

## i18n (UI-04)

**Loader (`anvil-web/src/i18n.rs`):**
- Embed `themes/default/locales/{lang}/*.ftl` with rust-embed. A theme dir may add or override `locales/{lang}/*.ftl`, as for templates.
- Build one `fluent_bundle::concurrent::FluentBundle<FluentResource>` per locale at startup. Fail startup on parse errors, as broken template overrides already do.
- `bundle.set_use_isolating(false)`. Fluent's default FSI/PDI isolation marks break exact-text assertions (e2e, conformance browser sentences) and attribute values. Use `<bdi>` around user-provided values in templates instead.

**Keys:**
- Fluent identifiers are `[a-zA-Z][a-zA-Z0-9_-]*`, with **no dots**. Map existing keys deterministically: `login.invalid_credentials` → `login-invalid_credentials`. Keep the stable dotted keys in `FormMessage.key` and `data-message-key` (tests and themes depend on them).
- Core stops producing English: `message_text` in `flow/engine.rs`, `service/session.rs`, `service/account.rs`, `ui/consent.rs`, and labels in `field(...)`, become keys.
- The web renderer resolves keys with the request locale before rendering. `FormMessage.text` and `FormField.label` are filled in by the web layer, which keeps the headless API (UI-5) able to choose its own strings.

**Templates:** every hard-coded sentence becomes `{{ t("login-heading") }}` / `{{ t("login-remaining", count=n) }}`.
- `t` is a minijinja function capturing the request's negotiated locale. Pass it per render as a context value (a closure over the bundle + locale), since the environment is shared.
- Output stays auto-escaped. Never mark Fluent output safe.

**Negotiation (locked order):**
1. `ui_locales` (stored in `AuthorizationParams` for flows started by `/authorize`; also on `/logout`)
2. `Accept-Language` (`fluent_langneg::accepted_languages::parse`)
3. Tenant `default_locale` (new `TenantSettings` field, default `en`)
4. `en`

Strategy `NegotiationStrategy::Filtering`, falling back to `en` for missing keys (a two-bundle fallback chain). Account pages also consider the user's `locale` claim, after `ui_locales` and before Accept-Language.

**HTML:** `<html lang="{{ page.lang }}" dir="{{ page.dir }}">`, where `dir = rtl` for `ar, he, fa, ur, ps, yi` primary subtags. Switch `anvil.css` physical margins/paddings to logical properties (`margin-inline-start`) so a future RTL catalog just works. Advertise `ui_locales_supported` in discovery (the available locales).

**Plurals:** Fluent selectors, e.g. `{ $remaining -> [one] One code left *[other] { $remaining } codes left }`. These cover recovery codes remaining and "try again in N seconds".

**Second language (discretion):** recommend **German (`de`)**. Its long compound words stress layouts and catch overflow. Use pt-BR instead if the maintainer can review it better. Add a CI check that every locale defines every `en` message id (missing ids fail the test), plus a snapshot of one page per locale.

**Emails:** default email templates stay English in 0.3 (tenant overrides are single-language minijinja with a variable contract). Record this as a known limitation; UI-04 requires pages only. The console is out of scope.

**Conformance and e2e:** HtmlUnit and Playwright default to English Accept-Language, so the English contract sentences stay intact. Add one e2e test with `ui_locales=de`.

## Data model changes (foundation)

**SQLite `0005_release_0_3.sql`** (one transaction; rebuilds have no inbound FKs; mark rebuilds `-- anvil:non-destructive-rebuild`):
- Rebuilds:
  - `flow`: kind += `logout`.
  - `self_service_token`: kind += `email_change`.
  - `email_template`: kind += `login_code`, `email_change`, `email_changed`.
- New tables:
  - `connection` (id, tenant_id, slug UNIQUE per tenant, kind CHECK ('google','apple','microsoft','github','oidc','oauth2'), display_name, enabled, config JSON, secret_enc BLOB, trust_email_verified, created_at, updated_at; org_id later)
  - `identity_link` (id, tenant_id, user_id → user cascade via composite FK, connection_id → connection cascade, subject, email_at_link, created_at, last_used_at; UNIQUE (tenant_id, connection_id, subject))
  - `rp_session` (tenant_id, session_id → browser_session cascade, client_id, created_at; PK (tenant_id, session_id, client_id))
  - `logout_delivery` (id, tenant_id, client_id, uri, sub, sid, attempts, next_attempt_at, created_at, expires_at, delivered_at, last_error, give_up_at)
  - `branding` (tenant_id, scope_key, tokens JSON, custom_css, logo BLOB, logo_type, draft JSON/columns, preview_hash, preview_expires_at, updated_at; PK (tenant_id, scope_key))
- New columns:
  - `client`: `post_logout_redirect_uris` JSON NOT NULL DEFAULT '[]', `backchannel_logout_uri` TEXT, `backchannel_logout_session_required` INTEGER NOT NULL DEFAULT 0, `allowed_resources` JSON NOT NULL DEFAULT '[]', `mfa_policy` TEXT NULL CHECK.
  - `authorization_code`, `token_family`, `access_token`: `resource` JSON NOT NULL DEFAULT '[]'.

**Postgres `0004_release_0_3.sql`:** the same, additively, using `DROP CONSTRAINT/ADD CONSTRAINT` for the CHECK swaps, as in 0003. Use `uuid`, `jsonb` and `timestamptz` per conventions, and composite tenant FKs for new user-scoped tables.

**Other foundation requirements:**
- `TenantSettings` JSON additions (serde default, no migration): `mfa_policy`, `email_otp`, `magic_link`, `auto_link`, `upstream_registration`, `default_locale`.
- Upgrade tests (`tests/upgrade.rs` in both crates): 0.2 → 0.3 with fixtures, then the contract suite.
- Regenerate `.sqlx` metadata per crate (`just sqlx-prepare crate=crates/anvil-storage-sqlite` etc.).
- Do not touch `scripts/released-migrations.sha256` until the release plan.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWS verify/sign, alg allow-list | New JWT code for upstream or logout tokens | `anvil-jose::verify_jwt`, `SigningKey::sign_jwt`, `verify_op_token_algs(..., ExpiryCheck::Ignore)` for `id_token_hint` | Already fuzzed and tested; alg confusion handled |
| Secret encryption | Ad-hoc AES | `Kek::seal/open` with a new purpose string + row AAD | Single crypto backend, AAD binding |
| CSRF for new pages | HMAC tokens, double-submit cookies | Flow binding (cookie + synchronizer token), new `FlowKind::Logout` | One implementation per concern |
| Rate limiting sends/attempts | Counters in tables | `anvil-cache` limiter keys/classes (+ flow-state attempt counter for per-code limits) | One limiter |
| Background delivery | New scheduler | Outbox-style claim/lease in storage + existing job runner + `Notify` wake | Proven for email in 0.2 |
| Plurals / locale negotiation | String concatenation, own Accept-Language parser | fluent-bundle + fluent-langneg | Correct CLDR plural rules, q-values |
| OIDC RP client | `openidconnect`/`oauth2` crates | Hand-rolled on reqwest + anvil-jose | Crates are banned by deps policy (chrono, rsa) |
| Single-use secrets | Check-then-update | `FlowRepo::swap_state` CAS / atomic intent methods | Race-free on both backends |

**Key insight:** almost every Phase 4 security property maps to a primitive that 0.2 already built and tested (CAS, KEK, flow binding, limiter, outbox leasing, alg allow-lists). The risk is creating second versions of them, not missing capability.

## Common Pitfalls

### Pitfall 1: Strict flow cookie missing on IdP callbacks and magic-link clicks
**What goes wrong:** The callback can't find or bind the flow; users see "flow expired" after Google/Apple; magic links fail from webmail.
**Why:** `SameSite=Strict` cookies are never sent on navigations started cross-site, including redirect chains. Lax cookies are sent only on top-level GET.
**How to avoid:** Use the Pattern 2 Lax binding cookie and the Apple POST→303→GET hop. Make the magic-link GET render a same-site POST button.
**Warning signs:** Tests pass only when the mock IdP and AnvilID share a host name. Run the e2e mock on `127.0.0.1` and AnvilID on `localhost`.

### Pitfall 2: Fetch-Metadata CSRF layer rejects legitimate cross-site POSTs
**What goes wrong:** Apple `form_post` callbacks and RP `POST /logout` get the 403 CSRF page.
**How to avoid:** Explicit exemptions for exactly those two routes, each with a negative test proving its own protection (state/binding for the callback; hint validation for logout). Every other route stays protected.

### Pitfall 3: SSRF guard bypasses
**What goes wrong:** IP-literal URLs skip the resolver; redirects lead to internal hosts; `HTTPS_PROXY` routes through a proxy; IPv4-mapped IPv6 (`::ffff:127.0.0.1`) passes a naive check; DNS rebinding between the check and the connect.
**How to avoid:** Validate literal hosts before the request. `Policy::none()` and `no_proxy()`. Check embedded IPv4. Filter inside the resolver, the address actually used to connect, so the guard is rebinding-safe.
**Warning signs:** A test hitting `http://127.0.0.1:{wiremock}` succeeds without the allow-list.

### Pitfall 4: Microsoft multi-tenant issuer
**What goes wrong:** Exact `iss == metadata.issuer` fails for `/common` (`{tenantid}` template). The "fix" of disabling issuer validation accepts tokens from any tenant.
**How to avoid:** Substitute the token's `tid`, then compare exactly. Optional allowed-tenants list. Test a wrong `tid` and a missing `tid`.

### Pitfall 5: Apple specifics
**What goes wrong:**
- Name lost: it arrives only on the first authorization, in the `user` form field, not in the ID token.
- `email_verified: "true"` as a string parsed as false or rejected.
- `form_post` required with `name email` scope.
- Long-lived client secrets cached past rotation.
**How to avoid:** Persist the sanitised name at JIT creation. Use a tolerant bool parser for Apple claims only. Mint the client secret per token request (5 min exp).

### Pitfall 6: Back-channel delivery semantics
**What goes wrong:**
- Retrying on 400 (spec says don't).
- Treating 204 as failure.
- Signing the token at enqueue time, so retries after 2 min send expired tokens.
- Adding parameters besides `logout_token` (suite WARNING → CI failure).
- `nonce` copied from ID-token claim helpers (forbidden).
**How to avoid:** A dedicated `logout_token_claims()` pure builder with a unit test asserting the exact claim set. Sign at send. Status classification: 200/204 delivered, 400 give up, 5xx/network/timeout retry with backoff (e.g. 10 s × 2ⁿ, cap 1 h, give up after 24 h).

### Pitfall 7: Conformance callback TLS and SSRF
**What goes wrong:** Back-channel module times out because anvilid refuses `localhost.emobix.co.uk` (127.0.0.1) or the nginx `CN=localhost` cert.
**How to avoid:** The harness CA + leaf mounted into nginx; `outbound_ca_file` + `outbound_allow_cidrs`. Use a CA cert + leaf, not a self-signed leaf.

### Pitfall 8: Repeated `resource` parameter
**What goes wrong:** The existing "duplicated parameter → invalid_request" rule in `authorize_request.rs` (`first_duplicate`) and `/token` (repeated → invalid_request) rejects RFC 8707's multi-valued `resource`.
**How to avoid:** Allow-list `resource` as the only multi-valued parameter in both parsers, with tests both ways.

### Pitfall 9: OpenAPI / generated-file merge conflicts
**What goes wrong:** Two parallel plans each add admin routes and regenerate `docs/openapi/admin-v1.json` + `admin-ui/src/api/schema.d.ts`.
**How to avoid:** At most one OpenAPI-changing plan per wave. Console plans depend on the API plan of an earlier wave.

### Pitfall 10: Fluent pitfalls
**What goes wrong:** Dots in message ids (parse error); isolation marks breaking exact-text tests; missing keys silently rendering the id.
**How to avoid:** Key mapping; `set_use_isolating(false)`; a CI completeness test against `en`; startup failure on malformed `.ftl`.

### Pitfall 11: SQLite CHECK constraints
**What goes wrong:** Inserting `flow.kind='logout'` or the new email kinds fails at runtime on SQLite only. Postgres passes because its constraint was swapped.
**How to avoid:** Rebuild those tables in 0005 and run the contract suite on SQLite memory + file + Postgres.

### Pitfall 12: Theme breaking accessibility or dark mode
**What goes wrong:** Brand colors fail contrast; the dark scheme from `prefers-color-scheme` overrides the brand with mismatched colors.
**How to avoid:** Contrast warnings/refusals; `color-scheme: light` when no dark tokens are set; axe e2e on a themed page.

### Pitfall 13: Session switching with select_account / upstream login
**What goes wrong:** Signing in as user B leaves user A's session alive server-side and invisible (one cookie), so A's RPs never get logged out.
**How to avoid:** A new sign-in in a browser that holds a different user's session revokes the old session through the normal intent (back-channel enqueued).

## Code Examples

### Logout token claims (pure; sign at send time)
```rust
// Source: OIDC Back-Channel Logout 1.0 §2.4 (Final, errata set 1, 2023-12-15). Sketch.
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";
pub const LOGOUT_TOKEN_TTL: Duration = Duration::minutes(2);
pub const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

pub fn logout_token_claims(issuer: &str, client_id: &str, sub: &str, sid: &str,
                           jti: &str, now: OffsetDateTime) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("iss".into(), issuer.into());
    m.insert("aud".into(), client_id.into());
    m.insert("iat".into(), now.unix_timestamp().into());
    m.insert("exp".into(), (now + LOGOUT_TOKEN_TTL).unix_timestamp().into());
    m.insert("jti".into(), jti.into());
    m.insert("sub".into(), sub.into());
    m.insert("sid".into(), sid.into());           // == browser_session.id, as in ID tokens
    m.insert("events".into(), serde_json::json!({ BACKCHANNEL_EVENT: {} }));
    m                                             // never "nonce"
}
// signer.sign_jwt(Some(LOGOUT_TOKEN_TYP), &claims) with the client's id_token alg key.
```

### Microsoft issuer check
```rust
// Source: Microsoft identity platform guidance on tenant-independent metadata. Sketch.
fn expected_ms_issuer(template: &str, claims: &Map<String, Value>) -> Option<String> {
    let tid = claims.get("tid")?.as_str()?;
    if uuid::Uuid::parse_str(tid).is_err() { return None; }
    Some(template.replace("{tenantid}", tid))
}
// iss must equal expected exactly; optional allowed-tenants check on tid.
```

### Apple client secret
```rust
// Source: Apple "Creating a client secret" (claims per long-standing docs; MEDIUM). Sketch.
let key = SigningKey::from_pkcs8(&apple_key_id, Alg::ES256, &p8_pkcs8_der)?; // .p8 opened from KEK seal
let claims = json!({ "iss": team_id, "iat": now, "exp": now + 300,
                     "aud": "https://appleid.apple.com", "sub": services_id });
let client_secret = key.sign_jwt(None, &claims)?; // header {alg:ES256, kid:<Key ID>}
```

### Fluent bundle + minijinja function
```rust
// Source: fluent-bundle 0.16 API (concurrent::FluentBundle, add_resource, get_message,
// format_pattern, set_use_isolating). Sketch.
let mut b = fluent_bundle::concurrent::FluentBundle::new_concurrent(vec![lang.clone()]);
b.set_use_isolating(false);
b.add_resource(FluentResource::try_new(src).map_err(|_| WebError::Config(..))?)?;
fn fluent_id(key: &str) -> String { key.replace('.', "-") }
// per render: ctx.insert("t", Value::from_function(move |key: &str, kwargs: Kwargs| -> String { … }))
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Logout token without `exp`, untyped | `exp` REQUIRED, `typ: logout+jwt` RECOMMENDED | Back-Channel Logout 1.0 final (2022), errata 2023-12-15 | Include both |
| `add_root_certificate` | `tls_certs_merge` / `tls_certs_only` | reqwest 0.13 | Use the new API (old one deprecated) |
| GitHub OAuth without PKCE | PKCE S256 supported (optional) | 2025-07-14 | Send PKCE to GitHub |
| Trusting Entra `email` | Key on `sub`/`oid`+`tid`; unverified-domain emails removed for new multi-tenant apps | June 2023 | Never auto-link Microsoft by email |
| `prompt=create` ad hoc | Initiating User Registration via OIDC 1.0 Final | 2022-12-02 | Advertise per tenant |

**Deprecated/outdated:**
- `EdDSA` alg name: AnvilID accepts only `Ed25519` (RFC 9864). Upstream IdPs still using `EdDSA` keys won't verify. Document this.
- ARCHITECTURE §6.1 `rp_session.sid` column: redundant with `sid = browser_session.id`. Raise it.

## Open Questions

1. **Bounded inline wait for back-channel before the post-logout redirect.**
   - What we know: the spec says the redirect follows notification; the suite accepts either order.
   - Recommendation: enqueue + wake, no blocking. Revisit only if a real RP complains.
2. **UserInfo audience rule with resource indicators.**
   - What we know: RFC 8707 audience-restricts tokens; 0.2 UserInfo does not check `aud`.
   - Recommendation: accept only `aud ∋ client_id` or `{issuer}/userinfo`; document it. Confirm with the owner because it changes behaviour for clients that request resources.
3. **`unmet_authentication_requirements` vs `access_denied`** for unmet essential `acr`.
   - Recommendation: use `unmet_authentication_requirements` if the spec status is acceptable at implementation time; otherwise `access_denied`.
4. **MFA policy precedence** (override vs strictest).
   - Recommendation: most-specific explicit setting wins, audited. Flag in docs.
5. **amr values for email OTP/magic link and social sign-in** (no registered RFC 8176 value for email or federation).
   - Recommendation: email → `["otp"]`; upstream-only → omit `amr` (or empty) and keep acr single-factor. The owner may prefer otherwise.
6. **Apple PKCE.** Undocumented. Recommendation: capability flag off; verify in the manual checklist.
7. **Host-based tenants and console preview.** Confirm `/t/{slug}` resolves on the public host for host-mapped tenants (§12 order: host match first, then path). Otherwise the preview needs a different route.
8. **Localized email templates.** Deferred. Confirm UI-04 covers pages only.

## Suggested plan decomposition (discretion; maximizes parallelism)

**Shared-file ownership rules:**
- `Cargo.toml`/`Cargo.lock`, `anvil-core/src/model/*`, `ports.rs`, `anvil-storage/src/contract/*` → 04-01 only.
- `anvilid/src/config.rs`, `anvil-web/src/config.rs` → 04-02 only.
- Migrations → 04-04 (SQLite) and 04-05 (Postgres) only.
- `protocol/discovery.rs` → 04-11 (logout + OIDC-14 + i18n fields all at once, after the features exist), or a tiny dedicated edit in each owning plan in different waves.
- OpenAPI regen → at most one plan per wave.
- Login-engine files (`flow/login.rs`, `flow/engine.rs`, `service/flow.rs`, `ui/login.rs`, `templates/login.html`) → a serial chain: 04-06 → 04-15 → 04-20 → 04-23.

| Wave | Plan | Scope (files) | Reqs |
|---|---|---|---|
| 1 | 04-01 Core model + ports + contract suite | model/{connection,branding,logout}.rs, client/session/grant/tenant/flow/mail_settings additions, ports.rs (ConnectionRepo, BrandingRepo, LogoutRepo, new intents incl. complete_email_change, upgrade_auth, logout enqueue semantics in revoking intents, rp_session in create_code), contract tests; backends temporarily return `StorageError::Unsupported` (Phase 2 precedent, never success); `engine.rs` match arm for `FlowKind::Logout` → explicit error; Fluent deps in workspace | foundation |
| 1 | 04-02 Guarded outbound client + config | adapters/outbound.rs, config keys `outbound_allow_cidrs`, `outbound_ca_file`, AppConfig wiring; migrate captcha/hibp clients onto it; security tests (literal IPs, mapped IPv6, redirects, proxy, private DNS answers, http scheme) | SEC (SSRF), enables OIDC-12/AUTH-07 |
| 1 | 04-03 Conformance harness extension | tests/conformance/{run.sh,setup.sh,compose.override.yml,config.template.json,README.md}: new selections `logout`, `backchannel` (not yet in `all`), CA/leaf + nginx mount, client logout metadata | OIDC-12 |
| 2 | 04-04 SQLite 0005 + repos | migrations, src/*, .sqlx, upgrade test | foundation |
| 2 | 04-05 Postgres 0004 + repos | same | foundation |
| 2 | 04-06 i18n infrastructure + English catalog | anvil-web/src/i18n.rs, render.rs, every template, core message keys (engine.rs, session.rs, account.rs, ui/consent.rs), locales/en, `<html lang dir>`, logical CSS properties | UI-04 |
| 2 | 04-07 Upstream core (pure) | anvil-core/src/upstream/*, UpstreamClient port (new trait in its own file re-exported from ports via 04-01 placeholder or `upstream/port.rs`), provider presets, claim validation, link_decision, Apple claims | AUTH-07/11 |
| 2 | 04-08 Pure protocol pieces | oauth/logout.rs (end-session decision, logout token claims), oauth/resource.rs, policy/mfa.rs + unit/proptests | OIDC-12/16, AUTH-08 |
| 3 | 04-09 Admin API: client logout/resource/MFA fields, tenant settings, connections CRUD (secret sealing) | admin/{dto,clients,tenants,connections}.rs, service/connection.rs, OpenAPI + admin-ui schema regen | SEC-03, OIDC-12/16, AUTH-08 |
| 3 | 04-10 Resource indicators end to end | authorize_request.rs (multi-valued `resource`), service/authorize.rs build_code, service/token.rs, service/claims.rs aud, introspect.rs, userinfo.rs aud rule, protocol/token.rs parser | OIDC-16 |
| 3 | 04-11 RP-initiated logout | protocol/logout.rs, service/logout.rs, flow/logout.rs, ui/logout.rs, templates logout_confirm/logged_out, CSRF exemption for POST /logout, discovery fields (end_session_endpoint, backchannel_*), cookie clearing | OIDC-12 |
| 3 | 04-12 Upstream adapters + wiremock suites | adapters/upstream/{oidc,github,apple}.rs (discovery/JWKS cache, token exchange, userinfo, emails), tests/upstream_{google,microsoft,apple,github,oidc,oauth2}.rs | AUTH-07 |
| 3 | 04-13 Account profile, email change, password change | ui/account_profile.rs, service/account.rs additions, templates, email kinds (templates in themes/default/emails) | AUTH-13 |
| 4 | 04-14 Back-channel delivery worker | adapters/backchannel.rs, anvilid/src/jobs.rs registration + Notify wake, service/logout delivery, retries/classification tests (wiremock RP) | OIDC-12 |
| 4 | 04-15 Login engine: MFA policy + step-up + in-flow enrolment + select_account/create/login_hint | flow/login.rs, engine.rs, service/flow.rs, service/authorize.rs (prompt create/select_account), ui/login.rs, templates login/select_account, discovery prompt/acr values | AUTH-08, OIDC-14 |
| 4 | 04-16 Theming backend | model use, service/branding.rs, anvil-web/src/theme.rs (CSS/logo routes, cache), base.html link, validators, admin/branding.rs + preview token + ui/preview.rs, OpenAPI regen (only OpenAPI plan in wave 4) | UI-03 |
| 5 | 04-17 Console: connections + client logout/resource/MFA fields | admin-ui routes/connections, ClientForm | AUTH-07, UI |
| 5 | 04-18 Console: theme editor + live preview | admin-ui routes/branding (iframe, debounce, contrast warnings) | UI-03 |
| 5 | 04-19 Conformance green: logout + backchannel in `all`, CI workflow | tests/conformance/*, .github/workflows/conformance.yml | OIDC-12 |
| 5 | 04-20 Upstream login flow + linking | flow/upstream.rs, service/upstream.rs, ui/upstream.rs, login.html buttons, Lax binding cookie, callback CSRF exemption, PendingLink confirm, JIT create | AUTH-07/11 |
| 6 | 04-21 Linked identities on account page | ui/account_linked.rs, connect via settings flow, unlink guard | AUTH-11/13 |
| 6 | 04-22 Second language (de) + completeness check + locale e2e | locales/de, i18n tests | UI-04 |
| 6 | 04-23 Email OTP + magic link | flow/email_code.rs, ui/email_code.rs, login.html method, EmailKind::LoginCode template, limiter keys | AUTH-06 |
| 7 | 04-24 e2e: mock-idp.ts, social (AnvilID-as-upstream, Apple-like form_post cross-site, GitHub-like), logout + back-channel via sample RP, email OTP/magic link via Mailpit, theming live preview, i18n, MFA required/step-up, account pages; axe on new pages | tests/e2e/*, examples/node-rp logout support | all |
| 7 | 04-25 Docs: manual provider checklist, UPGRADING 0.2→0.3, ARCHITECTURE (§6.1 rp_session, §10, §11 SSRF row, §18 M3 exit wording), theme README contract (logout ids/sentences), OpenAPI docs | docs/* | all |
| 8 | 04-26 Gate: QUAL-01 map (SSRF now mapped; all new controls), `just ci`, e2e both backends, conformance all, release 0.3.0 + released-migrations manifest | scripts/check-security-tests.sh, release | all |

The critical path is 04-01 → 04-04/05 → 04-15 → 04-20 → 04-23 → 04-24 → 04-26. Other tracks fill waves 2–6 in parallel. Plan numbering is indicative.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `cargo test` (unit, contract via `storage_contract_tests!`, HTTP integration in `anvil-web/tests`, binary tests in `anvilid/tests`), proptest, insta snapshots, wiremock; Playwright (tests/e2e, chromium + nojs projects); OpenID conformance suite release-v5.3.5 (tests/conformance) |
| Config file | `justfile`, `tests/e2e/playwright.config.ts`, `tests/conformance/config.template.json`, `scripts/check-security-tests.sh` |
| Quick run command | `cargo test -p anvil-core --lib` / `cargo test -p anvil-web --test <file>` |
| Full suite command | `just ci` (fmt, clippy, deny, deps, migrations-check, test, test-pg, release-graph, security-tests, console-check) + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OIDC-12 | end-session decision table (hint valid/invalid/alg none/foreign key, URI exact/query-added, no hint + URI, client_id path, idempotent) | unit (pure) | `cargo test -p anvil-core oauth::logout` | ❌ Wave 2 |
| OIDC-12 | `/logout` GET+POST, confirm flow CSRF, no redirect on errors, state echoed, prompt=none fails afterwards | integration | `cargo test -p anvil-web --test logout` and `--test security_logout` | ❌ |
| OIDC-12 | logout token exact claims, typ, no nonce, sign at send; delivery 200/204 ok, 400 no retry, 5xx retry; every revoking intent enqueues | unit + contract + integration (wiremock RP) | `cargo test -p anvil-core logout_token`; `cargo test -p anvil-storage-sqlite --test contract logout`; `cargo test -p anvil-web --test backchannel` | ❌ |
| OIDC-12 | conformance RP-Initiated + Back-Channel plans | conformance | `tests/conformance/run.sh logout && tests/conformance/run.sh backchannel` | ❌ (04-03/04-19) |
| OIDC-14 | prompt create (per-tenant advert, invalid_request otherwise), select_account (switch revokes old session), login_hint prefill, acr step-up upgrades session, essential acr unmet | unit + integration | `cargo test -p anvil-core decision mfa`; `cargo test -p anvil-web --test authorize_prompt` | ❌ |
| OIDC-16 | multi-valued resource accepted only for `resource`; invalid_target (not allowed, fragment, relative); downscoping on code/refresh/cc; aud string vs array; introspection aud; UserInfo aud rule | unit + integration | `cargo test -p anvil-core oauth::resource`; `cargo test -p anvil-web --test resource_indicators` | ❌ |
| AUTH-06 | code single-use, 5-attempt cap, TTL, HMAC at rest; link consumed only on POST; cross-browser POST fails; enumeration-identical responses; send limits | unit + integration + e2e | `cargo test -p anvil-web --test flow_email_code` / `--test security_email_code`; `tests/e2e/run.sh sqlite specs/email-code.spec.ts` | ❌ |
| AUTH-07 | each provider adapter vs its wiremock (discovery, JWKS cache/refresh, iss rules incl. Google/MS, aud/azp, nonce, exp, alg none/HS256 rejected, Apple form_post + string email_verified + first-login user JSON, GitHub verified primary only) | integration | `cargo test -p anvil-web --test upstream_google` (…microsoft, apple, github, oidc, oauth2) | ❌ |
| AUTH-07 | browser round trip through AnvilID-as-upstream and Node mock (cross-site) | e2e | `tests/e2e/run.sh sqlite specs/social.spec.ts` | ❌ |
| AUTH-07 | real providers | manual | `docs/social-login-checklist.md` (owner, pre-release) | ❌ |
| AUTH-08 | mfa_requirement table exhaustive; Required → enrolment; Off skips TOTP; client override; amr/acr in ID token | unit + integration + e2e | `cargo test -p anvil-core policy::mfa`; `cargo test -p anvil-web --test flow_mfa_policy`; `specs/mfa-policy.spec.ts` | ❌ |
| AUTH-11 | link_decision exhaustive; no link on unverified (upstream or local); Microsoft never auto; existing link wins over email; unlink last-method guard; enumeration on link page | unit + integration | `cargo test -p anvil-core upstream::linking`; `cargo test -p anvil-web --test security_linking` | ❌ |
| AUTH-13 | profile edit, email change (token to new, notice to old, conflict, re-auth required, POST-only), password change (re-auth, policy, breach, sessions revoked) | contract + integration + e2e | `cargo test -p anvil-storage-sqlite --test contract email_change`; `cargo test -p anvil-web --test account_profile`; `specs/account.spec.ts` | ❌ |
| UI-03 | token validation (colors, radius, font), CSS validator rejects @import/url()/backslash/oversize, contrast warnings, merge precedence, CSS route hashed + immutable, logo sniffing, preview frame-ancestors only on preview | unit + integration + e2e | `cargo test -p anvil-core branding`; `cargo test -p anvil-web --test theme` / `--test security_theme`; `specs/theme.spec.ts` | ❌ |
| UI-04 | negotiation order (ui_locales > Accept-Language > tenant default > en), every locale has every en id, fallback for missing ids, lang/dir attributes, plural forms | unit + integration + e2e | `cargo test -p anvil-web i18n`; `cargo test -p anvil-web --test i18n`; `specs/i18n.spec.ts` | ❌ |
| SEC-03 | connection secret sealed (AAD bound: wrong tenant/row fails), never in plaintext on disk, write-only API | unit + storage plaintext + integration | `cargo test -p anvil-storage-sqlite --test plaintext`; `cargo test -p anvil-web --test admin_connections` | ✅ plaintext.rs exists (extend) / ❌ admin test |
| SSRF (cross-cutting) | guard blocks literal private IPs, mapped IPv6, private DNS answers, redirects, http without allow-list; allow-list + CA file work | unit + integration | `cargo test -p anvil-web outbound`; `cargo test -p anvil-web --test security_ssrf` | ❌ |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate> --lib` plus the specific `--test <file>` touched (< 30 s each).
- **Per wave merge:** `just ci` (includes `test-pg` and the security map).
- **Phase gate:** `just ci` green, `tests/e2e/run.sh sqlite` + `postgres` green, `tests/conformance/run.sh all` (now five plans) green with `expected-failures.json = []`, before `/gsd:verify-work`.

### Wave 0 Gaps
- [ ] `crates/anvil-storage/src/contract/{connections,identity_links,rp_sessions,logout_deliveries,branding}.rs` + extensions to users.rs (email change) and sessions.rs (enqueue on revoke, upgrade_auth): 04-01
- [ ] `crates/anvil-web/tests/support` helpers: create connection, mock-provider builder (wiremock + test signing keys), logout helpers
- [ ] `tests/e2e/lib/mock-idp.ts` (Node, zero dependencies) and e2e helpers for a second tenant as upstream
- [ ] `examples/node-rp`: RP-initiated logout link + back-channel endpoint (for e2e)
- [ ] `tests/conformance`: logout/backchannel selections, CA/leaf generation, nginx cert mount, browser overrides
- [ ] `scripts/check-security-tests.sh`: entries for every new control (SSRF now mapped; remove the "not mapped" note)
- [ ] Fluent deps in `[workspace.dependencies]` (04-01) and `cargo deny` pass

## Sources

### Primary (HIGH confidence)
- Local codebase at `7a3b01a`: `anvil-core` ports/model/flow/oauth/services, `anvil-web` adapters/layers/render/protocol/ui, both migration sets, `themes/default`, `tests/conformance`, `tests/e2e`, `.planning/STATE.md`, docs/ARCHITECTURE.md, docs/PRD.md
- OpenID conformance suite source at tag `release-v5.3.5` (local `./suite` object store): `OIDCCRpInitiatedLogoutTestPlan`, `OIDCCBackchannelRpInitiatedLogoutTestPlan`, `AbstractOIDCCRpInitiatedLogout`, all logout modules, `ValidateLogoutTokenClaims`, `CheckForUnexpectedParameters*`, `CreateEndSessionEndpointRequest`, `nginx/Dockerfile`, `nginx/nginx.conf`, `.gitlab-ci/local-provider-oidcc-conformance-config.json`, `.gitlab-ci/run-tests.sh`
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html): claims, typ, metadata, responses, retries (Final, errata 2023-12-15)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): parameters, confirmation, redirect rules (Final 2022-09-12)
- [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html): `prompt=create` (Final 2022-12-02)
- [Apple: Request an authorization to the Sign in with Apple server](https://developer.apple.com/tutorials/data/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server..md): form_post, user JSON first time only
- [GitHub changelog: PKCE support for OAuth and GitHub App authentication (2025-07-14)](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/)
- crates.io API (2026-11-25): versions and dependency lists for openidconnect 4.1.0, oauth2 5.0.0, fluent-bundle 0.16.0, fluent-langneg 0.14.2, fluent-templates 0.15.1, reqwest 0.13.5
- [reqwest 0.13.5 ClientBuilder docs](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html), [Resolve trait](https://docs.rs/reqwest/0.13.5/reqwest/dns/trait.Resolve.html)

### Secondary (MEDIUM confidence)
- [Microsoft: Migrate away from using email claims](https://learn.microsoft.com/en-nz/entra/identity-platform/migrate-off-email-claim-authorization), [Optional claims reference (xms_edov)](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference), [Semperis nOAuth analysis](https://www.semperis.com/blog/noauth-abuse-alert-full-account-takeover/), [Okta: Saying "No Thanks" to nOAuth](https://sec.okta.com/articles/2023/08/saying-no-thanks-noauth/)
- [Microsoft Q&A on the `{tenantid}` issuer template](https://learn.microsoft.com/en-au/answers/questions/38386/azure-app-registration-and-gitea-oauth2-issuer-pro), [ID tokens in the Microsoft identity platform](https://learn.microsoft.com/entra/identity-platform/id-tokens)
- Apple client-secret JWT claims (Apple docs page body not retrievable; consistent with long-standing documentation and [Scott Brady's guide](https://www.scottbrady.io/openid-connect/implementing-sign-in-with-apple-in-aspnet-core))
- [fluent_bundle::concurrent](https://docs.rs/fluent-bundle/0.16.0/fluent_bundle/concurrent/index.html) (type alias confirmed; method set from stable API)

### Tertiary (LOW confidence, flagged for validation)
- Apple PKCE support (conflicting third-party reports; treat as unsupported)
- Status of `xms_edov` (possibly being deprecated; irrelevant if Microsoft is never auto-linked)
- `unmet_authentication_requirements` spec status
- Exact plan variant string for the logout plans with static clients (verify on first harness run)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Existing workspace deps; new Fluent crates verified on crates.io; OIDC crate rejection verified from dependency lists.
- Architecture: HIGH. Derived from the actual 0.2 code (ports, cookies, CSP, migrations, flow engine).
- Logout/conformance: HIGH. Read from suite source at the pinned tag; the variant string is MEDIUM.
- Provider quirks: MEDIUM. Google/GitHub HIGH; Microsoft MEDIUM-HIGH; Apple MEDIUM/LOW. The manual checklist covers the rest.
- Pitfalls: HIGH for codebase-derived ones (SameSite, CHECK constraints, duplicate-parameter rule, OpenAPI regen); MEDIUM for SSRF edge cases (standard knowledge).

**Research date:** 2026-11-25
**Valid until:** 2026-12-25 (provider behaviours and the suite tag can change; re-check the suite tag before bumping `CONFORMANCE_TAG`)
