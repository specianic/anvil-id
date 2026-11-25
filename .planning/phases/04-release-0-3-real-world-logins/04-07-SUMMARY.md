---
phase: 04-release-0-3-real-world-logins
plan: 07
subsystem: core
tags: [upstream, federation, oidc, oauth2, apple, microsoft, google, github, account-linking, proptest]

requires:
  - phase: 04-release-0-3-real-world-logins
    provides: "04-01 Connection/ConnectionConfig/SocialConfig/ClaimMapping/IdentityLink model, ProviderMetadata/TokenEndpointAuth/ApiProfile ports, pre-declared upstream modules"
provides:
  - "upstream::providers::resolve(&Connection, Option<&ProviderMetadata>) -> ResolvedProvider (incl. apple_audience)"
  - "APPLE_ISSUER, apple_client_secret_claims(team, services_id, audience, now), authorization_url(...)"
  - "upstream::claims::validate_id_token + UpstreamTokenError + UpstreamIdentity + normalise_{oidc,apple,github,oauth2}"
  - "upstream::linking::link_decision(&LinkInputs) -> LinkDecision"
affects: [04-14, 04-21]

tech-stack:
  added: []
  patterns:
    - "Upstream security rules are pure functions; email_verified is AND-ed with connection trust at normalisation so callers cannot link on untrusted email"

key-files:
  created: []
  modified:
    - crates/anvil-core/src/upstream/mod.rs
    - crates/anvil-core/src/upstream/providers.rs
    - crates/anvil-core/src/upstream/claims.rs
    - crates/anvil-core/src/upstream/linking.rs

key-decisions:
  - "UpstreamTokenError adds UnknownKey (service refreshes JWKS once) and HostedDomain (Google hd) to the planned variants"
  - "Microsoft tid must be a canonical lowercase hyphenated UUID (braced/urn/uppercase rejected) and is checked for every Microsoft token, also single-tenant Exact issuers"
  - "An issuer override replaces the preset issuer rule with Exact(override); a Microsoft override containing {tenantid} stays a template"
  - "Apple user JSON contributes names only; email always comes from the signed ID token"
  - "Presets accept RS256 only; resolve validates every endpoint as an absolute http(s) URL so authorization_url is infallible"
  - "Any present azp must equal client_id (not only with several audiences)"

requirements-completed: []

duration: 25min
completed: 2026-11-25
---

# Phase 4 Plan 07: Pure Upstream Federation Logic Summary

**Provider presets and endpoint resolution, fixed-order upstream ID-token validation, per-provider claim normalisation with trust-gated email_verified, the Apple client-secret claim set with an explicit audience, and the account-linking decision. All of it is pure anvil-core code covered by 64 unit tests and proptests.**

Note: AUTH-07 and AUTH-11 depend on this plan, but neither is delivered until the adapter (04-14) and the service (04-21) land. No requirement checkbox was ticked.

## Performance

- **Duration:** about 25 min
- **Completed:** 2026-11-25
- **Tasks:** 1 TDD feature (RED and GREEN commits)
- **Files modified:** 4

## Public API

### providers.rs
- `pub const APPLE_ISSUER = "https://appleid.apple.com"`, `GOOGLE_ISSUER`, `MICROSOFT_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0"`, `TENANT_PLACEHOLDER`, `GITHUB_API_BASE`, `SUPPORTED_ID_TOKEN_ALGS`, `APPLE_CLIENT_SECRET_TTL_SECS = 300`
- `enum Protocol { Oidc, OAuth2 }`, `enum IssuerRule { Exact(String), Google, MicrosoftTemplate(String) }`, `enum ResponseMode { Query, FormPost }`
- `struct ResolvedProvider { kind, protocol, authorization_endpoint: Url, token_endpoint, userinfo_endpoint: Option, jwks_uri: Option, issuer_rule: Option<IssuerRule>, allowed_algs: Vec<Alg>, scopes, use_pkce, response_mode, token_auth: TokenEndpointAuth, email_trusted, api_profile: ApiProfile, api_base_url: Option, apple_audience: Option, allowed_tenants, hosted_domains }`
- `fn resolve(&Connection, Option<&ProviderMetadata>) -> Result<ResolvedProvider, CoreError>`
- `fn apple_client_secret_claims(team_id, services_id, audience: &str, now) -> Map` (exactly iss, sub, aud, iat, exp = iat + 300)
- `fn authorization_url(&ResolvedProvider, client_id, redirect_uri, state, nonce, code_challenge, login_hint) -> Url`

| Preset | Protocol | Issuer rule | Scopes | PKCE | Token auth | Notes |
|---|---|---|---|---|---|---|
| Google | Oidc | Google (both forms) | openid email profile | on | Basic | hd allow-list (lowercased) |
| Microsoft | Oidc | common/organizations/consumers: Template; UUID tenant: Exact | openid email profile | on | Basic | email_trusted always false; allowed_tenants lowercased |
| Apple | Oidc | Exact(apple_audience) | name email | off | Post | FormPost when name/email requested; requires `apple` config |
| GitHub | OAuth2 | none | read:user user:email | on | Post | userinfo `{api}/user`, ApiProfile::Github |
| Generic OIDC | Oidc | Exact(config.issuer) | openid is always included | config | Basic | requires metadata, issuer must match, algs = metadata ∩ {RS256, PS256, ES256, Ed25519}, empty intersection is an error |
| Generic OAuth2 | OAuth2 | none | config | config | Basic | |

### claims.rs
- `enum UpstreamTokenError { Signature, UnknownKey, Issuer, HostedDomain, Audience, Expired, IssuedInFuture, Nonce, MissingClaim(&'static str) }`. Display is fixed text.
- `struct UpstreamIdentity { subject, email, email_verified, given_name, family_name, name, metadata }`
- `fn validate_id_token(token, &Jwks, &ResolvedProvider, client_id, expected_nonce, now) -> Result<Map, UpstreamTokenError>`. Checks run in this order: allow-list and signature, then iss (plus Microsoft tid and Google hd), then aud/azp, then exp > now-60, iat <= now+60 and nbf, then nonce, then a non-empty sub.
- `normalise_oidc(&claims, &ResolvedProvider, trust)`: only a strict boolean `true` counts. Metadata keeps Microsoft tid/oid and Google hd.
- `normalise_apple(&claims, Option<&str>, trust)`: accepts a boolean or the strings "true"/"false". Names come from the user JSON, trimmed, with control characters stripped and at most 200 characters per part. Malformed user JSON is ignored.
- `normalise_github(&user, &emails, trust)`: the subject is the numeric `id` as a string. The email comes only from an entry that is both primary and verified. Metadata keeps `login`.
- `normalise_oauth2(&profile, &ClaimMapping, trust)`: the subject must be a non-empty string or an integer. email_verified requires a mapped boolean `true` and trust.
- Emails are dropped unless the address has exactly one `@`, no whitespace or control characters, and at most 320 characters.

### linking.rs: decision table
| Existing link | Upstream email verified and trusted | Local match | Auto-link on | Kind | Decision |
|---|---|---|---|---|---|
| yes, active | any | any | any | any | SignIn(link.user_id) |
| yes, inactive | any | any | any | any | Refuse(Inactive) |
| no | yes | verified | yes | not Microsoft | AutoLink(user) |
| no | yes | any other case | | | PendingLink { candidate: Some(user) } |
| no | no | any | | | PendingLink { candidate: None } |
| no | any | none | registration allowed | | JitCreate { email_verified } |
| no | any | none | registration not allowed | | Refuse(NoAccount) |

Proptest invariants: an unverified email never produces AutoLink and never reveals a candidate. Microsoft never produces AutoLink. An existing active link always produces SignIn(link.user_id). AutoLink only happens with a verified local email and auto-link enabled.

## Task Commits

1. **RED**: `59736cf` test(04-07): failing tests (60 failed and 4 passed against placeholder bodies that return errors)
2. **GREEN**: `9ae3560` feat(04-07): implementation (64 of 64 upstream tests pass)

No separate refactor commit was needed. Each function was already kept small.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] Extra error variants `UnknownKey` and `HostedDomain`**
- `UnknownKey` lets 04-21 refresh the JWKS once (`force_refresh`) for an unknown `kid` instead of failing outright. `HostedDomain` keeps Google hd rejections distinct from issuer rejections.
- Commits: 59736cf, 9ae3560

**2. [Rule 2 - Security] Canonical-UUID tid and a tid check on every Microsoft token**
- `Uuid::try_parse` also accepts braced and urn forms. Substituting those into the template would make the issuer comparison depend on attacker-shaped strings, so only the lowercase hyphenated form is accepted. Single-tenant (Exact) Microsoft connections also require a valid tid and honour allowed_tenants.

**3. [Rule 2 - Security] Apple user JSON email ignored**
- The user JSON is unsigned form data. Only names are taken from it, and the email always comes from the validated ID token.

**4. Extra ResolvedProvider fields** (`kind`, `api_base_url`, `allowed_tenants`, `hosted_domains`). `issuer_rule` and `jwks_uri` are `Option` because plain OAuth2 never accepts an ID token: validate_id_token returns `Signature` when the allow-list is empty. `authorization_endpoint` is a `Url` validated in `resolve`, so `authorization_url` cannot fail.

**5. HS256 test uses fake signature bytes**
- anvil-core has no HMAC dependency, and adding one was out of scope. The test builds an HS256 header with the RSA modulus as signature bytes. That is enough because anvil-jose rejects the algorithm before key lookup or crypto, and the test asserts `Signature`.

## Verification
- `cargo test -p anvil-core --lib` passed (488 tests, including 64 upstream tests) in a clean worktree (target/wt-04-07 at 12685aa plus these files).
- `cargo clippy -p anvil-core --all-targets -- -D warnings` is clean.
- `cargo fmt -p anvil-core --check` is clean.
- `scripts/check-deps.sh` passes ("dependency rules OK"), so core stays pure. upstream/* has no I/O.
- Verification ran in a separate worktree because other wave-2 plans had in-progress anvil-core edits in the main tree. The worktree and its target dir were removed afterwards.

## Issues Encountered
- My first worktree base was 04-08's RED commit, where `oauth/resource.rs` failed clippy. I re-based the worktree on the current main (04-08 GREEN), where it passes. Nothing was changed in that file.

## Next Phase Readiness
- 04-14 (adapter) and 04-21 (service) can call `resolve`, `authorization_url`, `apple_client_secret_claims(…, resolved.apple_audience, …)`, `validate_id_token` (on `UnknownKey`, refetch the JWKS with force_refresh and retry once), the `normalise_*` functions and `link_decision`.

## Self-Check: PASSED
- All four files exist (claims.rs 1161 lines, linking.rs 359 lines, providers.rs 972 lines). Commits 59736cf and 9ae3560 are in the history.
