---
phase: 04-release-0-3-real-world-logins
plan: 03
subsystem: e2e-infrastructure
tags: [e2e, playwright, mock-idp, apple, github, logout, backchannel, sample-rp]
requires: []
provides:
  - "tests/e2e/lib/mock-idp.ts: startMockIdp({kind: 'apple'|'github', clientId, redirectUri, clientSecret?, appleClientKeyJwk?, appleKeyId?, appleTeamId?, users?}) -> {url, clientSecret, users, authorizations, jwks, selectUser, stop}"
  - "tests/e2e/lib/mock-idp.ts: mockIdpRedirectUri, signEs256Jwt, decodeJwt, verifyEs256Jwt, Jwk type"
  - "tests/e2e/lib/upstream.ts: createUpstreamTenant(token, slug, downstreamRedirectUri), createConnection(token, tenant, body), appleKeyPair(), appleClientSecret(), tenantIssuer(), randomSlug()"
  - "tests/e2e/lib/logout.ts: endSessionUrl(issuer, {...}), backchannelReceived(rpUrl, sub?), waitForBackchannel(rpUrl, sub, timeoutMs)"
  - "examples/node-rp: GET /logout, GET /logged-out, POST /backchannel_logout, GET /backchannel_logout/received"
  - "tests/e2e/run.sh: default = every specs/*.spec.ts (a11y first, qual04 excluded)"
affects: [04-11, 04-14, 04-21, social/logout e2e specs]
tech-stack:
  added: []
  patterns:
    - "Mock IdP bound to 127.0.0.1 while AnvilID runs on localhost (cross-site, real SameSite behaviour)"
    - "Mock and logout-token verification use node:crypto only; keys generated at runtime"
key-files:
  created:
    - tests/e2e/lib/mock-idp.ts
    - tests/e2e/lib/mock-idp-cli.ts
    - tests/e2e/lib/upstream.ts
    - tests/e2e/lib/logout.ts
    - tests/e2e/specs/mock-idp.spec.ts
  modified:
    - examples/node-rp/server.js
    - examples/node-rp/README.md
    - tests/e2e/run.sh
decisions:
  - "Sample RP verifies logout tokens with node:crypto against the issuer JWKS (RS256/PS256/ES256/Ed25519 intersected with the issuer's advertised algs); jose is only a transitive dependency of openid-client, so it is not imported"
  - "run.sh default glob excludes qual04.spec.ts (driven by scripts/qual04.sh; it would consume the setup token)"
  - "end_session_endpoint assumed at {issuer}/logout (research); upstream callback {issuer}/ui/login/upstream/{slug}/callback"
metrics:
  duration: 25min
  completed: 2026-11-25
---

# Phase 4 Plan 03: E2E infra (mock IdP, helpers, sample RP logout) Summary

A zero-dependency Node mock IdP covers Apple and GitHub. Apple-like: form_post, ES256 ID tokens with string `email_verified`, user JSON only on first authorization, and an ES256 client-secret check with aud equal to the mock URL. GitHub-like: the token format depends on the Accept header, errors come back as HTTP 200, PKCE is S256, and the API requires a User-Agent. The plan also adds upstream/logout helpers, a self-test spec, RP-initiated and verifying back-channel logout in the sample RP, and a spec-glob default in run.sh.

## Mock API

`startMockIdp(opts)` binds `127.0.0.1:0` and returns `{ url, kind, clientId, clientSecret, users, authorizations, jwks, selectUser(subOrEmail), stop() }`. Every request is appended to `authorizations` (`endpoint, method, params` with secrets redacted, `status, error, sub, userSent, pkce, userAgent, accept`). Signing keys come from `generateKeyPairSync` at start-up and are never written to disk.

### Apple-like quirks (`/auth/authorize`, `/auth/token`, `/auth/keys`)
- client_id and redirect_uri must match exactly. `response_mode=form_post` is required when the scope contains `name` or `email`.
- The approval page has a `#mock-continue` button inside a `method=post` form aimed at redirect_uri. The form carries `code`, `state`, `id_token` (with c_hash) and, only on the first authorization per subject, a `user` JSON field (`{"name":{"firstName","lastName"},"email"}`). Works without JS.
- Token endpoint: `client_secret` must be an ES256 JWT verified against `appleClientKeyJwk`, with kid matching, `iss` equal to the team id (if `appleTeamId` is set), `sub` equal to client_id, `aud` equal to the mock base URL, exp in the future and iat not in the future. Anything else returns `invalid_client`. Client auth is checked before the code, so rejected attempts don't consume it. Codes are single-use and bound to client and redirect_uri. Without a client key the endpoint fails closed.
- ID token: ES256, `iss` = mock URL, `aud`, `sub`, `nonce`, `email`, plus `email_verified` and `is_private_email` as STRINGS, and `at_hash` in the token response.

### GitHub-like quirks
- `/login/oauth/authorize`: optional PKCE (S256 only). The `#mock-continue` link goes to redirect_uri with code and state.
- `/login/oauth/access_token`: client credentials can come in the body or via Basic auth. The response is JSON only when the request sends `Accept: application/json`, form-encoded otherwise. Errors (`incorrect_client_credentials`, `bad_verification_code`, `redirect_uri_mismatch`) come back as HTTP 200 with an `error` member. The PKCE verifier is required whenever a challenge was sent. Codes are single-use.
- `/user` and `/user/emails` answer 403 without a User-Agent and 401 with a bad token. `/user` returns a numeric `id` and `email: null`. `/user/emails` returns one primary verified address, one verified non-primary and one unverified, or `MockUser.emails` when that override is set.

## Sample RP endpoints
- `GET /logout`: clears the local login, stores a random state, then redirects (via `client.buildEndSessionUrl`) to `end_session_endpoint` with `id_token_hint`, `post_logout_redirect_uri={BASE_URL}/logged-out`, `state` and `client_id`. Returns 501 if the endpoint isn't advertised.
- `GET /logged-out`: compares state in constant time and shows "Signed out of the sample app". A mismatch gets 400.
- `POST /backchannel_logout`: accepts urlencoded `logout_token` only. It checks the alg allow-list (no none/HMAC), `typ` logout+jwt if present, the signature against the JWKS (refetched on unknown kid at most every 10 s), `iss`, `aud`, `iat` within 5 min, `exp` if present, `jti`, the backchannel event, absence of `nonce`, and that `sub` or `sid` is present. A replayed jti gets 400. On success it records `{sub, sid, jti, received_at}`, ends matching sessions (by sid, else sub) and returns 200. Every failure is a 400 with an empty body.
- `GET /backchannel_logout/received?sub=`: JSON list (sample-only debugging endpoint, documented in README).

## Verification
- `npx tsc --noEmit` (tests/e2e): passes.
- `npx playwright test specs/mock-idp.spec.ts --project=chromium`: 5/5 pass in about 2 s, no AnvilID needed.
- `node --check examples/node-rp/server.js`, `bash -n tests/e2e/run.sh`, and `grep 'specs/\*.spec.ts'` all pass.
- Back-channel endpoint checked ad hoc with a scratch discovery/JWKS server. A valid token and a sid-only token were accepted (200). These were all rejected with 400: replay, nonce, empty events, wrong aud, wrong iss, no sub/sid, typ JWT, alg none, bad signature, a token 1 h old, and a JSON body.
- No real provider hostnames in tests/e2e lib/specs/run.sh.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Default spec glob would have run qual04.spec.ts**
- **Found during:** Task 2
- **Issue:** The old hard-coded list left out `qual04.spec.ts`, which needs QUAL04_CLIENT_FILE and consumes the single-use setup token. A naive glob would have broken the suite.
- **Fix:** The glob excludes qual04 (and puts a11y first). The header comment documents this.
- **Files modified:** tests/e2e/run.sh
- **Commit:** 03c8bfe

**2. [Rule 3 - Blocking] Logout token verification without importing transitive jose**
- **Found during:** Task 2
- **Issue:** The plan suggested "openid-client/jose helpers already in the RP's dependencies". However, `jose` is only a transitive dependency, and openid-client 6 has no generic JWT verifier.
- **Fix:** Verification uses `node:crypto` (`createPublicKey({format:'jwk'})` + `crypto.verify`). No package.json change.
- **Commit:** 03c8bfe

Other notes: package.json already had a `typecheck` script, so it was not modified. `createUpstreamTenant` takes the admin token and the downstream redirect URI as extra parameters, because the helpers hold no credentials.

## Self-Check: PASSED
- FOUND: tests/e2e/lib/mock-idp.ts, mock-idp-cli.ts, upstream.ts, logout.ts, specs/mock-idp.spec.ts
- FOUND: commits a872073, 03c8bfe
