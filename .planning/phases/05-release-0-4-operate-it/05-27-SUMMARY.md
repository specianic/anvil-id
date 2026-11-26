---
phase: 05-release-0-4-operate-it
plan: 27
subsystem: e2e-and-docs
tags: [playwright, e2e, webhooks, dcr, rbac, attributes, docs, operations, upgrading]

requires:
  - phase: 05-release-0-4-operate-it
    provides: attributes (05-19), webhooks (05-14), DCR (05-21), RBAC claims (05-12), admin API bundle (05-23), observability (05-05), Redis limiter (05-08/05-16), Helm/Compose (05-22)
provides:
  - Browser e2e for account attributes, signed webhooks after UI sign-up/sign-in, DCR under each policy, role/permission claims
  - Loopback webhook sink verifying Standard Webhooks v1 signatures (tests/e2e/lib/webhook-sink.ts)
  - docs/WEBHOOKS.md integrator guide
  - 0.3 -> 0.4 upgrade notes, 0.4 operations guide, ARCHITECTURE Phase 5 divergences, README 0.4 feature list
affects: [05-28]

tech-stack:
  added: []
  patterns:
    - "Code-flow e2e client tolerates a redirect straight to an unrouted redirect URI (Playwright routes only the first request of a redirect chain)"

key-files:
  created:
    - tests/e2e/lib/webhook-sink.ts
    - tests/e2e/lib/code-flow.ts
    - tests/e2e/lib/admin-api.ts
    - tests/e2e/specs/attributes.spec.ts
    - tests/e2e/specs/webhooks.spec.ts
    - tests/e2e/specs/dcr.spec.ts
    - tests/e2e/specs/rbac-claims.spec.ts
    - docs/WEBHOOKS.md
  modified:
    - docs/OPERATIONS.md
    - docs/UPGRADING.md
    - docs/ARCHITECTURE.md
    - README.md
    - .planning/phases/05-release-0-4-operate-it/deferred-items.md

key-decisions:
  - "rbac-claims reads tokens through a minimal code+PKCE client (lib/code-flow.ts) because the sample RP has no token view and examples/ is not in this plan's files"
  - "Two shared helpers added beyond webhook-sink.ts (code-flow.ts, admin-api.ts) so specs do not duplicate a token client and an admin call"
  - "Docs state the webhook payload's data.tenant is the tenant id (actual behaviour), not the slug"
  - "DCR/CIMD policy rules documented in OPERATIONS.md (operator reference); MCP.md (05-25) covers the integrator side and is linked"

requirements-completed: []

duration: ~1h
completed: 2026-11-26
---

# Phase 5 Plan 27: Feature e2e and the 0.4 docs pass Summary

**Four Playwright specs prove the non-console 0.4 journeys in a real browser (all 7 tests passed in a local run against a debug build). The 0.4 docs now match what Phase 5 built: a new WEBHOOKS.md, a 0.3 → 0.4 upgrade section, an operations guide for HA/Redis/metrics/OTel/drain/registration policies, the ARCHITECTURE divergences, and a README feature list.**

No REQUIREMENTS.md checkbox was ticked (wave rule).

## Task 1: Feature e2e (commit dc6221f)

| Spec | What it proves |
|---|---|
| `attributes.spec.ts` (2 tests) | Admin defines `department` (user-editable enum, claim `department` in the ID token) and `cost_center` (admin-only) through the API. The user sees only the editable one, saves `sales` (`attributes.saved`, stored value checked through the admin API, admin value kept). A tampered option is refused with `attributes.invalid`, `#attr-department-error` and `aria-invalid`, and nothing changes. The claim appears in the ID token of a code flow. A no-JS context (`javaScriptEnabled: false`) saves and clears the value |
| `webhooks.spec.ts` | Sink on 127.0.0.1. Endpoint created via API (secret `whsec_…` once; the view shows only `secret_configured`). UI registration, then UI sign-in, deliver `user.created` and `session.created` with the user's id. Every delivery's signature is verified with node:crypto, no `@`, email or IP in the body, `data` keys are restricted to the ids-only set, and there are no unsubscribed types. The delivery log shows both as `delivered` |
| `dcr.spec.ts` (3 tests) | `open`: discovery advertises `registration_endpoint`, 201 with `no-store`, RFC 7592 read without secret, admin view `registration_source: dynamic`, sign-in through the consent screen, ID token aud/iss, email via UserInfo. `allow_listed`: 401 `invalid_token` without or with a bogus token; a single-use IAT survives a refused wrong-host request (400 `invalid_redirect_uri`), registers once, then 401. `disabled`: 404, not advertised; RFC 7592 GET 404 after disabling again; `system` 404 |
| `rbac-claims.spec.ts` | Roles `editor`/`viewer` via API. With scope `roles`: AT `roles: [editor]`, `permissions` sorted, ID token roles and no permissions. Swapping the role and refreshing gives `[viewer]`/`[docs:read]`. Without `roles`: no roles claim, permissions still present |

Helpers: `lib/webhook-sink.ts` (sink, `signWebhook`, `verifyWebhook` with timestamp tolerance and constant-time compare), `lib/code-flow.ts` (code + PKCE client returning the whole token response, refresh, `jwtClaims`), `lib/admin-api.ts` (generic admin call). Each test uses a fresh tenant and deletes it.

## Task 2: Documentation (commit 91a38c9)

- **docs/WEBHOOKS.md (new):** management routes, events table with `data` ids, payload (tenant **id**), headers, verification algorithm with Node and Python samples, at-least-once delivery, dedupe on `webhook-id`, the 410/retry table and schedule, `Retry-After`, 24 h rotation with dual signatures, operating notes.
- **docs/OPERATIONS.md:** contents line plus new sections:
  - 0.4 config keys table: every key checked against `anvilid config show`.
  - Health, readiness and drain (aliases, `503 draining`, choosing a drain value).
  - HA on Postgres: stateless nodes, shared KEK, concurrent first start, LB checks, **no retries of non-idempotent POSTs** and why, pool sizing, background work, per-node limits without Redis.
  - Redis: key hashing, startup failure, breaker, closed/local failure-mode table (429 on the `auth` class).
  - Metrics names and labels, OTel (base URL + `/v1/traces`, `OTEL_EXPORTER_OTLP_HEADERS`, trusted `traceparent`), logs.
  - Outbound policy, with operator infrastructure exempt (OTLP, Redis, healthcheck, Postgres, SMTP).
  - The 5 s host negative cache.
  - DCR/CIMD rules: defaults, allow-list syntax, IAT bounds, informational URIs neither stored nor echoed, soft `max_clients`, the `auth` rate class, CIMD cache bounds, per-host installation-wide budget, `dcr.allowed_resources` for CIMD, `jwks_uri` limitation.
  - Helm/Compose and CONFIG-YAML pointers, 0.4 limitations.
- **docs/UPGRADING.md "0.3 to 0.4":**
  - Migrations (SQLite 0007, Postgres 0006) and the administrator backfill.
  - Behaviour changes: role-bounded console scopes (new system users need a role), role/permission claims, a consent re-prompt for resource-requesting clients, sessions surviving the upgrade (no cookie change in Phase 5: `git log` on cookies.rs is empty), 413, health aliases, the host cache, passkey enrolment, the log format, discovery, the admin API.
  - New keys and defaults, including Redis fail-closed and drain.
  - Limitations: `jwks_uri`, KEK rotation, tenant id in payloads.
  - Helm `database.type` and Redis for replicas > 1.
  - What to configure next.
- **docs/ARCHITECTURE.md:**
  - §2: telemetry compiled in, Redis limiter backend, jsonschema and serde-saphyr rows.
  - §3: Redis behaviour.
  - §6.1: no `client_metadata_cache` (CIMD materialised in `client`), plus role/attribute/webhook/IAT rows and a 0.4 migration paragraph.
  - §10.1: `/register*`.
  - §10.3: the 0.4 admin resources and RBAC admin scopes.
  - §10.5: aliases, drain and the metrics listener.
  - §11: SSRF row (webhooks/CIMD added, operator infrastructure exempt), `/register` in the auth class, and new DCR/CIMD/webhooks/RBAC rows with their negative-test files.
  - §13: 0.4 keys and the CLI as built.
  - §14: the webhook worker.
  - §15: as built.
  - §18: M4 status with evidence pointers. Historical paragraphs are kept.
- **README.md:** a "Coming in 0.4" list with links, and doc links.

## Verification

- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- **Local browser run without Docker:** the debug `anvilid` (built in the main tree) was copied to a scratch dir and run with the run.sh flags (fresh data dir, `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=1200`, `--breach-check off`, no SMTP), then `playwright test` ran on the four specs. **7/7 passed**. The scratch dir and process were removed afterwards.
- The plan's docs verify command (`config show` keys present in OPERATIONS.md, `webhook-signature` in WEBHOOKS.md, `0.4` in UPGRADING.md): OK. All 8 Phase 5 keys from `config show` appear in OPERATIONS.md.
- A link check over README/OPERATIONS/UPGRADING/WEBHOOKS/ARCHITECTURE found no broken relative links or anchors. MCP.md (05-25) exists and agrees on `jwks_uri`, `dcr.allowed_resources` and the per-host budget.
- Facts checked against code: OTLP path appending (`telemetry::traces_url`), the exporter reading `OTEL_EXPORTER_OTLP_HEADERS` (opentelemetry-otlp 0.33.1), `status_class` values, metric names (`observability.rs`), backend error labels (`limiter/redis.rs`), webhook event mapping and payload keys (`policy/webhook_event.rs`), migration file names and columns, logs on stderr.

## Not run

- `tests/e2e/run.sh sqlite|postgres` itself: it needs Docker (Mailpit, Postgres). With Mailpit present, the webhook spec's registration also sends a verification email, which does not affect the assertions. CI runs both backends.
- The Postgres backend for these specs (CI).

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 3 - Blocking] The sample RP has no token view**
- The plan says "roles + permissions in the access token via the sample RP's token view". `examples/node-rp` shows only sub/email, and examples/ is not in this plan's files.
- rbac-claims uses a minimal code + PKCE client (`lib/code-flow.ts`) that reads the token response directly.

**2. [Rule 3 - Blocking] Forced extra helper files**
- `tests/e2e/lib/code-flow.ts`: attributes, DCR and RBAC all need a code flow with a custom scope and the full token response. `lib/account.ts` `signInForIdToken` has a fixed scope, returns only ID-token claims, and is read-only for this plan.
- `tests/e2e/lib/admin-api.ts`: a generic admin call (PUT/PATCH/DELETE for the 0.4 resources). `upstream.ts`'s `adminRequest` is not exported.
- Shared rule: one helper per concern in tests/e2e/lib, recorded here.

**3. [Rule 1 - Own code] Redirect straight to an unrouted redirect URI**
- With an existing session, `/authorize` redirects straight to the callback. Playwright routes only the first request of a redirect chain, so the `goto` fails with ERR_NAME_NOT_RESOLVED even though the request carrying the code was made.
- `authorizationCodeFlow` accepts that case when the callback request was observed.
- `account.ts` `signInForIdToken` has the same limitation, so the attributes spec does not use it with a no-op sign-in.

**4. Spec details adjusted to actual behaviour (no server defect)**
- Webhook endpoint names allow only `[a-z0-9_-]`.
- The ID token `aud` is an array.
- `email` is not in the ID token when an access token is issued for the `email` scope (it is in UserInfo, standard OIDC behaviour), so the DCR spec checks UserInfo.

**5. Config.rs and webhook_event.rs notes not edited**
- Rust source is reserved for 05-26 in this wave. The two stale code comments (config.rs 05-16 notes, and the webhook_event.rs "tenant slug" doc) are logged in deferred-items.md for the gate. **Forced extra file:** deferred-items.md (one entry).

## Server defects found

None. Every e2e mismatch was a spec assumption (deviation 4).

## Self-Check: PASSED
- Files: all 8 created files and 4 modified docs exist.
- Commits: dc6221f (e2e), 91a38c9 (docs) are in `git log`.
