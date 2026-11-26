# Phase 5: Release 0.4 "Operate it" - Context

**Gathered:** 2026-11-26
**Status:** Ready for research
**Source:** docs/PRD.md, docs/ARCHITECTURE.md (M4), ROADMAP Phase 5, Phase 4 carry-overs, orchestrator defaults (user runs GSD in autonomous mode)

<domain>
## Phase Boundary

Operators can run AnvilID for many tenants in production with high availability, and integrators can automate and extend
it. Requirements: ORG-01, ORG-05, ADM-05, ADM-06, ADM-07, OIDC-17, AGT-01, AGT-02, AUTH-14, OPS-03, OPS-07, OPS-08, OPS-09,
QUAL-05 (read their exact wording in .planning/REQUIREMENTS.md and docs/PRD.md).

Roadmap success criteria:
1. HA test: 3 stateless nodes on one Postgres, shared rate limiting, under load, no errors through node restarts; token
   endpoint meets PRD §6.3 (≥1,000 req/s at p99 < 50 ms on 4 vCPU; idle memory < 100 MB).
2. Tenant configuration exported as YAML re-applies idempotently and round-trips into a fresh instance; CLI can back up and
   restore online, rotate keys and recover admin access.
3. An MCP client completes authorization using a Client ID Metadata Document and resource indicators; dynamic client
   registration obeys admin policy (disabled / allow-listed / open).
4. Operator manages multiple isolated tenants (each with its own issuer) from the console; defines roles, permissions and
   custom attributes that appear in tokens; receives signed, retried webhooks for lifecycle events.
5. In-repo Helm chart and Docker Compose examples deploy a working instance exposing health endpoints, Prometheus metrics,
   OpenTelemetry traces and JSON logs.
</domain>

<decisions>
## Implementation Decisions (locked)

- All CLAUDE.md rules apply: no stubs, one implementation per concern (one rate limiter, one outbound HTTP client, one job
  runner pattern, one audit path), a negative test for every security check, storage only through the storage traits,
  public-repo hygiene (no secrets, hostnames, personal data, unverified claims about other products).
- **Shared rate limiting:** Redis-backed (ARCHITECTURE M4) as an optional backend of the ONE existing limiter (governor-based
  in-memory stays the default for single-node). No second limiter implementation path in handlers. Failure mode when Redis
  is unreachable must be explicit and documented (fail closed for auth endpoints unless configured otherwise) and tested.
- **Nodes are stateless:** everything shared lives in Postgres (and Redis for limiter counters only). Background jobs
  (outbox, back-channel, webhooks, purge) stay leased/SKIP LOCKED so N nodes never double-deliver.
- **Webhooks:** delivered through the existing outbox/lease pattern (no second queue), signed (HMAC-SHA256 over id,
  timestamp and body, following the widely used "Standard Webhooks" header layout), retried with backoff, per-tenant
  endpoints, secrets sealed with the KEK, SSRF-guarded via the single outbound client, delivery log visible in the console.
- **Declarative config:** YAML export/apply per tenant through the admin API and the CLI; apply is idempotent (re-applying
  is a no-op) and produces a plan/diff before changes; secrets are never exported in clear (references or sealed blobs).
- **CLI operations:** online backup/restore (SQLite via its online backup API; Postgres documented pg_dump path plus an
  AnvilID-consistent export), key rotation, admin access recovery (local, requires shell access to the host — never a
  network backdoor).
- **DCR (RFC 7591) and MCP:** dynamic registration policy per tenant: disabled (default) / allow-listed / open; Client ID
  Metadata Documents fetched only through the SSRF-guarded client with size/time limits and caching; resource indicators
  (RFC 8707, shipped in 0.3) bind tokens to the MCP server.
- **RBAC:** tenant-scoped roles, permissions and custom user attributes, mapped into tokens via an explicit claim mapping
  (no arbitrary expression language in 0.4). Org-scoped roles arrive in Phase 6; keep the schema ready for an org scope.
  Permissions engine choice (D5) stays deferred to 3.0 — 0.4 is plain role → permission sets.
- **Multi-tenant console:** an operator (system tenant admin) can create, list, switch between and manage isolated tenants;
  each tenant keeps its own issuer.
- **Observability:** `/healthz` (liveness) and `/readyz` (readiness, checks DB), Prometheus metrics endpoint (opt-in bind
  or same port behind config), OpenTelemetry traces via OTLP (off unless configured), JSON logs option. No PII or secrets in
  metrics labels, spans or logs (test it).
- **Deployment:** in-repo Helm chart and Docker Compose examples; CI validates them (helm lint/template, and an actual
  deploy smoke test in kind or compose).
- **HA + performance tests run in CI** (Docker is available on CI runners; locally Docker is often down — executors leave
  those runs to CI and say so). Performance results are measured on the documented runner size; the CI job fails if the
  targets are missed, and records the numbers.
- **Phase 4 carry-overs (must be planned here):**
  - Remembered consent covering resources (consent_grant schema, consent screen, revocation) — fits with the RBAC/permission
    work.
  - In-flow passkey enrolment as an MFA choice under `required`.
  - Fuzz targets are not built on push to main (a stale target slipped through in 0.3): build the fuzz crate in `ci` or add
    push paths to fuzz.yml.
  - Cosmetic: streamed oversized bodies get 400 on form pages/admin API vs 413 on /token and /logout — unify to 413.

### Claude's Discretion
- Plan decomposition and waves (maximize parallel plans with disjoint files; shared files in an early foundation plan).
- Redis client crate choice (must pass cargo deny; prefer a maintained async client on tokio; keep it optional via a
  feature or runtime config — not in the default dependency graph if the binary-size gate is at risk).
- Load-test tool (k6, oha, or a Rust harness) and HA orchestration (compose in CI).
- Exact YAML schema, provided it is documented, versioned and validated.
</decisions>

<deferred>
## Deferred Ideas
- Organizations, org-scoped roles, per-org SSO, SAML (Phase 6)
- Fine-grained authorization engine (D5, 3.0)
- Localized email templates (noted in 0.3)
</deferred>

---
*Phase: 05-release-0-4-operate-it*
