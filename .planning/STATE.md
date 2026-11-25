---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: verifying
stopped_at: Completed 02-04-PLAN.md
last_updated: "2026-11-25T01:52:00.000Z"
last_activity: "2026-11-25 — Completed 01-08 (phase gate: CI green on GitHub, spike verdicts, stack confirmed)"
progress:
  total_phases: 7
  completed_phases: 1
  total_plans: 19
  completed_plans: 8
  percent: 53
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-11-25)

**Core value:** A standards-correct, secure OIDC provider that anyone can run in two minutes.
**Current focus:** Phase 1: Foundations and Spikes (M0)

## Current Position

Phase: 1 of 7 (Foundations and Spikes (M0))
Plan: 8 of 8 in current phase (phase complete; all plans 01-01 through 01-08 done)
Status: Phase complete — ready for verification
Last activity: 2026-11-25 — Completed 01-08 (phase gate: CI green on GitHub, spike verdicts, stack confirmed)

Progress: [█████░░░░░] 53%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
| Phase 01 P01 | 15min | 3 tasks | 28 files |
| Phase 01 P04 | 5min | 2 tasks | 7 files |
| Phase 01 P03 | 4min | 3 tasks | 13 files |
| Phase 01 P02 | 15min | 3 tasks | 3 files |
| Phase 01 P06 | 9min | 2 tasks | 6 files |
| Phase 01 P05 | 4min | 2 tasks | 10 files |
| Phase 01 P07 | 10min | 3 tasks | 9 files |
| Phase 01 P08 | 20min | 2 tasks | 4 files |
| Phase 02 P03 | 10min | 2 tasks | 21 files |
| Phase 02 P04 | 8min | 2 tasks | 12 files |
| Phase 02 P01 | 16min | 3 tasks | 29 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: One phase per ARCHITECTURE.md §18 milestone; M5 (1.0) split into Phase 6 (organizations and SSO) and Phase 7 (certification and release)
- [Roadmap]: Cross-cutting requirements mapped to the phase where they are first fully delivered (e.g. ORG-01 and ADM-07 to Phase 5, ADM-02 to Phase 6), even though parts land earlier
- [Roadmap]: QUAL-01 (negative test per security control) is mapped to Phase 2 but remains a gate for every later phase
- [Phase 01]: Storage ports live in anvil_core::ports; backends normal-depend on anvil-core only, anvil-storage (contract suite) is a dev-dependency
- [Phase 01]: ConsumeOutcome::Consumed holds AuthorizationCode unboxed (documented clippy expect)
- [Phase 01]: If-None-Match uses RFC 9110 weak comparison; anvilid rejects issuers with query, fragment or non-http(s) scheme
- [Phase 01]: Discovery document serialised once at router build; advertised-but-unbuilt endpoints return 501 JSON
- [Phase 01]: SQLite storage passes the contract (incl. 32-way consume) with the production single-writer config; no multi-connection writer
- [Phase 01]: sqlx metadata prepared per crate via scripts/sqlx.sh (skips crates without sqlx.toml); dev Postgres bound to 127.0.0.1
- [Phase 01]: cargo-deny >= 0.22 required (0.21 fails on transitive dev-only unmaintained advisories); bans not loosened
- [Phase 01]: Dependency rules apply to normal+build edges only (cargo tree -p, --target all); self-test counts only RULE VIOLATION output as rejection
- [Phase 01]: Conformance: INTERRUPTED module counts as complete in run-test-plan.py, so the M0 ratchet passes over plain http (no TLS fallback needed for M0)
- [Phase 01]: M0 discovery advertises only ES256 but ARCHITECTURE makes RS256 default and certification requires it: Phase 2 must advertise RS256 (raised as doc/code divergence)
- [Phase 01]: Postgres backend passes the shared contract (incl. 32-way consume) with one PgPool and zero query overrides; two sqlx backends judged manageable (§2.1 condition 3 met)
- [Phase 01]: anvilid serve requires --database-url (no implicit default DB); unknown schemes rejected without echoing the URL; Postgres pool 10
- [Phase 01]: Spike B local x86_64 static-pie musl: 9.44 MiB, 18.3 MB idle RSS (vs probe 3.5 MB/9.1 MB, now with sqlx SQLite+Postgres + aws-lc-rs linked); arm64 proven in CI (plan 08)
- [Phase 01]: Phase 1 gate: §2.1 conditions 1-3 met (conformance green in CI, static musl amd64+arm64, two sqlx backends manageable); Rust stack confirmed
- [Phase 01]: Conformance suite fetched via blobless --no-checkout clone (sparse-checkout not portable across git versions); mongo on a named volume removed by down -v
- [Phase 02]: Theme selector/text contract (input id=name, {form.id}-submit, mgmt-client-*, error_key sentences) documented in themes/default/README.md; forms use novalidate so errors come from FormDescription
- [Phase 02]: Sample RP (examples/node-rp) uses client.ClientSecretBasic explicitly; openid-client 6 defaults to client_secret_post for a bare secret
- [Phase 02]: Sample RP allows insecure http only for localhost/127.0.0.1 issuers and fails on a refresh response without a rotated refresh token
- [Phase 02]: e2e helpers take all endpoints from ANVIL_URL/MAILPIT_URL/RP_URL; credentials are created at runtime via /setup
- [Phase 02]: anvil-jose signs/verifies via jsonwebtoken::crypto::{sign,verify} (public in 12.0); headers, JWKs and thumbprints are built in-crate; RSA PKCS#8 loaded as PRIVATE KEY PEM
- [Phase 02]: All Phase 2 deps declared up front (tower-http 0.6.x to match reqwest 0.13); deny.toml allows 0BSD for quoted_printable (lettre); ring absent
- [Phase 02]: Client assertions: aud exactly the issuer (string or 1-element array), iss==sub==client_id, exp within 5 min, jti required (<=256 chars); future nbf/iat rejected; jti replay left to GrantRepo::record_jti

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 6]: Decision D4 (pure-Rust SAML XML-DSig vs alternatives) must be resolved before M5; SAML stays experimental until it passes a signature-wrapping attack corpus
- [Phase 4]: Social login exit criterion requires testing against real providers in a staging environment (provider app registrations needed)

## Session Continuity

Last session: 2026-11-25T01:24:20.336Z
Stopped at: Completed 02-03-PLAN.md
Resume file: None
