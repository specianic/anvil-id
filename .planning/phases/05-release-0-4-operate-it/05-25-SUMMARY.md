---
phase: 05-release-0-4-operate-it
plan: 25
subsystem: testing, docs
tags: [mcp, cimd, rfc8707, rfc8414, rfc9728, rfc9207, e2e, playwright, docs]

requires:
  - phase: 05-release-0-4-operate-it
    provides: "05-13 resource-aware consent and the CIMD consent screen; 05-15 ClientResolver, the CIMD fetcher and the discovery flag; 05-21 DCR; 05-23 admin API dcr/cimd tenant settings and the tenant issuer"
provides:
  - "resource_indicators.rs: RFC 8414 path insertion carries the MCP fields for a path tenant; a CIMD client's token is bound to the MCP server only"
  - "tests/mcp: zero-dependency mock MCP resource server and MCP client (library and CLI)"
  - "tests/e2e/specs/mcp.spec.ts: the MCP authorization journey (CIMD + resource indicator) and the disabled-policy error page"
  - "docs/MCP.md and docs/examples/mcp/oauth-protected-resource.json"
affects: [05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "MCP mocks under tests/mcp are ES modules with only node:http/node:crypto, runnable directly with Node type stripping and imported by the e2e lib"

key-files:
  created:
    - tests/mcp/mock-mcp-server.ts
    - tests/mcp/mock-mcp-client.ts
    - tests/mcp/README.md
    - tests/mcp/package.json
    - tests/e2e/lib/mcp.ts
    - tests/e2e/specs/mcp.spec.ts
    - docs/MCP.md
    - docs/examples/mcp/oauth-protected-resource.json
  modified:
    - crates/anvil-web/tests/resource_indicators.rs

key-decisions:
  - "MCP claims are pinned to MCP authorization revision 2026-07-28, checked against the published spec source on 2026-11-26; MCP cites CIMD draft-00 while AnvilID implements draft-03 (stated in MCP.md)"
  - "The mock server's resource_metadata hint is the RFC 9728 path-inserted URL ({base}/.well-known/oauth-protected-resource/mcp), so the client's RFC 9728 §3.3 check (resource identical to the requested URL) holds; the root URL is also served as the MCP fallback"
  - "The mock client fails closed like a real MCP client: issuer must equal the issuer it started from, S256 must be advertised, state and iss (RFC 9207) are checked on the callback"
  - "The CIMD document uses application_type native with a loopback redirect URI (the only http redirect AnvilID accepts)"
  - "No server defects found; two MCP-compatibility notes (OIDC path insertion not served, exact resource case matching) are documented as 0.4 limits and logged for the gate"

patterns-established:
  - "MCP e2e: fresh path tenant per run, policies through PATCH /tenants/{slug}, tenant deleted in afterAll"

requirements-completed: [AGT-01, AGT-02]

duration: ~55min
completed: 2026-11-26
---

# Phase 5 Plan 25: MCP end to end (CIMD + resource indicators) and docs/MCP.md Summary

**A zero-dependency mock MCP client finds AnvilID from a mock MCP server's 401 and RFC 9728 document, discovers the tenant through RFC 8414 path insertion, identifies itself with a Client ID Metadata Document on 127.0.0.1, and completes code + PKCE with `resource=<MCP server>` through a real browser sign-in and consent. The mock server verifies the token (JWKS signature, `typ`, `iss`, `aud`, `exp`) and answers 200, and a second server refuses it on audience. With the CIMD policy disabled, the same URL shows the error page. docs/MCP.md explains the setup for integrators.**

Note: `requirements-completed` lists the plan's requirement ids. No checkbox in REQUIREMENTS.md was ticked (wave rule).

## Accomplishments

- `crates/anvil-web/tests/resource_indicators.rs` has two new tests (17 pass in total):
  - `rfc8414_path_insertion_serves_the_mcp_fields_of_a_path_tenant`: for a path tenant, `/.well-known/oauth-authorization-server/t/agents` and `/t/agents/.well-known/openid-configuration` agree on issuer, the authorization/token/jwks endpoints, `code_challenge_methods_supported` (S256), `client_id_metadata_document_supported`, `registration_endpoint`, `authorization_response_iss_parameter_supported` and `scopes_supported`. With the default policies, neither form has the CIMD flag or the registration endpoint. The root RFC 8414 document stays the default tenant's.
  - `a_cimd_client_gets_a_token_for_the_mcp_server_and_no_other_resource`: in dev mode with a loopback document server, a resource outside `dcr.allowed_resources` gets an `invalid_target` redirect. A token request for another resource gets `invalid_target`, and the code is burned. The MCP-shaped exchange gives `aud` == the MCP URL (a string), `iss`, and `client_id` == the document URL, while the ID token keeps `aud` = [client_id]. UserInfo refuses the token.
- `tests/mcp/mock-mcp-server.ts`: on `/mcp` it answers 401 with `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`. It serves the RFC 9728 document (`resource`, `authorization_servers` = [tenant issuer], `bearer_methods_supported`). It validates tokens with node:crypto (RS256/PS256/ES256/Ed25519, `typ` at+jwt, JWKS from the issuer metadata with one refetch on an unknown kid, `iss`, `aud`, `exp`/`nbf`/`iat`) and logs only the refusal reason.
- `tests/mcp/mock-mcp-client.ts` follows the MCP steps: probe, PRM via the hint (or the RFC 9728 well-known fallbacks) with the §3.3 resource check, then AS metadata in MCP order with the issuer and S256 checks. It serves the CIMD document and the callback on 127.0.0.1, builds the PKCE authorization URL with `resource`, checks the callback (`state`, `iss`), exchanges the code with `resource` and calls the MCP endpoint. Both modules also run standalone (`node tests/mcp/mock-mcp-*.ts …`).
- `tests/e2e/lib/mcp.ts`: `setAgentPolicies` (PATCH of `cimd.policy` / `dcr.allowed_resources`), plus re-exports of the mocks. The spec reuses `createTenant`/`randomSlug`/`tenantIssuer` (upstream.ts), `deleteTenant` (email-code.ts) and `login`/`createUser` (anvil.ts).
- `tests/e2e/specs/mcp.spec.ts`, run serially with two tests:
  - The journey test: discovery assertions, then login, then consent. On the consent page `#consent-client` is the client_id host:port, the CIMD block and the unverified label are present, `#consent-resource-1` is the MCP URL, and the page has no `<img>`. Then the callback (`iss` equals the issuer), the token (`aud`/`iss`/`client_id`), the MCP server answering 200, and another MCP server refusing with `reason=aud`.
  - The disabled-policy test: discovery no longer has the flag, and `/authorize` answers 400 with `data-error-key="unknown_client"`. The page stays on AnvilID, with no callback and no document fetch.
- `docs/MCP.md` covers:
  - the issuer and its metadata URLs (including which MCP discovery URLs are served)
  - publishing RFC 9728 metadata, with a `WWW-Authenticate` example
  - allowing the resource: exact matching, with `dcr.allowed_resources` for CIMD and DCR clients and `allowed_resources` per static client
  - enabling CIMD with one PATCH or YAML: policies, allow-list rules, document rules, `jwks_uri` unsupported, https only in production, dev-mode loopback http, fetch protections, cache clamping, errors never cached, the installation-wide per-host budget
  - optional DCR: policies, default scopes, informational URIs neither stored nor echoed, IAT limits, single-use IATs not consumed on rejection, the soft `max_clients` cap, 404 once disabled, the Auth rate class, `application_type`
  - consent behaviour
  - token shape and the MCP server's validation checklist
  - local testing and the 0.4 limits

## Task Commits

1. **Task 1: resource indicator tests, docs/MCP.md, example JSON:** `8b74daa` (test)
2. **Task 2: mock MCP client/server, e2e lib and spec:** `eea99f4` (test)

## Verification run

- `cargo test -p anvil-web --test resource_indicators`: 17 passed (SQLite). `cargo clippy -p anvil-web --test resource_indicators -- -D warnings`: clean. `rustfmt --edition 2024` was run on the file.
- `python3 -c "import json; json.load(open('docs/examples/mcp/oauth-protected-resource.json'))"`: OK.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean. This also type-checks tests/mcp through the imports.
- **The e2e spec ran locally without Docker and passed (2/2).** The run used the main-tree `target/debug/anvilid`, copied to a scratch dir and started with a fresh data dir and the run.sh flags (`--public-url http://localhost:18125 --breach-check off`, `ANVILID_RATE_LIMIT_AUTH_PER_MINUTE=1200`, no SMTP). Playwright chromium was run with `ANVIL_URL`/`SETUP_URL`/`E2E_STATE_FILE`. It passed both before and after the resource_metadata hint change. The scratch dir and the processes were removed afterwards.
- Standalone smoke test: `node tests/mcp/mock-mcp-server.ts <issuer> 18931` and `node tests/mcp/mock-mcp-client.ts http://127.0.0.1:18931/mcp` against a tenant with CIMD open. Discovery succeeded and the authorization URL was printed (the browser step was not driven by hand).
- MCP claims were checked against the spec source in the modelcontextprotocol repository, revisions 2025-11-25 and 2026-07-28 (the latest released): authorization index, discovery, client registration, security considerations and changelog. RFC 9728 §2/§3.3/§5.1 were checked against rfc-editor.org. The downloaded copies were deleted.

## Not run

- `tests/e2e/run.sh sqlite specs/mcp.spec.ts` as written (it needs Docker for Mailpit) and the Postgres e2e variant. These are left for CI. The release-binary build that run.sh performs was not repeated; the debug binary was used.
- `ANVILID_TEST_DB=postgres cargo test -p anvil-web --test resource_indicators` (Docker). Left for CI.

## Deviations from Plan

### Forced extras

**1. [Rule 3 - Blocking] `tests/mcp/package.json` (`"type": "module"`, no dependencies)**
- **Found during:** Task 2, first local run.
- **Issue:** Playwright loaded `tests/mcp/*.ts` as CommonJS because no `package.json` above them sets the module type. `import.meta` and the top-level await of the standalone CLIs then fail ("Cannot use 'import.meta' outside a module").
- **Fix:** a minimal private package.json that marks the directory as ESM. It has no dependencies and no lockfile.
- **Commit:** eea99f4

**2. deferred-items.md entries** (shared phase file; committed with this summary)
- Two MCP-compatibility notes and a docs hand-off for 05-27 (see below).

### Interpretation choices
- Plan wording `resource_metadata="…/.well-known/oauth-protected-resource"`: the hint is the path-inserted form `…/.well-known/oauth-protected-resource/mcp`, and the root form is also served. The RFC 9728 §3.3 reason is in key-decisions.
- "Token refused for another resource" is proven three ways: `invalid_target` at the token endpoint (Rust), UserInfo `invalid_token` (Rust), and a second mock MCP server refusing on `aud` (e2e).
- TDD: these are test/doc tasks against existing server behaviour. No RED commit was made because every assertion passed against the current server on first run. The Rust tests were checked to fail on wrong values by their exact-equality assertions; no mutation run was done.

## Server defects for the gate

None found. All assertions passed against the current server. Logged in deferred-items.md as notes rather than defects:
- The OIDC path-insertion URL `/.well-known/openid-configuration/t/{slug}` (second in the MCP order) is not served. URL 1 answers first, so MCP clients are unaffected.
- MCP says implementations SHOULD accept uppercase scheme and host in resource URIs. AnvilID matches exactly, by design, and this is documented as a 0.4 limit.

## Self-Check: PASSED
- Files exist: every path under key-files
- Commits in history: 8b74daa, eea99f4
