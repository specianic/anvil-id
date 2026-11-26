---
phase: 06-release-1-0-orgs-and-sso
plan: 26
subsystem: release-gate
tags: [gate, QUAL-01, security-map, plaintext-scan, rustdoc, ci, release, migrations, load, ha, deploy, fuzz, conformance, e2e]
requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-01..06-25 and the gap plans 06-28..06-31"
provides:
  - "QUAL-01 map covers every Phase 6 control: 921 control/test pairs (289 new, up from 632)"
  - "Plaintext-at-rest scans (SQLite and Postgres) cover the invitation token, an org connection secret, a sealed SAML identity and return_to_sealed in flow JSON"
  - "`just doc` (rustdoc, -D broken and private intra-doc links) in `just ci` and the ci lint job; every such link fixed"
  - "Pre-0.4 console redirect pages removed (decision recorded below)"
  - "anvilid 1.0.0-beta.1 on main; SQLite 0008/0009 and Postgres 0007 pinned"
  - "ORG-02, ORG-03 (SAML experimental behind the operator flag), ORG-04 and ADM-02 complete"
  - "Every workflow green on the gate commit (run ids below)"
affects: [06-27 (v1.0.0-beta.1 prerelease, blocked on the Q8 tags), Phase 7]
tech-stack:
  added: []
  patterns:
    - "Phase 6 plaintext scans seed the flow state through the real public types (FlowState::Login, SamlPending, SealedIdentity, parse_return_target) and seal under the real purposes and upstream_aad"
key-files:
  created:
    - .planning/phases/06-release-1-0-orgs-and-sso/06-26-SUMMARY.md
  modified:
    - scripts/check-security-tests.sh
    - scripts/released-migrations.sha256
    - crates/anvilid/Cargo.toml
    - Cargo.lock
    - crates/anvil-storage-sqlite/tests/plaintext.rs
    - crates/anvil-storage-postgres/tests/plaintext.rs
    - justfile
    - .github/workflows/ci.yml
    - admin-ui/src/routeTree.gen.ts
    - admin-ui/src/routes/t/$tenant/audit/index.tsx
    - admin-ui/src/components/ui/badge.tsx
    - tests/e2e/specs/console-tenants.spec.ts
    - docs/UPGRADING.md
    - .planning/REQUIREMENTS.md
key-decisions:
  - "Legacy console redirect pages (16 files, `TRANSITIONAL: remove in 0.5.`) are removed: 0.5 became 1.0, the pages only ever redirected to the `default` tenant, and the audit page was still typed against one of them. UPGRADING tells operators to update bookmarks"
  - "`just doc` also denies rustdoc::private_intra_doc_links (a superset of the requested broken_intra_doc_links check), because links to private items render as dead links in the published docs"
  - "Tenant connections page still pages organizations for owner names: deferred to Phase 7 (needs an organization name/slug on the connection view of the admin API, not a small fix)"
  - "Q8: v0.3.0 and v0.4.0 are not tagged. Push authorized by the orchestrator, ordering waived for the gate's CI only; no tag created. The v1.0.0-beta.1 prerelease (06-27) stays blocked on both tags"
requirements-completed: [ORG-02, ORG-03, ORG-04, ADM-02]
duration: ~2h40min
completed: 2026-11-26
---

# Phase 6 Plan 26: Phase 6 gate (release 1.0-beta) Summary

**The security map now names a registered negative test for every Phase 6 control: 921 pairs, up from 632. Both plaintext scans also cover the 1.0 secrets. Every intra-doc link is fixed, and `just doc` keeps it that way. The pre-0.4 console redirects are removed. anvilid is 1.0.0-beta.1 and the 1.0 migrations are pinned. ci, e2e (both backends, including the first CI runs of the org, SAML and HRD specs), conformance, release-build, the release dry run (macOS included), fuzz, deploy and load are all green on the gate commit. The v1.0.0-beta.1 prerelease is blocked on the owner-gated v0.3.0 and v0.4.0 tags.**

(Run ids and perf numbers: see "CI on the gate commit".)

## Performance

- **Duration:** ~2h40min
- **Started:** 2026-11-26T14:00Z
- **Completed:** 2026-11-26
- **Tasks:** 3 (Task 2's checkpoint resolved by the orchestrator's standing push authorization; Q8 recorded, not met)
- **Files modified:** 53 (incl. 16 deleted console routes)

## Accomplishments

### Security map (QUAL-01)

`scripts/check-security-tests.sh`: 921 control/test pairs, all present and registered, `--self-test` OK. New groups, one per control:

- **SAML corpus (D4):** all 67 cases of `security_saml.rs`, grouped as signature wrapping/placement, signature required and configured key only, comment/markup injection, DTD/entities/exhaustion, namespace and canonicalization tricks, algorithm/transform allow-list, exact reference, strict structure, and valid responses / claims only from the verified node.
- **SAML conditions:** the 26 `rejects_*` tests of `anvil-core/src/saml/validate.rs`, plus the adapter's `has_conditions_*`, certificate, DOCTYPE, size/depth and metadata refusals, the relay state check and the `record_jti_saml_assertion_id_replay` contract.
- **SAML flow (`saml_login.rs`):** binding cookie, replay (also across instances), unsolicited, cross-flow/connection, expiry, flag off 404, 256 KiB body limit, generic error page, transient NameID, unsigned/foreign-signed, foreign-domain email, tenant MFA. SAML connections are refused at tenant level and with the flag off, invalid input answers 422, and the metadata URL goes through the SSRF guard.
- **Org connections and branding:** write-only sealed secret, org isolation, not listed on the tenant sign-in page, org branding only for its own org.
- **Domains (`security_domains.rs`, core, DNS adapter, contract):** suffix/IP/reserved/wildcard/scheme refusals, exact TXT record and canonical token, uniform DNS outcome (API and `domain_check`), bounded/uncached/FQDN-only resolver, the recheck grace period and its leased job, one verified org per domain (contract + concurrency + API), tenant/org isolation.
- **Routing guards (`hrd_login.rs`, `home_realm`, contract):** a route needs a verified domain and an enabled connection of the same org. Matching is exact-domain and flag-aware, the identify step is bound to its flow, and password and email code are refused on a routed domain without `allow_local_password`.
- **Identifier-first:** no enumeration (`security_enumeration`, the core local-route page, the lock page). The email-first decision is flag-aware, and the lock/CAPTCHA pages keep the email-first form in routed tenants (06-28).
- **Invitations (`org_invitations.rs`, contract, service):** hashed token with a unique hash, closed tokens invalid, bounded presented tokens. Single use (contract + concurrent POSTs), bound to the invited verified email, isolated per tenant. GET consumes nothing and POST needs CSRF, every invalid token gets one page, and the admin API neither enumerates nor lists the token or hash. Registration modes, password policy and existing email are covered. A failed registration sets no session (06-31), registration replaces another user's session, and the template contract is exact.
- **Return-to (06-31):** open-redirect refusals (spec, `policy::return_to`, `service::flow`), tampered or moved sealed value, request wins, token never stored in plaintext.
- **Org claims:** membership re-checked at refresh, removal revokes only that org's tokens, no claims without an active org, mapped attributes cannot spoof or shadow, `organization` refused for off clients and non-members, prompt=none never shows the switcher.
- **org:admin:** bounded to the permission in the active org (client_credentials never). Reserved from DCR, CIMD and the system tenant (`security_org_scopes.rs`, config validate).
- **Org switcher and org MFA:** own memberships only, CSRF, single use, flow-bound, stricter org MFA steps up, and the strictest policy wins exhaustively.
- **Org-admin principal (`security_admin_v10.rs`):** isolated to its org (other org, other tenant, tenant routes, installation routes, per-user organizations, `?email=` lookup). Every request needs the scope, `org_id`, audience, a JWT and live membership/permission. No escalation, the last org admin is kept, and orgs are refused in the system tenant. Roles cover org-owned roles, assignment needing membership, and org assignments never counting as tenant admins.
- **Admin v1.0 routes:** scopes, plus the new per-user organizations and `?email=` routes (06-29).
- **Cross-org email trust and org JIT (06-28):** `enterprise_oidc.rs`, the `security_linking.rs` additions and the core `enterprise_trust_*`. JIT outside the org's verified domains is refused, and tenant connections still follow `upstream_registration`.
- **Org config exclusion, keys API (scopes, isolation, no private material, disabled alg), passkey picker carry-over** (`flow_mfa_policy.rs`, `allow_credentials_refuse_malformed_options`).
- **Release 1.0 secrets at rest** (both backends, below).
- Header comment updated for release 1.0 (beta). The browser-only note now also covers console orgs/SSO/domains/keys, the org switcher, invitations, SAML, HRD and nojs-HRD. The aws-lc Cargo.lock rule is listed as a script-enforced control (check-deps and its self-test case I).

### Plaintext-at-rest scans

New test `release_1_0_secrets_never_stored_plaintext` in both `crates/anvil-storage-{sqlite,postgres}/tests/plaintext.rs`. Everything is seeded through the storage ports exactly as the services store it:

- **Invitation:** `random_token()`, stored only as `SecretHash(secret_hash(token))`. Its email, whose link carries the token, is sealed into the outbox with `seal_payload`.
- **Org connection secret:** an org-owned OIDC connection whose client secret is KEK-sealed (`CONNECTION_SECRET_PURPOSE`, `connection_aad`).
- **Login flow:** the state is `FlowState::Login` with a `SamlPending` holding a `SealedIdentity` sealed under `SAML_IDENTITY_PURPOSE`. `return_to_sealed` holds `parse_return_target("/ui/invitation?token=…")` sealed under `RETURN_TO_PURPOSE`. Both use `upstream_aad(tenant, flow)` and open only under their own flow.
- **Assertions:** the token (alone and as `token=`), the connection secret and the SAML subject and email appear in no column. On SQLite they are also absent from the raw file and WAL, before and after a checkpoint. The invitation digest is stored exactly once (`org_invitation.token_hash`, 32 bytes).
- **Positive controls:** the sealed values are found once (`flow.state`, `connection.secret_enc`). The domain TXT challenge token and the SAML certificate are found, and the test documents why they are public by design (DNS, IdP metadata).

### Rustdoc

- **Broken links (errors):** `contract` in anvil-storage, `OutboundClient` in cimd.rs and `WEBHOOK_CONCURRENCY` in webhook.rs. The anvilid `smtp_from` help text (`[default: AnvilID <no-reply@…>]`) was parsed as a link; it and a bare HIBP URL now use `(default: \`…\`)`.
- **Other link warnings:** 23 private-item links and 6 redundant explicit links in anvil-core (flow/login, flow/email_code, saml/request, service/{flow,upstream,saml,authorize,audit,introspect,org_domain}) and anvil-web.
- **Recipe:** new `doc` runs `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" cargo doc --workspace --no-deps --locked`. It is part of `just ci`, and the ci.yml lint job runs `just doc`. The doc build has no warnings left.

### Release prep

- **Version:** `crates/anvilid` is 1.0.0-beta.1, recorded in Cargo.lock.
- **Migration pins:** sha256 lines for `0008_release_1_0.sql`, `0009_release_1_0_rebuild.sql` (SQLite) and `0007_release_1_0.sql` (Postgres). `check-migrations.sh` and its `--self-test` pass.
- **Deploy defaults:** they stay on image 0.4.0 (helm `appVersion`, compose, deploy README). A prerelease does not move `latest`; 06-27 or the 1.0.0 release decides when to change them.

### Requirements

- **At plan start:** all four were unticked (`[ ]`, traceability `Pending`).
- **Now ticked in the list and the traceability table:**
  - ORG-02, ORG-04, ADM-02: `Complete`.
  - ORG-03: `Complete (SAML experimental, operator flag)`, with a note that SAML 2.0 ships behind `saml_experimental` (off by default) until the Phase 7 external review.
- **Evidence:** the owning plans' tests and the green CI runs below.
  - ORG-02: org_claims, org_switch, org_invitations, admin_orgs, console-orgs.spec, org-switch.spec, invitation.spec.
  - ORG-03: enterprise_oidc, saml_login, security_saml, admin_org_sso, console-org-sso.spec, saml.spec.
  - ORG-04: security_domains, hrd_login, dns_txt_adapter, hrd.spec, nojs-hrd.
  - ADM-02: the console specs incl. console-keys, console-orgs, console-org-sso and console-tenants.

## Local gate

- **Recipes that passed in the first `just ci` run:** fmt-check, lint, doc, deny, deps, migrations-check.
- **`just deps` (06-30's single aws-lc rule, which replaces 06-01's cargo-tree check):** `dependency rules OK`. Cargo.lock holds exactly one `aws-lc-rs` (1.19.0) and one `aws-lc-sys` (0.47.0). `deps-selftest` passes all cases, including `I: Cargo.lock gains a second aws-lc-sys version (checker: fail, expected: fail)`.
- **test (first attempt):** the console test `hashed_assets_are_negotiated_cached_and_revalidated` failed. My plain `npx vite build`, used to regenerate the route tree, had written `admin-ui/dist` without the `.br`/`.gz` sidecars. After `npm run build` it passed. Nothing in the product changed.
- **Postgres and Redis tests under the full run:** Docker Desktop's WSL port forwarding refused connections, the same environment problem 05-28 hit: `upgrade.rs`, four test-pg binaries, and `test-redis`. Each passed when rerun on its own:
  - `cargo test --workspace --no-fail-fast`: green.
  - `just test-redis`: green.
  - `upgrade`: 242/242.
  - `account_apps`, `account_linked`, `security_setup`, `security_theme` on Postgres: all green.
- **Other recipes:** release-graph, security-tests (921 pairs), security-tests-selftest, console-check and fuzz-check passed.
- **Local e2e (sqlite):** the two specs I changed or fixed, `console-tenants.spec.ts` and `console-org-sso.spec.ts`. The full e2e suite and the conformance suite ran only in CI, which is authoritative.

## CI on the gate commit

Gate commit **9c40f61** (`9c40f61a40d0d323c52449a57c102a6154199ec6`). All runs are on that SHA:

| Workflow | Event | Run | Result |
|---|---|---|---|
| ci (fmt+clippy, `just doc`, deny, deps, sqlx, tests sqlite + postgres + redis, security map 921 pairs, release graph, console, fuzz compile) | push | 45853281859 | success |
| e2e (Playwright sqlite 128 passed, postgres 128 passed, QUAL-04 both backends, image size gate) | push | 45853282048 | success |
| conformance (Basic, Config, Form Post, RP-Initiated and Back-Channel Logout; 0 expected failures) | push | 45853282049 | success |
| release-build (console, musl x86_64 + aarch64) | push | 45853281854 | success |
| release dry run (musl x86_64 + aarch64, **macos aarch64-apple-darwin + x86_64-apple-darwin**, container image gate; nothing published) | dispatch | 45853367546 | success |
| fuzz (jwt_decode, client_assertion, authorize_parse, redirect_match, saml_response_parse, saml_metadata_parse, org_domain_parse) | dispatch | 45853360949 | success |
| deploy (compose smoke, chart lint, chart install on kind) | dispatch | 45853378180 | success |
| load (perf + HA) | dispatch | 45853373260 | success |

The macOS jobs of the release dry run are the macOS proof of bergshamra on aws-lc. `release-build` has only musl targets; the macOS binaries are built only by `release.yml`, so it was dispatched in its dry-run mode. The plan's verify command (`unique conclusions on HEAD == success`) passes.

Earlier gate commits: on 8b4831f every workflow except e2e was green (ci 45844438858, conformance 45844438750, release-build 45844438680, deploy 45844438724, load 45844438824, fuzz smoke 45844438674); e2e 45844438761 failed on the removed redirects (fixed in 97dfccf). On 97dfccf, e2e 45848637937 failed on the badge contrast race (fixed in df8a9d0). On df8a9d0, e2e 45852299699 passed. Superseded dispatches on 8b4831f, 97dfccf and df8a9d0 were cancelled.

### Load (QUAL-05, run 45853373260)

Perf job (public GitHub 4 vCPU runner shared by k6, Postgres and AnvilID; 1000 req/s target, p99 < 50 ms, median of 3):

| trial | p99 (ms) | throughput (req/s) | failed | dropped | HTTP 429 |
|---|---|---|---|---|---|
| 1 (median) | 2.64 | 1000.0 | 0 | 0 | 0 |
| 2 | 2.74 | 1000.0 | 0 | 0 | 0 |
| 3 | 2.45 | 1000.0 | 0 | 0 | 0 |

Idle VmRSS (host /proc, Postgres backend): 54,500 kB (VmHWM 56,744 kB; limit 102,400 kB). The perf gate never missed today (8b4831f: median p99 3.96 ms, 57,128 kB).

HA job:
- 36,001 requests at 300 req/s through HAProxy across 3 node restarts: 0 failed, 0 dropped, 0 HTTP 429, p99 3.19 ms, 3/3 nodes running after.
- Webhooks during restarts: 80 users created, 80 deliveries, 80 unique webhook-ids, 0 duplicates, 0 malformed (exactly once).
- Shared limit: 90 requests in 0.153 s across 3 nodes at 10/s (burst 10): 10 allowed (bound 13; a per-node limiter would allow at least 30), 80 limited.

## D4 corpus report

`crates/anvil-web/tests/security_saml.rs`, 67 cases, result: **67 passed, 0 failed** (local `cargo test`, and the ci `tests (sqlite)` job on the gate commit).

- Accepted (3): valid RSA and ECDSA responses, other prefixes, claims read only from the verified assertion.
- Signature wrapping / placement (18): XSW1-XSW8, clone before/after signed (two variants), signed assertion in SubjectConfirmationData / Advice, signature moved to a sibling, assertion signature not after Issuer, response signature out of place, stray signature in Extensions, two response signatures, foreign signed element in Extensions.
- Signature required / key (8): unsigned assertion, signed response with unsigned assertion, empty SignatureValue, empty DigestValue, KeyInfo key injection, KeyInfo RetrievalMethod, tampered assertion, invalid response signature.
- Text-node injection (4): comment in NameID, comment in attribute value, element in NameID, processing instruction.
- DTD / exhaustion (6): DOCTYPE without entities, billion laughs, external entity, deep nesting, oversized response, markup flood.
- Namespace / canonicalization (6): redefined saml prefix, redefined ds prefix, default namespace trick, prefixed-ID attribute pollution, void canonicalization (relative namespace, in transform).
- Algorithms / transforms (10): SHA-1 signature, SHA-1 digest, HMAC, C14N with comments, inclusive C14N, XPath, XSLT, extra, missing and reordered transforms.
- References (6): empty URI, reference to another element, external URL, relative file, two references, Signature Object.
- Structure (6): duplicate IDs, second assertion, EncryptedAssertion, EncryptedID, wrong root/version, unknown Response child.

Total 3 + 18 + 8 + 4 + 6 + 6 + 10 + 6 + 6 = 67.

SAML stays behind the operator flag `saml_experimental` (Q3) through 1.0 regardless of the corpus result, until the Phase 7 external review and the real-IdP interop checklist.

## For the owner

- **deny.toml chrono exception:** `{ crate = "chrono", wrappers = ["tsp-ltv"] }` (bergshamra-keys -> tsp-ltv needs chrono; our code stays on `time`). This is the only chrono exception (decision Q2, option A). It still needs your review.
- **Q8 tags:** `git tag -l v0.3.0 v0.4.0` lists nothing, locally and on origin. 04-33 (the manual provider checklist, then v0.3.0) and 05-29 (v0.4.0) are owner-gated. Following the orchestrator's instruction, this gate pushed main for CI without them and created no tag. **06-27 (v1.0.0-beta.1) is blocked until both tags exist.**

## Task Commits

1. **Task 1 (map, scans, local gate, version, pins, requirements):**
   - `bd863e5` fix: rustdoc intra-doc links, `just doc` in ci
   - `c86d8dd` refactor: remove the pre-0.4 console redirect pages
   - `119ccb2` test: security map and 1.0 plaintext scans
   - `faf95a6` chore: 1.0.0-beta.1, migration pins, requirements
2. **Task 2 (checkpoint):** resolved by the orchestrator's standing push authorization. The Q8 tags are absent, and the waiver is recorded above.
3. **Task 3 (CI to green):**
   - `97dfccf` test: the console e2e expects the not-found page for pre-0.4 links
   - `df8a9d0` fix: the console badge changes colour in one step (axe contrast race)
   - `9c40f61` test: file the C14N-with-comments corpus case under the algorithm group (map label only; gate commit)

## Decisions Made

See key-decisions in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Audit page filter navigation typed against a legacy route**
- **Found during:** Task 1 (legacy page decision)
- **Issue:** `t/$tenant/audit/index.tsx` used `useNavigate({ from: "/audit/" })`, i.e. the pre-0.4 redirect route
- **Fix:** `useNavigate({ from: Route.fullPath })`
- **Commit:** c86d8dd

**2. [Rule 1 - Bug] e2e step still asserted the removed redirects**
- **Found during:** Task 3 (e2e run 45844438761, both backends)
- **Issue:** console-tenants.spec.ts "pre-0.4 deep links redirect to the default tenant"
- **Fix:** the step now expects the console's not-found page for `/console/clients` and `/console/audit`, and opens `t/default/settings` directly for the undeletable-tenant check (same assertions there)
- **Commit:** 97dfccf

**3. [Rule 1 - Bug] Badge colour transition produced a transient contrast failure**
- **Found during:** Task 3 (e2e run 45848637937, console-org-sso.spec.ts axe check after domain verification, both backends)
- **Issue:** the Badge transitioned `color` while the background switched immediately. A Pending (outline) to Verified (primary) change showed #6b6b6b text on #171717 for up to 150 ms (3.36:1). It passed earlier by timing alone.
- **Fix:** the Badge transitions only `box-shadow`. The axe check and its threshold are unchanged.
- **Commit:** df8a9d0

**4. [Rule 2] `just doc` also denies private intra-doc links** (broader than the requested broken-link check; 23 such links fixed).

**5. [Rule 1] Map label:** the C14N-with-comments corpus case was filed under the text-node injection control (substring "comment"); `9c40f61` moves it to the algorithm/transform group. All workflows were re-dispatched on that commit.

**6. [Scope] Gate items from deferred-items.md handled here:** the legacy console pages (removed), rustdoc (fixed + CI), the aws-lc rule output (recorded). Files outside the plan list: justfile, ci.yml, 20 doc-comment files, admin-ui routes and badge, the e2e spec, UPGRADING.md.

## Issues Encountered

- **Local Docker Desktop on WSL:** port forwarding refused Postgres/Redis connections under the full `just ci` run. Every affected binary passed in an isolated rerun (details under Local gate).
- **CI runs that do not trigger on every commit:** fuzz, load, deploy and the release dry run do not trigger on admin-ui/e2e-only commits. They were dispatched on each gate commit so that every workflow has a run on the final SHA. The superseded runs on 97dfccf were cancelled.

## Deferred to Phase 7

- **Tenant connections page owner names:** `admin-ui/src/routes/t/$tenant/connections/index.tsx` pages through up to `MAX_ORG_PAGES` of organizations to show owner names. The fix is an organization name/slug on the connection view of the admin API (an OpenAPI change), so it does not fit the gate.
- **Tenant-restricted system administrators:** decision Q1.
- **Lifting the SAML flag:** after the external review and the real-IdP checklist (Q3).

## Next Phase Readiness

- **Ready:** Phase 6's success criteria hold in CI on the gate commit.
- **Blocked:** 06-27 (the v1.0.0-beta.1 tag) needs the owner's 04-33 checklist and v0.3.0, then 05-29 and v0.4.0.

## Self-Check: PASSED

All key files exist; commits bd863e5, c86d8dd, 119ccb2, faf95a6, 97dfccf, df8a9d0 and 9c40f61 are in history; the plan verify command passes on 9c40f61.
