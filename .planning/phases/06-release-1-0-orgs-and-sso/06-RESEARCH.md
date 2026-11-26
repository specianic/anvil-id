# Phase 6: Release 1.0 "Credible for business" (Organizations and SSO) - Research

**Researched:** 2026-11-26
**Domain:** B2B identity inside a tenant: organizations with members, invitations and org-scoped roles; an org claim and org switching in OIDC; per-org enterprise SSO (SAML 2.0 SP and OIDC RP) with JIT provisioning; home-realm discovery by verified email domain (DNS TXT); a console that covers every managed object. Built on the 0.4 codebase.
**Confidence:** HIGH for the codebase (read at `f1e08c1`) and for the crate facts, which come from crates.io manifests and from crate sources downloaded today. MEDIUM for SAML spec section numbers: the OASIS PDFs could not be text-extracted here, so they are cross-checked against the OWASP SAML cheat sheet and implementer sources. MEDIUM/LOW for the claims about the SAML library's runtime behaviour, which need the Wave 1 spike.

## Summary

Most of Phase 6 reuses machinery that already exists:

- `RoleService` and `UserClaimSource`, plus `policy::claims_mapping`;
- the 0.3 upstream sign-in (connection table, sealed secrets, `UpstreamService` start/callback, the Apple `form_post` hop, `link_decision`);
- the guarded `OutboundClient`;
- `replay_guard` with `GrantRepo::record_jti`;
- the sealed email outbox;
- the user-bound consent flow that the `select_account` chooser reuses;
- the admin API and its OpenAPI drift test, plus the OpenAPI-typed console;
- the storage contract suite and the SQLite rebuild procedure of migration 0004.

Four findings constrain the design more than anything else. The planner must account for each.

1. **D4 cannot be closed as written: every pure-Rust XML-DSig candidate fails our cargo-deny policy or is unproven.**
   - `bergshamra` 0.12.0 has an `aws-lc` provider, so it stays on our single crypto backend. Its xmlsec interop suite (1064 passed, 0 failed) runs on the RustCrypto provider only.
   - `bergshamra-keys` hard-depends on `tsp-ltv` 0.6.1, which hard-depends on **`chrono`**. chrono is banned in `deny.toml`.
   - `saml-rs` 0.8.0 builds on bergshamra and has a `crypto-aws-lc` feature, so it inherits the chrono problem. It also parses each message twice, with **two different XML parsers**: quick-xml for extraction and uppsala inside bergshamra for verification. That is the parser-differential class behind the 2025 ruby-saml bypasses.
   - `saml` 0.1.0-alpha.5 and `xml-sec` 0.6.0 pull RustCrypto RSA unconditionally.

   Recommendation: `bergshamra-dsig` with `aws-lc` only, uppsala as the **single** parser, and our own narrow SAML SP layer. This needs a scoped `chrono` wrapper exception for `tsp-ltv`, which is an owner decision (Q2). SAML stays experimental in 1.0 whichever option is chosen.
2. **Org admins cannot reach the admin API today.** It accepts only system-tenant tokens, and 05-32 refuses `admin:*` scopes outside the system tenant. "Organization admin configures SSO" therefore needs either a narrowly scoped acceptance of application-tenant tokens on org routes, or a scope cut to tenant admins only. This is owner decision Q1. The CONTEXT also folds in "tenant-restricted admins", which is a different principal (a system-tenant user limited to some tenants). That needs clarifying too.
3. **The schema forces SQLite table rebuilds.**
   - `connection.kind` has a CHECK without `saml`, and `connection` is referenced by `identity_link` (ON DELETE CASCADE).
   - `role` needs a composite FK on `org_id`, and it is referenced by `role_assignment`.
   - The `replay_guard.kind` and `email_template.kind` CHECKs need new values.

   With foreign keys on, `DROP TABLE connection` cascade-deletes every identity link. The rebuild must use the `-- no-transaction` + `PRAGMA foreign_keys = OFF` + `pragma_foreign_key_check` procedure of `0004_release_0_2_token_family.sql`. Postgres swaps CHECK constraints and adds composite FKs in place.
4. **Identifier-first login is new.** Today's `LoginStep::Identify` is a combined email + password form, and e2e/no-JS tests depend on it. Home-realm discovery needs an email-only first step. Enable it only when the tenant has at least one verified, routed domain, and decide only from the domain (public), never from account existence, so enumeration safety holds.

**Primary recommendation:**

- Store the active org on the authorization request, the code and the token family, and recompute org claims at every refresh through `UserClaimSource`.
- Ship SAML as an SP-initiated, POST-binding, signed-assertion-only profile behind a runtime experimental flag, verified by `bergshamra-dsig`/aws-lc on one uppsala DOM, and gated by an in-repo attack corpus.
- Verify domains with hickory-resolver TXT lookups on `_anvilid-challenge.{domain}`.
- Treat an enterprise IdP's email as trusted only for domains its org has verified.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- All CLAUDE.md rules apply (no stubs, one implementation per concern, a negative test per security check, storage only
  through traits, public-repo hygiene).
- **Organizations live inside a tenant** (tenant = isolation boundary with its own issuer; org = customer within it). The
  0.4 schema already reserves `org_id` on roles; org-scoped roles reuse RoleService/claims mapping rather than a parallel
  system. MFA policy precedence extends to org (strictest wins: tenant / org / client), as decided in Phase 4.
- **Org admins** are tenant users with an org-scoped admin role; they manage their org (members, invitations, connections,
  domains) through scoped admin API endpoints. This also delivers "tenant-restricted admins" deferred from Phase 5 Q3.
- **Invitations:** single-use, expiring, hashed at rest, delivered through the sealed outbox; accepting binds to a signed-in
  or newly registered user; no account enumeration.
- **Org claim and switcher:** the token carries the active org (claim name per research; e.g. `org_id` + optional
  `org_slug`), selectable via an authorization parameter and a switcher page for users in several orgs; consent and
  sessions stay per user.
- **Enterprise OIDC connections** reuse the Phase 4 upstream machinery (connection table, SSRF-guarded client, ID token
  validation, linking rules), scoped to an org instead of the tenant.
- **SAML 2.0 SP:** experimental flag until it passes a signature-wrapping attack corpus (D4). Strict XML handling (no DTDs,
  no external entities), exact signature-reference checks, audience/recipient/destination/time checks, replay protection
  via assertion id cache, signed assertions required. Library choice per research (pure Rust, passes cargo deny, single
  crypto backend aws-lc-rs).
- **JIT provisioning** creates users on first SSO login inside the org, with attribute mapping; never links to an existing
  account without the Phase 4 safe-linking rules.
- **Domain routing:** domains verified by DNS TXT record (resolver through a dedicated, timeout-bounded lookup; no
  user-controlled hostnames beyond the domain itself); identifier-first login routes verified domains to the org IdP;
  a domain belongs to at most one org per tenant.
- **Console:** every managed object administrable (ADM-02), including organizations, members, invitations, org roles,
  org connections, domains, keys and sessions.
- **Phase 5 carry-overs to consider here:**
  - Role/permission claims for opaque tokens and introspection (05-12, deferred because roles get reworked for orgs).
  - Resource URI case folding (05-25) — revisit only if a design need appears; otherwise keep exact matching.
  - Narrowing the browser passkey picker to the step's user at the second-factor step (05-30).

### Claude's Discretion
- Plan decomposition and waves (maximize parallel plans with disjoint files; shared files in early foundation plans).
- Exact claim names, invitation flow details, DNS resolver crate, SAML library (subject to D4), SAML metadata handling.

### Deferred Ideas (OUT OF SCOPE)
- OIDC certification filing, external security review, migration tooling, docs site (Phase 7)
- SCIM provisioning, fine-grained authorization engine (D5, 3.0)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ORG-02 | Tenant admin can create organizations with membership, invitations, org-scoped roles, org claim in tokens and an org switcher | Data model (§Org data model), hybrid role assignment (Pattern 2), `organization` parameter + `org_*` claims bound to the token family (Pattern 3), switcher on the user-bound consent flow (Pattern 4), invitations (Pattern 5), carry-over: claims for opaque tokens/introspection |
| ORG-03 | Organization admin can configure enterprise SSO connections (SAML 2.0 SP, OIDC RP) with JIT provisioning | Org-scoped connections (Pattern 6), SAML SP profile + library analysis (§D4, Pattern 7), ACS hop through the flow (Pattern 8), domain-bound email trust + JIT membership (Pattern 9), org-admin access path (Owner Q1) |
| ORG-04 | Users are routed to their organization's IdP by email domain; domains are verified by DNS TXT record | hickory-resolver TXT adapter behind a core port (Pattern 10), record format per draft-ietf-dnsop-domain-verification-techniques-13, PSL refusal, partial unique index (one verified org per domain), identifier-first login (Pattern 11) |
| ADM-02 | Admin can manage tenants, users, clients, organizations, connections, branding, keys, sessions and the audit log from the console | Gap analysis (§Console/ADM-02): organizations and keys are missing (no keys admin API exists), SAML connection form, org branding scope, new audit actions in the audit page record |
</phase_requirements>

## Standard Stack

### Core (already present, reused)
| Component | Where | Reuse in Phase 6 |
|---|---|---|
| `RoleService`, `UserClaimSource`, `policy::claims_mapping` (`RESERVED_CLAIMS`, `mapped_claims`) | anvil-core `service/role.rs`, `policy/claims_mapping.rs` | Org roles/permissions as two more mapping rules; org claims added to `RESERVED_CLAIMS` |
| Upstream sign-in (`UpstreamService`, `flow::upstream`, `link_decision`, `ConnectionService::open_secret`) | anvil-core | Enterprise OIDC = the `Oidc` config with `org_id`; SAML adds a sibling start/ACS path using the same pending-state and binding-cookie pattern |
| `OutboundClient` (SSRF guard) | anvil-web `adapters/outbound.rs` | SAML metadata URL import; OIDC discovery/JWKS for org connections (unchanged) |
| `GrantRepo::record_jti` + `replay_guard` | ports / both backends | SAML assertion-ID replay cache (new `ReplayKind::SamlAssertionId`) |
| Sealed outbox (`anvilid/outbox-payload/v1`) | anvil-core/mail | Org invitation emails |
| `policy::mfa` (strictest wins) | anvil-core | Gains an org input |
| `KeyRotationService::rotate_now` | anvil-core `service/key_rotation.rs` | Keys admin API (same call as `anvilid keys rotate`) |
| `JobRepo::try_lease` | ports | Domain re-verification job |
| utoipa + `openapi_drift.rs`, `openapi-typescript` | anvil-web, admin-ui | New org/keys routes; one OpenAPI owner per wave |

### New dependencies (versions verified on crates.io 2026-11-26)
| Crate | Version | Purpose | Notes |
|---|---|---|---|
| `bergshamra-dsig` (+ `bergshamra-keys`, `bergshamra-xml`, `bergshamra-core`) | 0.12.0 | XML-DSig verification (exc-c14n, enveloped transform, RSA/ECDSA) | `default-features = false, features = ["aws-lc"]`. BSD-2-Clause. **Pulls `tsp-ltv` 0.6.1 → `chrono` 0.4 (`std`, `clock`) unconditionally**, which the deny ban refuses (Owner Q2). Depend on the sub-crates, not the top `bergshamra` crate: the top crate also pulls `clap` and `bergshamra-enc` |
| `uppsala` | 0.12.1 | The one XML parser (bergshamra's DOM) | BSD-2-Clause, zero deps. `Parser::with_forbid_dtd(true)`; DTDs are **parsed by default**, so the flag is mandatory |
| `hickory-resolver` | 0.26.4 | DNS TXT lookups for domain verification | Default features (`system-config`, `tokio`) pull no ring/TLS. MIT/Apache-2.0. Use a fully qualified name (trailing dot) so `/etc/resolv.conf` search domains never apply |
| `psl` | 2.1.264 | Refuse public suffixes as org domains | Draft-13: "SHOULD NOT allow verification for public suffixes". Updated with the list |
| `flate2` | 1.x, `default-features = false, features = ["rust_backend"]` | DEFLATE for the HTTP-Redirect AuthnRequest | Pure Rust (miniz_oxide). Not in the lock today |
| (tests only) `xml-crypto` (npm) | 6.4.0 | Signs responses in the Playwright mock SAML IdP | Test tooling only, never shipped. MIT |

**Installation (after Q2 is decided):**
```toml
# workspace Cargo.toml
bergshamra-dsig = { version = "0.12.0", default-features = false, features = ["aws-lc"] }
bergshamra-keys = { version = "0.12.0", default-features = false, features = ["aws-lc"] }
bergshamra-xml  = { version = "0.12.0", default-features = false }
uppsala         = "0.12.1"
hickory-resolver = "0.26.4"
psl             = "2.1"
flate2          = { version = "1", default-features = false, features = ["rust_backend"] }
```
```toml
# deny.toml (Q2 option A): chrono allowed only through tsp-ltv
{ crate = "chrono", wrappers = ["tsp-ltv"], reason = "bergshamra-keys -> tsp-ltv (X.509 trust facade) needs chrono; our code stays on `time` (ARCHITECTURE §2)" },
```

### D4: SAML/XML-DSig candidates (evidence)
| Candidate | Pure Rust | Single backend (aws-lc) | cargo-deny as configured | Notes |
|---|---|---|---|---|
| `bergshamra` 0.12.0 (kushaldas) | yes | **yes** (`aws-lc` feature; providers are mutually exclusive, "never fall back to another provider") | **fails: chrono** via `bergshamra-keys` → `tsp-ltv` | Created 2026-02, 25 releases. xmlsec interop suite: Enc 700/0/1, DSig 364/0/86 skipped, **RustCrypto provider only**; alternate providers use "focused capability and policy tests". C14N/transforms are provider-independent, so that evidence carries over to c14n. `trusted_keys_only`, `strict_verification`, duplicate-ID rejection, `VerifiedReference.resolved_node`. No audit statement |
| `saml-rs` 0.8.0 (salasebas) | yes | yes with `crypto-aws-lc` | **fails: chrono** (via bergshamra) | SP + IdP, POST/Redirect/SimpleSign/Artifact, SLO, metadata. README: "the crate has had no external security audit", "Pre-1.0", minor releases may change behaviour. **Two parsers:** quick-xml DOM for extraction and uppsala for verification. Ships `tests/xsw.rs` (10 cases, not the full XSW1–8 set). `InMemoryReplayCache` is single-process |
| `risaml` 0.7.0 / `ribergshamra` 0.11.0 | yes | ? | chrono via `ritsp-ltv` (same shape) | Self-described "maintained forks" created 2026-09-26 with low downloads. Avoid: unclear provenance |
| `saml` 0.1.0-alpha.5 | yes | **no**: RustCrypto `rsa` 0.10 unconditional | **fails: rsa ban** | Alpha |
| `xml-sec` 0.6.0 | yes | **no**: the `xmldsig` feature enables RustCrypto RSA (`sad-rsa`), ed25519-dalek, p256…; `aws-lc-fips` only adds aws-lc on top | second backend | Apache-2.0 AND MIT |
| `samael`, `xmlsec` | no (libxml2/xmlsec1) | no | banned | |
| In-house narrow verifier (roxmltree/uppsala + aws-lc-rs) | yes | yes | passes | Hand-rolled exclusive C14N, which is the area of the "void canonicalization" bypasses. Contradicts the research rule "no hand-rolled crypto primitives" and the "C14N tests from a public corpus" condition (docs/research/04-tech-stack.md) |

**Alternatives considered:**
| Instead of | Could use | Tradeoff |
|---|---|---|
| bergshamra-dsig + own SAML layer | saml-rs | Much less code to write, but two parsers (parser-differential class), a large surface we don't need (IdP, SLO, artifact, SOAP) and pre-1.0 churn (16 releases in 5 months). Useful as a **reference** for checks |
| hickory-resolver | `domain` 0.13.0 (NLnet Labs) | Fine, but less common as a stub resolver; hickory has `system-config` and a simple `txt_lookup` |
| `psl` | no PSL check | DNS control already proves ownership. The draft still says SHOULD NOT, and the crate is cheap |

## Architecture Patterns

### Recommended module layout (new files; keeps parallel plans disjoint)
```
crates/anvil-core/src/
  model/organization.rs        Organization, Membership, Invitation, OrgDomain, OrgSettings, ids
  model/saml.rs                SamlConfig, SamlAttributeMapping, NameIdFormat (ConnectionConfig::Saml)
  policy/org_claims.rs         active-org resolution + org_* claims (pure)
  policy/home_realm.rs         domain normalisation, PSL/label rules, routing decision (pure)
  policy/domain_verification.rs record name/value format, token check (pure)
  saml/mod.rs                  pure SAML SP rules on an extracted, already-verified assertion struct
  saml/request.rs              AuthnRequest XML (escaped template), RelayState, redirect URL building
  saml/validate.rs             Destination/InResponseTo/Issuer/Audience/Recipient/time/bearer checks
  service/organization.rs      OrgService (CRUD, members, invitations, domains, org roles via RoleService)
  service/saml.rs              SamlService (start, acs, continue) mirroring UpstreamService
crates/anvil-web/src/
  adapters/saml_xml.rs         uppsala parse (forbid_dtd, caps) + profile pre-check + bergshamra verify + extraction
  adapters/dns_txt.rs          hickory-resolver TXT lookup (timeouts, FQDN, uniform errors)
  admin/organizations.rs       org CRUD, members, roles, invitations, domains, org connections
  admin/keys.rs                signing keys list + rotate
  ui/organization.rs           /ui/select-organization, /ui/invitation
  ui/saml.rs                   /ui/login/saml/{slug} start, /acs (POST), /continue (GET), /metadata
admin-ui/src/routes/t/$tenant/organizations/{index,new,$orgId}.tsx (+ tabs: members, invitations,
  roles, connections, domains, branding), keys/index.tsx
```

### Org data model (both backends; SQLite `0008_release_1_0.sql` additive + `0009_release_1_0_rebuild.sql`, Postgres `0007_release_1_0.sql`)
| Table | Columns | Constraints |
|---|---|---|
| `organization` | id, tenant_id, slug, display_name, mfa_policy (nullable), settings (JSON), metadata (JSON), created_at, updated_at | UNIQUE (tenant_id, slug); UNIQUE (tenant_id, id) as composite FK target; refused in the `system` tenant (service rule) |
| `org_membership` | tenant_id, org_id, user_id, created_at | PK (tenant_id, org_id, user_id); FK (tenant_id, org_id) → organization CASCADE; FK (tenant_id, user_id) → user CASCADE |
| `org_invitation` | id, tenant_id, org_id, email (normalised), roles (JSON role ids), token_hash (SHA-256, UNIQUE), invited_by (actor JSON), created_at, expires_at, accepted_at, accepted_user_id, revoked_at | FK org CASCADE; accept = one conditional UPDATE (`accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now`) inside the accept intent |
| `org_domain` | id, tenant_id, org_id, domain (lowercase A-label), token, status (pending/verified), connection_id (nullable, routing target), routing (bool), verified_at, last_checked_at, created_at | FK org CASCADE; **partial UNIQUE (tenant_id, domain) WHERE verified_at IS NOT NULL** (one verified org per domain); several orgs may hold pending claims |
| `role` (rebuilt) | + FK (tenant_id, org_id) → organization CASCADE | UNIQUE (tenant_id, org_id, name) WHERE org_id IS NOT NULL (tenant-level index unchanged) |
| `role_assignment` (rebuilt) | + org_id (nullable) | Partial UNIQUE (tenant_id, role_id, user_id) WHERE org_id IS NULL, and (tenant_id, role_id, user_id, org_id) WHERE org_id IS NOT NULL; FK (tenant_id, org_id, user_id) → org_membership CASCADE (MATCH SIMPLE: not checked when org_id is NULL, both engines) |
| `connection` (rebuilt) | + org_id (nullable); kind CHECK gains `saml` | FK (tenant_id, org_id) → organization CASCADE |
| `authorization_code`, `token_family` | + org_id (nullable, ADD COLUMN) | No FK; deleting an org or a membership revokes the org-bound families in the same intent (reason `admin`: no CHECK change) |
| `replay_guard` (rebuilt) | kind CHECK gains `saml_assertion_id` | |
| `email_template` (rebuilt) | kind CHECK gains `org_invitation` | |
| `branding` | scope_key gains `org:{uuid}` (TEXT, no CHECK) | Precedence client > org > tenant |

### Pattern 1: SQLite rebuild of referenced tables (no-transaction procedure)
**What:** `connection` (referenced by `identity_link` CASCADE) and `role` (referenced by `role_assignment` CASCADE) must be rebuilt to change CHECKs and add composite FKs. With `foreign_keys = ON`, `DROP TABLE connection` runs an implicit `DELETE` that cascades to every identity link.
**How:** follow `crates/anvil-storage-sqlite/migrations/0004_release_0_2_token_family.sql`:
- the file starts with `-- no-transaction` and turns `PRAGMA foreign_keys = OFF` before an explicit `BEGIN`;
- create `x_new`, copy every row, `DROP TABLE x`, `ALTER TABLE x_new RENAME TO x`, recreate the indexes;
- insert `(SELECT count(*) FROM pragma_foreign_key_check)` into a temp table whose CHECK accepts only 0, then `COMMIT` and `PRAGMA foreign_keys = ON`;
- annotate the file `-- anvil:non-destructive-rebuild` for `scripts/check-migrations.sh`.

Keep the additive part (new tables, ADD COLUMN) in a separate, normal transactional file, so a rebuild failure leaves the additive schema intact and the lint stays readable.
**Postgres:** `ALTER TABLE connection DROP CONSTRAINT connection_kind_check, ADD CONSTRAINT connection_kind_check CHECK (...)`. Inline CHECKs are auto-named `{table}_{column}_check`, as `0004_release_0_3.sql` did for flow. Composite FKs come through `ADD CONSTRAINT … FOREIGN KEY`. On `role_assignment`, drop the `role_assignment_pkey` constraint and add the two partial unique indexes. The lint allows `DROP CONSTRAINT`.
**Test:** `tests/upgrade.rs` 0.4 → 1.0 in both crates, with fixtures holding identity links and role assignments. Row counts must be equal after the upgrade, and the contract suite must pass.

### Pattern 2: Org-scoped roles = one assignment table, hybrid definitions
**What:** Auth0's docs describe two kinds of org roles: tenant roles ("Defined at the tenant level") assigned to org members, and roles "Scoped to a specific Organization". Support both without a parallel system:
- A tenant-level role (`org_id NULL`) assigned with `role_assignment.org_id = X` holds only in org X.
- An org-owned role (`role.org_id = X`) can only be assigned with `assignment.org_id = X` (service check plus a contract test).
- A tenant-wide assignment (`org_id NULL`) works as in 0.4.

`RoleRepo` gains `roles_for_user_in_org(tenant, user, org)`. `UserClaimSource::load` takes `active_org: Option<OrgId>` and returns tenant roles and org roles separately.
**Never:** org roles granting `admin:*` (`is_reserved_admin_token` refuses them, as for clients); orgs in the `system` tenant.

### Pattern 3: Active org bound to the grant, claims recomputed per issuance
**What:**
- `/authorize` accepts `organization` (an org id or slug; Auth0 uses the same parameter name). It is stored in `authorization_request.params` (JSON, no schema change), resolved after sign-in, then copied to `authorization_code.org_id` and `token_family.org_id`.
- Refresh keeps the family's org. Switching orgs means a new authorization request (`organization=Y`, optionally `prompt=none`). There is **no** non-standard refresh parameter.
- At code exchange and at every refresh, `UserClaimSource` reloads membership and roles. A user no longer in the org gets `invalid_grant`. The membership-removal intent revokes the user's families with that `org_id` in the same transaction, so this is belt and braces.

**Claims (discretion, recommended):**
- `org_id` (UUID string) and `org_slug`, in the ID token, the JWT access token, UserInfo and introspection.
- `org_roles` and `org_permissions` as two new `ClaimMappingSettings` rules (defaults mirror `roles`/`permissions`: `org_roles` gated by scope `roles`, `org_permissions` in the access token only).
- Add `org_id` and `org_slug` to `RESERVED_CLAIMS` so mapped attributes can't spoof them.

Precedents: Auth0 emits `org_id` (plus optional `org_name`) and tells APIs to validate it. WorkOS emits `org_id`, `role` and `permissions`, and switches orgs on refresh with `organization_id`.

**Client policy (discretion):** add `client.organization` = `off` (default; no claim, the parameter is refused) / `optional` / `required`. With `required`, a user in no org gets `access_denied`. A user in several orgs who sent no `organization` sees the switcher.

### Pattern 4: Org switcher on the existing user-bound flow
**What:** `/ui/select-organization?request=` reuses the user-bound `FlowKind::Consent` flow, as `/ui/select-account` does (ARCHITECTURE §9). This avoids widening `flow.kind`, whose CHECK change on SQLite would mean another rebuild. Only the user's memberships are listed. The choice is written to the stored authorization request by compare-and-swap. Effective MFA is then re-evaluated with the org's policy, and the existing step-up path upgrades the session if the org is stricter.

### Pattern 5: Invitations
**What:**
- Create: `org_invitation` row with a 256-bit token stored as SHA-256 and an expiry (7 days, like `INVITATION_TTL`). The email goes through the sealed outbox with the new template kind `org_invitation`. The admin response is identical whether or not the address has an account. Unlike the 0.1 admin invite, **no user is created**.
- Link `GET {issuer}/ui/invitation?token=` shows only a button and consumes nothing, like the magic link.
- `POST`, signed in, as a user whose **verified** email equals the invited email: accept. The atomic intent consumes the token, adds the membership and the role assignments, and is audited.
- `POST`, signed in as anyone else: offer "sign in with another account", and keep the token.
- `POST`, not signed in: show sign-in or registration with the email prefilled and locked. Registration through an invitation marks the email verified, because the link proves inbox control. It is allowed under `invite_only` and refused under `disabled`.

### Pattern 6: Org-scoped connections
**What:** `connection.org_id` set means the connection is an org's enterprise connection.
- It never appears as a button on the tenant sign-in page. It is reached through domain routing, the `organization` parameter or `login_hint`.
- The slug stays unique per tenant (same callback URL format).
- The Oidc variant is reused unchanged.
- Tenant config YAML (ADM-06) must **exclude org-scoped connections and org-owned roles** from export, plan and `--prune`. Otherwise an apply with prune deletes them, the same trap as runtime clients (`plan_excluding`).

### Pattern 7: SAML SP profile (deliberately narrow)
- **Scope:**
  - SP-initiated Web Browser SSO only. AuthnRequest over HTTP-Redirect (DEFLATE + base64 + URL-encode), unsigned in 1.0 (discretion; an RSA-SHA256 query-string signature with aws-lc needs no XML-DSig and can come later).
  - Response over HTTP-POST.
  - **Signed `Assertion` required**. A signed `Response` is verified too if present, and a present but invalid signature rejects.
  - `EncryptedAssertion` is refused with an explicit error. SP metadata publishes no encryption key, so IdPs don't encrypt.
  - No SLO, artifact or ECP. Unsolicited (IdP-initiated) responses are refused (Owner Q4).
- **Config** (`ConnectionConfig::Saml`): `idp_entity_id`, `sso_url` (https), `signing_certs` (1–3 PEM certs, for rollover), `name_id_format` (default `unspecified`), attribute mapping (email, given_name, family_name, name; names or friendly names), `metadata_url` (optional, fetched through `OutboundClient`). Only the public key of each cert is used. Chain and expiry are ignored; the console warns about expired certs.
- **SP identifiers:** entity ID `{issuer}/saml/{slug}`, ACS `{issuer}/ui/login/saml/{slug}/acs`, metadata `GET {issuer}/saml/{slug}/metadata` (unsigned XML, generated from an escaped template).
- **RelayState:** `{flow_id}.{base64url(16 random bytes)}`, 59 bytes, under the Bindings 80-byte RelayState limit (§3.4.3/3.5.3, MEDIUM).

### Pattern 8: ACS processing (POST validates, GET continues with the binding cookie)
The IdP's POST is cross-site, so neither the `Strict` flow cookie nor the `Lax` binding cookie arrives. This mirrors the Apple `form_post` hop (`UpstreamService::form_post`).
1. `POST /ui/login/saml/{slug}/acs` sits outside the Fetch-Metadata CSRF layer, like the upstream callback, with a dedicated body limit of 256 KiB (the logo-upload precedent).
2. Split RelayState and load the flow and its pending SAML request (request ID hash, connection id, freshness). Then verify fully (Pattern 7 + Code Example 1) against `InResponseTo`.
3. Record the assertion ID in `replay_guard`: kind `saml_assertion_id`, value `sha256(idp_entity_id ‖ 0x00 ‖ ID)`, expiry = min(`NotOnOrAfter`, now + 1 h) and at least now + skew.
4. Seal the extracted identity (not the XML) into the flow by compare-and-swap. Answer 303 to `GET …/continue?state=`.
5. `GET continue` checks the binding cookie hash, then follows the Phase 4 path: link decision (Pattern 9), JIT, MFA, session.

### Pattern 9: Enterprise email trust = verified org domain
Phase 4's `link_decision` folds trust into `UpstreamIdentity.email_verified`. For org connections:

`email_verified := email present ∧ email's domain ∈ verified domains of the connection's org ∧ (SAML: true | OIDC: upstream email_verified strict true)`

Otherwise the email is untrusted: never auto-linked, and a match needs confirmation. This stops a customer's IdP from asserting addresses at someone else's domain (cross-org account takeover).

JIT creates the user, the identity link **and the org membership** in one transaction (extend `ConnectionRepo::create_user_with_link` with `Option<&NewMembership>`). It applies the attribute mapping, and default org roles if configured. A sign-in through an org connection by an existing linked user who is not a member adds the membership (JIT membership).

### Pattern 10: DNS TXT domain verification
- **Record** (draft-ietf-dnsop-domain-verification-techniques-13, BCP-intended, not yet an RFC): name `_anvilid-challenge.{domain}.`, value `anvilid-domain-verification={token}`, with a 128-bit random token encoded base32 without padding (the draft recommends base32/hex for DNS). Verified if **any** TXT RR of the RRset matches exactly, after joining the character-strings of one RR.
- **Lookup:** a `DomainTxtLookup` port in core and a hickory adapter in web; `AppDeps` gains it, the binary wires hickory and tests wire a fake in test code.
  - `ResolverOpts { timeout: 2 s, attempts: 2, cache_size: 0, ndots: 0, .. }`, plus a `tokio::time::timeout` of 5 s overall. Query an FQDN.
  - Every failure (NXDOMAIN, SERVFAIL, timeout, no match) maps to one `NotVerified` outcome, so an org admin can't probe internal DNS.
  - Optional operator key `domain_verification_resolvers` (list of IPs); the system config otherwise.
- **Domain input rules:**
  - trim, lowercase, IDNA to A-label (`idna`, already in the lock);
  - no scheme, port, path or wildcard; at least two labels, each label 1–63, total ≤ 253;
  - not an IP literal; not `localhost`, `*.local`, `*.internal`, `*.localhost`, `*.invalid`, `*.test`, `*.example`;
  - **not a public suffix** (`psl`) and must have a known ICANN suffix.
- **Verify:** an atomic intent sets `verified_at` only if no other verified row exists (the partial unique index decides: `Conflict`). Audited.
- **Re-check:** a daily leased job re-verifies verified domains. After 7 consecutive days of failure the domain drops to `pending`, routing stops, and the change is audited and emitted as a webhook event. Draft-13 asks persistent validations to state their re-validation frequency, so document it.

### Pattern 11: Identifier-first login (home-realm discovery)
- **Off** when the tenant has no verified domain with routing on: the current combined form is unchanged, and so are the e2e and no-JS suites.
- **On:**
  - The first page asks for the email only. Passkey (usernameless) and the social buttons stay on that page.
  - The routing decision is `policy::home_realm::route(domain) -> Route::Sso(connection) | Route::Local` from the **domain only**.
  - `Local` renders the password step for **every** non-routed address, whether or not an account exists. Same page, same timing, so there is no enumeration.
  - `login_hint` with an email, or `organization` with a single routed connection, skips straight to the IdP.
- **Password for routed domains** (Owner Q7). Recommendation: route by default, with a per-domain `allow_local_password` (default false) that shows a "Use password instead" link.

### Anti-Patterns to Avoid
- **Two XML parsers** (one for verifying, one for reading). Extract only from the uppsala node that bergshamra verified (`resolved_node`), in the same `Document`.
- **Library-chosen signature** (`verify_document*` takes the *first* `<Signature>` in document order). Locate the expected signature by exact path (`Response/Assertion/ds:Signature`, direct child), refuse any other `ds:Signature` in the document, and use `verify_all_document_with_source`, mapping results by position.
- **Calling bergshamra before the profile pre-check.** Its reference resolver falls back to reading **local files relative to the process CWD** for non-fragment `Reference URI`s (`read_relative_reference_uri`). Refuse everything except exactly one `Reference` whose URI is `#` + the assertion's `ID` before any library call.
- **Trusting `KeyInfo`.** Keys come only from the connection (`with_trusted_keys_only(true)`).
- **Org claim from the session or a cookie.** Only the grant (code/family) carries it; consent and sessions stay per user.
- **A second invitation or replay mechanism.** Use `replay_guard`/`record_jti` and the outbox. `org_invitation` is a new aggregate only because `self_service_token` requires a `user_id`.
- **Domain suffix as authorization.** Routing is a convenience. Authorization decisions use memberships and verified domains stored as normalised values, never a re-parse of IdP XML (PortSwigger's "Fragile Lock" advice).

## SAML profile checks (each one is a negative test)

Sources: OWASP SAML Security Cheat Sheet (cites Profiles 4.1.4.1–4.1.4.3 and 4.1.5, Core 3.2.2.1, 5.3, 5.4 and errata E93); SAML 2.0 Bindings §3.4/3.5; implementer practice. Section numbers are MEDIUM (PDFs not machine-readable here).

1. **Transport/parse:**
   - POST form field `SAMLResponse`, base64 decoded size ≤ 256 KiB;
   - uppsala with `forbid_dtd(true)`, depth ≤ 64, a node cap;
   - UTF-8 only; no processing instructions outside the prolog.
2. **Structure:**
   - root `{urn:oasis:names:tc:SAML:2.0:protocol}Response` (namespace URI, not prefix), `Version="2.0"`;
   - exactly one `{…:assertion}Assertion` child; `EncryptedAssertion` refused;
   - duplicate `ID` attributes anywhere refused;
   - unqualified `ID` only, and an element carrying both `ID` and `*:ID` is refused (attribute pollution).
3. **Response:**
   - `Destination` == ACS URL exactly (required);
   - `InResponseTo` == the pending request ID;
   - `Status/StatusCode` == Success, else a generic failure audited with the status code only;
   - `Issuer`, if present, == `idp_entity_id`;
   - `IssueInstant` within skew.
4. **Signature profile pre-check** (before crypto):
   - the Assertion has exactly one direct `ds:Signature` child;
   - the Response has at most one direct `ds:Signature` child, and no other `ds:Signature` exists anywhere;
   - `SignedInfo` has exactly one `Reference`, `URI="#{Assertion/@ID}"`;
   - `Transforms` are exactly [enveloped-signature, exc-c14n (optional `InclusiveNamespaces PrefixList`)];
   - `CanonicalizationMethod` is exc-c14n without comments;
   - `SignatureMethod` ∈ {rsa-sha256, rsa-sha384, rsa-sha512, ecdsa-sha256, ecdsa-sha384}; `DigestMethod` ∈ {sha256, sha384, sha512}. SHA-1, HMAC, XPath and XSLT are refused.
5. **Crypto:** bergshamra with only the connection's keys, `strict_verification(true)`, every reference digest verified, `resolved_node` == the pre-checked Assertion node.
6. **Assertion (read from the verified node only):**
   - `Issuer` == `idp_entity_id`.
   - `Subject/NameID`: non-empty; text = all text nodes; refused if it contains comments or child elements (comment injection, CVE-2017-11427 class).
   - `SubjectConfirmation Method=bearer` with `SubjectConfirmationData`: `Recipient` == ACS, `NotOnOrAfter` > now − skew, `InResponseTo` == the request ID.
   - `Conditions`: `NotBefore`/`NotOnOrAfter` with skew 90 s. **Every** `AudienceRestriction` contains the SP entity ID.
   - An `AuthnStatement` is present.
7. **Replay:** `record_jti` insert-or-fail (Pattern 8). A second POST of the same response fails even on another node (DB-backed).
8. **Errors:** one generic page. Audit `saml_login_failed` with a reason code only (never XML, NameID or attribute values).

## Attack corpus for D4 (in-repo, generated at test time)

A test-only IdP signer (`crates/anvil-web/tests/saml_support/`) builds responses and signs them with `bergshamra-dsig` `sign` (aws-lc) under keys generated at test time. No private key is committed. Each case asserts a rejection with the expected audit reason:

- **XSW1–XSW8** from Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012), the variants SAML Raider automates. Secondary write-ups disagree on the exact numbering, so define each case by its structure in the test, not by name only: cloned assertion before/after the signed one; the signed assertion wrapped in `Extensions`, `Object`, `SubjectConfirmationData` or `Advice`; the signature moved to a sibling; the forged assertion as the root's child with the original moved into the signature.
- **Signature exclusion:** unsigned assertion, signed Response with an unsigned assertion, empty `SignatureValue`.
- **Key injection:** a valid signature by an attacker key embedded in `KeyInfo`.
- **Comment injection** in NameID and in attribute values.
- **Parser-differential shapes** (ruby-saml CVE-2025-25291 DOCTYPE and CVE-2025-25292 namespace confusion): DOCTYPE present (refused at parse), redefined `ds`/`saml` prefixes, `xmlns` tricks, attribute pollution (`ID` + `samlp:ID`).
- **Overly broad signature lookup:** a valid IdP-signed element (for example signed metadata or another response) placed in `Extensions` with the forged assertion unsigned.
- **Void canonicalization:** a relative namespace URI in a transform or the element; the expectation is an error, never a digest over empty input (PortSwigger "The Fragile Lock", 2025).
- **Algorithm downgrade:** SHA-1 signature or digest; HMAC `SignatureMethod`; XPath/XSLT transforms; extra or missing transforms; `Reference URI=""`; a `Reference URI="some/file"` (must not touch the filesystem); two References.
- **Duplicate IDs;** a second assertion; `EncryptedAssertion`.
- **Conditions:** wrong `Destination`, `Recipient`, `Audience` (one of two restrictions missing), `InResponseTo`, issuer; expired or not yet valid; replay of the same assertion ID.
- **XML bombs:** DTD with entities (billion laughs), external entity, deep nesting, an oversized body (413).

The corpus is the gate for D4. Passing it is **necessary, not sufficient**, for lifting the experimental flag (Owner Q3).

## Console / ADM-02 gap analysis

| Object | API today | Console today | Phase 6 work |
|---|---|---|---|
| Tenants, users, clients, sessions, audit log, branding (tenant/client), connections (social/OIDC/OAuth2) | yes | yes (`routes/t/$tenant/*`) | Users page: org memberships tab. Audit page: add every new audit action to its action record (05-12 found this record breaks `npm run typecheck` when actions are added) |
| **Organizations** (members, invitations, org roles, connections, domains, org branding) | no | no | New `admin/organizations.rs` + console section |
| **Signing keys** | **no admin API** (only `anvilid keys rotate`) | no | `GET /tenants/{slug}/keys` (kid, alg, state, activated/retired/expires; never private material), `POST /tenants/{slug}/keys/rotate {alg, immediate}` → `KeyRotationService::rotate_now` with the admin actor, audited. Scope `admin:settings:{read,write}` (the `Settings` resource doc already names signing keys); `admin:write` for the system tenant |
| SAML connections | no | no | Connection form variant (metadata paste or URL import, certs, mapping, SP values to copy: entity ID, ACS, metadata URL) with an "Experimental" badge |

New admin resource scope `admin:organizations:{read,write}`: add it to `Resource` and `ALL_ADMIN_SCOPES`, and prove it in a new `security_admin_v10.rs`, following the per-release precedent.

## Don't Hand-Roll

| Problem | Don't build | Use instead | Why |
|---|---|---|---|
| XML canonicalization + XML-DSig | own exc-c14n/DSig | `bergshamra-dsig` (aws-lc) | C14N edge cases are where real bypasses live (void canonicalization, namespace handling) |
| XML parsing with entity/DTD safety | regex/string scanning, a second parser | uppsala `Parser::with_forbid_dtd(true)` | One parser for verifying and reading |
| DNS wire protocol | raw UDP TXT queries | `hickory-resolver` `txt_lookup` | Truncation/TCP fallback, multi-string TXT, resolv.conf parsing |
| Public suffix list | a hardcoded TLD list | `psl` | The list changes constantly |
| IDNA | own punycode | `idna` (already in the lock) | |
| DEFLATE | own | `flate2` rust_backend | |
| Replay cache, sealed values, email delivery, job leasing | new tables/workers | `replay_guard`, KEK seal, outbox, `JobRepo::try_lease` | One implementation per concern |
| Org claim pipeline | a separate claim builder | `UserClaimSource` + `claims_mapping` rules | One claims implementation; reserved-claim checks already there |

**Key insight:** for SAML, the risk sits in the glue more than in the crypto: which element was signed versus which element is read. Narrow the accepted profile until every check can be stated and tested, and read only from what was verified.

## Common Pitfalls

### Pitfall 1: SQLite rebuild cascades away identity links or role assignments
**What goes wrong:** Rebuilding `connection` or `role` in a normal transactional migration deletes their children through ON DELETE CASCADE, and the upgrade silently loses data.
**How to avoid:** Use the `-- no-transaction` procedure (Pattern 1) and an upgrade test with fixtures that counts rows.
**Warning signs:** the upgrade test passes on empty databases only.

### Pitfall 2: Parser differential between verification and extraction
**What goes wrong:** One parser verifies the signature and another reads the claims, so an attacker crafts XML the two see differently (ruby-saml 2025).
**How to avoid:** Use one uppsala `Document` and read claims from the verified `NodeId`. Never re-parse the bytes.

### Pitfall 3: bergshamra file-read fallback
**What goes wrong:** A `Reference URI="relative/path"` makes the verifier read a local file relative to the CWD before the signature check.
**How to avoid:** Run the profile pre-check first. Test that a file-URI reference is refused without filesystem access (place a file at the referenced relative path in a temp CWD and assert the result is the profile error, not a digest result).

### Pitfall 4: First-signature lookup
**What goes wrong:** `verify_document_with_source` verifies the first `<Signature>` in the document.
**How to avoid:** Pin the signature by path and refuse stray signatures (Anti-patterns).

### Pitfall 5: DTD parsing on by default in uppsala
**How to avoid:** Always build the parser with `with_forbid_dtd(true)`. A test sends a DOCTYPE without entities and expects a refusal.

### Pitfall 6: Cross-site ACS POST has no cookies
**What goes wrong:** SameSite=Lax cookies are not sent on a cross-site POST, so a binding-cookie check at the ACS always fails, or tempts someone to drop it.
**How to avoid:** POST validates and seals, GET checks the binding (Pattern 8).

### Pitfall 7: A customer IdP asserts someone else's email
**What goes wrong:** An org's SAML or OIDC IdP can assert any email, which enables auto-link takeover.
**How to avoid:** Trust only verified-domain emails of the same org (Pattern 9). Test: org A's IdP asserts `victim@orgB.example` (verified by org B) and the result is never an auto-link.

### Pitfall 8: Tenant config YAML prunes org objects
**What goes wrong:** `apply --prune` deletes org connections and org roles that are absent from the document.
**How to avoid:** Exclude them in export, plan and prune, and test it.

### Pitfall 9: Org claim drift on refresh
**What goes wrong:** A removed member keeps refreshing tokens that still say `org_id`.
**How to avoid:** Revoke in the removal intent and re-check at refresh (Pattern 3).

### Pitfall 10: Enumeration via identifier-first or invitations
**How to avoid:**
- Route only on the domain; render the password step for every non-routed email.
- The invitation API answers identically whether or not the address has an account.
- The accept page never names the existing account.

### Pitfall 11: DNS probing and search domains
**What goes wrong:** A relative name plus resolv.conf `search` queries internal zones, and distinct error messages leak whether internal names exist.
**How to avoid:** FQDN queries, `ndots: 0`, one uniform outcome, PSL and reserved-name refusal.

### Pitfall 12: The hickory resolver cache hides a fresh TXT record
**What goes wrong:** An admin publishes the record, clicks "verify", and gets a cached negative answer.
**How to avoid:** `cache_size: 0` for the verification resolver (draft-13 §6.4 also suggests a low negative caching TTL).

### Pitfall 13: New audit actions break three places
**What goes wrong:** `policy::webhook_event::classify` matches `AuditAction` exhaustively (compile error by design), the console audit page has an action record (typecheck), and `security_admin_v10`/`check-security-tests.sh` must list the new controls.
**How to avoid:** The foundation plan adds all new `AuditAction`s and their webhook classification. The console plan updates the audit record.

### Pitfall 14: OpenAPI and `schema.d.ts` conflicts between parallel plans
**How to avoid:** One OpenAPI owner per wave (Phase 5 rule). Org API and keys API in different waves, or in one plan.

### Pitfall 15: RelayState too long
**What goes wrong:** Some IdPs (OpenSAML logs a warning) reject RelayState over 80 bytes.
**How to avoid:** Use the 59-byte format of Pattern 7.

### Pitfall 16: SAML clock and X.509 validity in the library
**What goes wrong:** The library's own certificate time checks use system time, not the core `Clock`, and IdP certs are often expired self-signed certs.
**How to avoid:** Skip X.509 time and chain checks for pinned keys (`skip_time_checks`, keys from config). Do all assertion time checks in core with the injected clock (fake clock in tests).

### Pitfall 17: Single-tenant data in a multi-node cluster
**What goes wrong:** Any in-memory replay cache (saml-rs's `InMemoryReplayCache`) is per node.
**How to avoid:** The DB-backed `replay_guard` works across nodes (OPS-03).

## Code Examples

### 1. Verify-then-read from the same DOM (sketch; API names from bergshamra-dsig 0.12.0 / uppsala 0.12.1 sources, MEDIUM until the spike compiles it)
```rust
// crates/anvil-web/src/adapters/saml_xml.rs (sketch)
let doc = uppsala::Parser::new()
    .with_forbid_dtd(true)
    .with_max_depth(64)
    .parse(xml)?;                                   // the one parser
let pre = profile::precheck(&doc)?;                 // root, single Assertion, pinned ds:Signature,
                                                    // one Reference "#"+Assertion/@ID, transform and
                                                    // algorithm allow-lists, no stray signatures
let mut keys = bergshamra_keys::KeysManager::new();
for pem in &cfg.signing_certs { keys.add_key(bergshamra_keys::loader::load_x509_cert_pem(pem.as_bytes())?); }
let ctx = bergshamra_dsig::DsigContext::new(keys)
    .with_trusted_keys_only(true)                   // never KeyInfo keys
    .with_strict_verification(true)
    .with_require_reference_digests(true)
    .with_skip_time_checks(true);                   // time checks happen in core on the fake-able Clock
let results = bergshamra_dsig::verify::verify_all_document_with_source(&ctx, &doc, Some(xml))?;
let assertion_sig = results.get(pre.assertion_signature_index).ok_or(SamlXmlError::Signature)?;
let VerifyResult::Valid { references, .. } = assertion_sig else { return Err(SamlXmlError::Signature) };
if references.len() != 1 || references[0].resolved_node != Some(pre.assertion_node) || !references[0].digest_verified {
    return Err(SamlXmlError::Signature);
}
if let Some(i) = pre.response_signature_index { require_valid(&results[i])?; } // present => must verify
let extracted = extract::assertion(&doc, pre.assertion_node)?;  // read ONLY below the verified node
// core: saml::validate::check(&extracted, &expected, clock.now()) -> Result<SamlIdentity, SamlReject>
```

### 2. DNS TXT lookup (hickory-resolver 0.26)
```rust
// crates/anvil-web/src/adapters/dns_txt.rs (sketch)
let mut opts = ResolverOpts::default();
opts.timeout = Duration::from_secs(2);
opts.attempts = 2;
opts.cache_size = 0;
opts.ndots = 0;
let resolver = hickory_resolver::Resolver::builder_tokio()?.with_options(opts).build()?;
let fqdn = format!("_anvilid-challenge.{domain}.");           // trailing dot: no search domains
let found = tokio::time::timeout(Duration::from_secs(5), resolver.txt_lookup(fqdn)).await;
let matched = matches!(found, Ok(Ok(ref l)) if l.iter().any(|txt| {
    let joined: Vec<u8> = txt.txt_data().iter().flat_map(|s| s.iter().copied()).collect();
    joined == expected.as_bytes()                              // "anvilid-domain-verification=<token>"
}));
// any error or no match -> DomainCheck::NotVerified (uniform)
```

### 3. Effective MFA with org (pure, `policy::mfa`)
```rust
pub fn effective_policy(tenant: MfaPolicy, org: Option<MfaPolicy>, client: Option<MfaPolicy>) -> MfaPolicy {
    [Some(tenant), org, client].into_iter().flatten().max().unwrap_or(tenant) // Required > Optional > Off
}
```

### 4. Claim mapping extension (model)
```rust
pub struct ClaimMappingSettings {
    pub roles: Option<ClaimRule>,
    pub permissions: Option<ClaimRule>,
    pub org_roles: Option<ClaimRule>,        // default "org_roles": AT, ID, UserInfo; scope "roles"
    pub org_permissions: Option<ClaimRule>,  // default "org_permissions": AT only
}
// RESERVED_CLAIMS += "org_id", "org_slug"
```

## State of the Art

| Old approach | Current approach | When changed | Impact |
|---|---|---|---|
| SAML in Rust needed libxml2/xmlsec (samael) | Pure-Rust stacks (bergshamra, saml-rs) exist, all pre-1.0 and unaudited | 2026 | Feasible behind an experimental flag; D4 stays open until corpus + review |
| XSW defences = "check the reference" | Parser differentials, attribute pollution, void canonicalization (ruby-saml CVE-2025-25291/25292; PortSwigger "The Fragile Lock", 2025) | 2025 | One parser, read only the verified node, error on any c14n failure |
| Ad-hoc apex TXT verification | Underscore-prefixed challenge names, expiry and re-validation guidance (draft-ietf-dnsop-domain-verification-techniques-13, 2026-06) | 2023–2026 | `_anvilid-challenge` label, documented re-check |

**Deprecated/outdated:** SHA-1 signatures and digests in SAML; trusting `KeyInfo` certificates; XPath `//ds:Signature` selection.

## Resolved here (no owner decision needed)

1. **Claim and parameter names.** `organization` at `/authorize`; `org_id`, `org_slug`, `org_roles`, `org_permissions` (Pattern 3). Per-client `organization` policy `off|optional|required`, default `off`.
2. **Switching** is a new authorization request; the org is bound to the token family; no refresh extension.
3. **Switcher** reuses the user-bound consent flow kind (no `flow.kind` change).
4. **Invitations:** `org_invitation` table, new `org_invitation` email template kind, no user created at invite time, accept by POST only.
5. **Replay:** `replay_guard` kind `saml_assertion_id` via `record_jti`.
6. **Membership/org removal** revokes org-bound families with reason `admin` (avoids a `token_family` rebuild).
7. **Orgs in the `system` tenant** are refused.
8. **Effective MFA** = strictest(tenant, active org, client).
9. **Org branding** scope `org:{id}`, precedence client > org > tenant (UI-03 names org overrides; §10.7 defers orgs to Phase 6).
10. **Keys admin API** under `admin:settings` (ADM-02 needs it).
11. **Carry-over, opaque/introspection claims:** introspection and UserInfo for opaque tokens call the same `UserClaimSource` (roles, permissions, org claims) from the family's user and org. One implementation.
12. **Carry-over, resource URI case folding:** keep exact matching (no design need appeared).
13. **Carry-over, passkey picker:** at the second-factor step, pass the step user's credential ids as `allowCredentials` (the server already checks ownership). A small independent plan; negative test: another user's passkey is still refused server-side.
14. **SAML AuthnRequest** unsigned in 1.0; no encryption; SP metadata without an encryption key; SLO out of scope.
15. **DNS crate:** hickory-resolver 0.26.4; record `_anvilid-challenge.{domain}` TXT `anvilid-domain-verification={token}`.
16. **SQLite migrations** split into additive `0008_release_1_0.sql` and `0009_release_1_0_rebuild.sql` (`-- no-transaction`); Postgres `0007_release_1_0.sql`.

## Open Questions (owner decision needed)

1. **Q1: How do organization admins administer their org, and what are "tenant-restricted admins"?**
   - Today the admin API accepts only system-tenant tokens, and admin scopes are refused outside `system` (05-32). Org admins are users of an application tenant.
   - **Recommendation (A):**
     - The org sub-routes (`/api/admin/v1/tenants/{slug}/organizations/{org}/{members,invitations,roles,connections,domains}`) also accept access tokens issued by tenant `{slug}` itself.
     - Such a token must carry scope `org:admin` (a new reserved, non-registrable-by-DCR scope that the client must be allowed), bounded at issuance and refresh by the user's org-role permissions (`org:admin`), and `org_id` equal to the path org. This is the same bounding pattern as 0.4 admin scopes.
     - One `AdminAuth` extractor with a principal enum.
     - Org admins use the API from the SaaS builder's own UI; the console stays for system/tenant admins; the self-service portal UI remains ORG-6 (2.0).
   - **Alternative (B):** only tenant admins configure org SSO in 1.0, and ORG-03's "organization admin" is read as "the admin acting for an organization". Smaller and safer, but a weaker fit to the requirement wording.
   - **Tenant-restricted admins** (Phase 5 Q3) are system-tenant users limited to some tenants. That is a different principal from org admins. Suggested shape: system roles gain an optional tenant list; the console token carries `admin_tenants`; `AdminAuth` checks the path tenant. Confirm it is in scope for Phase 6 and that this shape is acceptable.
2. **Q2: D4 library choice.**
   - (A) **Recommended:** `bergshamra-dsig` (aws-lc) + uppsala + our own SAML layer, with a `chrono` wrapper exception scoped to `tsp-ltv` in `deny.toml`. chrono stays out of our code, and ARCHITECTURE §2 gets a third documented exception.
   - (B) `saml-rs` with `crypto-aws-lc`: same exception, less code, but two parsers.
   - (C) An in-house narrow verifier (exc-c14n + aws-lc-rs): no exception, but hand-rolled C14N, against the research conditions.
   - (D) Defer SAML from 1.0 (ORG-03 OIDC-only) until a candidate passes deny unmodified.
   - All options keep the experimental flag. The Wave 1 spike must confirm (A) builds with `aws-lc` only, that `cargo tree -i rsa` shows only `crypto-glue`, that no `ring` appears, and that `cargo deny check` passes with the one exception.
3. **Q3: What lifts "experimental"?**
   - Recommendation: a runtime operator key (for example `saml_experimental = true`, default off; SAML connection create refused with an explicit error when off; console badge).
   - Keep the flag through 1.0 even when the corpus is green, until the Phase 7 external security review covers SAML and a real-IdP interop checklist (like 04-33: at least Entra ID, Okta, Google Workspace, Keycloak) is done.
   - Confirm, or decide that a green corpus alone lifts it.
4. **Q4: IdP-initiated (unsolicited) SSO.** Recommendation: refuse in 1.0 with an explicit page. A later option is "bounce": answer an unsolicited response by starting an SP-initiated request to the same connection, never trusting the unsolicited assertion. Many enterprise users start from IdP dashboards, so confirm the gap is acceptable.
5. **Q5: Org role model.** Recommendation: hybrid (tenant roles assignable per org, plus org-owned roles), with one assignment table (Pattern 2). Alternatives: tenant-catalog-only (simpler; `role.org_id` stays unused) or org-owned-only (every org recreates "admin"/"member").
6. **Q6: Org connections and tenant-level social logins together.** Should an org's members still be able to use the tenant's social buttons and password, or does an org with an enterprise connection enforce SSO for its members? Recommendation: enforcement per verified domain (Q7), not per org.
7. **Q7: Routed domains and local passwords.** Recommendation: route by default; a per-domain `allow_local_password` (default false) shows "Use password instead". Confirm the default. It locks out password sign-in for existing local accounts on that domain once routing is turned on.
8. **Q8 (sequencing):** 04-33 (manual provider checklist, v0.3.0) and 05-29 (v0.4.0) are still open. The 0.4 → 1.0 upgrade test pins 0.4 migrations (already in the manifest since db8a199). Confirm Phase 6 may start on main before the tags.

## Suggested plan decomposition (discretion; maximizes parallelism)

**Shared-file ownership:**
- Workspace `Cargo.toml`/`Cargo.lock`/`deny.toml` → 06-01 only.
- `anvil-core/src/model/*`, `ports.rs`, `anvil-storage/src/contract/*`, `AppDeps`/`state.rs` (new `DomainTxtLookup` dep) and the test-support constructors → 06-02.
- SQLite migrations → 06-03; Postgres → 06-04.
- OpenAPI regeneration → one plan per wave.
- `flow/login.rs` and `ui/login.rs` (identifier-first) → one plan.
- `admin-ui` route tree and `lib/tenant.ts` `TENANT_PAGES` → the first console plan, then feature pages.

| Wave | Plan | Scope | Reqs |
|---|---|---|---|
| 1 | 06-01 D4 spike + dependencies | bergshamra-dsig/uppsala (aws-lc only), hickory-resolver, psl, flate2; `deny.toml` per Q2; prove the graph (`cargo tree -i rsa/ring/chrono`, `cargo deny`), one fixture verify test; record the verdict in ARCHITECTURE §20 D4 | ORG-03 |
| 1 | 06-02 Core model + ports + contract skeleton | organization/membership/invitation/domain, `OrgRepo`, role assignment org dimension, `ConnectionConfig::Saml`, code/family `org_id`, `ReplayKind::SamlAssertionId`, `EmailTemplateKind::OrgInvitation`, `AuditAction`s + webhook classification, `Resource::Organizations`, reserved claims, `DomainTxtLookup` port in `AppDeps`; backends `Unsupported` until wave 2 | foundation |
| 2 | 06-03 SQLite 0008 + 0009 rebuild + repos + upgrade test 0.4→1.0 | | foundation |
| 2 | 06-04 Postgres 0007 + repos + upgrade test | | foundation |
| 2 | 06-05 Pure core | `policy/{org_claims,home_realm,domain_verification}`, `saml/{request,validate}`, effective MFA with org, invitation token rules; unit + proptests | ORG-02/03/04 |
| 2 | 06-06 SAML XML adapter + attack corpus | `adapters/saml_xml.rs`, `tests/saml_support` signer, `security_saml.rs` corpus, fuzz targets `saml_response_parse`, `saml_metadata_parse` | ORG-03 (D4) |
| 2 | 06-07 DNS adapter | `adapters/dns_txt.rs` + local UDP stub test (hickory-proto encodes answers) | ORG-04 |
| 3 | 06-08 OrgService + org admin API (**OpenAPI owner wave 3**) | CRUD, members, org roles, invitations (create/list/revoke), domains (create/verify/delete), org connections; Q1 principal | ORG-02/03/04 |
| 3 | 06-09 Org claims in the grant | authorize `organization`, client `organization` policy, code/family `org_id`, token/refresh/UserInfo/introspection via `UserClaimSource` (carry-over), switcher page | ORG-02 |
| 3 | 06-10 SAML login | `service/saml.rs`, `ui/saml.rs` (start, ACS POST, continue GET, SP metadata), JIT + membership, experimental flag, `saml_login.rs` | ORG-03 |
| 3 | 06-11 Enterprise OIDC + domain-bound trust | org connections in `UpstreamService`, Pattern 9 trust, JIT membership, `security_linking` extensions | ORG-03 |
| 4 | 06-12 Identifier-first HRD | login engine + templates + i18n, `hrd_login.rs`, no-JS path | ORG-04 |
| 4 | 06-13 Invitation acceptance UI + email template + domain re-check job | `ui/organization.rs`, `org_invitation` template, job registration | ORG-02/04 |
| 4 | 06-14 Keys API + SAML connection admin fields + org branding (**OpenAPI owner wave 4**) | `admin/keys.rs`, connection DTO `saml`, branding org scope | ADM-02 |
| 4 | 06-15 Passkey picker carry-over | second-factor `allowCredentials` | carry-over |
| 5 | 06-16 Console: organizations section | list/create/detail, tabs (members, invitations, roles, connections, domains with DNS instructions + verify, branding), user memberships tab | ADM-02, ORG-02/03/04 |
| 5 | 06-17 Console: keys page, SAML connection form, audit action record | | ADM-02 |
| 6 | 06-18 e2e + docs | specs `console-orgs`, `org-switch`, `invitations`, `saml` (xml-crypto mock IdP), `hrd`, `console-keys`; docs ORGANIZATIONS.md, SAML.md (experimental, supported profile, interop checklist), UPGRADING 0.4→1.0, ARCHITECTURE §6.1/§7.1/§9/§10/§11/§19/§20 updates | all |
| 7 | 06-19 Gate | security map entries, plaintext scan (invitation token hashes, domain tokens documented as public), `just ci`, e2e both backends, conformance `all`, corpus report for D4, version bump | all |

Critical path: 06-01/06-02 → 06-03/06-04 → 06-08/06-09/06-10 → 06-12/06-14 → 06-16 → 06-18 → 06-19.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `cargo test` (unit; storage contract via `storage_contract_tests!`; HTTP integration in `anvil-web/tests`; binary tests in `anvilid/tests`), proptest, insta, wiremock, testcontainers (Postgres); Playwright e2e (`tests/e2e`); OpenID conformance (`tests/conformance`); cargo-fuzz (`fuzz/`, own workspace). **New:** test-time SAML signer (bergshamra `sign`, aws-lc), local UDP DNS stub, `xml-crypto` mock SAML IdP in e2e |
| Config file | `justfile`, `tests/e2e/playwright.config.ts`, `scripts/check-security-tests.sh`, `scripts/check-migrations.sh`, `fuzz/Cargo.toml` |
| Quick run command | `cargo test -p anvil-core --lib <module>` / `cargo test -p anvil-web --test <file>` / `cargo test -p anvil-storage-sqlite --test contract orgs` |
| Full suite command | `just ci` (fmt, clippy, deny, deps, migrations-check, test, test-pg, test-redis, release-graph, security-tests, console-check, fuzz-check) + `tests/e2e/run.sh sqlite` / `postgres` + `tests/conformance/run.sh all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ORG-02 | org CRUD; slug unique per tenant; system tenant refused; membership add/remove; cross-tenant member/role refused (composite FKs); org-owned role assignable only in its org; removing a member drops org assignments and revokes org-bound families | contract + integration | `cargo test -p anvil-storage-sqlite --test contract orgs`; `cargo test -p anvil-web --test admin_orgs` | ❌ |
| ORG-02 | `organization` param → `org_id`/`org_slug`/`org_roles`/`org_permissions` in ID token, JWT AT, UserInfo, introspection (opaque too); refresh keeps the org and recomputes roles; non-member → `invalid_grant`; client policy off/optional/required; reserved claims not spoofable by attribute mapping | unit + integration | `cargo test -p anvil-core policy::org_claims`; `cargo test -p anvil-web --test org_claims` | ❌ |
| ORG-02 | switcher lists only own orgs; foreign org id posted → refused; stricter org MFA triggers step-up; `prompt=none` + `organization` for a non-member → `login_required`/`access_denied` | integration + e2e | `cargo test -p anvil-web --test org_switch`; `tests/e2e/run.sh sqlite specs/org-switch.spec.ts` | ❌ |
| ORG-02 | invitation token hashed at rest, single use (concurrent accepts: one winner), expiry, revoke; GET consumes nothing; accept needs a matching verified email; registration via invite marks the email verified, refused when the tenant registration is `disabled`; identical admin responses for known/unknown emails | contract + integration + e2e | `cargo test -p anvil-storage-sqlite --test contract org_invitations`; `cargo test -p anvil-web --test org_invitations` / `--test security_orgs`; `specs/invitations.spec.ts` | ❌ |
| ORG-03 | SAML: AuthnRequest shape (ID, Destination, ACS, Issuer, NameIDPolicy, ForceAuthn on `prompt=login`), RelayState ≤ 80 bytes, DEFLATE round trip | unit | `cargo test -p anvil-core saml::request` | ❌ |
| ORG-03 | SAML attack corpus (XSW1–8 shapes, exclusion, key injection, comment injection, parser-differential shapes, stray/broad signature, void c14n, algorithm downgrade, file-URI reference, duplicate IDs, encrypted assertion, DTD/XXE/bombs, size) all rejected with reason codes | integration (security) | `cargo test -p anvil-web --test security_saml` | ❌ |
| ORG-03 | SAML conditions: Destination, Recipient, Audience (all restrictions), InResponseTo, Issuer, NotBefore/NotOnOrAfter with skew (fake clock), replay of the assertion ID refused (also across two app instances on one DB) | unit + integration | `cargo test -p anvil-core saml::validate`; `cargo test -p anvil-web --test saml_login` | ❌ |
| ORG-03 | SAML happy path: start → ACS POST → continue GET (binding cookie required; a missing or foreign cookie refused) → JIT user + link + membership with mapped attributes; experimental flag off → connection create refused | integration + e2e | `cargo test -p anvil-web --test saml_login`; `specs/saml.spec.ts` | ❌ |
| ORG-03 | enterprise OIDC: org connection hidden from the tenant sign-in page; email trusted only on the org's verified domains; org A IdP asserting org B's domain never auto-links; JIT adds membership | integration | `cargo test -p anvil-web --test enterprise_oidc`; `--test security_linking` (extend) | ❌ / ✅ extend |
| ORG-04 | domain input rules (IDNA, PSL, reserved names, IP literal, wildcard, length); record name/value format; verify succeeds with any matching TXT RR (multi-string joined); failure modes uniform; second org cannot verify an already verified domain (Conflict); re-check job drops routing after the grace | unit + contract + integration | `cargo test -p anvil-core policy::home_realm policy::domain_verification`; `cargo test -p anvil-storage-sqlite --test contract org_domains`; `cargo test -p anvil-web --test domain_verification` / `--test security_domains` | ❌ |
| ORG-04 | hickory adapter against a local UDP stub: FQDN queried (no search suffix), timeout bounded, NXDOMAIN/SERVFAIL → NotVerified | integration | `cargo test -p anvil-web --test dns_txt_adapter` | ❌ |
| ORG-04 | identifier-first only when routing exists; routed domain → IdP redirect; non-routed known and unknown emails get the identical password step; `login_hint` routes; no-JS works; combined form unchanged for tenants without routing | integration + e2e | `cargo test -p anvil-web --test hrd_login` / `--test security_enumeration` (extend); `specs/hrd.spec.ts`, `specs/nojs.spec.ts` (unchanged, must stay green) | ❌ / ✅ |
| ADM-02 | keys API lists without private material, rotate is audited and scope-checked (system tenant needs `admin:write`); org API scope matrix incl. Q1 principal and cross-tenant/cross-org isolation | integration (security) | `cargo test -p anvil-web --test admin_keys` / `--test security_admin_v10` | ❌ |
| ADM-02 | console: organizations (create, members, invite, roles, connections incl. SAML, domains with verify), keys (list, rotate), audit page shows new actions; axe clean | e2e + typecheck | `specs/console-orgs.spec.ts`, `specs/console-keys.spec.ts`; `cd admin-ui && npm run typecheck && npm run check:api` | ❌ |
| migrations | 0.4 → 1.0 keeps every row (identity links, role assignments, connections); rebuild passes the FK check; lint accepts the annotated rebuild | upgrade + lint | `cargo test -p anvil-storage-sqlite --test upgrade` / `-p anvil-storage-postgres --test upgrade`; `scripts/check-migrations.sh` | ✅ extend |
| config | tenant YAML export/plan/prune ignores org connections and org-owned roles | integration | `cargo test -p anvil-web --test admin_config` (extend); `cargo test -p anvilid --test tenant_config` (extend) | ✅ extend |
| carry-over | passkey picker narrowed to the step user's credentials; another user's passkey still refused | integration | `cargo test -p anvil-web --test flow_mfa` (extend) | ✅ extend |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate> --lib` plus the touched `--test <file>` (each < 30 s). Skip Postgres testcontainers locally when Docker is down, and say so.
- **Per wave merge:** `just ci`.
- **Phase gate:** `just ci` green; e2e on sqlite and postgres green; conformance `all` green with no new expected failures; the `security_saml` corpus green, with the case list recorded in the D4 verdict; then `/gsd:verify-work`.

### Wave 0 Gaps
- [ ] `crates/anvil-storage/src/contract/{orgs,org_invitations,org_domains}.rs` + extensions to `roles.rs` (org assignments, cascade on membership removal), `connections.rs` (org_id, saml kind, JIT with membership), `grants.rs` (org_id on code and family, `saml_assertion_id` replay kind), `mail_settings.rs` (`org_invitation` template)
- [ ] Upgrade fixtures 0.4 → 1.0 in both `tests/upgrade.rs` (identity links + role assignments present)
- [ ] `crates/anvil-web/tests/saml_support/` (test-time key generation, response builder, signer, mutators for each corpus case)
- [ ] `crates/anvil-web/tests/support`: fake `DomainTxtLookup` (test code only), org fixtures, a helper to mint org-scoped tokens
- [ ] A local UDP DNS stub for the hickory adapter test
- [ ] `tests/e2e/lib/mock-saml-idp.ts` (xml-crypto 6.4.0 signer; devDependency in `tests/e2e/package.json`), `lib/console-v10.ts`
- [ ] Fuzz targets `saml_response_parse`, `saml_metadata_parse`, `org_domain_parse`
- [ ] `scripts/check-security-tests.sh`: entries for every new control (SAML corpus cases and conditions, replay, binding cookie, experimental flag, domain rules, uniform DNS outcome, one verified org per domain, invitation single-use/hash/enumeration, org claim membership re-check, cross-org trust, org admin scope bounding, keys API scopes)
- [ ] Framework installs: none beyond the crates above and `xml-crypto` for e2e

## Sources

### Primary (HIGH confidence)
- Local codebase at `f1e08c1`: `anvil-core/src/{ports.rs, model/{role,connection,tenant,grant}.rs, service/{role,claims,upstream,connection,user,key_rotation,admin_scope}.rs, policy/claims_mapping.rs, upstream/linking.rs, flow/login.rs}`, `anvil-web/src/{admin/{mod,auth}.rs, adapters/outbound.rs, state.rs}`, both migration sets (0004 rebuild procedure, 0005/0007 schemas, 0006 Postgres), `scripts/{check-migrations.sh, released-migrations.sha256, check-security-tests.sh}`, `deny.toml`, `justfile`, `admin-ui/{package.json, src/lib/tenant.ts, src/routes}`, `docs/openapi/admin-v1.json` paths, Phase 4/5 SUMMARYs (04-21, 04-26, 05-04, 05-10, 05-12, 05-24, 05-32) and `05-.../deferred-items.md`
- crates.io API (2026-11-26): versions, features and dependency lists for saml-rs 0.8.0, risaml 0.7.0, bergshamra(-core/-crypto/-dsig/-keys/-xml/-c14n/-transforms/-enc/-pkcs12) 0.12.0, kryptering 0.7.1, tsp-ltv 0.6.1 (non-optional `chrono`), uppsala 0.12.1, xml-sec 0.6.0, saml 0.1.0-alpha.5, ribergshamra-keys 0.11.0, hickory-resolver/proto 0.26.4, domain 0.13.0, psl 2.1.264, idna 1.1.0
- Crate sources read (downloaded to the session scratchpad): bergshamra-dsig 0.12.0 (`verify.rs`: `verify_document_with_source` takes the first Signature; `verify_all_document_with_source`; `read_relative_reference_uri` CWD fallback; `context.rs` options), bergshamra-keys 0.12.0 (`[dependencies.tsp-ltv]` non-optional; `loader::load_x509_cert_pem`), uppsala 0.12.1 (`forbid_dtd` off by default), saml-rs 0.8.0 (`xml/dom.rs` quick-xml DOM; `crypto/verify.rs` uppsala; `tests/xsw.rs`), kryptering 0.7.1 (`aws-lc`/`rustcrypto` mutually exclusive); hickory-resolver 0.26.3 from the local registry (features, `ResolverOpts`, `txt_lookup`)
- [saml-rs README](https://github.com/salasebas/saml-rs) ("no external security audit", "Pre-1.0", replay cache note)
- [bergshamra README](https://github.com/kushaldas/bergshamra) (provider selection, xmlsec suite numbers on RustCrypto only, strict mode, duplicate IDs)
- [draft-ietf-dnsop-domain-verification-techniques-13](https://datatracker.ietf.org/doc/draft-ietf-dnsop-domain-verification-techniques/) (2026-06-22; underscore label, token entropy/encoding, expiry, PSL, DNSSEC, caching)
- [Auth0: Work with tokens and Organizations](https://auth0.com/docs/manage-users/organizations/using-tokens) (`org_id`, `org_name`, `organization` parameter, API validation), [Auth0: add member roles](https://auth0.com/docs/manage-users/organizations/configure-organizations/add-member-roles) (tenant vs organization roles)
- [WorkOS: Sessions](https://workos.com/docs/user-management/sessions) (`org_id`, `role`, `permissions`; switching via refresh with `organization_id`)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [GitHub Security Lab: parser differentials in ruby-saml](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/), [GHSL-2024-329/330 advisory](https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/)
- [PortSwigger: The Fragile Lock](https://portswigger.net/research/the-fragile-lock) (attribute pollution, namespace confusion, broad signature lookup, void canonicalization; recommendations)
- [Somorovsky et al., On Breaking SAML (USENIX Security 2012)](https://usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)

### Secondary (MEDIUM confidence)
- SAML 2.0 Core/Bindings/Profiles section numbers (Profiles 4.1.4.x, 4.1.5; Bindings 3.4.3/3.5.3 RelayState 80 bytes, 3.4.4.1, 3.5.5.2; Core 5.4): from OWASP's citations and implementer sources ([Broadcom KB](https://knowledge.broadcom.com/external/article/22808/warning-length-of-relay-state-url-is-gre.html), [OpenSAML SAMLBindingSupport](https://shibboleth.net/api/java-opensaml/4.3.2-SNAPSHOT/org/opensaml/saml/common/binding/SAMLBindingSupport.html)); the OASIS PDFs could not be text-extracted in this environment
- Keycloak organizations (`organization` scope/claim, identity-first login by email domain): [Red Hat build of Keycloak 26.0 guide](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.0/html/server_administration_guide/managing_organizations) via search excerpts
- XSW variant numbering: [NetSPI](https://www.netspi.com/blog/technical-blog/web-application-pentesting/attacking-sso-common-saml-vulnerabilities-ways-find/) and other write-ups disagree; define corpus cases by structure
- xml-crypto 6.4.0 (npm registry metadata, 2026-10-14)

### Tertiary (LOW confidence, flagged for validation)
- That bergshamra builds and verifies RSA/ECDSA with the `aws-lc` provider alone on all five deny targets (the README says AWS-LC is "initially supported on Linux x86_64/aarch64"; **macOS targets unverified**, which is a spike item)
- The exact uppsala `Parser` builder method names beyond `with_forbid_dtd` (for example a depth setter) and bergshamra API details in Code Example 1
- That common IdPs (Entra ID, Okta, Google Workspace, ADFS) accept unsigned AuthnRequests and sign assertions by default: verify in the interop checklist

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH for versions and dependency graphs (manifests and sources read). MEDIUM for bergshamra on aws-lc across all targets (README limits AWS-LC to Linux initially; spike required).
- Architecture: HIGH, derived from the code (ports, upstream service, claims source, migrations, admin auth).
- SAML checks and corpus: HIGH for the attack classes (primary write-ups); MEDIUM for spec section numbers.
- Pitfalls: HIGH for codebase- and source-derived ones (rebuild cascade, file-read fallback, first-signature lookup, DTD default, config prune); MEDIUM for IdP interop behaviour.

**Research date:** 2026-11-26
**Valid until:** 2026-12-10 for the SAML crates (bergshamra/saml-rs release every few weeks; re-check versions and the `tsp-ltv`/chrono edge before 06-01). 2026-12-26 for the rest.
