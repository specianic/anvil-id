---
phase: 06-release-1-0-orgs-and-sso
plan: 23
subsystem: admin-console
tags: [console, organizations, enterprise-sso, saml, oidc, domains, routing, branding, e2e, mock-dns, axe, ADM-02, ORG-03, ORG-04]

requires:
  - phase: 06-release-1-0-orgs-and-sso
    provides: "06-03 mocks (startMockSamlIdp, mock-dns-cli.ts, publishTxt/removeTxt); 06-17 org SSO admin API (connections incl. SAML + saml-metadata, domains + verify, org branding, TenantView.features.saml, ConnectionView.sp/organization, DomainView); 06-21 org detail layout (ORG_SECTIONS) and console-v10.ts"
provides:
  - "Org detail sections Connections, Domains, Branding (/t/$tenant/organizations/$orgId/{connections,domains,branding})"
  - "SamlConnectionForm (metadata import by XML or URL, certs with client-side subject/expiry, NameID, attribute mapping, SamlSpValues with copy, ExperimentalBadge, flag-off state)"
  - "DomainPanel (add, TXT record name/value with copy, verify, check state, routing editor with the allow-local-password trade-off and inline 409)"
  - "ConnectionForm.tsx: ORG_KINDS, orgConnectionsQueryKey/useOrgConnections, SecretRotation"
  - "ThemeEditor/ThemePreview org scope (BrandingScope kind 'org', getBranding)"
  - "Tenant connections list: Organization column, org connections read-only with a link to their org"
  - "tests/e2e/run.sh: one suite-wide mock DNS before anvilid; E2E_DNS_PORT, E2E_DNS_CONTROL_URL; ANVILID_SAML_EXPERIMENTAL=true; ANVILID_DOMAIN_VERIFICATION_RESOLVERS"
  - "tests/e2e/specs/console-org-sso.spec.ts and console-v10.ts helpers orgDomains, orgConnections, orgBrandingPrimary, randomOrgDomain"
affects: [06-24, 06-25, 06-26]

tech-stack:
  added: []
  patterns:
    - "Org connection opens in a side Modal (\"Connection {name}\") with the IdP values, settings and (OIDC) secret; create stays inline under the list"
    - "Write-only secret replace/remove as one reusable component (SecretRotation) with the secret passed through a ref, never the mutation variables"
    - "Client-side X.509 details by a minimal DER reader (subject CN, notAfter); a parse failure only hides the details, the server stays the judge"

key-files:
  created:
    - admin-ui/src/components/SamlConnectionForm.tsx
    - admin-ui/src/components/DomainPanel.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/connections.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/domains.tsx
    - admin-ui/src/routes/t/$tenant/organizations/$orgId/branding.tsx
    - tests/e2e/specs/console-org-sso.spec.ts
  modified:
    - admin-ui/src/routes/t/$tenant/organizations/$orgId.tsx
    - admin-ui/src/components/ConnectionForm.tsx
    - admin-ui/src/components/ThemeEditor.tsx
    - admin-ui/src/components/ThemePreview.tsx
    - admin-ui/src/routes/t/$tenant/connections/index.tsx
    - admin-ui/src/routeTree.gen.ts
    - tests/e2e/run.sh
    - tests/e2e/lib/console-v10.ts

key-decisions:
  - "SAML is offered only when TenantView.features.saml is true; otherwise the SAML radio is disabled with an explanation naming saml_experimental / ANVILID_SAML_EXPERIMENTAL (and existing SAML connections note that disable/delete still work)"
  - "Routing editor offers only enabled org connections as targets (a disabled current target stays visible, labelled); 409s from the routing guards are shown inline with the API's detail"
  - "Allow local password is a plain checkbox, default on, with the Q6/Q7 trade-off and the 'only after a sign-in through the connection' rule in its hint"
  - "Tenant connections list links org connections to the org's Connections page instead of the tenant detail page (the API answers 409 to tenant-level edits)"
  - "The mock DNS starts after the release build and right before anvilid, so a failed build never leaves it running; ports 53535/53536 overridable"

requirements-completed: []

duration: ~17min
completed: 2026-11-26
---

# Phase 6 Plan 23: Console org SSO (connections, domains, routing, branding) and e2e runner DNS Summary

**An organization's page now has Connections, Domains and Branding sections. Connections offers OIDC (the Phase 4 form, write-only secret) and SAML (marked Experimental; metadata import from pasted XML or a URL, signing certificates with subject and expiry, NameID format, attribute mapping, and the SP entity ID / ACS URL / metadata URL with copy buttons). SAML is shown disabled with an explanation when the operator flag is off. Domains shows the exact TXT record to publish, verifies it, shows the check state and edits routing, including the allow-local-password trade-off and the API's 409 explanation. Branding reuses the theme editor with a new org scope. The tenant's connection list shows org connections read-only with their organization. run.sh starts one mock DNS for the whole suite and turns on SAML and DNS-based verification for anvilid.**

No requirement checkbox was ticked (shared rule). ADM-02 (connections, branding) and ORG-03/ORG-04 (console administration) are ready for the gate.

## Pages and test ids

| Where | Test ids |
|---|---|
| Org section nav "Organization sections" | adds Connections, Domains, Branding (aria-current on the active one) |
| Connections: create | `org-connection-kind-oidc`, `org-connection-kind-saml`, `saml-unavailable` (flag off), `saml-experimental`; OIDC uses `connection-form`, `connection-secret-input`, `connection-submit` |
| Connections: SAML form | `saml-metadata-form`, `saml-metadata-xml`, `saml-metadata-url`, `saml-import-metadata`, `saml-connection-form`, `saml-display-name`, `saml-slug`, `saml-idp-entity-id`, `saml-sso-url`, `saml-metadata-source`, `saml-cert-{n}`, `saml-cert-info`, `saml-cert-expired`, `saml-name-id-format`, `saml-attr-{email,given_name,family_name,name}`, `saml-submit`, `saml-flag-off` |
| Connections: list and panel | row cell `org-connection-{slug}` with "Open {name}" / "Delete {name}"; dialog "Connection {name}" (`org-connection-details`): `saml-sp-values` (`saml-sp-entity-id`, `saml-sp-acs-url`, `saml-sp-metadata-url`, each with `copy-…`) or `connection-redirect-uri`; `connection-secret-status`, `rotate-connection-secret`; `close-org-connection` |
| Domains | `add-domain-form`, `add-domain-input`, `add-domain`; `domain-card` (`data-domain`, `data-status`), `domain-status`, `domain-record-name`, `domain-record-value` (+ `copy-…`), `verify-domain`, `domain-checks`, `domain-failing-since`, `domain-routing-form`, `domain-connection`, `domain-routing`, `domain-allow-password`, `save-domain-routing`, `domain-routing-error`, `delete-domain` |
| Branding | ThemeEditor ids (`color-colors.primary`, `publish-theme`, `branding-state`, ...) |
| Tenant connections list | `connection-organization` ("Read-only here" badge) |

There are no inline styles (console CSP). Certificates are public and are shown. Secrets go through refs and never into query or mutation caches.

## e2e runner (run.sh)

- `node --experimental-strip-types tests/e2e/lib/mock-dns-cli.ts --port $E2E_DNS_PORT --control-port $E2E_DNS_CONTROL_PORT` runs after the release build and before `anvilid serve`. The script waits for `READY`; if the mock exits, its log is printed and the run fails.
- It exports `E2E_DNS_PORT` (default 53535) and `E2E_DNS_CONTROL_URL=http://127.0.0.1:$E2E_DNS_CONTROL_PORT` (default port 53536).
- `env_args` (both backends) gains `ANVILID_SAML_EXPERIMENTAL=true` and `ANVILID_DOMAIN_VERIFICATION_RESOLVERS=127.0.0.1:$E2E_DNS_PORT`.
- The cleanup trap kills and waits for the mock. The header comment documents the mock, the ports and the fresh-tenant rule.

## Spec coverage (console-org-sso.spec.ts)

The spec uses a fresh tenant from `setUpConsoleTenant` (signed in with `createConsoleAdmin`) and asserts that the slug is not `default`.
1. The three new sections appear. SAML is enabled under the suite flag. axe.
2. SAML:
   - The mock's metadata as served (http SSO location) is refused at import, with the reason next to the XML field. axe.
   - The same metadata with an https location imports and fills in the entity ID, SSO URL and certificate. The certificate details show the mock's CN and no expiry warning. axe.
   - A hand-entered http SSO URL gets the 422 next to the field, and nothing is stored. axe.
   - Saving with https creates the connection. The panel shows the SP entity ID, ACS URL and metadata URL. The Copy button puts the ACS URL on the clipboard. axe on the dialog. The API confirms kind saml and the owning org.
3. Domain `acme-e2e-<hex>.com`:
   - The record name is `_anvilid-challenge.{domain}.` and the value is `anvilid-domain-verification=…`. Copy is checked.
   - Verify before the record exists stays pending with the generic message.
   - `publishTxt` then Verify gives Verified, confirmed through the API. axe.
4. Routing to the SAML connection with passwords allowed (the default, with its trade-off text) saves, confirmed through the API. axe.
5. Unchecking "Allow local password" shows the 409 inline ("at least one sign-in"). The API still has the value true. axe.
6. An org OIDC connection pointing at the existing mock IdP (lib/mock-idp.ts) shows the redirect URI and secret Configured. The secret never appears in the page. axe on the dialog.
7. Org branding: the primary colour is published and confirmed through the API (scope `org`). axe.
8. The tenant connection list shows both org connections with "Acme Corp" and "Read-only here". The name link opens the org's Connections. axe.
- Cleanup: `removeTxt`, the mocks are stopped and the tenant is deleted.

## Task Commits

1. Task 1, org SSO tabs, SAML form, domain panel, org branding scope, tenant list column: `49bb697` (feat)
2. axe fix found by the spec (copy status inside `dd`): `627ee3d` (fix)
3. Task 2, run.sh mock DNS + env, console-v10 helpers, console-org-sso spec: `4061acf` (test)

## Verification

- `cd admin-ui && npm run check:api && npm run typecheck && npm run build`: green. `grep -q domains src/routeTree.gen.ts`: yes. The route tree is committed, and a second build leaves the tree clean.
- `cd tests/e2e && npx tsc --noEmit -p .`: clean.
- `scripts/check-release-graph.sh`: OK.
- The run.sh mock DNS block was run on its own, extracted from the script: it reached READY, the control API answered 200, and the mock exited 0 on SIGTERM.
- **Local browser e2e without Docker (SQLite).**
  - Setup: `cargo build -p anvilid` (debug, main tree; it built cleanly with 06-22's in-progress files). The binary was hardlinked into a scratch dir. I started the mock DNS myself (`mock-dns-cli.ts --port 53545 --control-port 53546`), then anvilid with a fresh data dir, the run.sh flags, `ANVILID_SAML_EXPERIMENTAL=true` and `ANVILID_DOMAIN_VERIFICATION_RESOLVERS=127.0.0.1:53545`. Specs got `E2E_DNS_CONTROL_URL`.
  - `console-org-sso.spec.ts`: **passed** twice.
  - Regression in the same run: `console-connections`, `console-orgs`, `console-tenants` and `theme` **passed** (5/5).
  - Every process was stopped, the scratch dir deleted, and `e2e-results/` removed.

## Not run

- `tests/e2e/run.sh sqlite specs/console-org-sso.spec.ts` as written. It needs Docker for Mailpit and builds a release binary, and the shared rules say not to depend on Docker. Its new DNS block was checked on its own, as described above. The Postgres variant is left for CI.

## Deviations from Plan

### Auto-fixed / forced extras

1. **[Rule 3 - Blocking] `admin-ui/src/components/ThemePreview.tsx`** (outside files_modified). `BrandingScope`, `brandingQueryKey`, `postPreview` and `postPublish` live there, so the org scope for the ThemeEditor (the plan's "add the org scope without duplicating the editor") needs them.
2. **[Rule 1 - Bug] axe `definition-list`.** The copy status live region was a direct child of a `dl` group, in both the SP values and the DNS record lists. It now sits inside the `dd`. Commit `627ee3d`.
3. **SAML metadata from the mock.** AnvilID requires an https SSO URL in the metadata parser and in `SamlConfig::validate`, and the 06-03 mock serves plain http. The spec therefore asserts that refusal (a negative check through the UI) and then imports the same metadata with the location switched to https. That is enough here, because this spec never signs in through the connection. **This blocks a SAML sign-in e2e (06-24 saml.spec).** It is logged in deferred-items.md with two options: an https listener in the mock (recommended), or allowing loopback http.
4. **"Experimental" label.** The KIND_LABELS entry for SAML already said "(experimental)". The new pages show a separate `Experimental` badge (`saml-experimental`) wherever a SAML connection appears.

### Interpretations

- The plan says "allow-local-password switch". It is a native checkbox with the help text, the same control the rest of the console uses.
- The plan says "warns on expired certs without blocking". The warning sits under each certificate and the save stays allowed (only the public key is used).
- `SecretRotation` in ConnectionForm.tsx duplicates the tenant page's private `SecretCard` (`connections/$connectionId.tsx` is not in this plan's files). Switching that page over is logged in deferred-items.md.

## Self-Check: PASSED

- FOUND: admin-ui/src/components/SamlConnectionForm.tsx (contains "Experimental"), admin-ui/src/components/DomainPanel.tsx (contains "_anvilid-challenge"), tests/e2e/specs/console-org-sso.spec.ts (contains "publishTxt"), tests/e2e/run.sh (contains "ANVILID_DOMAIN_VERIFICATION_RESOLVERS")
- FOUND commits: 49bb697, 627ee3d, 4061acf
