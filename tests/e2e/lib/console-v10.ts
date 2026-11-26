// Shared helpers for the 1.0 console specs (Phase 6: console-keys, and the org/SSO console specs
// of later plans). Tenant set-up and sign-in reuse lib/console-v04.ts: each spec works in a tenant
// of its own, created through the admin API and deleted afterwards, signed in as a console
// administrator created at runtime with createConsoleAdmin. Specs never change the default
// tenant's signing keys or settings (other specs and the sample RP depend on them).
//
// Console test ids used here (admin-ui, plan 06-16):
// - signing keys page: `rotate-key` (opens the dialog), `rotate-key-dialog`, `rotate-key-alg`,
//   `rotate-key-immediate`; the state badge in each row is `key-state` (find a row by its kid text)
// - organizations (06-21): list `new-org`, `open-org-{slug}`, `orgs-system-tenant`; form `org-form`,
//   `org-display-name`, `org-slug`, `org-mfa-policy`, `org-default-roles`, `org-submit`; overview
//   `delete-org`; section navigation "Organization sections" (Overview, Members, Invitations, Roles);
//   members `add-member-form`, `add-member-email`, `add-member-roles`, `add-member`, row actions
//   "Roles of {email}" / "Remove {email}", role panel `org-role-assignments`,
//   `org-assign-role-select` (option values `org:{name}` / `tenant:{name}`), `org-assign-role`,
//   `member-role-{name}` with `role-scope`; roles `new-org-role`, `org-role-form`, `org-role-name`,
//   `org-role-permissions`, `org-role-submit`, rows `org-role-{name}`; invitations `invite-form`,
//   `invite-email`, `invite-roles` (checkboxes carry `data-role="{scope}:{name}"`), `send-invitation`,
//   `invitations-include-closed`, rows `invitation-row` with `data-email` and `data-status`,
//   `invitation-status`; user page `user-organizations`; client form `client-organization-policy`,
//   client details `client-organization`
// - org SSO (06-23): section navigation adds Connections, Domains, Branding.
//   Connections: kind radios `org-connection-kind-oidc` / `org-connection-kind-saml` (SAML disabled with
//   `saml-unavailable` when the operator flag is off), `saml-experimental` badge; SAML form
//   `saml-metadata-form`, `saml-metadata-xml`, `saml-metadata-url`, `saml-import-metadata`,
//   `saml-connection-form`, `saml-display-name`, `saml-slug`, `saml-idp-entity-id`, `saml-sso-url`,
//   `saml-cert-{n}`, `saml-cert-info`, `saml-cert-expired`, `saml-name-id-format`, `saml-attr-{email|
//   given_name|family_name|name}`, `saml-submit`; OIDC uses the Phase 4 `connection-form`; table row
//   actions "Open {name}" / "Delete {name}" (cell `org-connection-{slug}`); the side panel "Connection
//   {name}" (`org-connection-details`) shows `saml-sp-values` (`saml-sp-entity-id`, `saml-sp-acs-url`,
//   `saml-sp-metadata-url`, each with `copy-…`) or `connection-redirect-uri`, and
//   `connection-secret-status`; `close-org-connection`.
//   Domains: `add-domain-form`, `add-domain-input`, `add-domain`; per domain `domain-card` (`data-domain`,
//   `data-status`), `domain-status`, `domain-record-name`, `domain-record-value`, `verify-domain`,
//   `domain-checks`, `domain-routing-form`, `domain-connection`, `domain-routing`,
//   `domain-allow-password`, `save-domain-routing`, `domain-routing-error` (the API's 409 detail),
//   `delete-domain`. Branding: the ThemeEditor test ids (`color-colors.primary`, `publish-theme`, ...).
//   Tenant connections list: `connection-organization`.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, type Page } from '@playwright/test';
import { adminCall, tenantPath } from './admin-api';
import { tenantIssuer } from './upstream';

export { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from './console-v04';

/**
 * Opens a tenant section through the main navigation (as a user would) from any tenant page and
 * waits for its heading. `label` is the TENANT_PAGES label, `path` its route segment.
 */
export async function openSectionFromNav(
  page: Page,
  slug: string,
  label: string,
  path: string,
  heading = label,
): Promise<void> {
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: label, exact: true }).click();
  await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/${path}`);
  await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
}

/** A signing key as the admin API lists it (06-11 KeyView). */
export interface KeyView {
  kid: string;
  alg: string;
  state: 'next' | 'active' | 'retired';
  created_at: string;
  activated_at?: string | null;
  retired_at?: string | null;
  expires_at?: string | null;
}

/** The tenant's signing keys through the admin API (newest first). */
export async function listTenantKeys(token: string, slug: string): Promise<KeyView[]> {
  const body = await adminCall<{ items: KeyView[] }>(token, 'GET', tenantPath(slug, '/keys'));
  return body.items;
}

/** The kids published in the tenant's JWKS (located through its discovery document). */
export async function tenantJwksKids(slug: string): Promise<string[]> {
  const discovery = await fetch(`${tenantIssuer(slug)}/.well-known/openid-configuration`);
  expect(discovery.status).toBe(200);
  const { jwks_uri: jwksUri } = (await discovery.json()) as { jwks_uri: string };
  const jwks = await fetch(jwksUri, { headers: { accept: 'application/json' } });
  expect(jwks.status).toBe(200);
  const { keys } = (await jwks.json()) as { keys: Array<{ kid?: string }> };
  return keys.map((k) => k.kid ?? '');
}

/** An organization as the admin API returns it (06-12 OrganizationView). */
export interface OrgView {
  id: string;
  slug: string;
  display_name: string;
  mfa_policy?: 'off' | 'optional' | 'required' | null;
  default_role_ids: string[];
}

/** An invitation as the admin API lists it (06-12 InvitationView: never a token or hash). */
export interface InvitationView {
  id: string;
  email: string;
  role_ids: string[];
  status: 'open' | 'accepted' | 'revoked' | 'expired';
  expires_at: string;
  [field: string]: unknown;
}

/** Creates an organization through the admin API. */
export function createOrg(token: string, slug: string, org: { slug: string; display_name: string }): Promise<OrgView> {
  return adminCall<OrgView>(token, 'POST', tenantPath(slug, '/organizations'), org, 201);
}

/** The organization `org` (id or slug), or null when the API answers 404. */
export async function findOrg(token: string, slug: string, org: string): Promise<OrgView | null> {
  const body = await adminCall<Partial<OrgView>>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}`),
    undefined,
    [200, 404],
  );
  return typeof body.id === 'string' ? (body as OrgView) : null;
}

/** The roles a member holds in the org (`scope` org or tenant). */
export async function orgMemberRoles(
  token: string,
  slug: string,
  org: string,
  userId: string,
): Promise<Array<{ name: string; scope: 'org' | 'tenant' }>> {
  const body = await adminCall<{ items: Array<{ name: string; scope: 'org' | 'tenant' }> }>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}/members/${encodeURIComponent(userId)}/roles`),
  );
  return body.items;
}

/** Every invitation of the org, accepted and revoked ones included. */
export async function orgInvitations(token: string, slug: string, org: string): Promise<InvitationView[]> {
  const body = await adminCall<{ items: InvitationView[] }>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}/invitations?include_closed=true`),
  );
  return body.items;
}

/** A domain claim as the admin API returns it (06-17 DomainView). */
export interface DomainView {
  id: string;
  domain: string;
  status: 'pending' | 'verified';
  record_name: string;
  record_value: string;
  connection_id?: string | null;
  routing: boolean;
  allow_local_password: boolean;
  [field: string]: unknown;
}

/** The org's domain claims. */
export async function orgDomains(token: string, slug: string, org: string): Promise<DomainView[]> {
  const body = await adminCall<{ items: DomainView[] }>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}/domains`),
  );
  return body.items;
}

/** A connection as the admin API returns it (only the fields the specs read). */
export interface OrgConnectionView {
  id: string;
  slug: string;
  kind: string;
  enabled: boolean;
  organization?: string | null;
  secret_configured: boolean;
  redirect_uri: string;
  sp?: { entity_id: string; acs_url: string; metadata_url: string } | null;
  config: Record<string, unknown>;
}

/** The org's connections. */
export async function orgConnections(token: string, slug: string, org: string): Promise<OrgConnectionView[]> {
  const body = await adminCall<{ items: OrgConnectionView[] }>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}/connections`),
  );
  return body.items;
}

/** The org's stored branding tokens (06-17 BrandingView, scope `org`). */
export async function orgBrandingPrimary(token: string, slug: string, org: string): Promise<string | null> {
  const body = await adminCall<{ scope: string; tokens: { colors?: { primary?: string | null } | null } }>(
    token,
    'GET',
    tenantPath(slug, `/organizations/${encodeURIComponent(org)}/branding`),
  );
  expect(body.scope).toBe('org');
  return body.tokens.colors?.primary ?? null;
}

/**
 * A unique test domain under a real ICANN suffix that is not a reserved name (so the API accepts
 * it). Only the suite's mock DNS answers for it during verification: nothing leaves the machine.
 */
export function randomOrgDomain(prefix = 'acme-e2e'): string {
  return `${prefix}-${randomBytes(5).toString('hex')}.com`;
}
