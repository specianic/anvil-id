// Admin API helpers for the Phase 6 organization journeys (06-24: org-switch, invitations, saml, hrd,
// nojs-hrd). Typed fetch calls over lib/admin-api.ts with a management token; the read helpers the
// console specs already use (createOrg, orgDomains, orgConnections, ...) are re-exported from
// lib/console-v10.ts, so there is one implementation per call.
//
// Rules the specs follow (tests/e2e/run.sh header):
// - every spec works in tenants of its own (createOrgTenant); the default tenant never gets a routed
//   domain, so its sign-in page stays the combined form for the rest of the suite;
// - DNS records are published only through the suite-wide mock DNS (publishTxt, E2E_DNS_CONTROL_URL);
//   no spec starts a DNS server of its own.
//
// Hosted-page selectors used by the helpers (06-22 login_identify.html): email page form
// `login-identify-form`, input `identifier`, button `login-identify-submit`; choice page
// `login-sso-continue`, `login-use-password`, `login-change-email`, `login-email-locked`.
//
// Env: ANVIL_URL, E2E_DNS_CONTROL_URL (see tests/e2e/run.sh).

import { expect, type Page } from '@playwright/test';
import { adminCall, tenantPath } from './admin-api';
import { createClient, type CreatedClient } from './anvil';
import { orgConnections, type DomainView, type InvitationView, type OrgConnectionView } from './console-v10';
import { deleteTenant } from './email-code';
import { publishTxt } from './mock-dns';
import type { MockSamlIdp } from './mock-saml-idp';
import { createTenant, randomSlug, tenantIssuer } from './upstream';

export {
  createOrg,
  findOrg,
  orgConnections,
  orgDomains,
  orgInvitations,
  orgMemberRoles,
  randomOrgDomain,
  type DomainView,
  type InvitationView,
  type OrgConnectionView,
  type OrgView,
} from './console-v10';

/** `/tenants/{slug}/organizations/{org}` plus `rest`. */
function orgPath(slug: string, org: string, rest = ''): string {
  return tenantPath(slug, `/organizations/${encodeURIComponent(org)}${rest}`);
}

/** A tenant of the spec's own (`{prefix}-xxxxxxxx`); `cleanup` deletes it (best effort). */
export interface OrgTenant {
  slug: string;
  issuer: string;
  cleanup(): Promise<void>;
}

/** Creates a fresh tenant for one spec or test (never the default tenant). */
export async function createOrgTenant(
  token: string,
  prefix: string,
  settings: Record<string, unknown> = {},
): Promise<OrgTenant> {
  const slug = randomSlug(prefix);
  await createTenant(token, slug, settings);
  return { slug, issuer: tenantIssuer(slug), cleanup: () => deleteTenant(token, slug) };
}

/** A member as the admin API lists it (06-12 MemberView). */
export interface MemberView {
  user_id: string;
  email?: string | null;
  [field: string]: unknown;
}

/** Adds `userId` to the org with the given role ids (201 added, 200 already a member). */
export async function addMember(
  token: string,
  slug: string,
  org: string,
  userId: string,
  roleIds: string[] = [],
): Promise<void> {
  await adminCall(token, 'POST', orgPath(slug, org, '/members'), { user_id: userId, role_ids: roleIds }, [200, 201]);
}

/** The org's members (first 200, enough for the per-test tenants). */
export async function orgMembers(token: string, slug: string, org: string): Promise<MemberView[]> {
  const body = await adminCall<{ items: MemberView[] }>(token, 'GET', orgPath(slug, org, '/members?limit=200'));
  return body.items;
}

/** Invites `email` to the org (the org_invitation email is queued). Never returns a token. */
export function createInvitation(
  token: string,
  slug: string,
  org: string,
  email: string,
  roleIds: string[] = [],
): Promise<InvitationView> {
  return adminCall<InvitationView>(token, 'POST', orgPath(slug, org, '/invitations'), { email, role_ids: roleIds }, 201);
}

/** Claims `domain` for the org (pending; the response carries the TXT record to publish). */
export async function claimDomain(token: string, slug: string, org: string, domain: string): Promise<DomainView> {
  const claim = await adminCall<DomainView>(token, 'POST', orgPath(slug, org, '/domains'), { domain }, 201);
  expect(claim.status).toBe('pending');
  return claim;
}

/** Runs the verification of claim `domainId` and returns the claim (verified or pending). */
export function verifyDomain(token: string, slug: string, org: string, domainId: string): Promise<DomainView> {
  return adminCall<DomainView>(token, 'POST', orgPath(slug, org, `/domains/${domainId}/verify`));
}

/**
 * Claims `domain` for the org, publishes its TXT record through the suite's mock DNS and verifies it.
 * Asserts the claim is verified and returns it (`record_name` is what to removeTxt afterwards).
 */
export async function addVerifiedDomain(token: string, slug: string, org: string, domain: string): Promise<DomainView> {
  const claim = await claimDomain(token, slug, org, domain);
  await publishTxt(claim.record_name, [claim.record_value]);
  const verified = await verifyDomain(token, slug, org, claim.id);
  expect(verified.status).toBe('verified');
  return verified;
}

/** PATCH of a domain claim's routing (06-17 DomainPatchDto). */
export interface DomainRoutingPatch {
  connection_id?: string | null;
  routing?: boolean;
  allow_local_password?: boolean;
}

/**
 * Updates the routing of domain claim `domainId`. Returns the status and body so specs can assert
 * the guards' 409 as well as the 200.
 */
export async function patchDomainRouting(
  token: string,
  slug: string,
  org: string,
  domainId: string,
  patch: DomainRoutingPatch,
  expected: number | number[] = 200,
): Promise<DomainView & { detail?: string }> {
  return adminCall<DomainView & { detail?: string }>(
    token,
    'PATCH',
    orgPath(slug, org, `/domains/${domainId}`),
    patch,
    expected,
  );
}

/** Creates an org OIDC connection (generic OIDC, discovery from `issuer`, write-only secret). */
export async function createOrgOidcConnection(
  token: string,
  slug: string,
  org: string,
  c: {
    slug: string;
    display_name: string;
    issuer: string;
    client_id: string;
    secret: string;
    scopes?: string[];
    fetch_userinfo?: boolean;
  },
): Promise<OrgConnectionView> {
  return adminCall<OrgConnectionView>(
    token,
    'POST',
    orgPath(slug, org, '/connections'),
    {
      slug: c.slug,
      display_name: c.display_name,
      config: {
        type: 'oidc',
        issuer: c.issuer,
        client_id: c.client_id,
        scopes: c.scopes ?? ['openid', 'profile', 'email'],
        fetch_userinfo: c.fetch_userinfo ?? true,
      },
      secret: c.secret,
    },
    201,
  );
}

/** What the metadata import returns (06-17 SamlMetadataView). */
interface SamlMetadataView {
  idp_entity_id: string;
  sso_url: string;
  signing_certs: string[];
  metadata_url?: string | null;
}

/** Where the IdP metadata comes from: pasted XML (the mock IdP) or an https URL (a real IdP). */
export type SamlMetadataSource = Pick<MockSamlIdp, 'metadataXml'> | { metadataUrl: string };

/** Optional connection settings that differ from the mock IdP's. */
export interface SamlConnectionOverrides {
  name_id_format?: string;
  attributes?: Record<string, string>;
}

/**
 * Creates an org SAML connection from IdP metadata: the metadata goes through the import endpoint
 * (pasted XML, or an https URL fetched by AnvilID's guarded outbound client; it refuses a non-https
 * sign-in URL: start the mock with `https: true`), then the connection is created from the imported
 * values. Defaults: `persistent` NameID and the mock's attribute names (email/given_name/family_name).
 */
export async function createOrgSamlConnection(
  token: string,
  slug: string,
  org: string,
  idp: SamlMetadataSource,
  c: { slug: string; display_name: string },
  overrides: SamlConnectionOverrides = {},
): Promise<OrgConnectionView> {
  const source = 'metadataUrl' in idp ? { url: idp.metadataUrl } : { xml: idp.metadataXml };
  const meta = await adminCall<SamlMetadataView>(
    token,
    'POST',
    orgPath(slug, org, '/connections/saml-metadata'),
    source,
  );
  const created = await adminCall<OrgConnectionView>(
    token,
    'POST',
    orgPath(slug, org, '/connections'),
    {
      slug: c.slug,
      display_name: c.display_name,
      config: {
        type: 'saml',
        idp_entity_id: meta.idp_entity_id,
        sso_url: meta.sso_url,
        signing_certs: meta.signing_certs,
        name_id_format: overrides.name_id_format ?? 'persistent',
        attributes: overrides.attributes ?? { email: 'email', given_name: 'given_name', family_name: 'family_name' },
        ...('metadataUrl' in idp ? { metadata_url: idp.metadataUrl } : {}),
      },
    },
    201,
  );
  expect(created.kind).toBe('saml');
  expect((await orgConnections(token, slug, org)).map((x) => x.id)).toContain(created.id);
  return created;
}

export type OrgClientPolicy = 'off' | 'optional' | 'required';

/** Sets a client's organization policy (PATCH /tenants/{t}/clients/{id}). */
export async function setClientOrganizationPolicy(
  token: string,
  slug: string,
  clientId: string,
  policy: OrgClientPolicy,
): Promise<void> {
  const body = await adminCall<{ organization: OrgClientPolicy }>(
    token,
    'PATCH',
    tenantPath(slug, `/clients/${encodeURIComponent(clientId)}`),
    { organization: policy },
  );
  expect(body.organization).toBe(policy);
}

/**
 * A confidential first-party code client (client_secret_basic, consent skipped) in `slug` with the
 * given organization policy. The redirect URI is never served (lib/code-flow.ts captures it).
 */
export async function createOrgClient(
  token: string,
  slug: string,
  redirectUri: string,
  policy: OrgClientPolicy,
): Promise<{ client_id: string; client_secret: string; redirect_uri: string }> {
  const client: CreatedClient = await createClient(
    token,
    {
      name: `e2e org client (${policy})`,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
    },
    slug,
  );
  if (!client.client_secret) throw new Error('client created without a secret');
  await setClientOrganizationPolicy(token, slug, client.client_id, policy);
  return { client_id: client.client_id, client_secret: client.client_secret, redirect_uri: redirectUri };
}

/** On the email-first page (already open): submits `email`. */
export async function submitEmailFirst(page: Page, email: string): Promise<void> {
  await expect(page.locator('#login-identify-form')).toBeVisible();
  await page.locator('#identifier').fill(email);
  await page.locator('#login-identify-submit').click();
}

/** Expects the "Continue with single sign-on" choice for `email` (06-22 SsoChoice step). */
export async function expectSsoChoice(page: Page, email: string): Promise<void> {
  await expect(page.locator('#login-sso-continue')).toBeVisible();
  await expect(page.locator('#login-use-password')).toBeVisible();
  await expect(page.locator('#login-email-locked')).toContainText(email.toLowerCase());
}

/** Expects the password step after the email page (email locked, no SSO choice). */
export async function expectPasswordStep(page: Page, email: string): Promise<void> {
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('#password')).toBeVisible();
  await expect(page.locator('#login-email-locked')).toContainText(email.toLowerCase());
  await expect(page.locator('#login-sso-continue')).toHaveCount(0);
}

/** On the email page: a routed address, then "Continue with single sign-on" (to the IdP). */
export async function chooseSso(page: Page, email: string): Promise<void> {
  await submitEmailFirst(page, email);
  await expectSsoChoice(page, email);
  await page.locator('#login-sso-continue').click();
}
