// ORG-03 SAML 2.0 sign-in in a browser (06-18, experimental; the suite runs anvilid with
// ANVILID_SAML_EXPERIMENTAL=true).
//
// In a tenant of its own, an organization creates a SAML connection from the mock IdP's metadata
// (lib/mock-saml-idp.ts, started with `https: true`: AnvilID accepts only https sign-in URLs, and only
// the browser talks to the IdP, so the context ignores the mock's self-signed certificate), verifies a
// domain through the suite's mock DNS (publishTxt) and routes it to the brand-new connection with
// passwords still allowed (no prior sign-in is needed for that). Then:
//   1. at the RP, an address on the domain gets "Continue with single sign-on", is sent to the IdP
//      with an AuthnRequest, and comes back signed in: the user is created just in time with the
//      asserted profile, is a member of the org, and the token carries the org;
//   2. the mock's wrong-audience variant ends on the generic SAML error page (axe-clean), and no
//      account is created.
//
// The default tenant never gets a routed domain. Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE,
// E2E_DNS_CONTROL_URL (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminToken, sharedManagementCredential } from '../lib/anvil';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { removeTxt } from '../lib/mock-dns';
import { startMockSamlIdp, type MockSamlIdp } from '../lib/mock-saml-idp';
import {
  addVerifiedDomain,
  createOrg,
  createOrgClient,
  createOrgSamlConnection,
  createOrgTenant,
  expectSsoChoice,
  orgMembers,
  patchDomainRouting,
  randomOrgDomain,
  submitEmailFirst,
  type OrgTenant,
  type OrgView,
} from '../lib/org';
import { tenantUsers } from '../lib/upstream';

test.use({ ignoreHTTPSErrors: true });
test.describe.configure({ mode: 'serial' });

let tenant: OrgTenant | undefined;
let idp: MockSamlIdp | undefined;
let recordName: string | undefined;
let token = '';
let org: OrgView;
let domain = '';
let client: { client_id: string; client_secret: string; redirect_uri: string };

test.beforeAll(async ({ browser }) => {
  token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createOrgTenant(token, 'saml');
  expect(tenant.slug).not.toBe('default');
  const { slug } = tenant;
  org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  idp = await startMockSamlIdp({ https: true });
  expect(idp.ssoUrl).toMatch(/^https:\/\/127\.0\.0\.1:/);
  const connection = await createOrgSamlConnection(token, slug, org.id, idp, {
    slug: 'acme-saml',
    display_name: 'Acme SAML',
  });
  domain = randomOrgDomain('acme-saml');
  const claim = await addVerifiedDomain(token, slug, org.id, domain);
  recordName = claim.record_name;
  // Routing to a connection nobody has signed in through yet, passwords still allowed.
  const routed = await patchDomainRouting(token, slug, org.id, claim.id, { connection_id: connection.id, routing: true });
  expect(routed.routing).toBe(true);
  expect(routed.allow_local_password).toBe(true);
  // `required`: the JIT membership is the user's only one, so the token carries that org.
  client = await createOrgClient(token, slug, 'https://saml-rp.example.test/callback', 'required');
});

test.afterAll(async () => {
  if (recordName) await removeTxt(recordName).catch(() => undefined);
  await idp?.close();
  await tenant?.cleanup();
});

/** On the email page: the routed address, then "Continue with single sign-on" (to the IdP). */
async function chooseSso(page: Page, email: string): Promise<void> {
  await submitEmailFirst(page, email);
  await expectSsoChoice(page, email);
  await page.locator('#login-sso-continue').click();
}

test('a routed address signs in through the SAML IdP (JIT user and membership)', async ({ page }) => {
  test.setTimeout(120_000);
  if (!tenant || !idp) throw new Error('set-up failed');
  const { slug, issuer } = tenant;
  const samlUser = {
    id: `saml-${randomBytes(6).toString('hex')}`,
    email: `sam-${randomBytes(4).toString('hex')}@${domain}`,
    givenName: 'Sam',
    familyName: 'Ell',
  };
  idp.setUser(samlUser);
  idp.setVariant('ok');
  const before = idp.requests.length;

  const tokens = await authorizationCodeFlow(
    page,
    client,
    'openid email profile',
    async (p) => {
      await chooseSso(p, samlUser.email);
      // The mock's page submits itself to the ACS; AnvilID continues to the client.
    },
    issuer,
  );

  const requests = idp.requests.slice(before);
  expect(requests).toHaveLength(1);
  expect(requests[0].issuer).toBe(`${issuer}/saml/acme-saml`);
  expect(requests[0].acsUrl).toBe(`${issuer}/ui/login/saml/acme-saml/acs`);

  if (!tokens.id_token) throw new Error('no id_token');
  const claims = jwtClaims(tokens.id_token);
  expect(claims.org_id).toBe(org.id);
  const user = (await tenantUsers(token, slug)).find((u) => u.email === samlUser.email.toLowerCase());
  expect(user?.id).toBe(claims.sub);
  expect(user?.claims.given_name).toBe('Sam');
  expect(user?.claims.family_name).toBe('Ell');
  expect((await orgMembers(token, slug, org.id)).map((m) => m.user_id)).toContain(user?.id);
});

test('a response for the wrong audience ends on the generic SAML error page', async ({ page }) => {
  test.setTimeout(120_000);
  if (!tenant || !idp) throw new Error('set-up failed');
  const { slug, issuer } = tenant;
  const email = `wrong-${randomBytes(4).toString('hex')}@${domain}`;
  idp.setUser({ id: `saml-${randomBytes(6).toString('hex')}`, email });
  idp.setVariant('wrong-audience');
  try {
    await page.goto(`${issuer}/ui/login`);
    await chooseSso(page, email);
    const error = page.locator('#error-message');
    await expect(error).toHaveAttribute('data-error-key', 'saml_login_failed');
    await expect(page).toHaveURL((url) => url.pathname === `/t/${slug}/ui/login/saml/acme-saml/acs`);
    // One generic page: no reason, no assertion details.
    await expect(page.locator('main')).not.toContainText('audience');
    await expectNoA11yViolations(page);
    expect((await tenantUsers(token, slug)).find((u) => u.email === email)).toBeUndefined();
  } finally {
    idp.setVariant('ok');
  }
});
