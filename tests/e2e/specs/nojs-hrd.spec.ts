// ORG-04, UI-01: identifier-first sign-in and home-realm discovery without JavaScript (Playwright
// project `nojs`, JavaScript disabled). In a tenant of its own, a verified domain (suite mock DNS,
// publishTxt) is routed to an org SAML connection with passwords still allowed, so no prior sign-in
// through the connection is needed. With plain form posts and redirects only:
//   - the email page sends a routed address to the "Continue with single sign-on" choice; the SSO
//     button leads to the mock IdP, whose auto-submit form has a visible button (no script runs),
//     and the ACS brings the user back signed in (JIT);
//   - "Use password instead" leads to the password step and signs a local account in;
//   - an address outside the domain gets the password step directly.
//
// The mock SAML IdP serves https with a self-signed certificate (AnvilID accepts only https sign-in
// URLs); the context ignores certificate errors. axe needs script injection, so the audits of these
// pages live in hrd.spec.ts and saml.spec.ts (chromium project).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE, E2E_DNS_CONTROL_URL (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { adminToken, createUser, randomEmail, randomPassword, sharedManagementCredential } from '../lib/anvil';
import { removeTxt } from '../lib/mock-dns';
import { startMockSamlIdp, type MockSamlIdp } from '../lib/mock-saml-idp';
import {
  addVerifiedDomain,
  createOrg,
  createOrgSamlConnection,
  createOrgTenant,
  expectPasswordStep,
  expectSsoChoice,
  orgMembers,
  patchDomainRouting,
  randomOrgDomain,
  submitEmailFirst,
  type OrgTenant,
} from '../lib/org';
import { tenantUsers } from '../lib/upstream';

test.use({ ignoreHTTPSErrors: true });

let tenant: OrgTenant | undefined;
let idp: MockSamlIdp | undefined;
let recordName: string | undefined;

test.afterAll(async () => {
  if (recordName) await removeTxt(recordName).catch(() => undefined);
  await idp?.close();
  await tenant?.cleanup();
});

test('email-first routing, SAML sign-in and the password path without JavaScript', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createOrgTenant(token, 'nojs-hrd');
  const { slug, issuer } = tenant;
  expect(slug).not.toBe('default');
  const org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  idp = await startMockSamlIdp({ https: true });
  const connection = await createOrgSamlConnection(token, slug, org.id, idp, { slug: 'acme-saml', display_name: 'Acme SAML' });
  const domain = randomOrgDomain('acme-nojs');
  const claim = await addVerifiedDomain(token, slug, org.id, domain);
  recordName = claim.record_name;
  await patchDomainRouting(token, slug, org.id, claim.id, { connection_id: connection.id, routing: true });

  const samlUser = { id: `saml-${randomBytes(6).toString('hex')}`, email: `sam-${randomBytes(4).toString('hex')}@${domain}` };
  idp.setUser(samlUser);
  const local = { email: `local-${randomBytes(4).toString('hex')}@${domain}`, password: randomPassword() };
  await createUser(token, { ...local, email_verified: true }, slug);

  await test.step('routed address: SSO choice, the IdP form button, back signed in', async () => {
    await page.goto(`${issuer}/ui/login`);
    await submitEmailFirst(page, samlUser.email);
    await expectSsoChoice(page, samlUser.email);
    await page.locator('#login-sso-continue').click();
    // No script runs: the mock's form waits for its visible button.
    await expect(page).toHaveURL((url) => url.href.startsWith(idp?.ssoUrl ?? 'missing'));
    await expect(page.locator('#mock-saml-user')).toHaveText(samlUser.email);
    await page.locator('#mock-saml-continue').click();
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
    const user = (await tenantUsers(token, slug)).find((u) => u.email === samlUser.email.toLowerCase());
    expect(user).toBeDefined();
    expect((await orgMembers(token, slug, org.id)).map((m) => m.user_id)).toContain(user?.id);
  });

  await test.step('"Use password instead" signs the local account in', async () => {
    const context = await browser.newContext({ javaScriptEnabled: false, ignoreHTTPSErrors: true });
    try {
      const p = await context.newPage();
      await p.goto(`${issuer}/ui/login`);
      await submitEmailFirst(p, local.email);
      await expectSsoChoice(p, local.email);
      await p.locator('#login-use-password').click();
      await expectPasswordStep(p, local.email);
      await p.locator('#password').fill(local.password);
      await p.locator('#login-submit').click();
      await expect(p.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
    } finally {
      await context.close();
    }
  });

  await test.step('an address outside the domain gets the password step', async () => {
    const context = await browser.newContext({ javaScriptEnabled: false, ignoreHTTPSErrors: true });
    try {
      const p = await context.newPage();
      const other = randomEmail('nojs-hrd');
      await p.goto(`${issuer}/ui/login`);
      await submitEmailFirst(p, other);
      await expectPasswordStep(p, other);
    } finally {
      await context.close();
    }
  });
});
