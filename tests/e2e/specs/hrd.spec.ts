// ORG-04 identifier-first sign-in with home-realm discovery in a browser (06-22).
//
// In a tenant of its own, an organization verifies a domain through the suite's mock DNS
// (publishTxt) and routes it to an org OIDC connection whose IdP is a second tenant of the same
// AnvilID (the suite's generic OIDC provider, as in social.spec.ts: its own login page, client and
// discovery). Then:
//   1. passwords still allowed (the default): the tenant's sign-in page asks for the email first
//      (axe-clean); an address on the verified domain gets "Continue with single sign-on", and
//      "Use password instead" signs in with the local password;
//   2. turning passwords off is refused (409) while nobody has signed in through the connection;
//   3. a first sign-in through the connection: an RP request with organization=<org> goes straight
//      to the IdP, the user is created just in time as an org member and the token carries the org;
//   4. now allow_local_password=false is accepted, and the same address goes straight to the IdP
//      from the email page (no choice, no password);
//   5. an address outside the routed domain gets the password step.
//
// The default tenant never gets a routed domain (its sign-in page stays the combined form).
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE, E2E_DNS_CONTROL_URL (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { addAuthorizeParams } from '../lib/authorize';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { publishTxt, removeTxt } from '../lib/mock-dns';
import { mockIdpRedirectUri } from '../lib/mock-idp';
import {
  claimDomain,
  createOrg,
  createOrgClient,
  createOrgOidcConnection,
  createOrgTenant,
  expectPasswordStep,
  expectSsoChoice,
  orgDomains,
  orgMembers,
  patchDomainRouting,
  randomOrgDomain,
  submitEmailFirst,
  verifyDomain,
  type OrgTenant,
} from '../lib/org';
import { createUpstreamTenant, randomSlug, tenantUsers } from '../lib/upstream';

let tenant: OrgTenant | undefined;
let upstreamSlug: string | undefined;
let recordName: string | undefined;
let cleanupToken = '';

test.afterAll(async () => {
  if (recordName) await removeTxt(recordName).catch(() => undefined);
  await tenant?.cleanup();
  if (upstreamSlug) await deleteTenant(cleanupToken, upstreamSlug);
});

test('email-first routing: SSO choice, first sign-in through the connection, then SSO only', async ({
  page,
  browser,
}) => {
  test.setTimeout(180_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  cleanupToken = token;
  tenant = await createOrgTenant(token, 'hrd');
  const { slug, issuer } = tenant;
  expect(slug).not.toBe('default');
  const org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  const domain = randomOrgDomain('acme-hrd');

  // The org's IdP: a second tenant acting as a generic OIDC provider.
  const connectionSlug = 'acme-oidc';
  upstreamSlug = randomSlug('hrd-idp');
  const upstream = await createUpstreamTenant(token, upstreamSlug, mockIdpRedirectUri(anvilUrl(), slug, connectionSlug));
  const ssoUser = { email: `sso-${randomBytes(4).toString('hex')}@${domain}`, password: randomPassword() };
  await createUser(token, { ...ssoUser, email_verified: true }, upstream.slug);
  const connection = await createOrgOidcConnection(token, slug, org.id, {
    slug: connectionSlug,
    display_name: 'Acme Workforce',
    issuer: upstream.issuer,
    client_id: upstream.clientId,
    secret: upstream.clientSecret,
  });

  // The TXT record is published through the suite's mock DNS; before that, verification stays pending.
  const claim = await claimDomain(token, slug, org.id, domain);
  recordName = claim.record_name;
  expect((await verifyDomain(token, slug, org.id, claim.id)).status).toBe('pending');
  // Routing needs a verified domain (409 while pending).
  await patchDomainRouting(token, slug, org.id, claim.id, { connection_id: connection.id, routing: true }, 409);
  await publishTxt(claim.record_name, [claim.record_value]);
  expect((await verifyDomain(token, slug, org.id, claim.id)).status).toBe('verified');
  const routed = await patchDomainRouting(token, slug, org.id, claim.id, {
    connection_id: connection.id,
    routing: true,
  });
  expect(routed.routing).toBe(true);
  expect(routed.allow_local_password).toBe(true);

  // A local account on the routed domain (password sign-in while passwords are allowed).
  const local = { email: `local-${randomBytes(4).toString('hex')}@${domain}`, password: randomPassword() };
  await createUser(token, { ...local, email_verified: true }, slug);
  const client = await createOrgClient(token, slug, 'https://hrd-rp.example.test/callback', 'optional');

  await test.step('the sign-in page asks for the email first; a routed address gets the SSO choice', async () => {
    await page.goto(`${issuer}/ui/login`);
    await expect(page.locator('#login-identify-form')).toBeVisible();
    await expect(page.locator('#password')).toHaveCount(0);
    // The org connection has no button of its own on the page.
    await expect(page.locator(`#upstream-${connectionSlug}`)).toHaveCount(0);
    await expectNoA11yViolations(page);
    await submitEmailFirst(page, local.email);
    await expectSsoChoice(page, local.email);
    await expectNoA11yViolations(page);
  });

  await test.step('"Use password instead" signs in with the local password', async () => {
    await page.locator('#login-use-password').click();
    await expectPasswordStep(page, local.email);
    await page.locator('#password').fill(local.password);
    await page.locator('#login-submit').click();
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
    await page.context().clearCookies();
  });

  await test.step('passwords cannot be turned off before a sign-in through the connection', async () => {
    const refused = await patchDomainRouting(token, slug, org.id, claim.id, { allow_local_password: false }, 409);
    expect(JSON.stringify(refused)).toContain('sign-in');
    expect((await orgDomains(token, slug, org.id)).find((d) => d.id === claim.id)?.allow_local_password).toBe(true);
  });

  await test.step('an RP request with organization=<org> goes to the IdP; JIT member, org in the token', async () => {
    const stop = await addAuthorizeParams(page, { organization: org.slug }, issuer);
    const tokens = await authorizationCodeFlow(
      page,
      client,
      'openid email',
      async (p) => {
        await stop();
        // Straight to the org's IdP (the upstream tenant's own login page), no email page.
        await expect(p).toHaveURL((url) => url.pathname.startsWith(`/t/${upstream.slug}/ui/login`));
        await login(p, ssoUser.email, ssoUser.password);
      },
      issuer,
    );
    if (!tokens.id_token) throw new Error('no id_token');
    const claims = jwtClaims(tokens.id_token);
    expect(claims.org_id).toBe(org.id);
    const users = await tenantUsers(token, slug);
    const jit = users.find((u) => u.email === ssoUser.email.toLowerCase());
    expect(jit?.id).toBe(claims.sub);
    expect((await orgMembers(token, slug, org.id)).map((m) => m.user_id)).toContain(jit?.id);
    await page.context().clearCookies();
  });

  await test.step('allow_local_password=false is now accepted; the address goes straight to the IdP', async () => {
    const updated = await patchDomainRouting(token, slug, org.id, claim.id, { allow_local_password: false });
    expect(updated.allow_local_password).toBe(false);
    await page.goto(`${issuer}/ui/login`);
    await submitEmailFirst(page, local.email);
    await expect(page).toHaveURL((url) => url.pathname.startsWith(`/t/${upstream.slug}/ui/login`));
    await page.context().clearCookies();
  });

  await test.step('an address outside the routed domain gets the password step', async () => {
    const other = randomEmail('hrd-other');
    await page.goto(`${issuer}/ui/login`);
    await submitEmailFirst(page, other);
    await expectPasswordStep(page, other);
    await expectNoA11yViolations(page);
  });
});
