// ORG-02 in a browser: the organization switcher (06-19). A user who belongs to two organizations
// signs in to a client whose organization policy is `required`, picks one of them on
// /ui/select-organization (axe-clean) and the tokens carry that org. A new authorization request
// with `organization=<the other org>` then switches orgs on the existing session, with no password
// prompt and no switcher.
//
// The `organization` parameter is added by rewriting the authorization request (lib/authorize.ts,
// the 04-28 precedent); lib/code-flow.ts runs the code flow and reads the ID token claims.
//
// Runs in a tenant of its own (deleted afterwards). Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE.

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminToken, createUser, login, randomEmail, randomPassword, sharedManagementCredential } from '../lib/anvil';
import { addAuthorizeParams } from '../lib/authorize';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { addMember, createOrg, createOrgClient, createOrgTenant, type OrgTenant } from '../lib/org';

let tenant: OrgTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('a member of two orgs picks one on the switcher, then switches with organization=<other>', async ({
  page,
  browser,
}) => {
  test.setTimeout(120_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createOrgTenant(token, 'orgsw');
  const { slug, issuer } = tenant;
  expect(slug).not.toBe('default');

  const acme = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  const beta = await createOrg(token, slug, { slug: 'beta', display_name: 'Beta Labs' });
  // A third org the user is not a member of never shows up on the switcher.
  await createOrg(token, slug, { slug: 'gamma', display_name: 'Gamma Works' });
  const email = randomEmail('orgsw');
  const password = randomPassword();
  const user = await createUser(token, { email, password, email_verified: true }, slug);
  if (!user.id) throw new Error('created user has no id');
  await addMember(token, slug, acme.id, user.id);
  await addMember(token, slug, beta.id, user.id);
  const client = await createOrgClient(token, slug, 'https://orgsw-rp.example.test/callback', 'required');

  let firstSub = '';
  await test.step('sign in, pick Beta Labs on the switcher: the token carries beta', async () => {
    const tokens = await authorizationCodeFlow(
      page,
      client,
      'openid email',
      async (p) => {
        await login(p, email, password);
        await expect(p).toHaveURL((url) => url.pathname === `/t/${slug}/ui/select-organization`);
        const form = p.locator('form#select-organization-form');
        await expect(form).toBeVisible();
        await expect(p.locator('#organization-acme')).toBeVisible();
        await expect(p.locator('#organization-beta')).toBeVisible();
        await expect(p.locator('#organization-beta-label')).toContainText('Beta Labs');
        await expect(p.locator('#organization-gamma')).toHaveCount(0);
        await expect(form).not.toContainText('Gamma Works');
        await expectNoA11yViolations(p);
        await p.locator('#organization-beta').check();
        await p.locator('#select-organization-form-submit').click();
      },
      issuer,
    );
    if (!tokens.id_token) throw new Error('no id_token');
    const claims = jwtClaims(tokens.id_token);
    expect(claims.sub).toBe(user.id);
    expect(claims.org_id).toBe(beta.id);
    expect(claims.org_slug).toBe('beta');
    firstSub = String(claims.sub);
  });

  await test.step('a new request with organization=<acme> switches without a password prompt', async () => {
    const visited: string[] = [];
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) visited.push(frame.url());
    });
    const stop = await addAuthorizeParams(page, { organization: acme.id }, issuer);
    let tokens;
    try {
      tokens = await authorizationCodeFlow(
        page,
        client,
        'openid email',
        async () => {
          // The session satisfies the request: straight back to the client.
        },
        issuer,
      );
    } finally {
      await stop();
    }
    if (!tokens.id_token) throw new Error('no id_token');
    const claims = jwtClaims(tokens.id_token);
    expect(claims.sub).toBe(firstSub);
    expect(claims.org_id).toBe(acme.id);
    expect(claims.org_slug).toBe('acme');
    // Neither the sign-in page nor the switcher was shown.
    expect(visited.filter((u) => u.includes('/ui/login') || u.includes('/ui/select-organization'))).toEqual([]);
  });
});
