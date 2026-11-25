// AUTH-07: social and generic OIDC sign-in in a real browser, across sites.
//
// AnvilID runs on `localhost`; the Node mock IdP (lib/mock-idp.ts) binds 127.0.0.1, so Chromium
// treats the provider as another site and applies real SameSite rules to the return trip (the Lax
// binding cookie is the only cookie a cross-site form POST would not carry, and the callback turns
// Apple's form_post into a same-site GET first). Three round trips through the sample RP:
//
//   (a) AnvilID as a generic OIDC upstream: a second tenant of the same instance acts as the
//       provider (its own login page, client and discovery); the JIT user follows the untrusted
//       default (email not verified).
//   (b) Apple-like: form_post with the `user` JSON on the first authorization only, ES256 client
//       secret minted by AnvilID from the .p8 key; the first-login name is stored and a second
//       sign-in does not change it.
//   (c) GitHub-like: the verified primary address is the account email; the authorization request
//       carries PKCE (the mock's request log).
//
// Every test uses its own downstream tenant, so connection buttons never reach the shared default
// tenant's login page. The login page with connection buttons and the generic upstream error page
// pass the axe WCAG 2.2 AA audit. Only the mock and AnvilID are contacted.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminToken, anvilUrl, login, sharedManagementCredential } from '../lib/anvil';
import { startSampleRp, type SampleRp } from '../lib/console';
import { mockIdpRedirectUri, type MockIdp } from '../lib/mock-idp';
import {
  appleMockConnection,
  createConnection,
  createTenant,
  createUpstreamTenant,
  githubMockConnection,
  randomSlug,
  tenantIssuer,
  tenantUsers,
} from '../lib/upstream';

const rps: SampleRp[] = [];
const mocks: MockIdp[] = [];

test.afterEach(async () => {
  for (const rp of rps.splice(0)) await rp.stop();
  for (const mock of mocks.splice(0)) await mock.stop();
});

async function token(browser: Browser): Promise<string> {
  return adminToken(await sharedManagementCredential(browser));
}

/** A fresh downstream tenant with a sample RP signed in against it. */
async function downstream(tok: string, label: string): Promise<{ tenant: string; rp: SampleRp }> {
  const tenant = randomSlug('social');
  await createTenant(tok, tenant);
  const rp = await startSampleRp(tok, `e2e social ${label}`, tenant);
  rps.push(rp);
  return { tenant, rp };
}

/** Starts a sign-in at the RP and waits for the downstream tenant's login page with `slug`. */
async function openLoginWithConnection(page: Page, rp: SampleRp, tenant: string, slug: string): Promise<void> {
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.pathname.startsWith(`/t/${tenant}/ui/login`));
  const button = page.locator(`#upstream-${slug}`);
  await expect(button).toBeVisible();
  await expect(button).toHaveAttribute('data-connection', slug);
}

/** The RP's profile page after a completed sign-in. */
async function expectSignedInAtRp(page: Page, rp: SampleRp, email: string): Promise<string> {
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
  return ((await page.locator('#sub').textContent()) ?? '').trim();
}

test('AnvilID as a generic OIDC upstream (second tenant)', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await token(browser);
  const { tenant, rp } = await downstream(tok, 'oidc');
  const slug = 'anvil-upstream';
  const upstream = await createUpstreamTenant(
    tok,
    randomSlug('upstream'),
    mockIdpRedirectUri(anvilUrl(), tenant, slug),
  );
  await createConnection(tok, tenant, {
    slug,
    display_name: 'Upstream AnvilID',
    config: {
      type: 'oidc',
      issuer: upstream.issuer,
      client_id: upstream.clientId,
      scopes: ['openid', 'profile', 'email'],
    },
    secret: upstream.clientSecret,
  });

  await test.step('login page lists the connection and passes axe', async () => {
    await openLoginWithConnection(page, rp, tenant, slug);
    await expectNoA11yViolations(page);
  });

  await test.step('upstream tenant login, then back at the RP signed in', async () => {
    await page.locator(`#upstream-${slug}`).click();
    // The upstream tenant's own hosted login page (same instance, other tenant).
    await expect(page).toHaveURL((url) => url.pathname.startsWith(`/t/${upstream.slug}/ui/login`));
    await login(page, upstream.user.email, upstream.user.password);
    const sub = await expectSignedInAtRp(page, rp, upstream.user.email);
    expect(sub).not.toBe('');

    // Just-in-time account in the downstream tenant; a generic OIDC connection is untrusted by
    // default, so the asserted email is not taken as verified.
    const users = await tenantUsers(tok, tenant);
    expect(users).toHaveLength(1);
    expect(users[0].id).toBe(sub);
    expect(users[0].email).toBe(upstream.user.email.toLowerCase());
    expect(users[0].email_verified).toBe(false);
  });
});

test('Apple-like provider: cross-site form_post, first-login name kept', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await token(browser);
  const { tenant, rp } = await downstream(tok, 'apple');
  const slug = 'apple';
  const { mock } = await appleMockConnection(tok, tenant, slug, [
    {
      sub: '001234.e2e0apple0subject.0001',
      email: `apple-${tenant}@privaterelay.example.test`,
      emailVerified: true,
      isPrivateEmail: true,
      firstName: 'Ada',
      lastName: 'Lovelace',
    },
  ]);
  mocks.push(mock);
  expect(new URL(mock.url).hostname).toBe('127.0.0.1');
  const email = mock.users[0].email;

  /** One sign-in through the mock's approval page (a plain form POST to AnvilID's callback). */
  async function appleSignIn(p: Page): Promise<string> {
    await openLoginWithConnection(p, rp, tenant, slug);
    await p.locator(`#upstream-${slug}`).click();
    await expect(p).toHaveURL((url) => url.origin === mock.url && url.pathname === '/auth/authorize');
    const approve = p.locator('form#mock-approve');
    await expect(approve).toHaveAttribute('method', 'post');
    await expect(approve).toHaveAttribute('action', mockIdpRedirectUri(anvilUrl(), tenant, slug));
    // Cross-site POST (127.0.0.1 -> localhost); AnvilID answers 303 to its GET callback.
    await p.locator('#mock-continue').click();
    return expectSignedInAtRp(p, rp, email);
  }

  let sub = '';
  await test.step('first sign-in creates the account with the name from the user JSON', async () => {
    sub = await appleSignIn(page);
    const authorize = mock.authorizations.filter((a) => a.endpoint === '/auth/authorize');
    expect(authorize).toHaveLength(1);
    expect(authorize[0].params.response_mode).toBe('form_post');
    expect(authorize[0].params.code_challenge).toBeUndefined();
    expect(authorize[0].userSent).toBe(true);
    // AnvilID authenticated at the token endpoint with an ES256 client secret the mock accepted.
    const tokens = mock.authorizations.filter((a) => a.endpoint === '/auth/token');
    expect(tokens.map((t) => t.status)).toEqual([200]);

    const users = await tenantUsers(tok, tenant);
    expect(users).toHaveLength(1);
    expect(users[0].id).toBe(sub);
    expect(users[0].claims.given_name).toBe('Ada');
    expect(users[0].claims.family_name).toBe('Lovelace');
  });

  await test.step('second sign-in (no user JSON) keeps the stored name', async () => {
    // A provider-side rename that a real Apple would never send again; the mock does not either.
    mock.users[0].firstName = 'Changed';
    mock.users[0].lastName = 'Name';
    const context = await browser.newContext();
    try {
      const second = await context.newPage();
      expect(await appleSignIn(second)).toBe(sub);
    } finally {
      await context.close();
    }
    const authorize = mock.authorizations.filter((a) => a.endpoint === '/auth/authorize');
    expect(authorize).toHaveLength(2);
    expect(authorize[1].userSent).toBe(false);
    const users = await tenantUsers(tok, tenant);
    expect(users).toHaveLength(1);
    expect(users[0].claims.given_name).toBe('Ada');
    expect(users[0].claims.family_name).toBe('Lovelace');
  });
});

test('GitHub-like provider: verified primary email, PKCE', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await token(browser);
  const { tenant, rp } = await downstream(tok, 'github');
  const slug = 'github';
  const primary = `octo-${tenant}@example.test`;
  const { mock } = await githubMockConnection(tok, tenant, slug, [
    {
      sub: '7340001',
      id: 7340001,
      login: `octo-${tenant}`,
      name: 'Octo Cat',
      email: primary,
      emails: [
        { email: `secondary-${tenant}@example.test`, primary: false, verified: true, visibility: null },
        { email: primary, primary: true, verified: true, visibility: 'private' },
        { email: `unverified-${tenant}@example.test`, primary: false, verified: false, visibility: null },
      ],
    },
  ]);
  mocks.push(mock);
  expect(new URL(mock.url).hostname).toBe('127.0.0.1');

  await test.step('sign in through the mock', async () => {
    await openLoginWithConnection(page, rp, tenant, slug);
    await page.locator(`#upstream-${slug}`).click();
    await expect(page).toHaveURL((url) => url.origin === mock.url && url.pathname === '/login/oauth/authorize');
    await page.locator('#mock-continue').click();
    const sub = await expectSignedInAtRp(page, rp, primary);
    const users = await tenantUsers(tok, tenant);
    expect(users).toHaveLength(1);
    expect(users[0].id).toBe(sub);
    expect(users[0].email).toBe(primary);
  });

  await test.step('the mock saw PKCE S256 and the REST calls AnvilID must send', async () => {
    const authorize = mock.authorizations.filter((a) => a.endpoint === '/login/oauth/authorize');
    expect(authorize).toHaveLength(1);
    expect(authorize[0].pkce).toBe(true);
    expect(authorize[0].params.code_challenge_method).toBe('S256');
    const tokenCalls = mock.authorizations.filter((a) => a.endpoint === '/login/oauth/access_token');
    expect(tokenCalls).toHaveLength(1);
    expect(tokenCalls[0].error).toBeUndefined();
    expect(tokenCalls[0].params.code_verifier).toBe('<present>');
    const api = mock.authorizations.filter((a) => a.endpoint === '/user' || a.endpoint === '/user/emails');
    expect(api.length).toBeGreaterThan(0);
    for (const call of api) {
      expect(call.userAgent).toBe(true);
      expect(call.status).toBe(200);
    }
  });

  await test.step('a forged callback ends on the generic error page, which passes axe', async () => {
    const context = await browser.newContext();
    try {
      const p = await context.newPage();
      const resp = await p.goto(
        `${tenantIssuer(tenant)}/ui/login/upstream/${slug}/callback?state=forged.state&code=forged`,
      );
      expect(resp?.status()).toBe(400);
      await expect(p.locator('form#login')).toBeVisible();
      await expect(p.locator('[data-message-key="upstream.failed"]')).toBeVisible();
      await expect(p.locator(`#upstream-${slug}`)).toBeVisible();
      await expectNoA11yViolations(p);
    } finally {
      await context.close();
    }
    // The forged callback never reached the provider.
    expect(mock.authorizations.filter((a) => a.endpoint === '/login/oauth/access_token')).toHaveLength(1);
  });
});
