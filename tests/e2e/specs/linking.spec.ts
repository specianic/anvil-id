// AUTH-11: account linking in a real browser, with the mock IdP on 127.0.0.1 and AnvilID on
// localhost (cross-site, real SameSite behaviour).
//
//   1. auto-link: a trusted GitHub-like connection asserts a verified primary email equal to an
//      existing verified local account's, tenant auto_link on -> signed in as that account, no
//      duplicate user, identity_linked mode auto
//   2. confirmation: the same with auto_link off -> the link confirmation page -> password sign-in
//      -> linked (mode confirmed); the next upstream sign-in goes straight in
//   3. account page: connect the Apple-like provider from /ui/account/linked (form_post hop) ->
//      303 back to /ui/account/linked, where the new identity is listed; disconnect -> removed; a
//      user whose only sign-in method is the link cannot disconnect it
//
// The confirmation page and the linked accounts page pass the axe WCAG 2.2 AA audit. Each test uses its own tenant. No-JS coverage: nojs-linking.spec.ts.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { auditEvents } from '../lib/account';
import { startSampleRp, type SampleRp } from '../lib/console';
import type { MockIdp } from '../lib/mock-idp';
import {
  appleMockConnection,
  createTenant,
  githubMockConnection,
  randomSlug,
  signInAtTenant,
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

interface LocalUser {
  id: string;
  email: string;
  password: string;
}

async function localUser(tok: string, tenant: string, prefix: string): Promise<LocalUser> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  const created = await createUser(tok, { email, password, email_verified: true }, tenant);
  expect(created.id).toBeTruthy();
  return { id: created.id ?? '', email, password };
}

/** A GitHub-like mock user whose verified primary address is `email`. */
function githubUser(email: string, id: number) {
  return { sub: String(id), id, login: `octo-${id}`, name: 'Octo Cat', email };
}

/** RP -> login page -> GitHub-like button -> the mock's approval link. */
async function startGithubSignIn(page: Page, rp: SampleRp, tenant: string, mock: MockIdp): Promise<void> {
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.pathname.startsWith(`/t/${tenant}/ui/login`));
  await page.locator('#upstream-github').click();
  await expect(page).toHaveURL((url) => url.origin === mock.url);
  await page.locator('#mock-continue').click();
}

async function rpSub(page: Page, rp: SampleRp): Promise<string> {
  await expect(page).toHaveURL(`${rp.base}/me`);
  return ((await page.locator('#sub').textContent()) ?? '').trim();
}

async function linkModes(tok: string, tenant: string): Promise<unknown[]> {
  const events = await auditEvents(tok, { action: 'identity_linked' }, tenant);
  return events.map((e) => e.details.mode);
}

test('auto-link: trusted verified email signs in as the existing account', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await token(browser);
  const tenant = randomSlug('link-auto');
  await createTenant(tok, tenant, { auto_link: true });
  const user = await localUser(tok, tenant, 'autolink');
  const { mock } = await githubMockConnection(tok, tenant, 'github', [githubUser(user.email, 8100001)]);
  mocks.push(mock);
  const rp = await startSampleRp(tok, 'e2e linking auto', tenant);
  rps.push(rp);

  await startGithubSignIn(page, rp, tenant, mock);
  expect(await rpSub(page, rp)).toBe(user.id);
  await expect(page.locator('#email')).toHaveText(user.email);

  const users = await tenantUsers(tok, tenant);
  expect(users.map((u) => u.id)).toEqual([user.id]);
  expect(await linkModes(tok, tenant)).toEqual(['auto']);
});

test('confirmation: auto_link off asks for the password, then links', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await token(browser);
  const tenant = randomSlug('link-confirm');
  await createTenant(tok, tenant, { auto_link: false });
  const user = await localUser(tok, tenant, 'confirmlink');
  const { mock } = await githubMockConnection(tok, tenant, 'github', [githubUser(user.email, 8100002)]);
  mocks.push(mock);
  const rp = await startSampleRp(tok, 'e2e linking confirm', tenant);
  rps.push(rp);

  await test.step('the provider return shows the link confirmation page', async () => {
    await startGithubSignIn(page, rp, tenant, mock);
    await expect(page).toHaveURL((url) => url.origin === new URL(tenantIssuer(tenant)).origin);
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await expect(page.locator('[data-message-key="upstream.link_explain"]')).toBeVisible();
    await expect(page.locator('#link-cancel')).toBeVisible();
    await expectNoA11yViolations(page);
    // Nothing is linked and no second account exists before the password proof.
    expect(await linkModes(tok, tenant)).toEqual([]);
    expect((await tenantUsers(tok, tenant)).map((u) => u.id)).toEqual([user.id]);
  });

  await test.step('a wrong password links nothing', async () => {
    await page.locator('#identifier').fill(user.email);
    await page.locator('#password').fill(`${user.password}-wrong`);
    await page.locator('#upstream-link-submit').click();
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
    expect(await linkModes(tok, tenant)).toEqual([]);
  });

  await test.step('the password links the account and finishes the sign-in at the RP', async () => {
    await page.locator('#identifier').fill(user.email);
    await page.locator('#password').fill(user.password);
    await page.locator('#upstream-link-submit').click();
    expect(await rpSub(page, rp)).toBe(user.id);
    expect(await linkModes(tok, tenant)).toEqual(['confirmed']);
  });

  await test.step('the next upstream sign-in goes straight in', async () => {
    const context = await browser.newContext();
    try {
      const second = await context.newPage();
      await startGithubSignIn(second, rp, tenant, mock);
      expect(await rpSub(second, rp)).toBe(user.id);
    } finally {
      await context.close();
    }
    expect((await tenantUsers(tok, tenant)).map((u) => u.id)).toEqual([user.id]);
    expect(await linkModes(tok, tenant)).toEqual(['confirmed']);
  });
});

test('account page: connect and disconnect, last method refused', async ({ page, browser }) => {
  test.setTimeout(150_000);
  const tok = await token(browser);
  const tenant = randomSlug('link-account');
  await createTenant(tok, tenant);
  const user = await localUser(tok, tenant, 'accountlink');
  const linkedSub = '001111.e2e0account0link.0001';
  const onlySub = '002222.e2e0link0only.0002';
  const { mock } = await appleMockConnection(tok, tenant, 'apple', [
    { sub: linkedSub, email: `connect-${tenant}@privaterelay.example.test`, firstName: 'Con', lastName: 'Nect' },
    { sub: onlySub, email: `only-${tenant}@privaterelay.example.test`, firstName: 'On', lastName: 'Ly' },
  ]);
  mocks.push(mock);
  const linkedPage = `${tenantIssuer(tenant)}/ui/account/linked`;

  await test.step('the linked accounts page offers Connect and passes axe', async () => {
    await signInAtTenant(page, tenant, user.email, user.password);
    await page.goto(linkedPage);
    await expect(page.locator('#linked-heading')).toBeVisible();
    await expect(page.locator('#account-reauth')).toHaveCount(0);
    await expect(page.locator('#linked-none')).toBeVisible();
    await expect(page.locator('#linked-connect-apple-submit')).toHaveAttribute('data-connection', 'apple');
    await expect(page.locator('#account-nav-linked')).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('Connect runs the Apple-like form_post round trip and links the account', async () => {
    mock.selectUser(linkedSub);
    await page.locator('#linked-connect-apple-submit').click();
    await expect(page).toHaveURL((url) => url.origin === mock.url && url.pathname === '/auth/authorize');
    await page.locator('#mock-continue').click();
    // The callback answers 303 back to the linked accounts page, which lists the new identity.
    await expect(page).toHaveURL((url) => url.href.startsWith(linkedPage));
    await expect(page.locator('#linked-list tbody tr')).toHaveCount(1);
    await expect(page.locator('#linked-none')).toHaveCount(0);
    expect(await linkModes(tok, tenant)).toEqual(['account']);
    // Linking created no account.
    expect((await tenantUsers(tok, tenant)).map((u) => u.id)).toEqual([user.id]);
  });

  await test.step('the link is listed; Connect for Apple is gone', async () => {
    await page.goto(linkedPage);
    const rows = page.locator('#linked-list tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Apple');
    await expect(rows.first()).toContainText(`connect-${tenant}@privaterelay.example.test`);
    await expect(page.locator('#linked-connect-apple')).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  await test.step('Disconnect removes the link', async () => {
    await page.locator('#linked-list button[id^="linked-unlink-"]').click();
    await expect(page.locator('[data-message-key="linked.unlinked"]')).toBeVisible();
    await expect(page.locator('#linked-none')).toBeVisible();
    await expect(page.locator('#linked-connect-apple-submit')).toBeVisible();
    const unlinked = await auditEvents(tok, { action: 'identity_unlinked' }, tenant);
    expect(unlinked).toHaveLength(1);
  });

  await test.step('a link-only account cannot disconnect its last sign-in method', async () => {
    const context = await browser.newContext();
    try {
      const p = await context.newPage();
      mock.selectUser(onlySub);
      await p.goto(`${tenantIssuer(tenant)}/ui/login`);
      await p.locator('#upstream-apple').click();
      await expect(p).toHaveURL((url) => url.origin === mock.url);
      await p.locator('#mock-continue').click();
      await expect(p.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');

      await p.goto(linkedPage);
      await expect(p.locator('#account-reauth')).toHaveCount(0);
      const rows = p.locator('#linked-list tbody tr');
      await expect(rows).toHaveCount(1);
      const [resp] = await Promise.all([
        p.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/unlink')),
        p.locator('#linked-list button[id^="linked-unlink-"]').click(),
      ]);
      expect(resp.status()).toBe(409);
      const refusal = p.locator('[data-message-key="account.last_sign_in_method"]');
      await expect(refusal).toBeVisible();
      await expect(refusal).toHaveAttribute('role', 'alert');
      await expect(p.locator('#linked-list tbody tr')).toHaveCount(1);
      await expectNoA11yViolations(p);
    } finally {
      await context.close();
    }
    expect(await auditEvents(tok, { action: 'identity_unlinked' }, tenant)).toHaveLength(1);
  });
});
