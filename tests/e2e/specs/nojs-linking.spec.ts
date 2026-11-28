// AUTH-11, UI-01: the linked accounts page without JavaScript (Playwright project `nojs`). A
// password user connects a GitHub-like provider (mock IdP on 127.0.0.1, plain links and forms, no
// script) from /ui/account/linked, sees it listed and disconnects it again, all with JavaScript
// disabled. After the provider returns, the callback answers 303 back to /ui/account/linked, which
// lists the new identity.
//
// axe needs script injection, so the audits live in linking.spec.ts (chromium project).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import type { MockIdp } from '../lib/mock-idp';
import { createTenant, githubMockConnection, randomSlug, signInAtTenant, tenantIssuer } from '../lib/upstream';

let mock: MockIdp | undefined;

test.afterAll(async () => {
  await mock?.stop();
});

test('connect and disconnect on /ui/account/linked without JavaScript', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const tok = await adminToken(await sharedManagementCredential(browser));
  const tenant = randomSlug('nojs-link');
  await createTenant(tok, tenant);
  const email = randomEmail('nojslink');
  const password = randomPassword();
  await createUser(tok, { email, password, email_verified: true }, tenant);
  const upstreamEmail = `octo-${tenant}@example.test`;
  ({ mock } = await githubMockConnection(tok, tenant, 'github', [
    { sub: '8200001', id: 8200001, login: `octo-${tenant}`, name: 'Octo Cat', email: upstreamEmail },
  ]));
  const idp = mock;
  const linkedPage = `${tenantIssuer(tenant)}/ui/account/linked`;

  await signInAtTenant(page, tenant, email, password);

  await test.step('the page renders with a Connect form', async () => {
    await page.goto(linkedPage);
    await expect(page.locator('#linked-heading')).toBeVisible();
    await expect(page.locator('#linked-none')).toBeVisible();
    await expect(page.locator('form#linked-connect-github')).toHaveAttribute('method', 'post');
  });

  await test.step('Connect through the mock (plain link back to the callback)', async () => {
    await page.locator('#linked-connect-github-submit').click();
    await expect(page).toHaveURL((url) => url.origin === idp.url && url.pathname === '/login/oauth/authorize');
    await page.locator('#mock-continue').click();
    await expect(page).toHaveURL((url) => url.href.startsWith(linkedPage));
  });

  await test.step('the link is listed', async () => {
    const rows = page.locator('#linked-list tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('GitHub');
    await expect(page.locator('form#linked-connect-github')).toHaveCount(0);
  });

  await test.step('Disconnect posts the form and removes the link', async () => {
    await page.locator('#linked-list button[id^="linked-unlink-"]').click();
    await expect(page.locator('[data-message-key="linked.unlinked"]')).toBeVisible();
    await expect(page.locator('#linked-none')).toBeVisible();
    await expect(page.locator('form#linked-connect-github')).toBeVisible();
  });
});

test('link confirmation without JavaScript: copy matches the field, failed confirmation is PRG', async ({
  page,
  browser,
}) => {
  test.setTimeout(120_000);
  const tok = await adminToken(await sharedManagementCredential(browser));
  const tenant = randomSlug('nojs-confirm');
  await createTenant(tok, tenant, { auto_link: false });
  const email = randomEmail('nojsconfirm');
  const password = randomPassword();
  await createUser(tok, { email, password, email_verified: true }, tenant);
  const { mock: idp } = await githubMockConnection(tok, tenant, 'github', [
    { sub: '8200002', id: 8200002, login: `octo2-${tenant}`, name: 'Octo Cat', email },
  ]);
  try {
    await page.goto(`${tenantIssuer(tenant)}/ui/login`);
    await page.locator('#upstream-github').click();
    await expect(page).toHaveURL((url) => url.origin === idp.url);
    await page.locator('#mock-continue').click();
    await expect(page.locator('form#upstream-link')).toBeVisible();

    // U-M9: the copy and the address field agree.
    if (await page.locator('[data-message-key="upstream.link_explain"]').count()) {
      await expect(page.locator('#identifier')).toHaveValue(email);
    } else {
      await expect(page.locator('[data-message-key="upstream.link_explain_hidden"]')).toBeVisible();
      await expect(page.locator('#identifier')).toHaveValue('');
    }

    // A wrong password: Post/Redirect/Get back to the confirmation page; a reload is harmless.
    await page.locator('#identifier').fill(email);
    await page.locator('#password').fill(`${password}-wrong`);
    await page.locator('#upstream-link-submit').click();
    await expect(page).toHaveURL(/\/ui\/login\?flow=/);
    await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
    await page.reload();
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await expect(page.locator('#link-cancel')).toBeVisible();

    // The right password links and signs in.
    await page.locator('#identifier').fill(email);
    await page.locator('#password').fill(password);
    await page.locator('#upstream-link-submit').click();
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  } finally {
    await idp.stop();
  }
});
