// AUTH-11, UI-01: the linked accounts page without JavaScript (Playwright project `nojs`). A
// password user connects a GitHub-like provider (mock IdP on 127.0.0.1, plain links and forms, no
// script) from /ui/account/linked, sees it listed and disconnects it again, all with JavaScript
// disabled. After the provider returns, the browser shows the `upstream.linked` message page
// (current behaviour); the spec then opens the linked accounts page itself.
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
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'upstream.linked');
  });

  await test.step('the link is listed', async () => {
    await page.goto(linkedPage);
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
