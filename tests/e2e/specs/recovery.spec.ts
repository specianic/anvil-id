// Password recovery over real SMTP (Mailpit): the reset link sets a new password, the old one stops
// working with the generic message, and an unknown address gets the same page.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { extractLink, latestMessageTo } from '../lib/mailpit';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

async function requestReset(page: Page, email: string): Promise<string> {
  await page.goto(`${anvilUrl()}/ui/recovery`);
  await expect(page.locator('form#recovery')).toBeVisible();
  await page.locator('#email').fill(email);
  await page.locator('#recovery-submit').click();
  const body = page.locator('#message-body');
  await expect(body).toHaveAttribute('data-message-key', 'recovery.sent');
  return (await body.textContent())?.trim() ?? '';
}

async function loginError(page: Page, email: string, password: string): Promise<string> {
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  const msg = page.locator('[data-message-key="login.invalid_credentials"]');
  await expect(msg).toBeVisible();
  return (await msg.textContent())?.trim() ?? '';
}

test('recovery link sets a new password; the old one stops working', async ({ page }) => {
  const email = randomEmail('rec');
  const oldPassword = randomPassword();
  const newPassword = randomPassword();
  const token = await adminToken(creds);
  await createUser(token, { email, password: oldPassword, email_verified: true });

  const sentText = await requestReset(page, email);
  const message = await latestMessageTo(email);
  const link = extractLink(message.Text || message.HTML, '/ui/recovery');

  await page.goto(link);
  await page.locator('input[type="password"]').first().fill(newPassword);
  const confirm = page.locator('input[type="password"]').nth(1);
  if ((await confirm.count()) > 0) {
    await confirm.fill(newPassword);
  }
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.done');

  // The used link says so on opening, before anything is typed, and offers a new link.
  const reopened = await page.goto(link);
  expect(reopened?.status()).toBe(400);
  await expect(page.locator('[data-message-key="links.expired"]')).toBeVisible();
  await expect(page.locator('form#recovery')).toBeVisible();
  await expect(page.locator('input[type="password"]')).toHaveCount(0);

  // Old password: the same generic message as any wrong password.
  await page.context().clearCookies();
  const wrongText = await loginError(page, email, randomPassword());
  const oldText = await loginError(page, email, oldPassword);
  expect(oldText).toBe(wrongText);

  // New password works.
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, newPassword);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');

  // An unknown address gets exactly the same page text.
  await page.context().clearCookies();
  const unknownText = await requestReset(page, randomEmail('nobody'));
  expect(unknownText).toBe(sentText);
});
