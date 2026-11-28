// Self-service registration -> verification email (real SMTP, captured by Mailpit) -> confirm.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  findUserByEmail,
  getUser,
  login,
  randomEmail,
  randomPassword,
  register,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { extractLink, latestMessageTo } from '../lib/mailpit';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

test('a failed registration redirects (Post/Redirect/Get) and keeps the email, not the password', async ({
  page,
}) => {
  await page.goto(`${anvilUrl()}/ui/registration`);
  const email = randomEmail('reg-prg');
  await register(page, email, 'short');
  await expect(page).toHaveURL(/\/ui\/registration\?flow=/);
  await expect(page.locator('#password-msg-1')).toBeVisible();
  await expect(page.locator('#email')).toHaveValue(email);
  await expect(page.locator('#password')).toHaveValue('');
});

test('registration sends a verification email whose link verifies the address', async ({
  page,
}) => {
  const email = randomEmail('reg');
  const password = randomPassword();

  await page.goto(`${anvilUrl()}/ui/registration`);
  await expect(page.locator('form#registration')).toBeVisible();
  await register(page, email, password);
  await expect(page.locator('#message-body')).toBeVisible();

  const token = await adminToken(creds);
  const user = await findUserByEmail(token, email);
  expect(user, 'registered user exists').toBeDefined();
  expect(user!.email_verified).toBe(false);

  const message = await latestMessageTo(email);
  const link = extractLink(message.Text || message.HTML, '/ui/verification');

  // Opening the link does not consume the token; the confirm button does.
  await page.goto(link);
  expect((await getUser(token, user!.id)).email_verified).toBe(false);
  await page.locator('#verification-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute(
    'data-message-key',
    'verification.done',
  );

  expect((await getUser(token, user!.id)).email_verified).toBe(true);

  // The same link cannot be used twice: opening it again says so before anything is clicked,
  // and offers the way to sign in instead of the button.
  const reopened = await page.goto(link);
  expect(reopened?.status()).toBe(400);
  await expect(page.locator('[data-message-key="links.expired"]')).toBeVisible();
  await expect(page.locator('#verification-submit')).toHaveCount(0);
  await expect(page.locator('#link-login')).toBeVisible();

  // The new account can sign in.
  await page.context().clearCookies();
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
});
