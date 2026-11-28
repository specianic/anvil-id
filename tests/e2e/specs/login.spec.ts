// Hosted login page: a wrong password gets the generic message, and the page loads nothing from
// any host other than AnvilID itself.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
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

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

test('wrong password shows the generic message and the page makes no external requests', async ({
  page,
}) => {
  const email = randomEmail('login');
  const password = randomPassword();
  const token = await adminToken(creds);
  await createUser(token, { email, password, email_verified: true });

  const allowed = new URL(anvilUrl()).host;
  const foreign: string[] = [];
  page.on('request', (req) => {
    const url = new URL(req.url());
    if (url.protocol !== 'data:' && url.host !== allowed) {
      foreign.push(req.url());
    }
  });

  await page.goto(`${anvilUrl()}/ui/login`);
  await expect(page.locator('form#login')).toBeVisible();
  await login(page, email, randomPassword());
  const wrongPassword = page.locator('[data-message-key="login.invalid_credentials"]');
  await expect(wrongPassword).toBeVisible();
  // Post/Redirect/Get: the error page is a GET of the flow, with the identifier kept.
  await expect(page).toHaveURL(/\/ui\/login\?flow=/);
  await expect(page.locator('#identifier')).toHaveValue(email);
  const wrongText = (await wrongPassword.textContent())?.trim();

  // An unknown account gets the identical message.
  await login(page, randomEmail('nobody'), randomPassword());
  const unknown = page.locator('[data-message-key="login.invalid_credentials"]');
  await expect(unknown).toBeVisible();
  expect((await unknown.textContent())?.trim()).toBe(wrongText);

  // The password is never echoed back into the form.
  await expect(page.locator('#password')).toHaveValue('');

  // The right password signs in.
  await login(page, email, password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');

  expect(foreign, 'requests to hosts other than AnvilID').toEqual([]);
});
