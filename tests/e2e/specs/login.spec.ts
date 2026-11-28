// Hosted login page: a wrong password gets the generic message, and the page loads nothing from
// any host other than AnvilID itself. The first field has the initial focus, an empty submit
// asks for the address, and with email sign-in on there is one address field (plan 07.1-13).
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
import { createEmailSignInTenant, deleteTenant, requestEmailCode } from '../lib/email-code';

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

test('sign-in page: initial focus, empty submit asks for the address, one email field', async ({
  page,
  browser,
}) => {
  await page.goto(`${anvilUrl()}/ui/login`);
  // U-L2: the first field has the focus.
  await expect(page.locator('#identifier')).toBeFocused();

  // U-L1: an empty submit asks for the address instead of saying "incorrect".
  await page.locator('#login-submit').click();
  await expect(page).toHaveURL(/\/ui\/login\?flow=/);
  await expect(page.locator('[data-message-key="signin.identifier_required"]')).toBeVisible();
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toHaveCount(0);

  // U-M7: with email sign-in on, one address field serves both the password and the email code.
  const tok = await adminToken(await sharedManagementCredential(browser));
  const tenant = await createEmailSignInTenant(tok, 'login-onefield');
  try {
    const signIn = await browser.newPage();
    try {
      await signIn.goto(`${tenant.base}/ui/login`);
      await expect(signIn.locator('input[type=email]')).toHaveCount(1);
      await expect(signIn.locator('#email-code-request-submit')).toBeVisible();
      await expect(signIn.locator('#email-code-email')).toHaveCount(0);
      await requestEmailCode(signIn, randomEmail('onefield'));
    } finally {
      await signIn.close();
    }
  } finally {
    await deleteTenant(tok, tenant.slug);
  }
});
