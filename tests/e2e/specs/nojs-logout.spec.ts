// UI-01 for the 0.3 pages: the logout confirmation and the prompt=select_account chooser work with
// JavaScript disabled.
//
// Runs in the Playwright `nojs` project (JavaScript disabled); each test asserts that it really is off.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

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
import { userSessions } from '../lib/admin';
import { addAuthorizeParams } from '../lib/authorize';
import { endSessionUrl, startLogoutRp, waitForBackchannel, type LogoutRp } from '../lib/logout';

let creds: ManagementCredential;
let rp: LogoutRp;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  rp = await startLogoutRp(await adminToken(creds), 'e2e no-JS logout sample RP');
});

test.afterAll(async () => {
  await rp?.stop();
});

async function newUser(prefix: string): Promise<{ id: string; email: string; password: string }> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  const user = await createUser(await adminToken(creds), { email, password, email_verified: true });
  if (!user.id) throw new Error('created user has no id');
  return { id: user.id, email, password };
}

async function expectJavaScriptOff(page: Page): Promise<void> {
  await page.goto(`${anvilUrl()}/ui/login`);
  await page.setContent(
    '<p id="probe">no</p><script>document.getElementById("probe").textContent = "yes"</script>',
  );
  await expect(page.locator('#probe')).toHaveText('no');
}

async function signInAtRp(page: Page, email: string, password: string): Promise<string> {
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await login(page, email, password);
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
  return ((await page.locator('#sub').textContent()) ?? '').trim();
}

test('logout confirmation without JavaScript', async ({ page }) => {
  await expectJavaScriptOff(page);
  const user = await newUser('nojs-logout');
  await signInAtRp(page, user.email, user.password);

  await page.goto(endSessionUrl(anvilUrl()));
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/logout'));
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await expect(page.locator('#logout-message')).toHaveAttribute('data-message-key', 'logout.signed_out');
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(0);

  // Signed out: the account pages send the browser to the sign-in form.
  await page.goto(`${anvilUrl()}/ui/account/sessions`);
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
  await expect(page.locator('form#login')).toBeVisible();
});

test('account chooser without JavaScript: continue, then use another account', async ({ page }) => {
  await expectJavaScriptOff(page);
  const alice = await newUser('nojs-alice');
  const bob = await newUser('nojs-bob');
  const aliceSub = await signInAtRp(page, alice.email, alice.password);

  const stop = await addAuthorizeParams(page, { prompt: 'select_account' });
  try {
    // Continue with the current account.
    await page.goto(`${rp.base}/login`);
    await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/select-account'));
    await expect(page.locator('#select-account-email')).toHaveText(alice.email);
    await page.locator('#select-account-continue').click();
    await expect(page).toHaveURL(`${rp.base}/me`);
    await expect(page.locator('#email')).toHaveText(alice.email);

    // Use another account: the sign-in form, then the RP signed in as Bob.
    await page.goto(`${rp.base}/login`);
    await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/select-account'));
    await page.locator('#select-account-other').click();
    await expect(page.locator('form#login')).toBeVisible();
    await login(page, bob.email, bob.password);
    await expect(page).toHaveURL(`${rp.base}/me`);
    await expect(page.locator('#email')).toHaveText(bob.email);
  } finally {
    await stop();
  }

  // Alice's session was ended by the switch and her RP session told so over the back channel
  // (the switch does not wake the delivery worker: up to one 10 s poll interval).
  expect(await userSessions(await adminToken(creds), alice.id)).toHaveLength(0);
  expect(await waitForBackchannel(rp.base, aliceSub, 30_000)).not.toHaveLength(0);
});
