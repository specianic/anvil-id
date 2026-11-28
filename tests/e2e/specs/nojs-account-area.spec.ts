// 07.1-21 without JavaScript (U-M12, U-L8, UI-01): the confirmation step of destructive account
// actions is a plain HTML page (#form-confirm), a destructive POST changes nothing until it is
// confirmed, Cancel is a link back, a refused account form is a GET of the page, signing out this
// device ends on the signed-out page, and the header's Sign out is a POST form.
//
// Runs in the Playwright `nojs` project (JavaScript disabled); each test asserts that it really is off.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { userSessions } from '../lib/admin';
import { enrolTotp, signInDirect } from '../lib/account';

const account = (path: string) => `${anvilUrl()}/ui/account/${path}`;

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
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

test('removing the authenticator app asks first, without JavaScript', async ({ page }) => {
  await expectJavaScriptOff(page);
  const user = await newUser('nojs-confirm');
  await signInDirect(page, user.email, user.password);
  await enrolTotp(page);

  await page.goto(account('security'));
  const remove = page.locator('#totp form[id^="credential-delete-"] button');
  await remove.click();
  // The question is its own page; nothing was removed.
  await expect(page.locator('#account-confirm')).toHaveAttribute('data-action', 'remove-totp');
  await expect(page.locator('#form-confirm input[name="confirm"]')).toHaveValue('yes');
  await page.locator('#link-confirm-cancel').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/account/security'));
  await expect(page.locator('#recovery-codes-count')).toHaveText('10');

  // Confirmed: removed.
  await remove.click();
  await page.locator('#form-confirm-submit').click();
  await expect(page.locator('[data-message-key="account.totp_removed"]')).toBeVisible();
  await expect(page.locator('#totp-begin-submit')).toBeVisible();
});

test('sign out other devices asks first; signing out this device shows the signed-out page', async ({
  page,
  browser,
}) => {
  await expectJavaScriptOff(page);
  const user = await newUser('nojs-sessions');
  const other = await browser.newContext({ javaScriptEnabled: false });
  try {
    await signInDirect(await other.newPage(), user.email, user.password);
    await signInDirect(page, user.email, user.password);
    await page.goto(account('sessions'));
    await expect(page.locator('#session-list tbody tr')).toHaveCount(2);

    await page.locator('#sessions-revoke-others-submit').click();
    await expect(page.locator('#account-confirm')).toHaveAttribute('data-action', 'sign-out-others');
    expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(2);
    await page.locator('#form-confirm-submit').click();
    await expect(page.locator('[data-message-key="sessions.revoked_others"]')).toBeVisible();
    await expect(page.locator('#session-list tbody tr')).toHaveCount(1);
  } finally {
    await other.close();
  }

  // This device, from its own row: the signed-out page with a way forward (U-L8).
  await page.locator('tr[data-current] button[id$="-submit"]').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await expect(page.locator('#logout-message')).toHaveAttribute('data-message-key', 'logout.signed_out');
  await expect(page.locator('#link-login')).toBeVisible();
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(0);
});

test('a refused account form is a GET of the page and the header signs out with a POST', async ({
  page,
}) => {
  await expectJavaScriptOff(page);
  const user = await newUser('nojs-prg');
  await signInDirect(page, user.email, user.password);

  await page.goto(account('password'));
  await page.locator('#new_password').fill('short');
  await page.locator('#password-form-submit').click();
  await expect(page.locator('[data-message-key="account.password_too_short"]')).toBeVisible();
  await expect(page).toHaveURL(
    (url) => url.pathname.endsWith('/ui/account/password') && url.searchParams.has('flow'),
  );
  await page.reload();
  await expect(page.locator('[data-message-key="account.password_too_short"]')).toHaveCount(0);

  // Sign out from the header: a POST form, then the CSRF-bound confirmation.
  await expect(page.locator('#form-sign-out')).toHaveAttribute('method', 'post');
  await page.locator('#sign-out-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/logout'));
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(0);
});
