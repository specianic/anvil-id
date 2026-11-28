// 07.1-12 (U-H3, U-H4): the account area is reachable and leavable in a real browser.
//
// - Every account page has a header with the signed-in email (#account-identity) and a Sign out
//   button (#form-sign-out, a POST to the end-session endpoint that leads to the CSRF-protected
//   confirmation); it passes axe and does not overflow a phone screen.
// - An account link carrying the client_id of a static client with a home URL shows
//   "Back to <app>" (#link-back-to-app) with the stored URL, and the account navigation keeps it.
// - A signed-out deep link to an account page signs in and lands on that page.
// - 07.1-21: destructive actions ask first (#form-confirm; Cancel changes nothing), the sessions
//   page names devices ("Chrome on Windows"), the TOTP enrolment offers the otpauth:// link at
//   390px, and a refused password change is a GET of the page (Post/Redirect/Get).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createClient,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { enrolTotp, signInDirect } from '../lib/account';
import { expectNoHorizontalOverflow } from '../lib/layout';

const account = (path: string) => `${anvilUrl()}/ui/account/${path}`;

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

async function newUser(prefix: string): Promise<{ email: string; password: string }> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });
  return { email, password };
}

async function expectHeader(page: Page, email: string): Promise<void> {
  await expect(page.locator('#account-identity')).toHaveText(email);
  await expect(page.locator('#form-sign-out')).toHaveAttribute('method', 'post');
  await expect(page.locator('#sign-out-submit')).toBeVisible();
}

test('every account page shows who is signed in and signs out with a POST', async ({ page }) => {
  const user = await newUser('area-header');
  await signInDirect(page, user.email, user.password);

  for (const path of ['profile', 'email', 'password', 'security', 'sessions', 'apps', 'linked']) {
    await page.goto(account(path));
    await expectHeader(page, user.email);
    await expect(page.locator('#link-back-to-app')).toHaveCount(0);
  }
  await page.goto(account('profile'));
  await expectNoA11yViolations(page);
  await expectNoHorizontalOverflow(page, 390);

  // Sign out: the end-session endpoint asks, the confirmation (CSRF-bound) signs out.
  await page.locator('#sign-out-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/logout'));
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await page.goto(account('sessions'));
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
});

test('an account link from a static app offers "Back to <app>"', async ({ page }) => {
  const home = 'https://area-app.example.test/';
  const client = await createClient(await adminToken(creds), {
    name: 'e2e account area app',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: ['https://area-app.example.test/cb'],
    grant_types: ['authorization_code'],
    scopes: ['openid'],
    client_uri: home,
  });
  const user = await newUser('area-app');
  await signInDirect(page, user.email, user.password);

  await page.goto(`${account('profile')}?client_id=${encodeURIComponent(client.client_id)}`);
  await expectHeader(page, user.email);
  const back = page.locator('#link-back-to-app');
  await expect(back).toHaveAttribute('href', home);
  await expect(back).toHaveText('Back to e2e account area app');
  await expectNoA11yViolations(page);
  await expectNoHorizontalOverflow(page, 390);

  // The account navigation keeps the app.
  await page.locator('#account-nav-sessions').click();
  await expect(page).toHaveURL(
    (url) => url.pathname.endsWith('/ui/account/sessions') && url.searchParams.get('client_id') === client.client_id,
  );
  await expect(page.locator('#link-back-to-app')).toHaveAttribute('href', home);

  // An unknown client id: no link, no error, the id is not carried.
  await page.goto(`${account('profile')}?client_id=no-such-client`);
  await expectHeader(page, user.email);
  await expect(page.locator('#link-back-to-app')).toHaveCount(0);
  await expect(page.locator('#account-nav-sessions')).not.toHaveAttribute('href', /client_id/);
});

test('a signed-out deep link to an account page returns there after sign-in', async ({ page }) => {
  const user = await newUser('area-return');
  await page.context().clearCookies();
  await page.goto(account('security'));
  await expect(page).toHaveURL(
    (url) =>
      url.pathname.endsWith('/ui/login') && url.searchParams.get('return_to') === '/ui/account/security',
  );
  await login(page, user.email, user.password);
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/account/security'));
  await expect(page.locator('#passkeys-heading')).toBeVisible();
  await expectHeader(page, user.email);
});

test('destructive account actions ask first; Cancel changes nothing', async ({ page }) => {
  const user = await newUser('area-confirm');
  await signInDirect(page, user.email, user.password);
  const enrolment = await enrolTotp(page);
  await page.goto(account('security'));
  await expect(page.locator('#recovery-codes-count')).toHaveText('10');

  // New recovery codes: the question first, Cancel goes back with the old set intact.
  await page.locator('#recovery-codes-regenerate-submit').click();
  await expect(page.locator('#account-confirm')).toHaveAttribute('data-action', 'regenerate-recovery-codes');
  await expect(page.locator('#recovery-codes li')).toHaveCount(0);
  await expectHeader(page, user.email);
  await expectNoA11yViolations(page);
  await expectNoHorizontalOverflow(page, 390);
  await page.locator('#link-confirm-cancel').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/account/security'));
  await expect(page.locator('#recovery-codes-count')).toHaveText('10');

  // Confirmed: a new set.
  await page.locator('#recovery-codes-regenerate-submit').click();
  await page.locator('#form-confirm-submit').click();
  await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'account.recovery_codes_regenerated');
  const fresh = (await page.locator('#recovery-codes li code').allTextContents()).map((c) => c.trim());
  expect(fresh).toHaveLength(10);
  expect(fresh.some((c) => enrolment.recoveryCodes.includes(c))).toBe(false);

  // Removing the authenticator app asks too.
  await page.goto(account('security'));
  await page.locator('#totp form[id^="credential-delete-"] button').click();
  await expect(page.locator('#account-confirm')).toHaveAttribute('data-action', 'remove-totp');
  await page.locator('#form-confirm-submit').click();
  await expect(page.locator('[data-message-key="account.totp_removed"]')).toBeVisible();
  await expect(page.locator('#totp-begin-submit')).toBeVisible();
});

test('sessions name the device; TOTP enrolment offers the otpauth link on a phone', async ({ page }) => {
  const user = await newUser('area-device');
  await signInDirect(page, user.email, user.password);
  await page.goto(account('sessions'));
  const device = page.locator('tr[data-current] .anvil-session-device bdi');
  await expect(device).toHaveText(/^(Chrome|Edge|Firefox|Safari|Opera) on (Windows|macOS|Linux|Android|iOS)$/);
  await expect(page.locator('#session-list')).not.toContainText('Mozilla/');
  await expect(page.locator('tr[data-current] time').first()).toHaveAttribute('datetime', /Z$/);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(account('security'));
  await page.locator('#totp-begin-submit').click();
  const link = page.locator('#link-otpauth');
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute('href', /^otpauth:\/\/totp\//);
  await expect(page.locator('#totp-qr svg')).toBeVisible();
  await expectNoHorizontalOverflow(page, 390);
  await expectNoA11yViolations(page);
});

test('a refused password change is a GET of the page (Post/Redirect/Get)', async ({ page }) => {
  const user = await newUser('area-prg');
  await signInDirect(page, user.email, user.password);
  await page.goto(account('password'));
  await page.locator('#new_password').fill('short');
  await page.locator('#password-form-submit').click();
  await expect(page.locator('#account-messages [data-message-key="account.password_too_short"]')).toBeVisible();
  await expect(page).toHaveURL(
    (url) => url.pathname.endsWith('/ui/account/password') && url.searchParams.has('flow'),
  );
  await expect(page.locator('#new_password')).toHaveValue('');
  // Reload is a plain GET: no resubmission, the one-shot message is gone, nothing changed.
  await page.reload();
  await expect(page.locator('form#password-form')).toBeVisible();
  await expect(page.locator('[data-message-key="account.password_too_short"]')).toHaveCount(0);
  await page.context().clearCookies();
  await signInDirect(page, user.email, user.password);
});
