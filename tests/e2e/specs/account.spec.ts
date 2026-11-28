// AUTH-13: the complete account page in a real browser, over real SMTP (Mailpit).
//
// - Every entry of the account navigation (Profile, Email, Password, Security, Sessions, Connected
//   apps, Linked accounts) opens its page, marks itself as current and passes axe; the security
//   page reaches passkeys and the authenticator app, the linked accounts page lists no links yet.
//   Every page has the account header (07.1-12): the signed-in email and the sign-out form.
// - Profile edits persist.
// - Email change: a confirmation link goes to the new address, opening it shows a button (nothing
//   changes on GET), confirming switches the address, the old address gets the "changed" notice,
//   and sign-in works with the new address.
// - Password change with "Sign out on all other devices": another browser's session ends, the new
//   password works and the old one gets the generic error.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createUser,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { signInDirect } from '../lib/account';
import { extractLink, latestMessageTo } from '../lib/mailpit';

/** The account navigation in DOM order (themes/default/templates/account_base.html). */
const ACCOUNT_NAV: Array<{ id: string; path: string; ready: string }> = [
  { id: 'account-nav-profile', path: '/ui/account/profile', ready: 'form#profile-form' },
  { id: 'account-nav-email', path: '/ui/account/email', ready: 'form#email-change' },
  { id: 'account-nav-password', path: '/ui/account/password', ready: 'form#password-form' },
  { id: 'account-nav-security', path: '/ui/account/security', ready: '#passkeys-heading' },
  { id: 'account-nav-sessions', path: '/ui/account/sessions', ready: '#session-list' },
  { id: 'account-nav-apps', path: '/ui/account/apps', ready: '#account-content' },
  { id: 'account-nav-linked', path: '/ui/account/linked', ready: '#linked-heading' },
];

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

/** A fresh browser context signed in on the hosted login page. */
async function signedInContext(
  browser: Browser,
  email: string,
  password: string,
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signInDirect(page, email, password);
  return { context, page };
}

/** The account page shows a "sign in again" notice: follow it and sign in. */
async function reauthIfPrompted(page: Page, email: string, password: string): Promise<void> {
  const notice = page.locator('#account-reauth');
  if ((await notice.count()) === 0) return;
  const back = page.url();
  await page.locator('#link-reauth').click();
  await login(page, email, password);
  await page.goto(back);
  await expect(notice).toHaveCount(0);
}

function accountMessage(page: Page, key: string) {
  return page.locator(`#account-messages [data-message-key="${key}"]`);
}

async function expectSignedOut(page: Page): Promise<void> {
  await page.goto(account('sessions'));
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
  await expect(page.locator('form#login')).toBeVisible();
}

test('every account navigation entry opens its page and passes axe', async ({ page }) => {
  const user = await newUser('acct-nav');
  await signInDirect(page, user.email, user.password);
  await page.goto(account('profile'));

  const navIds = await page.locator('#account-nav a').evaluateAll((els) => els.map((e) => e.id));
  expect(navIds).toEqual(ACCOUNT_NAV.map((n) => n.id));

  for (const entry of ACCOUNT_NAV) {
    await page.locator(`#${entry.id}`).click();
    await expect(page).toHaveURL((url) => url.pathname === entry.path);
    await expect(page.locator(entry.ready)).toBeVisible();
    await expect(page.locator(`#${entry.id}`)).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#account-nav [aria-current="page"]')).toHaveCount(1);
    await expect(page.locator('#account-identity')).toHaveText(user.email);
    await expect(page.locator('#form-sign-out')).toHaveAttribute('method', 'post');
    await expectNoA11yViolations(page);
  }

  // Security: passkeys and the authenticator app are reachable from the navigation.
  await page.locator('#account-nav-security').click();
  await expect(page.locator('#passkeys-heading')).toBeVisible();
  await expect(page.locator('#totp-begin-submit')).toBeVisible();

  // Linked accounts: reachable, and this user has no linked identity.
  await page.locator('#account-nav-linked').click();
  await expect(page.locator('#linked-none')).toBeVisible();
});

test('profile edits persist', async ({ page }) => {
  const user = await newUser('acct-profile');
  await signInDirect(page, user.email, user.password);
  await page.goto(account('profile'));

  await page.locator('#name').fill('Ada Lovelace');
  await page.locator('#given_name').fill('Ada');
  await page.locator('#family_name').fill('Lovelace');
  await page.locator('#locale').fill('en-GB');
  await page.locator('#profile-form-submit').click();
  await expect(accountMessage(page, 'account.profile_saved')).toBeVisible();
  await expectNoA11yViolations(page);

  // A fresh GET shows the stored values.
  await page.goto(account('profile'));
  await expect(page.locator('#name')).toHaveValue('Ada Lovelace');
  await expect(page.locator('#given_name')).toHaveValue('Ada');
  await expect(page.locator('#family_name')).toHaveValue('Lovelace');
  await expect(page.locator('#locale')).toHaveValue('en-GB');

  // An invalid locale is refused and nothing changes.
  await page.locator('#locale').fill('not a locale');
  await page.locator('#profile-form-submit').click();
  await expect(accountMessage(page, 'account.invalid_locale')).toBeVisible();
  await page.goto(account('profile'));
  await expect(page.locator('#locale')).toHaveValue('en-GB');
});

test('email change: link to the new address, notice to the old one, sign-in with the new address', async ({
  page,
  browser,
}) => {
  const user = await newUser('acct-old');
  const newEmail = randomEmail('acct-new');
  await signInDirect(page, user.email, user.password);
  await page.goto(account('email'));
  await reauthIfPrompted(page, user.email, user.password);
  await expect(page.locator('#current-email')).toHaveText(user.email);

  await page.locator('#new_email').fill(newEmail);
  await page.locator('#email-change-submit').click();
  await expect(accountMessage(page, 'account.email_change_sent')).toBeVisible();
  // Nothing changes until the link is confirmed.
  await page.goto(account('email'));
  await expect(page.locator('#current-email')).toHaveText(user.email);

  const changeMail = await latestMessageTo(newEmail);
  expect(changeMail.Subject).toMatch(/confirm your new email/i);
  const link = extractLink(changeMail.Text || changeMail.HTML, '/ui/account/email/confirm');

  // Opening the link (here in another browser, as from a mail client) only shows a button.
  const mailClient = await browser.newContext();
  try {
    const confirmPage = await mailClient.newPage();
    await confirmPage.goto(link);
    await expect(confirmPage.locator('form#email-confirm')).toBeVisible();
    await expectNoA11yViolations(confirmPage);
    const before = await findUserByEmail(await adminToken(creds), user.email);
    expect(before?.email).toBe(user.email);

    await confirmPage.locator('#email-confirm-submit').click();
    await expect(accountMessage(confirmPage, 'account.email_changed')).toBeVisible();
    await expect(confirmPage.locator('form#email-confirm')).toHaveCount(0);
  } finally {
    await mailClient.close();
  }

  // The old address is told about the change.
  const notice = await latestMessageTo(user.email);
  expect(notice.Subject).toMatch(/email address was changed/i);
  expect(notice.Text).toContain(newEmail);

  // The account shows the new, verified address.
  await page.goto(account('email'));
  await expect(page.locator('#current-email')).toHaveText(newEmail);
  await expect(page.locator('#email-verified')).toBeVisible();

  // Sign-in works with the new address; the old one no longer identifies the account.
  const fresh = await browser.newContext();
  try {
    const p = await fresh.newPage();
    await signInDirect(p, newEmail, user.password);
    await p.context().clearCookies();
    await p.goto(`${anvilUrl()}/ui/login`);
    await login(p, user.email, user.password);
    await expect(p.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  } finally {
    await fresh.close();
  }
});

test('password change signs out the other browsers', async ({ page, browser }) => {
  const user = await newUser('acct-pw');
  const newPassword = randomPassword();
  await signInDirect(page, user.email, user.password);
  const other = await signedInContext(browser, user.email, user.password);
  try {
    await other.page.goto(account('sessions'));
    await expect(other.page.locator('#session-list')).toBeVisible();

    await page.goto(account('password'));
    await reauthIfPrompted(page, user.email, user.password);
    await expect(page.locator('#revoke_others')).toBeChecked();
    await page.locator('#new_password').fill(newPassword);
    await page.locator('#password-form-submit').click();
    await expect(accountMessage(page, 'account.password_changed')).toBeVisible();
    await expectNoA11yViolations(page);

    // This browser stays signed in; the other one is signed out.
    await page.goto(account('sessions'));
    await expect(page.locator('#session-list tbody tr')).toHaveCount(1);
    await expectSignedOut(other.page);
  } finally {
    await other.context.close();
  }

  // The new password works; the old one gets the generic error.
  await page.context().clearCookies();
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await signInDirect(page, user.email, newPassword);
});
