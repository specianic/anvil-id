// AUTH-10: the account sessions page in a browser. A user signed in from several browsers sees each
// session at /ui/account/sessions with a readable device ("Chrome on Windows", never the raw user
// agent, 07.1-21); signing one out ends it (that browser is sent to the sign-in page on its next
// visit), "Sign out all other sessions" asks for confirmation and then keeps only the current one,
// and signing out this browser clears its own session and shows the signed-out page.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';

const SESSIONS = () => `${anvilUrl()}/ui/account/sessions`;

/** A fresh browser context signed in as the user, with its page on the sessions page. */
async function signedIn(
  browser: Browser,
  email: string,
  password: string,
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('form#login')).toHaveCount(0);
  await page.goto(SESSIONS());
  await expect(page.locator('#session-list')).toBeVisible();
  return { context, page };
}

async function expectSignedOut(page: Page): Promise<void> {
  await page.goto(SESSIONS());
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
  await expect(page.locator('form#login')).toBeVisible();
}

const rows = (page: Page) => page.locator('#session-list tbody tr');

test('list, sign out another browser, sign out all others, sign out this browser', async ({
  browser,
}) => {
  const creds = await sharedManagementCredential(browser);
  const email = randomEmail('sessions');
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });

  const a = await signedIn(browser, email, password);
  const b = await signedIn(browser, email, password);
  try {
    // A sees both sessions; its own row is marked.
    await a.page.reload();
    await expect(rows(a.page)).toHaveCount(2);
    await expect(a.page.locator('#session-list tr[data-current]')).toHaveCount(1);
    await expect(a.page.locator('tr[data-current] #session-current-marker')).toHaveText(
      '(this device)',
    );
    await expect(a.page.locator('#account-nav-sessions')).toHaveAttribute('aria-current', 'page');
    await expect(a.page.locator('#sessions-revoke-others-submit')).toBeVisible();
    // Readable devices: "<browser> on <OS>", never the raw user agent.
    for (const device of await a.page.locator('#session-list .anvil-session-device bdi').allTextContents()) {
      expect(device).toMatch(/^(Chrome|Edge|Firefox|Safari|Opera|Unknown browser)( on (Windows|macOS|Linux|Android|iOS))?$/);
    }
    await expect(a.page.locator('#session-list')).not.toContainText('Mozilla/');
    await expect(a.page.locator('#session-list time').first()).toContainText('UTC');

    // A signs out B.
    const other = a.page.locator('#session-list tbody tr:not([data-current])');
    await expect(other).toHaveCount(1);
    await other.locator('button[id$="-submit"]').click();
    await expect(a.page.locator('#account-messages [data-message-key="sessions.revoked"]')).toBeVisible();
    await expect(rows(a.page)).toHaveCount(1);
    await expect(a.page.locator('#sessions-revoke-others')).toHaveCount(0);

    // B's next visit goes to the sign-in page.
    await expectSignedOut(b.page);

    // Two more browsers; "Sign out all other sessions" keeps only A.
    const c = await signedIn(browser, email, password);
    const d = await signedIn(browser, email, password);
    try {
      await a.page.goto(SESSIONS());
      await expect(rows(a.page)).toHaveCount(3);
      await a.page.locator('#sessions-revoke-others-submit').click();
      // The confirmation step: nothing happens until it is confirmed.
      await expect(a.page.locator('#account-confirm')).toHaveAttribute('data-action', 'sign-out-others');
      await a.page.locator('#form-confirm-submit').click();
      await expect(
        a.page.locator('#account-messages [data-message-key="sessions.revoked_others"]'),
      ).toBeVisible();
      await expect(rows(a.page)).toHaveCount(1);
      await expect(a.page.locator('#session-list tr[data-current]')).toHaveCount(1);
      await expectSignedOut(c.page);
      await expectSignedOut(d.page);
    } finally {
      await c.context.close();
      await d.context.close();
    }

    // A is still signed in, then signs out this browser from its own row.
    await a.page.goto(SESSIONS());
    await expect(rows(a.page)).toHaveCount(1);
    await a.page.locator('tr[data-current] button[id$="-submit"]').click();
    // U-L8: a signed-out message with a way forward.
    await expect(a.page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
    await expect(a.page.locator('#logout-message')).toHaveAttribute('data-message-key', 'logout.signed_out');
    await expect(a.page.locator('#link-login')).toBeVisible();
    await expectSignedOut(a.page);
  } finally {
    await a.context.close();
    await b.context.close();
  }
});
