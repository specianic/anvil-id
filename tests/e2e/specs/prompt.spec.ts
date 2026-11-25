// OIDC-14 in a browser: prompt=select_account and prompt=create through the sample relying party.
//
// - select_account: with an AnvilID session from before the request the account chooser is shown
//   (axe-clean). "Continue" returns to the RP as the same user; "Use another account" leads to the
//   sign-in form, signing in as a second user returns that user to the RP, and the first user's
//   session is revoked with a back-channel logout delivered to the RP.
// - create: with open registration the request opens the registration page; registering returns
//   to the RP signed in as the new account. The tenant must not require email verification for
//   that (otherwise the request cannot resume), so the spec sets both settings and restores them.
//
// The sample RP builds its own authorization request; lib/authorize.ts adds the prompt value.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createUser,
  findUserByEmail,
  login,
  randomEmail,
  randomPassword,
  register,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { userSessions, withTenantSettings } from '../lib/admin';
import { addAuthorizeParams } from '../lib/authorize';
import { backchannelReceived, startLogoutRp, waitForBackchannel, type LogoutRp } from '../lib/logout';

let creds: ManagementCredential;
let rp: LogoutRp;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  rp = await startLogoutRp(await adminToken(creds), 'e2e prompt sample RP');
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

async function expectAtRp(page: Page, email: string): Promise<string> {
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
  return ((await page.locator('#sub').textContent()) ?? '').trim();
}

async function expectChooser(page: Page, email: string): Promise<void> {
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/select-account'));
  await expect(page.locator('form#select-account-form')).toBeVisible();
  await expect(page.locator('#select-account-email')).toHaveText(email);
  await expect(page.locator('#select-account-continue')).toBeVisible();
  await expect(page.locator('#select-account-other')).toBeVisible();
}

test('select_account: continue, then use another account switches users', async ({ page }) => {
  const alice = await newUser('prompt-alice');
  const bob = await newUser('prompt-bob');

  // Alice signs in at the RP without a prompt (RP session with her sid).
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await login(page, alice.email, alice.password);
  const aliceSub = await expectAtRp(page, alice.email);
  expect(aliceSub).toBe(alice.id);

  const stop = await addAuthorizeParams(page, { prompt: 'select_account' });
  try {
    // The chooser, then Continue: back at the RP as Alice, no password asked.
    await page.goto(`${rp.base}/login`);
    await expectChooser(page, alice.email);
    await expectNoA11yViolations(page);
    await page.locator('#select-account-continue').click();
    await expectAtRp(page, alice.email);
    expect(await userSessions(await adminToken(creds), alice.id)).toHaveLength(1);
    expect(await backchannelReceived(rp.base, aliceSub)).toHaveLength(0);

    // The chooser again, then Use another account: the sign-in form, then Bob at the RP.
    await page.goto(`${rp.base}/login`);
    await expectChooser(page, alice.email);
    await page.locator('#select-account-other').click();
    await expect(page.locator('form#login')).toBeVisible();
    await login(page, bob.email, bob.password);
    const bobSub = await expectAtRp(page, bob.email);
    expect(bobSub).toBe(bob.id);
  } finally {
    await stop();
  }

  // Alice's session was revoked by the switch (with its token families), and the RP got a
  // back-channel logout for her (the switch does not wake the delivery worker, so this can take up
  // to one 10 s poll interval); Bob holds the only session in this browser.
  const token = await adminToken(creds);
  expect(await userSessions(token, alice.id)).toHaveLength(0);
  expect(await userSessions(token, bob.id)).toHaveLength(1);
  const entries = await waitForBackchannel(rp.base, aliceSub, 30_000);
  expect(entries.length).toBeGreaterThan(0);
  expect(await backchannelReceived(rp.base, bob.id)).toHaveLength(0);
});

test('create: registration from the authorization request returns to the RP signed in', async ({
  page,
}) => {
  const token = await adminToken(creds);
  await withTenantSettings(token, { registration: 'open', require_verified_email: false }, async () => {
    const email = randomEmail('prompt-create');
    const password = randomPassword();
    await page.context().clearCookies();

    const stop = await addAuthorizeParams(page, { prompt: 'create' });
    try {
      await page.goto(`${rp.base}/login`);
      await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/registration'));
      await expect(page.locator('form#registration')).toBeVisible();
      await register(page, email, password);
      await expectAtRp(page, email);
    } finally {
      await stop();
    }

    const user = await findUserByEmail(token, email);
    expect(user, 'the registered user exists').toBeDefined();
    expect(user!.status).toBe('active');
  });
});
