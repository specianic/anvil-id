// OIDC-12 in a browser: RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 through the sample
// relying party (examples/node-rp), plus the confirmation page for a logout without a hint and the
// error page for an unregistered post_logout_redirect_uri, with WCAG 2.2 AA checks on the new pages.
//
// The RP's client is registered with post_logout_redirect_uris [{rp}/logged-out] and
// backchannel_logout_uri {rp}/backchannel_logout. The RP verifies the logout token (signature
// against the issuer JWKS, iss, aud, iat, jti, events, no nonce) before it records it, so an entry
// at /backchannel_logout/received is a valid token.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
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
import {
  backchannelReceived,
  endSessionUrl,
  startLogoutRp,
  waitForBackchannel,
  type LogoutRp,
} from '../lib/logout';

let creds: ManagementCredential;
let rp: LogoutRp;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  rp = await startLogoutRp(await adminToken(creds), 'e2e logout sample RP');
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

/** Signs in through the sample RP (fresh browser state) and returns the `sub` the RP shows. */
async function signInAtRp(page: Page, email: string, password: string): Promise<string> {
  await page.context().clearCookies();
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await login(page, email, password);
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
  return ((await page.locator('#sub').textContent()) ?? '').trim();
}

/** The next RP login stops at AnvilID's sign-in form: the AnvilID session is gone. */
async function expectAnvilSessionGone(page: Page): Promise<void> {
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await expect(page.locator('form#login')).toBeVisible();
}

test('RP-initiated logout returns to the RP with its state and delivers a back-channel logout token', async ({
  page,
}) => {
  const user = await newUser('logout-rp');
  const sub = await signInAtRp(page, user.email, user.password);
  expect(sub).toBe(user.id);

  // The ID token's sid is the browser session id; the admin API lists exactly that session.
  const sessions = await userSessions(await adminToken(creds), user.id);
  expect(sessions).toHaveLength(1);
  const sid = sessions[0].id;
  expect(await backchannelReceived(rp.base, sub)).toHaveLength(0);

  // RP logout: id_token_hint + registered post_logout_redirect_uri + state. The RP compares the
  // returned state with the one it sent (400 "Logout state mismatch" otherwise).
  await page.locator('#logout').click();
  await expect(page).toHaveURL((url) => url.href.startsWith(`${rp.base}/logged-out`));
  const back = new URL(page.url());
  expect([...back.searchParams.keys()]).toEqual(['state']);
  await expect(page.locator('#logged-out')).toBeVisible();
  await expect(page.locator('#error')).toHaveCount(0);

  // The back-channel delivery is asynchronous (worker woken by the logout).
  const entries = await waitForBackchannel(rp.base, sub, 15_000);
  expect(entries).toHaveLength(1);
  expect(entries[0].sid).toBe(sid);
  expect(entries[0].sub).toBe(sub);

  // The AnvilID session ended: no active session, and the next RP login asks for credentials.
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(0);
  await expectAnvilSessionGone(page);
});

test('logout without a hint asks for confirmation, then shows the signed-out page', async ({ page }) => {
  const user = await newUser('logout-confirm');
  const sub = await signInAtRp(page, user.email, user.password);

  // {issuer}/logout without parameters: the confirmation page under /ui/logout; nothing ends yet.
  await page.goto(endSessionUrl(anvilUrl()));
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/logout'));
  await expect(page.locator('form#logout-confirm-form')).toBeVisible();
  await expect(page.locator('#logout-confirm-submit')).toHaveText('Sign out');
  await expect(page.locator('#logout-cancel')).toBeVisible();
  await expectNoA11yViolations(page);
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(1);

  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  const message = page.locator('#logout-message');
  await expect(message).toHaveAttribute('data-message-key', 'logout.signed_out');
  await expect(message).toHaveText('You have been signed out.');
  await expectNoA11yViolations(page);

  // The session (and its token family at the RP) ended: back-channel delivered, sign-in asked.
  const entries = await waitForBackchannel(rp.base, sub, 15_000);
  expect(entries).toHaveLength(1);
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(0);
  await expectAnvilSessionGone(page);
});

test('an unregistered post_logout_redirect_uri is refused and the user stays signed in', async ({
  page,
}) => {
  const user = await newUser('logout-bad-uri');
  const sub = await signInAtRp(page, user.email, user.password);

  for (const uri of [`${rp.base}/elsewhere`, `${rp.base}/logged-out?foo=bar`, `${rp.base}/logged-out/`]) {
    const res = await page.goto(
      endSessionUrl(anvilUrl(), { clientId: rp.clientId, postLogoutRedirectUri: uri, state: 'st-1' }),
    );
    expect(res?.status()).toBe(400);
    // No redirect anywhere: the error page is served at /logout.
    await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/logout`));
    const message = page.locator('#logout-message');
    await expect(message).toHaveAttribute('data-message-key', 'logout.redirect_uri_not_registered');
    await expect(message).toHaveText(
      'The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client.',
    );
  }
  await expectNoA11yViolations(page);

  // Still signed in: the session is active, nothing was delivered, and the RP login needs no form.
  expect(await userSessions(await adminToken(creds), user.id)).toHaveLength(1);
  expect(await backchannelReceived(rp.base, sub)).toHaveLength(0);
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(user.email);
});
