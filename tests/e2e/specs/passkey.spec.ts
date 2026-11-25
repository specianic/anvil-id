// AUTH-04 in a browser: passkey registration on /ui/account/security, usernameless sign-in through
// the sample relying party, clone detection (sign counter rolled back), and rejection of bogus
// signatures, missing user verification and a second registration of the same authenticator.
//
// Uses the CDP virtual authenticator (fixtures/webauthn.ts): a CTAP 2.1 platform authenticator
// with resident keys and user verification. Chromium project only. "Signing out" clears the
// context's cookies; the authenticator (attached to the page) keeps its credentials.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type VirtualAuthenticator } from '../fixtures/webauthn';
import type { Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createClient,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import {
  auditEvents,
  freePort,
  openAccountSecurity,
  registerPasskey,
  signInDirect,
  signInForIdToken,
  startSampleRp,
  type CodeClient,
  type SampleRp,
} from '../lib/account';

let creds: ManagementCredential;
let rp: SampleRp;
let codeClient: CodeClient;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  const token = await adminToken(creds);
  rp = await startSampleRp((redirectUri) =>
    createClient(token, {
      name: 'e2e passkey sample RP',
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
    }),
  );
  const redirectUri = `http://localhost:${await freePort()}/cb`;
  const client = await createClient(token, {
    name: 'e2e passkey id-token client',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code'],
    scopes: ['openid', 'email'],
  });
  codeClient = {
    client_id: client.client_id,
    client_secret: client.client_secret ?? '',
    redirect_uri: redirectUri,
  };
});

test.afterAll(async () => {
  await rp?.stop();
});

interface PasskeyUser {
  id: string;
  email: string;
  credentialId: string;
}

/** A new user who signed in with a password and registered one passkey; then signed out. */
async function userWithPasskey(page: Page, authenticator: VirtualAuthenticator): Promise<PasskeyUser> {
  const email = randomEmail('passkey');
  const password = randomPassword();
  const user = await createUser(await adminToken(creds), { email, password, email_verified: true });
  if (!user.id) throw new Error('created user has no id');

  await signInDirect(page, email, password);
  await registerPasskey(page, 'Laptop');
  const stored = await authenticator.getCredentials();
  expect(stored).toHaveLength(1);
  await page.context().clearCookies();
  return { id: user.id, email, credentialId: stored[0].credentialId };
}

/** Starts at the RP, clicks "Sign in with a passkey" on the hosted login page. */
async function passkeyLoginViaRp(page: Page): Promise<void> {
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await clickPasskeyButton(page);
}

async function clickPasskeyButton(page: Page): Promise<void> {
  const button = page.locator('#login-passkey-submit');
  await expect(button).toBeVisible();
  await button.click();
}

async function expectPasskeyFailure(page: Page): Promise<void> {
  await expect(page.locator('[data-message-key="login.passkey_failed"]')).toBeVisible();
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  // No session was created: the account page still asks for a sign-in.
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
}

test('a passkey registered on the account page is a resident credential', async ({
  page,
  authenticator,
}) => {
  const email = randomEmail('passkey');
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });
  await signInDirect(page, email, password);

  await openAccountSecurity(page);
  await expect(page.locator('#passkeys-empty')).toBeVisible();
  await registerPasskey(page, 'Work laptop');
  await expect(page.locator('#passkey-list tbody tr')).toHaveCount(1);

  const stored = await authenticator.getCredentials();
  expect(stored).toHaveLength(1);
  expect(stored[0].isResidentCredential).toBe(true);
  expect(stored[0].rpId).toBe(new URL(anvilUrl()).hostname);
  expect(stored[0].userHandle).toBeTruthy();
});

test('usernameless passkey sign-in through the sample RP', async ({ page, authenticator }) => {
  const user = await userWithPasskey(page, authenticator);

  await passkeyLoginViaRp(page);
  // No identifier or password was typed: the RP shows the user's profile.
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#sub')).toHaveText(user.id);
  await expect(page.locator('#email')).toHaveText(user.email);

  // The ID token of a passkey sign-in (user verification required) is multi-factor.
  await page.context().clearCookies();
  const claims = await signInForIdToken(page, codeClient, clickPasskeyButton);
  expect(claims.sub).toBe(user.id);
  expect(claims.amr).toEqual(expect.arrayContaining(['mfa']));

  // The account page shows when the passkey was last used.
  await openAccountSecurity(page);
  await expect(page.locator('#passkey-list tbody tr td').nth(2)).not.toHaveText('Never');
});

test('a sign counter that goes backwards fails the sign-in and is audited as a suspected clone', async ({
  page,
  authenticator,
}) => {
  const user = await userWithPasskey(page, authenticator);

  await passkeyLoginViaRp(page);
  await expect(page).toHaveURL(`${rp.base}/me`);
  const [afterLogin] = await authenticator.getCredentials();
  expect(afterLogin.signCount).toBeGreaterThan(0);

  // A cloned authenticator: same key, counter behind the one the server has seen.
  await authenticator.setSignCount(user.credentialId, 0);
  await page.context().clearCookies();
  await passkeyLoginViaRp(page);
  await expectPasskeyFailure(page);

  const events = await auditEvents(await adminToken(creds), {
    action: 'passkey_clone_suspected',
    target: user.id,
  });
  expect(events.length).toBeGreaterThanOrEqual(1);
  expect(events[0].outcome).toBe('failure');
});

test('an assertion with a bogus signature is rejected', async ({ page, authenticator }) => {
  await userWithPasskey(page, authenticator);

  await authenticator.overrideResponse({ isBogusSignature: true });
  await passkeyLoginViaRp(page);
  await expectPasskeyFailure(page);

  // The same credential works again once the signature is genuine.
  await authenticator.overrideResponse({});
  await passkeyLoginViaRp(page);
  await expect(page).toHaveURL(`${rp.base}/me`);
});

test('an assertion without user verification is rejected', async ({ page, authenticator }) => {
  await userWithPasskey(page, authenticator);

  await authenticator.overrideResponse({ isBadUV: true });
  await passkeyLoginViaRp(page);
  await expectPasskeyFailure(page);

  await authenticator.overrideResponse({});
  await passkeyLoginViaRp(page);
  await expect(page).toHaveURL(`${rp.base}/me`);
});

test('the same authenticator cannot register a second passkey for the account', async ({
  page,
  authenticator,
}) => {
  const email = randomEmail('passkey');
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });
  await signInDirect(page, email, password);
  await registerPasskey(page, 'Laptop');

  await openAccountSecurity(page);
  await page.locator('#label').fill('Laptop again');
  await page.locator('#passkey-register-submit').click();
  // excludeCredentials makes the authenticator refuse (InvalidStateError); webauthn.js reports
  // the failure. A server-side refusal (account.passkey_exists) is accepted as well.
  await expect(
    page
      .locator('#passkey-register-status', { hasText: 'could not be added' })
      .or(page.locator('[data-message-key="account.passkey_exists"]')),
  ).toBeVisible();

  await openAccountSecurity(page);
  await expect(page.locator('#passkey-list tbody tr')).toHaveCount(1);
  expect(await authenticator.getCredentials()).toHaveLength(1);
});
