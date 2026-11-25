// QUAL-04: zero-config start -> first login in the sample relying party.
//
// Driven by scripts/qual04.sh in two Playwright invocations around starting examples/node-rp:
//   1. `--grep @qual04-setup`  completes /setup at SETUP_URL, obtains a management token and
//      registers a confidential client for the RP. The client credentials are written to the JSON
//      file named by QUAL04_CLIENT_FILE (created by the script in a private temp dir).
//   2. `--grep @qual04-rp`     drives the RP: login -> AnvilID login page -> create account ->
//      back at the RP with sub/email from UserInfo -> refresh (rotation) -> UserInfo still works.
//
// Env: ANVIL_URL, SETUP_URL, QUAL04_CLIENT_FILE, and RP_URL for step 2.

import { writeFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  completeSetup,
  createClient,
  randomEmail,
  randomPassword,
  register,
  requireEnv,
} from '../lib/anvil';
import { rpLogin, rpMe, rpRefresh, rpUrl } from '../lib/rp';

test.describe.configure({ mode: 'serial' });

test('setup, management token and RP client @qual04-setup', async ({ page }) => {
  const setupUrl = requireEnv('SETUP_URL');
  const clientFile = requireEnv('QUAL04_CLIENT_FILE');

  const creds = await completeSetup(page, setupUrl, {
    email: randomEmail('admin'),
    password: randomPassword(),
  });
  const token = await adminToken(creds);
  const client = await createClient(token, {
    name: 'QUAL-04 sample RP',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: ['http://localhost:3000/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
  });
  expect(client.client_id).toBeTruthy();
  expect(client.client_secret).toBeTruthy();

  writeFileSync(
    clientFile,
    JSON.stringify({ client_id: client.client_id, client_secret: client.client_secret }),
    { mode: 0o600 },
  );
});

test('register in the RP login, UserInfo, refresh with rotation @qual04-rp', async ({ page }) => {
  const anvil = anvilUrl();
  const email = randomEmail('qual04');
  const password = randomPassword();

  await rpLogin(page);
  // The RP redirects to /authorize, which shows AnvilID's hosted login page.
  await expect(page).toHaveURL((url) => url.href.startsWith(anvil));
  await page.locator('#link-registration').click();
  await expect(page.locator('#registration')).toBeVisible();
  await register(page, email, password);

  // Registration signs the user in and continues the authorization request back to the RP.
  await expect(page).toHaveURL(`${rpUrl()}/me`);
  const me = await rpMe(page);
  expect(me.sub).not.toBe('');
  expect(me.email).toBe(email);
  expect(me.refreshCount).toBe(0);

  const refreshed = await rpRefresh(page);
  expect(refreshed.refreshCount).toBe(1);
  expect(refreshed.sub).toBe(me.sub);
  expect(refreshed.email).toBe(email);

  // /me still renders the session after the rotation.
  await page.goto(`${rpUrl()}/me`);
  const after = await rpMe(page);
  expect(after.sub).toBe(me.sub);
  expect(after.refreshCount).toBe(1);
});
