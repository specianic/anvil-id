// OIDC-13 / OIDC-25: the consent screen in a browser, end to end through the sample relying party.
//
// - First sign-in to a consent-required client shows the consent screen; Allow returns to the RP.
// - The decision is remembered: the next sign-in goes straight back to the RP.
// - Removing the app at /ui/account/apps revokes its refresh tokens (the RP's refresh fails) and the
//   next sign-in asks again.
// - Deny returns `access_denied` to the RP.
// - response_mode=form_post: the hosted page auto-submits the authorization response to the
//   redirect URI as a POST (captured with a Playwright route handler).
// - The screen names the signed-in account; "Use another account" signs someone else in, who is
//   asked for their own consent (07.1-14, U-M15).
//
// The spec starts its own examples/node-rp on a free loopback port with a client it creates through
// the admin API with consent_mode `required` (createClient defaults to skip_first_party).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createClient,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';

const RP_SERVER = fileURLToPath(new URL('../../../examples/node-rp/server.js', import.meta.url));
const CLIENT_NAME = 'e2e consent RP';

let rp: ChildProcess | undefined;
let rpBase = '';
let rpLog = '';
let rpClientId = '';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === 'object') resolve(addr.port);
        else reject(new Error('no port'));
      });
    });
  });
}

async function waitForRp(url: string): Promise<void> {
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      const res = await fetch(`${url}/healthz`);
      if (res.ok) return;
    } catch {
      // not listening yet
    }
    if (rp?.exitCode !== null && rp?.exitCode !== undefined) {
      throw new Error(`sample RP exited (${rp.exitCode}):\n${rpLog}`);
    }
    if (Date.now() > deadline) throw new Error(`sample RP did not start:\n${rpLog}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

test.beforeAll(async ({ browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  const port = await freePort();
  rpBase = `http://localhost:${port}`;
  const client = await createClient(
    token,
    {
      name: CLIENT_NAME,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [`${rpBase}/callback`],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
    },
    'default',
    'required',
  );
  rpClientId = client.client_id;
  rp = spawn(process.execPath, [RP_SERVER], {
    env: {
      ...process.env,
      ISSUER: anvilUrl(),
      CLIENT_ID: client.client_id,
      CLIENT_SECRET: client.client_secret ?? '',
      PORT: String(port),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  rp.stdout?.on('data', (d: Buffer) => (rpLog += d.toString()));
  rp.stderr?.on('data', (d: Buffer) => (rpLog += d.toString()));
  await waitForRp(rpBase);
});

test.afterAll(async () => {
  if (rp && rp.exitCode === null) {
    const exited = new Promise((r) => rp!.once('exit', r));
    rp.kill('SIGTERM');
    await exited;
  }
});

/** Records every document URL the page navigates to (to prove a page was never shown). */
function trackNavigations(page: Page): string[] {
  const seen: string[] = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) seen.push(frame.url());
  });
  return seen;
}

async function newUser(page: Page): Promise<{ email: string; password: string }> {
  const creds = await sharedManagementCredential(page.context().browser()!);
  const email = randomEmail('consent');
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });
  return { email, password };
}

test('consent is asked once, remembered, revocable at Connected apps, and Deny returns access_denied', async ({
  page,
}) => {
  const user = await newUser(page);
  const navigations = trackNavigations(page);

  // 1. First sign-in: the consent screen names the client and lists the requested scopes.
  await page.goto(`${rpBase}/login`);
  await expect(page.locator('form#login')).toBeVisible();
  await login(page, user.email, user.password);
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-client')).toHaveText(CLIENT_NAME);
  const scopes = await page
    .locator('#consent-scopes [data-scope]')
    .evaluateAll((els) => els.map((e) => e.getAttribute('data-scope')));
  expect(scopes).toEqual(expect.arrayContaining(['profile', 'email']));
  await expect(page.locator('#consent-allow')).toBeVisible();
  await expect(page.locator('#consent-deny')).toBeVisible();

  // 2. Allow: back at the RP, signed in.
  await page.locator('#consent-allow').click();
  await expect(page).toHaveURL(`${rpBase}/me`);
  await expect(page.locator('#email')).toHaveText(user.email);

  // 3. The decision is remembered: a second sign-in never shows the consent screen.
  navigations.length = 0;
  await page.goto(`${rpBase}/login`);
  await expect(page).toHaveURL(`${rpBase}/me`);
  await expect(page.locator('#email')).toHaveText(user.email);
  expect(
    navigations.filter((u) => u.includes('/ui/consent')),
    'consent screen not shown again',
  ).toEqual([]);

  // The RP's refresh token works while the grant stands.
  await page.goto(`${rpBase}/refresh`);
  await expect(page.locator('#refresh-count')).toHaveText('1');

  // 4. Connected apps lists the client; removing it revokes the grant and its tokens.
  await page.goto(`${anvilUrl()}/ui/account/apps`);
  const app = page.locator(`#app-list > li[data-client-id="${rpClientId}"]`);
  await expect(app).toBeVisible();
  await expect(app.locator('h2')).toHaveText(CLIENT_NAME);
  await app.locator('button[id$="-submit"]').click();
  await expect(page.locator('#account-messages [data-message-key="apps.revoked"]')).toBeVisible();
  await expect(page.locator(`li[data-client-id="${rpClientId}"]`)).toHaveCount(0);

  // The RP's refresh now fails (the token family was revoked with the grant).
  await page.goto(`${rpBase}/refresh`);
  await expect(page.locator('#error')).toContainText('invalid_grant');

  // 5. The next sign-in asks again (the AnvilID session is still active, so no password).
  await page.goto(`${rpBase}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-client')).toHaveText(CLIENT_NAME);

  // 6. Deny: the RP receives error=access_denied.
  await page.locator('#consent-deny').click();
  await expect(page).toHaveURL((url) => url.href.startsWith(`${rpBase}/callback`));
  await expect(page.locator('#error')).toContainText('access_denied');

  // Denying stored nothing: Connected apps is empty for this user.
  await page.goto(`${anvilUrl()}/ui/account/apps`);
  await expect(page.locator('#apps-empty')).toBeVisible();
});

test('consent names the account and Use another account asks the next user for their own consent', async ({
  page,
}) => {
  const alice = await newUser(page);
  const bob = await newUser(page);

  await page.goto(`${rpBase}/login`);
  await login(page, alice.email, alice.password);
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-account-email')).toHaveText(alice.email);
  await expect(page.locator('#consent-other')).toBeVisible();

  // Use another account: the sign-in page for the same request.
  await page.locator('#consent-other').click();
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/login?request=`));
  await login(page, bob.email, bob.password);

  // Bob is asked himself: Alice's screen is not reused.
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-account-email')).toHaveText(bob.email);
  await page.locator('#consent-allow').click();
  await expect(page).toHaveURL(`${rpBase}/me`);
  await expect(page.locator('#email')).toHaveText(bob.email);
});

test('response_mode=form_post posts the code to the redirect URI', async ({ page, browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  // Nothing listens on this port: the route handler below answers the POST in the browser.
  const fpBase = `http://localhost:${await freePort()}`;
  const redirectUri = `${fpBase}/fp-callback`;
  const client = await createClient(token, {
    name: 'e2e form_post client',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code'],
    scopes: ['openid', 'email'],
  });
  const user = await newUser(page);

  let posted: { method: string; body: URLSearchParams } | undefined;
  await page.route(`${fpBase}/**`, async (route) => {
    const req = route.request();
    posted = { method: req.method(), body: new URLSearchParams(req.postData() ?? '') };
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><html lang="en"><title>RP</title><p id="received">received</p></html>',
    });
  });

  const state = randomBytes(16).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const authorize = new URL(`${anvilUrl()}/authorize`);
  authorize.search = new URLSearchParams({
    client_id: client.client_id,
    response_type: 'code',
    response_mode: 'form_post',
    scope: 'openid email',
    redirect_uri: redirectUri,
    state,
    nonce: randomBytes(16).toString('base64url'),
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();

  await page.goto(authorize.href);
  await expect(page.locator('form#login')).toBeVisible();
  await login(page, user.email, user.password);

  // form_post.js submits the hidden form; the browser POSTs to the redirect URI.
  await expect(page.locator('#received')).toBeVisible();
  expect(posted?.method).toBe('POST');
  expect(posted?.body.get('state')).toBe(state);
  expect(posted?.body.get('code') ?? '').not.toBe('');
  expect(posted?.body.get('iss')).toBe(anvilUrl());
});
