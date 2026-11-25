// UI-01/UI-02: the password login through the sample relying party works with JavaScript disabled
// (Playwright project `nojs`). RP -> /authorize -> hosted login -> back at the RP with the profile
// read from UserInfo.
//
// 0.2 (plan 03-27), still without JavaScript: password + TOTP second factor through the sample RP,
// consent Allow, response_mode=form_post (the Continue button), and signing out another session at
// /ui/account/sessions.
//
// The spec starts its own examples/node-rp process on a free loopback port with a client it creates
// through the admin API, so run.sh does not need to manage the RP.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect, test, type Browser, type Page } from '@playwright/test';
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
import { totp } from '../lib/totp';

const RP_SERVER = fileURLToPath(new URL('../../../examples/node-rp/server.js', import.meta.url));

let rp: ChildProcess | undefined;
let rpBase = '';
let rpLog = '';

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
  const creds = await sharedManagementCredential(browser);
  const token = await adminToken(creds);
  const port = await freePort();
  rpBase = `http://localhost:${port}`;
  const client = await createClient(token, {
    name: 'e2e no-JS sample RP',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: [`${rpBase}/callback`],
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
  });
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

test('password login through the sample RP without JavaScript', async ({ page, browser }) => {
  const creds = await sharedManagementCredential(browser);
  const email = randomEmail('nojs');
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });

  // JavaScript really is off in this project.
  await page.goto(`${anvilUrl()}/ui/login`);
  await page.setContent('<p id="probe">no</p><script>document.getElementById("probe").textContent = "yes"</script>');
  await expect(page.locator('#probe')).toHaveText('no');

  await page.goto(`${rpBase}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await expect(page.locator('form#login')).toBeVisible();

  // A wrong password first: the error round trip works without JavaScript too.
  await login(page, email, randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();

  await login(page, email, password);
  await expect(page).toHaveURL(`${rpBase}/me`);
  await expect(page.locator('#sub')).not.toHaveText('');
  await expect(page.locator('#email')).toHaveText(email);
});

// ---------------------------------------------------------------------------------------------
// 0.2 flows without JavaScript.

async function newUser(browser: Browser, prefix: string): Promise<{ email: string; password: string }> {
  const creds = await sharedManagementCredential(browser);
  const email = randomEmail(prefix);
  const password = randomPassword();
  await createUser(await adminToken(creds), { email, password, email_verified: true });
  return { email, password };
}

async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await expect(page.locator('form#login')).toHaveCount(0);
}

/** A client whose redirect URI is a free loopback port nobody listens on. */
async function loopbackClient(
  browser: Browser,
  consentMode: 'required' | 'skip_first_party',
): Promise<{ clientId: string; redirectUri: string }> {
  const creds = await sharedManagementCredential(browser);
  const redirectUri = `http://localhost:${await freePort()}/cb`;
  const client = await createClient(
    await adminToken(creds),
    {
      name: `e2e no-JS ${consentMode} client`,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'email'],
    },
    'default',
    consentMode,
  );
  return { clientId: client.client_id, redirectUri };
}

function authorizeUrl(clientId: string, redirectUri: string, extra: Record<string, string> = {}): string {
  const url = new URL(`${anvilUrl()}/authorize`);
  url.search = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    scope: 'openid email',
    redirect_uri: redirectUri,
    state: randomBytes(12).toString('base64url'),
    code_challenge: createHash('sha256').update(randomBytes(32)).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  }).toString();
  return url.href;
}

test('password + authenticator app second factor through the sample RP without JavaScript', async ({
  page,
  browser,
}) => {
  const user = await newUser(browser, 'nojs-2fa');

  // Enrol the authenticator app (the account pages are plain forms too).
  await signIn(page, user.email, user.password);
  await page.goto(`${anvilUrl()}/ui/account/security`);
  // The passkey trigger needs JavaScript; without it the page says so and the button stays hidden.
  await expect(page.locator('#passkey-register-submit')).toBeHidden();
  await page.locator('#totp-begin-submit').click();
  const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  await page.locator('#code').fill(totp(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#recovery-codes li')).toHaveCount(10);
  await page.context().clearCookies();

  await page.goto(`${rpBase}/login`);
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('#login-passkey-submit')).toBeHidden();
  await login(page, user.email, user.password);
  await expect(page.locator('form#second-factor')).toBeVisible();
  // The step used to confirm the enrolment cannot be replayed; the next step is accepted.
  await page.locator('#code').fill(totp(secret, Date.now() / 1000 + 30));
  await page.locator('#second-factor-submit').click();
  await expect(page).toHaveURL(`${rpBase}/me`);
  await expect(page.locator('#email')).toHaveText(user.email);
});

test('consent Allow without JavaScript', async ({ page, browser }) => {
  const user = await newUser(browser, 'nojs-consent');
  const client = await loopbackClient(browser, 'required');
  await page.goto(authorizeUrl(client.clientId, client.redirectUri));
  await login(page, user.email, user.password);
  await expect(page.locator('form#consent-form')).toBeVisible();
  // The redirect target is not served; observe the browser requesting it.
  const redirected = page.waitForRequest((req) => req.url().startsWith(client.redirectUri));
  await page.locator('#consent-allow').click();
  expect(new URL((await redirected).url()).searchParams.get('code') ?? '').not.toBe('');
});

test('response_mode=form_post without JavaScript: Continue posts the response', async ({
  page,
  browser,
}) => {
  const user = await newUser(browser, 'nojs-fp');
  const client = await loopbackClient(browser, 'skip_first_party');
  let posted: URLSearchParams | undefined;
  await page.route(`${new URL(client.redirectUri).origin}/**`, async (route) => {
    posted = new URLSearchParams(route.request().postData() ?? '');
    await route.fulfill({ status: 200, contentType: 'text/html', body: '<p id="received">ok</p>' });
  });
  await page.goto(authorizeUrl(client.clientId, client.redirectUri, { response_mode: 'form_post' }));
  await login(page, user.email, user.password);
  await expect(page.locator('#form-post-continue')).toBeVisible();
  await page.locator('#form-post-continue').click();
  await expect(page.locator('#received')).toBeVisible();
  expect(posted?.get('code') ?? '').not.toBe('');
});

test('sign out another session at /ui/account/sessions without JavaScript', async ({
  page,
  browser,
}) => {
  const user = await newUser(browser, 'nojs-sess');
  // New contexts do not inherit the project's javaScriptEnabled option.
  const other = await browser.newContext({ javaScriptEnabled: false });
  try {
    const otherPage = await other.newPage();
    await signIn(otherPage, user.email, user.password);
    await signIn(page, user.email, user.password);
    await page.goto(`${anvilUrl()}/ui/account/sessions`);
    await expect(page.locator('#session-list tbody tr')).toHaveCount(2);
    await page.locator('#session-list tbody tr:not([data-current]) button').click();
    await expect(page.locator('[data-message-key="sessions.revoked"]')).toBeVisible();
    await expect(page.locator('#session-list tbody tr')).toHaveCount(1);

    await otherPage.goto(`${anvilUrl()}/ui/account/sessions`);
    await expect(otherPage).toHaveURL((url) => url.pathname.endsWith('/ui/login'));
  } finally {
    await other.close();
  }
});
