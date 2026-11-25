// UI-01/UI-02: the password login through the sample relying party works with JavaScript disabled
// (Playwright project `nojs`). RP -> /authorize -> hosted login -> back at the RP with the profile
// read from UserInfo.
//
// The spec starts its own examples/node-rp process on a free loopback port with a client it creates
// through the admin API, so run.sh does not need to manage the RP.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
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
