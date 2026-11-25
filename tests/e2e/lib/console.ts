// Helpers for driving the admin console at /console/ (03-25) and a sample relying party next to it.
//
// The console signs in as the public client `anvil-console` of the system tenant (authorization
// code + PKCE); admins are users of the system tenant. Endpoints come from ANVIL_URL only.

import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { expect, type Locator, type Page } from '@playwright/test';
import { anvilUrl, createClient, login, type AdminAccount } from './anvil';
import { tenantIssuer } from './upstream';

/** The console URL for a path inside it (`users`, `audit?action=x`, ...). */
export function consoleUrl(path = ''): string {
  return `${anvilUrl()}/console/${path.replace(/^\/+/, '')}`;
}

/**
 * Opens /console/, follows the OIDC redirect to the system tenant's hosted login page, signs in
 * and waits for the console shell (the Users page is the landing page).
 */
export async function consoleLogin(page: Page, admin: AdminAccount): Promise<void> {
  await page.goto(consoleUrl());
  await expect(page).toHaveURL((url) => url.pathname.startsWith('/t/system/ui/login'));
  await login(page, admin.email, admin.password);
  await expectConsoleHome(page);
}

/** The signed-in console shell on its landing page. */
export async function expectConsoleHome(page: Page): Promise<void> {
  await expect(page).toHaveURL((url) => url.pathname === '/console/users');
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
}

/**
 * Pages through a console DataTable (Next button) until `row` is visible. Lists are cursor-paged,
 * and other specs of the same run create users and clients too.
 */
export async function findInPagedTable(page: Page, row: Locator, maxPages = 50): Promise<void> {
  for (let i = 0; i < maxPages; i++) {
    const table = page.getByRole('table');
    await expect(table).toHaveAttribute('aria-busy', 'false');
    if (await row.isVisible()) return;
    const next = page.getByRole('button', { name: 'Next' });
    if (!(await next.isEnabled())) break;
    await next.click();
  }
  await expect(row).toBeVisible();
}

export interface SampleRp {
  base: string;
  stop(): Promise<void>;
}

const RP_SERVER = fileURLToPath(new URL('../../../examples/node-rp/server.js', import.meta.url));

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

/**
 * Starts examples/node-rp on a free loopback port with a new confidential client of `tenant`
 * (default `default`; authorization code + refresh token).
 */
export async function startSampleRp(token: string, name: string, tenant = 'default'): Promise<SampleRp> {
  const port = await freePort();
  const base = `http://localhost:${port}`;
  const client = await createClient(token, {
    name,
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: [`${base}/callback`],
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
  }, tenant);
  let log = '';
  const rp: ChildProcess = spawn(process.execPath, [RP_SERVER], {
    env: {
      ...process.env,
      ISSUER: tenantIssuer(tenant),
      CLIENT_ID: client.client_id,
      CLIENT_SECRET: client.client_secret ?? '',
      PORT: String(port),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  rp.stdout?.on('data', (d: Buffer) => (log += d.toString()));
  rp.stderr?.on('data', (d: Buffer) => (log += d.toString()));

  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      const res = await fetch(`${base}/healthz`);
      if (res.ok) break;
    } catch {
      // not listening yet
    }
    if (rp.exitCode !== null) throw new Error(`sample RP exited (${rp.exitCode}):\n${log}`);
    if (Date.now() > deadline) throw new Error(`sample RP did not start:\n${log}`);
    await new Promise((r) => setTimeout(r, 200));
  }

  return {
    base,
    async stop() {
      if (rp.exitCode === null) {
        const exited = new Promise((r) => rp.once('exit', r));
        rp.kill('SIGTERM');
        await exited;
      }
    },
  };
}
