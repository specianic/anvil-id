// Headless flow API, browser mode (UI-05, plan 07-10): a single-page app on another port of the
// same host drives the login through `/api/flows/v1`, then follows `result.continue_to` and the
// relying party receives an authorization code.
//
// Same-site on purpose: the SPA (http://localhost:<port>) and AnvilID (ANVIL_URL, http://localhost)
// share a site, so the browser sends AnvilID's SameSite flow and session cookies with the SPA's
// credentialed fetches. Browsers block third-party cookies cross-site, so a cross-site SPA cannot
// use browser mode (docs/HEADLESS.md).
//
// The SPA origin is allow-listed in a dedicated tenant created through the declarative config
// API (`tenant.settings.headless.allowed_origins`): at the time of writing the admin tenant
// settings do not expose the allow-list yet (plan 07-12). A second SPA instance on an unlisted
// port gets a CORS failure. The tenant is deleted and both static servers stopped afterwards.
//
// A JavaScript client by definition: skipped in the nojs project.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { readFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
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
import { adminCall, tenantPath } from '../lib/admin-api';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { randomSlug, tenantIssuer } from '../lib/upstream';

const FIXTURE_DIR = fileURLToPath(new URL('../fixtures/headless-spa/', import.meta.url));
const REDIRECT_URI = 'https://headless-rp.example.test/callback';

interface StaticSpa {
  origin: string;
  stop(): Promise<void>;
}

/** Serves the SPA fixture (index.html, app.js) on a free loopback port. */
async function startSpa(): Promise<StaticSpa> {
  const files: Record<string, { body: Buffer; type: string }> = {
    '/': { body: await readFile(`${FIXTURE_DIR}index.html`), type: 'text/html; charset=utf-8' },
    '/app.js': {
      body: await readFile(`${FIXTURE_DIR}app.js`),
      type: 'text/javascript; charset=utf-8',
    },
  };
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://fixture').pathname;
    const file = files[path];
    if (!file) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': file.type, 'cache-control': 'no-store' }).end(file.body);
  });
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('no port'));
    });
  });
  // The AnvilID host name with the fixture's port: same site, another origin.
  const host = new URL(anvilUrl()).hostname;
  return {
    origin: `http://${host}:${port}`,
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

let creds: ManagementCredential;
let token: string;
let spa: StaticSpa;
let unlisted: StaticSpa;
const slug = randomSlug('headless');

test.beforeAll(async ({ browser }, testInfo) => {
  if (testInfo.project.name === 'nojs') return;
  creds = await sharedManagementCredential(browser);
  token = await adminToken(creds);
  spa = await startSpa();
  unlisted = await startSpa();
  // A tenant of its own whose allow-list names the SPA's exact origin (created by the apply).
  await adminCall(token, 'POST', tenantPath(slug, '/config/apply'), {
    version: 1,
    kind: 'TenantConfig',
    tenant: {
      slug,
      display_name: 'Headless e2e',
      settings: { headless: { allowed_origins: [spa.origin] } },
    },
  });
});

test.afterAll(async () => {
  await spa?.stop();
  await unlisted?.stop();
  if (token) await deleteTenant(token, slug);
});

test.beforeEach(({}, testInfo) => {
  test.skip(testInfo.project.name === 'nojs', 'the headless API is a JavaScript client');
});

test('an allow-listed same-site SPA signs in through the API and the RP receives a code', async ({
  page,
}) => {
  const email = randomEmail('headless');
  const password = randomPassword();
  await createUser(token, { email, password, email_verified: true }, slug);
  const client = await createClient(
    token,
    {
      name: 'Headless SPA RP',
      client_type: 'public',
      application_type: 'web',
      auth_method: 'none',
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code'],
      scopes: ['openid'],
    },
    slug,
  );

  // A wrong password first: the form comes back with the error key, the flow continues.
  const tokens = await authorizationCodeFlow(
    page,
    { client_id: client.client_id, redirect_uri: REDIRECT_URI },
    'openid',
    async (p) => {
      await p.waitForURL(/\/ui\/login\?request=/);
      const request = new URL(p.url()).searchParams.get('request') ?? '';
      const spaUrl = new URL(`${spa.origin}/`);
      spaUrl.searchParams.set('issuer', tenantIssuer(slug));
      spaUrl.searchParams.set('request', request);
      await p.goto(spaUrl.href);
      await expect(p.locator('#spa-status')).toHaveText('form:login');
      await p.locator('#spa-field-identifier').fill(email);
      await p.locator('#spa-field-password').fill(`${password}-wrong`);
      await p.locator('#spa-submit').click();
      await expect(p.locator('[data-key="login.invalid_credentials"]')).toBeVisible();
      await expect(p.locator('#spa-field-identifier')).toHaveValue(email);
      await p.locator('#spa-field-password').fill(password);
      await p.locator('#spa-submit').click();
    },
    tenantIssuer(slug),
  );
  expect(tokens.id_token).toBeTruthy();
  expect(jwtClaims(tokens.id_token ?? '').sub).toBeTruthy();
});

test('an SPA on an origin that is not allow-listed gets a CORS failure', async ({ page }) => {
  const spaUrl = new URL(`${unlisted.origin}/`);
  spaUrl.searchParams.set('issuer', tenantIssuer(slug));
  await page.goto(spaUrl.href);
  await expect(page.locator('#spa-error')).toHaveText('network-error');
  await expect(page.locator('#spa-form')).toBeHidden();
  // The server refused it too (not only the browser): 403 without CORS headers.
  const res = await fetch(`${tenantIssuer(slug)}/api/flows/v1/login`, {
    method: 'POST',
    headers: { origin: unlisted.origin, 'content-type': 'application/json' },
    body: '{}',
  });
  expect(res.status).toBe(403);
  expect(res.headers.get('access-control-allow-origin')).toBeNull();
  expect(((await res.json()) as { code: string }).code).toBe('forbidden_origin');
});
