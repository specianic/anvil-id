// AGT-03 (plan 07-16): the consent screen identifies AI agents and supports incremental step-up.
//
// - An agent client (client_kind = agent, created through the admin API) shows the
//   "AI agent / automated client" badge (#consent-agent) and its provenance (#consent-provenance,
//   data-provenance="static" for an administrator-registered client).
// - After allowing two scopes, a request for a third lists only that scope under
//   #consent-new-scopes; the two allowed ones sit in the collapsed #consent-granted-scopes block.
// - Denying the step-up returns access_denied and keeps the earlier grant: the first two scopes
//   still go straight back to the client.
// - The same journey in a browser context with JavaScript disabled (the consent page needs none).
//
// The redirect URI is served by a minimal HTTP server started by the spec (it answers every
// request with a plain page), so the authorization response can be read from the browser's URL.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
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

const AGENT_NAME = 'e2e research agent';

interface Client {
  clientId: string;
  redirectUri: string;
}

let agent: Client;
let callback: Server | undefined;

/** Starts the redirect URI server on a free port (all interfaces, so `localhost` resolves either way). */
function startCallbackServer(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('callback');
    });
    srv.once('error', reject);
    srv.listen(0, () => {
      const addr = srv.address();
      callback = srv;
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('no port'));
    });
  });
}

test.beforeAll(async ({ browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  const redirectUri = `http://localhost:${await startCallbackServer()}/cb`;
  const created = await createClient(
    token,
    {
      name: AGENT_NAME,
      client_type: 'public',
      application_type: 'web',
      auth_method: 'none',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'profile', 'email'],
      client_kind: 'agent',
    },
    'default',
    'required',
  );
  agent = { clientId: created.client_id, redirectUri };
});

test.afterAll(async () => {
  await new Promise((resolve) => (callback ? callback.close(resolve) : resolve(undefined)));
});

async function newUser(browser: Browser): Promise<{ email: string; password: string }> {
  const token = await adminToken(await sharedManagementCredential(browser));
  const email = randomEmail('consent-agent');
  const password = randomPassword();
  await createUser(token, { email, password, email_verified: true });
  return { email, password };
}

function authorizeUrl(scope: string): string {
  const url = new URL(`${anvilUrl()}/authorize`);
  url.search = new URLSearchParams({
    client_id: agent.clientId,
    response_type: 'code',
    scope,
    redirect_uri: agent.redirectUri,
    state: randomBytes(12).toString('base64url'),
    code_challenge: createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  return url.href;
}

/** Runs `action`, waits until the browser is at the redirect URI and returns its query parameters. */
async function redirectParams(page: Page, action: () => Promise<unknown>): Promise<URLSearchParams> {
  await action();
  await expect(page).toHaveURL((url) => url.href.startsWith(agent.redirectUri));
  return new URL(page.url()).searchParams;
}

/** The `attr` value of every element matching `selector`, in document order. */
async function listed(page: Page, selector: string, attr: string): Promise<(string | null)[]> {
  const items = page.locator(selector);
  const out: (string | null)[] = [];
  for (let i = 0; i < (await items.count()); i++) {
    out.push(await items.nth(i).getAttribute(attr));
  }
  return out;
}

async function stepUpJourney(page: Page, browser: Browser): Promise<void> {
  const user = await newUser(browser);

  // 1. First request for two scopes: the badge, the provenance, everything new.
  await page.goto(authorizeUrl('openid profile'));
  await expect(page.locator('form#login')).toBeVisible();
  await login(page, user.email, user.password);
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-client')).toHaveText(AGENT_NAME);
  await expect(page.locator('#consent-agent strong')).toHaveText('AI agent / automated client');
  // The badge says what an agent is (07.1-14, U-L4).
  await expect(page.locator('#consent-agent-explain')).toHaveText(
    'It acts on its own, for example as an AI assistant, and can use this access while you are not there.',
  );
  await expect(page.locator('#consent-provenance')).toHaveAttribute('data-provenance', 'static');
  await expect(page.locator('#consent-provenance')).toHaveText(
    'Set up by the administrators of this sign-in service.',
  );
  expect(await listed(page, '#consent-new-scopes [data-scope]', 'data-scope')).toEqual(['openid', 'profile']);
  await expect(page.locator('#consent-granted-scopes')).toHaveCount(0);
  const first = await redirectParams(page, () => page.locator('#consent-allow').click());
  expect(first.get('code')).toBeTruthy();
  expect(first.get('error')).toBeNull();

  // 2. Step-up: a third scope. Only it is new; the allowed two are collapsed.
  await page.goto(authorizeUrl('openid profile email'));
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  await expect(page.locator('#consent-agent')).toBeVisible();
  expect(await listed(page, '#consent-new-scopes [data-scope]', 'data-scope')).toEqual(['email']);
  const granted = page.locator('#consent-granted-scopes');
  await expect(granted).toBeVisible();
  expect(await granted.getAttribute('open')).toBeNull();
  expect(await listed(page, '#consent-granted-scopes [data-granted-scope]', 'data-granted-scope')).toEqual([
    'openid',
    'profile',
  ]);

  // 3. Deny the step-up: access_denied, and the earlier grant still holds.
  const denied = await redirectParams(page, () => page.locator('#consent-deny').click());
  expect(denied.get('error')).toBe('access_denied');
  const again = await redirectParams(page, () => page.goto(authorizeUrl('openid profile')));
  expect(again.get('code')).toBeTruthy();

  // 4. Allow the step-up: all three scopes are now covered.
  await page.goto(authorizeUrl('openid profile email'));
  await expect(page).toHaveURL((url) => url.href.startsWith(`${anvilUrl()}/ui/consent`));
  const allowed = await redirectParams(page, () => page.locator('#consent-allow').click());
  expect(allowed.get('code')).toBeTruthy();
  const covered = await redirectParams(page, () => page.goto(authorizeUrl('openid profile email')));
  expect(covered.get('code')).toBeTruthy();
}

test('agent badge, provenance and step-up showing only the new scope', async ({ page, browser }) => {
  await stepUpJourney(page, browser);
});

test('the agent consent journey works without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await stepUpJourney(page, browser);
  } finally {
    await context.close();
  }
});
