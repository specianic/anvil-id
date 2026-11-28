// No dead ends (plan 07.1-08): error pages, the tenant root page and a reopened setup link.
//
// - Error pages are localized from the browser language (Accept-Language) and from ui_locales:
//   German heading and the unchanged German contract sentence, a danger label, and a way forward
//   (expectWayForward) for page not found, an unknown client, an expired sign-in link and a
//   cross-site form post (CSRF).
// - Technical detail is shown only in development mode (the dev banner is the marker).
// - The tenant root page: signed out it offers sign-in (and "Administration" on the default
//   tenant), signed in the account link and the sign-out form.
// - A reopened setup link (SETUP_URL, consumed by the time this runs) says setup is complete and
//   links the console.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createUser,
  login,
  randomEmail,
  randomPassword,
  requireEnv,
  sharedManagementCredential,
} from '../lib/anvil';
import { expectWayForward } from '../lib/layout';

/** The German contract sentences (themes/default/locales/de/main.ftl, unchanged by 07.1-08). */
const DE = {
  notFound: 'Seite nicht gefunden.',
  unknownClient: 'Diese Anwendung ist nicht registriert.',
  csrf: 'Dieses Formular konnte nicht überprüft werden. Bitte versuchen Sie es erneut.',
};

/** A verified user created through the admin API. */
async function newUser(browser: Browser, prefix: string): Promise<{ email: string; password: string }> {
  const token = await adminToken(await sharedManagementCredential(browser));
  const email = randomEmail(prefix);
  const password = randomPassword();
  await createUser(token, { email, password, email_verified: true });
  return { email, password };
}

/** The friendly parts every error page shows. */
async function expectFriendlyError(page: Page, key: string): Promise<void> {
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', key);
  await expect(page.locator('#error-label')).toBeVisible();
  await expect(page.locator('#error-explanation')).toBeVisible();
  await expectWayForward(page);
}

test.beforeAll(async ({ browser }) => {
  // Setup must be complete: the root page and the setup link depend on it.
  await sharedManagementCredential(browser);
});

test('page not found is German for a German browser and offers sign-in', async ({ browser }) => {
  const context = await browser.newContext({ locale: 'de-DE', extraHTTPHeaders: { 'accept-language': 'de-DE,de;q=0.9' } });
  try {
    const page = await context.newPage();
    const resp = await page.goto(`${anvilUrl()}/e2e-does-not-exist`);
    expect(resp?.status()).toBe(404);
    await expect(page.locator('html')).toHaveAttribute('lang', 'de');
    await expect(page.locator('h1')).toHaveText('Diese Seite gibt es nicht');
    await expect(page.locator('#error-message')).toHaveText(DE.notFound);
    await expectFriendlyError(page, 'not_found');
    await expect(page.locator('#link-login')).toBeVisible();
    await expectNoA11yViolations(page);
  } finally {
    await context.close();
  }
});

test('authorization errors honour ui_locales=de', async ({ page }) => {
  const url = new URL(`${anvilUrl()}/authorize`);
  url.search = new URLSearchParams({
    client_id: 'e2e-unknown-client',
    response_type: 'code',
    scope: 'openid',
    redirect_uri: 'http://localhost:1/callback',
    ui_locales: 'de',
  }).toString();
  const resp = await page.goto(url.href);
  expect(resp?.status()).toBe(400);
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.locator('#error-message')).toHaveText(DE.unknownClient);
  await expectFriendlyError(page, 'unknown_client');
});

test('an expired sign-in link offers to start again', async ({ page }) => {
  const resp = await page.goto(`${anvilUrl()}/authorize/continue?request=0190a6d4-0000-7000-8000-0000000000aa`);
  expect(resp?.status()).toBe(400);
  await expect(page.locator('h1')).toHaveText('This sign-in link has expired');
  await expectFriendlyError(page, 'flow_expired');
  await page.locator('#link-login').click();
  await expect(page.locator('form#login, form#login-identify').first()).toBeVisible();
});

test('a cross-site form post is a localized CSRF page with a way forward', async ({ page }) => {
  const resp = await page.request.post(`${anvilUrl()}/ui/login`, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'sec-fetch-site': 'cross-site',
      'accept-language': 'de',
    },
    data: 'identifier=nobody%40example.com&password=x',
    maxRedirects: 0,
  });
  expect(resp.status()).toBe(403);
  const html = await resp.text();
  await page.setContent(html);
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.locator('#error-message')).toHaveText(DE.csrf);
  await expectFriendlyError(page, 'csrf');
  await expect(page.locator('#link-login')).toHaveAttribute('href', `${anvilUrl()}/ui/login`);
});

test('technical detail is shown only in development mode', async ({ page }) => {
  const resp = await page.request.post(`${anvilUrl()}/authorize`, {
    headers: { 'content-type': 'text/plain' },
    data: 'client_id=x',
  });
  expect(resp.status()).toBe(400);
  const html = await resp.text();
  const devMode = html.includes('id="dev-mode-banner"');
  expect(html.includes('id="error-detail"'), `detail rendered iff dev mode (dev=${devMode})`).toBe(devMode);
});

test('tenant root page: signed out offers sign-in, signed in the account and sign-out', async ({ page, browser }) => {
  await page.goto(`${anvilUrl()}/`);
  await expect(page.locator('#link-login')).toBeVisible();
  await expect(page.locator('#link-administration')).toHaveAttribute('href', `${anvilUrl()}/console/`);
  await expect(page.locator('#form-sign-out')).toHaveCount(0);

  const user = await newUser(browser, 'e2e-root');
  await page.locator('#link-login').click();
  await login(page, user.email, user.password);
  await expect(page.locator('#link-account')).toBeVisible();
  for (const path of ['/', '/ui']) {
    await page.goto(`${anvilUrl()}${path}`);
    await expect(page.locator('#link-account')).toBeVisible();
    await expect(page.locator('#form-sign-out button')).toBeVisible();
    await expect(page.locator('#link-login')).toHaveCount(0);
  }
});

test('a reopened setup link says setup is complete and links the console', async ({ page }) => {
  const resp = await page.goto(requireEnv('SETUP_URL'));
  expect(resp?.status()).toBe(200);
  await expect(page.locator('h1')).toHaveText('Setup is already complete');
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'errors_friendly.setup_used');
  await expect(page.locator('form#setup')).toHaveCount(0);
  const consoleLink = page.locator('#link-console');
  await expect(consoleLink).toHaveAttribute('href', `${anvilUrl()}/console/`);
});
