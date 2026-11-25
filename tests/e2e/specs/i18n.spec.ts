// UI-04: page language selection in the browser, with German as the second shipped language.
//
// - An authorization request with ui_locales=de renders the login page in German (<html lang="de">,
//   heading, field labels, button); the consent page that follows stays German.
// - A browser preferring German (Accept-Language de-DE) gets German without ui_locales.
// - ui_locales=xx en (unknown tag first) falls through to English, as does an English browser.
// - The account security page is German for ui_locales=de and for a German browser.
// - German layouts hold at 320 CSS px (no horizontal scrolling) on login, consent and account pages,
//   and the German login page passes axe (valid lang attribute).
// - Discovery advertises de in ui_locales_supported.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { createHash, randomBytes } from 'node:crypto';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { freePort } from '../lib/account';
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

interface Client {
  clientId: string;
  redirectUri: string;
}

let client: Client;

/** A verified user created through the admin API. */
async function newUser(browser: Browser, prefix: string): Promise<{ email: string; password: string }> {
  const token = await adminToken(await sharedManagementCredential(browser));
  const email = randomEmail(prefix);
  const password = randomPassword();
  await createUser(token, { email, password, email_verified: true });
  return { email, password };
}

/** /authorize for the consent-required test client, plus `extra` parameters. */
function authorizeUrl(extra: Record<string, string> = {}): string {
  const url = new URL(`${anvilUrl()}/authorize`);
  url.search = new URLSearchParams({
    client_id: client.clientId,
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: client.redirectUri,
    state: randomBytes(12).toString('base64url'),
    nonce: randomBytes(12).toString('base64url'),
    code_challenge: createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  }).toString();
  return url.href;
}

/** Fails when the page scrolls horizontally at 320 CSS px; restores the desktop viewport. */
async function expectReflowAt320(page: Page): Promise<void> {
  await page.setViewportSize({ width: 320, height: 640 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, `horizontal scroll at 320 px on ${page.url()}`).toBeLessThanOrEqual(0);
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function expectGermanLogin(page: Page): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('#page-heading')).toHaveText('Anmelden');
  await expect(page.locator('label[for="identifier"]')).toHaveText('E-Mail-Adresse');
  await expect(page.locator('label[for="password"]')).toHaveText('Passwort');
  await expect(page.locator('#login-submit')).toHaveText('Anmelden');
}

async function expectEnglishLogin(page: Page): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('#page-heading')).toHaveText('Sign in');
  await expect(page.locator('label[for="password"]')).toHaveText('Password');
  await expect(page.locator('#login-submit')).toHaveText('Sign in');
}

async function expectGermanSecurityPage(page: Page): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.locator('#passkeys-heading')).toBeVisible();
  await expect(page.locator('#page-heading')).toHaveText('Sicherheit');
  await expect(page.locator('#account-nav-security')).toHaveText('Sicherheit');
  await expect(page.locator('#account-nav-sessions')).toHaveText('Sitzungen');
  await expect(page.locator('#account-nav-linked')).toHaveText('Verknüpfte Konten');
}

test.beforeAll(async ({ browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  // The redirect URI points at a free loopback port nobody listens on: the tests stop at consent.
  const redirectUri = `http://localhost:${await freePort()}/cb`;
  const created = await createClient(
    token,
    {
      name: 'e2e i18n client',
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'profile', 'email'],
    },
    'default',
    'required',
  );
  client = { clientId: created.client_id, redirectUri };
});

test('discovery advertises German', async () => {
  const res = await fetch(`${anvilUrl()}/.well-known/openid-configuration`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { ui_locales_supported?: string[] };
  expect(body.ui_locales_supported).toEqual(expect.arrayContaining(['en', 'de']));
});

test('ui_locales=de renders login and consent in German', async ({ page, browser }) => {
  const user = await newUser(browser, 'i18n-de');
  await page.goto(authorizeUrl({ ui_locales: 'de' }));
  await expectGermanLogin(page);
  await expectReflowAt320(page);
  await test.step('axe on the German login page', async () => {
    await expectNoA11yViolations(page);
  });

  await login(page, user.email, user.password);
  await expect(page.locator('form#consent-form')).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await expect(page.locator('#page-heading')).toHaveText('Zugriff auf Ihr Konto erlauben?');
  await expect(page.locator('#consent-allow')).toHaveText('Erlauben');
  await expect(page.locator('#consent-deny')).toHaveText('Ablehnen');
  await expect(page.locator('#consent-scopes li[data-scope="email"]')).toHaveText(
    'Ihre E-Mail-Adresse sehen',
  );
  await expectReflowAt320(page);
});

test('Accept-Language de-DE renders German without ui_locales', async ({ browser }) => {
  const context = await browser.newContext({ locale: 'de-DE' });
  try {
    const page = await context.newPage();
    await page.goto(authorizeUrl());
    await expectGermanLogin(page);
    await expect(page.locator('#link-recovery')).toHaveText('Passwort vergessen?');
  } finally {
    await context.close();
  }
});

test('an unknown ui_locales tag falls through to English', async ({ page }) => {
  await page.goto(authorizeUrl({ ui_locales: 'xx en' }));
  await expectEnglishLogin(page);
});

test('an English browser without ui_locales gets English', async ({ browser }) => {
  const context = await browser.newContext({ locale: 'en-US' });
  try {
    const page = await context.newPage();
    await page.goto(authorizeUrl());
    await expectEnglishLogin(page);
  } finally {
    await context.close();
  }
});

test('account security page in German via ui_locales and via the browser', async ({ page, browser }) => {
  const user = await newUser(browser, 'i18n-account');
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('form#login')).toHaveCount(0);

  await page.goto(`${anvilUrl()}/ui/account/security?ui_locales=de`);
  await expectGermanSecurityPage(page);
  await expectReflowAt320(page);

  // Without ui_locales an English browser reads English.
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('#page-heading')).toHaveText('Security');

  const german = await browser.newContext({ locale: 'de-DE' });
  try {
    const de = await german.newPage();
    await de.goto(`${anvilUrl()}/ui/login`);
    await expectGermanLogin(de);
    await login(de, user.email, user.password);
    await expect(de.locator('form#login')).toHaveCount(0);
    await de.goto(`${anvilUrl()}/ui/account/security`);
    await expectGermanSecurityPage(de);
    await expectReflowAt320(de);
  } finally {
    await german.close();
  }
});
