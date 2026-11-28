// UI-02: every hosted page (Phase 2 and the 0.2 additions) passes the axe WCAG 2.2 A/AA rules at a mobile and a desktop
// viewport, in the light and the dark colour scheme, and reflows without horizontal scrolling at
// 320 CSS px (WCAG 1.4.10).
//
// Pages: setup + setup done (only while the instance is not yet installed, i.e. when this spec runs
// first in a fresh run.sh instance), login (clean and with an error), registration (clean and with
// field errors), the registration "check your email" message, verification (via the Mailpit link),
// recovery request, the recovery "sent" message, recovery reset (via the Mailpit link) and error
// pages (unknown client, page not found, a reopened setup link).
//
// 07.1-08: before setup, `/` and `/console/` show the setup guidance (naming
// `anvilid admin setup-url`); the setup success page links the console (#link-console); the tenant
// root page (signed out) is audited after setup.
//
// 0.2 pages (plan 03-27): login with the passkey button, second factor (clean, with an error, with
// the recovery-code disclosure open), consent, the form_post interstitial, account security (empty,
// with a passkey, with an authenticator app), TOTP enrolment (clean and with a wrong code), recovery
// codes, sessions (two browsers) and connected apps (empty and with an app).
//
// 07.1 pages (plan 07.1-18), light and dark: Signed in, root signed in, logout confirmation, signed
// out, the expired sign-in link page, request-bound message pages with "Continue to <app>"
// (check-email naming the address, verification done, recovery sent), a used verification link,
// MFA enrolment with the otpauth link, the in-flow recovery codes page, sign-in with email sign-in
// on and the email code page, account pages with the account header, the account confirmation
// step, the org chooser, the non-member page, the upstream link confirmation and the changed
// console pages (overview, users list, user page, new client picker, client page, new connection,
// login settings, new tenant).
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { expectWayForward } from '../lib/layout';
import { test as webauthnTest } from '../fixtures/webauthn';
import {
  adminToken,
  anvilUrl,
  completeSetup,
  createClient,
  createConsoleAdmin,
  createUser,
  login,
  randomEmail,
  randomPassword,
  register,
  requireEnv,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { extractLink, latestMessageTo } from '../lib/mailpit';
import { totp } from '../lib/totp';
import { withTenantSettings } from '../lib/admin';
import { consoleUrl } from '../lib/console';
import { consoleSignIn } from '../lib/console-ux';
import { detourUser, startAtLogin } from '../lib/detours';
import { deleteTenant } from '../lib/email-code';
import { addMember, createOrg, createOrgClient, createOrgTenant } from '../lib/org';
import { createTenant, githubMockConnection, randomSlug, tenantIssuer } from '../lib/upstream';
import { atRp, authorizeUrl as uxAuthorizeUrl, fakeRp, fakeRpOrigin, token, uxState } from '../lib/ux-state';

const VIEWPORTS = [
  { name: 'mobile', width: 375, height: 812 },
  { name: 'desktop', width: 1280, height: 800 },
] as const;

const SCHEMES = ['light', 'dark'] as const;

/** axe at every viewport and colour scheme, plus the 320 px reflow check. */
async function auditPage(page: Page): Promise<void> {
  for (const scheme of SCHEMES) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const vp of VIEWPORTS) {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await test.step(`axe ${vp.name} ${scheme}`, async () => {
        await expectNoA11yViolations(page);
      });
    }
  }
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 320, height: 640 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow, `horizontal scroll at 320 px on ${page.url()}`).toBeLessThanOrEqual(0);
  await page.setViewportSize({ width: 1280, height: 800 });
}

function stateIsEmpty(stateFile: string): boolean {
  return !existsSync(stateFile) || readFileSync(stateFile, 'utf8').trim() === '';
}

let creds: ManagementCredential;

// Each page state is audited five times (2 viewports x 2 colour schemes + reflow); allow for it.
test.describe.configure({ timeout: 180_000 });

test('setup and setup-done pages', async ({ page }) => {
  const stateFile = requireEnv('E2E_STATE_FILE');
  test.skip(
    !stateIsEmpty(stateFile),
    'instance already installed by an earlier spec; the setup form is covered by the render snapshots',
  );
  // Before setup the root and the console explain how to finish it instead of a sign-in form.
  for (const path of ['/', '/console/']) {
    await page.goto(`${anvilUrl()}${path}`);
    await expect(page.locator('h1')).toHaveText('Setup is not complete');
    await expect(page.locator('#setup-command')).toHaveText('anvilid admin setup-url');
    await expect(page.locator('#link-login')).toHaveCount(0);
  }
  await auditPage(page);

  // GET does not consume the setup token; only the form POST does.
  await page.goto(requireEnv('SETUP_URL'));
  await expect(page.locator('form#setup')).toBeVisible();
  await auditPage(page);

  // Submitting without input shows field errors; audit that state too.
  await page.locator('#setup-submit').click();
  await expect(page.locator('form#setup [aria-invalid="true"]').first()).toBeVisible();
  await auditPage(page);

  creds = await completeSetup(page, requireEnv('SETUP_URL'), {
    email: randomEmail('admin'),
    password: randomPassword(),
  });
  // The way forward is the console; the credentials are the "For automation" block.
  const consoleLink = page.locator('#link-console');
  await expect(consoleLink).toBeVisible();
  await expect(consoleLink).toHaveAttribute('href', `${anvilUrl()}/console/`);
  await expect(page.locator('#setup-automation #mgmt-client-secret')).toBeVisible();
  await auditPage(page);
  // Share the credential with the other specs of this run (same format as sharedManagementCredential).
  writeFileSync(stateFile, JSON.stringify(creds), { mode: 0o600 });
});

test.beforeEach(async ({ browser }) => {
  if (!creds && !stateIsEmpty(requireEnv('E2E_STATE_FILE'))) {
    creds = await sharedManagementCredential(browser);
  }
});

test('login page, clean and with an error', async ({ page }) => {
  creds ??= await sharedManagementCredential(page.context().browser()!);
  await page.goto(`${anvilUrl()}/ui/login`);
  await expect(page.locator('form#login')).toBeVisible();
  // The passkey button (03-20) is revealed by webauthn.js in this (JavaScript) project.
  await expect(page.locator('#login-passkey-submit')).toBeVisible();
  await auditPage(page);

  await login(page, randomEmail('nobody'), randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await auditPage(page);
});

test('registration, check-email message and verification pages', async ({ page }) => {
  creds ??= await sharedManagementCredential(page.context().browser()!);
  await page.goto(`${anvilUrl()}/ui/registration`);
  await expect(page.locator('form#registration')).toBeVisible();
  await auditPage(page);

  // Field errors.
  await page.locator('#registration-submit').click();
  await expect(page.locator('form#registration [aria-invalid="true"]').first()).toBeVisible();
  await auditPage(page);

  const email = randomEmail('a11y-reg');
  await register(page, email, randomPassword());
  await expect(page.locator('#message-body')).toBeVisible();
  await auditPage(page);

  const message = await latestMessageTo(email);
  await page.context().clearCookies();
  await page.goto(extractLink(message.Text || message.HTML, '/ui/verification'));
  await expect(page.locator('form#verification')).toBeVisible();
  await auditPage(page);

  await page.locator('#verification-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'verification.done');
  await auditPage(page);
});

test('recovery request, sent message and reset pages', async ({ page }) => {
  creds ??= await sharedManagementCredential(page.context().browser()!);
  const email = randomEmail('a11y-rec');
  await createUser(await adminToken(creds), {
    email,
    password: randomPassword(),
    email_verified: true,
  });

  await page.goto(`${anvilUrl()}/ui/recovery`);
  await expect(page.locator('form#recovery')).toBeVisible();
  await auditPage(page);

  await page.locator('#email').fill(email);
  await page.locator('#recovery-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.sent');
  await auditPage(page);

  const message = await latestMessageTo(email);
  await page.goto(extractLink(message.Text || message.HTML, '/ui/recovery'));
  await expect(page.locator('form#recovery-reset')).toBeVisible();
  await auditPage(page);

  // A too-short password shows a field error.
  await page.locator('#password').fill('x');
  await page.locator('#recovery-reset-submit').click();
  await expect(page.locator('form#recovery-reset [aria-invalid="true"]').first()).toBeVisible();
  await auditPage(page);
});

test('error pages', async ({ page }) => {
  creds ??= await sharedManagementCredential(page.context().browser()!);
  const unknownClient = new URL(`${anvilUrl()}/authorize`);
  unknownClient.search = new URLSearchParams({
    client_id: 'a11y-unknown-client',
    response_type: 'code',
    scope: 'openid',
    redirect_uri: 'http://localhost:1/callback',
  }).toString();
  await page.goto(unknownClient.href);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'unknown_client');
  await auditPage(page);

  await expectWayForward(page);

  await page.goto(`${anvilUrl()}/a11y-does-not-exist`);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'not_found');
  await expectWayForward(page);
  await auditPage(page);

  // After setup, a reopened (or made-up) setup link explains that setup is complete.
  await page.goto(`${anvilUrl()}/setup?token=a11y-bogus`);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'errors_friendly.setup_used');
  await expect(page.locator('#link-console')).toBeVisible();
  await auditPage(page);
});

test('tenant root page', async ({ page }) => {
  creds ??= await sharedManagementCredential(page.context().browser()!);
  await page.goto(`${anvilUrl()}/`);
  await expect(page.locator('#link-login')).toBeVisible();
  await expect(page.locator('#link-administration')).toHaveAttribute('href', `${anvilUrl()}/console/`);
  await auditPage(page);
});

// ---------------------------------------------------------------------------------------------
// 0.2 pages (plan 03-27).

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

/** A verified user created through the admin API. */
async function newUser(browser: Browser, prefix: string): Promise<{ email: string; password: string }> {
  creds ??= await sharedManagementCredential(browser);
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

/**
 * A client whose redirect URI points at a free loopback port nobody listens on (form posts there
 * are answered by a route handler; redirects are observed with waitForRequest).
 */
async function loopbackClient(
  browser: Browser,
  name: string,
  consentMode: 'required' | 'skip_first_party',
): Promise<{ clientId: string; base: string; redirectUri: string }> {
  creds ??= await sharedManagementCredential(browser);
  const base = `http://localhost:${await freePort()}`;
  const redirectUri = `${base}/cb`;
  const client = await createClient(
    await adminToken(creds),
    {
      name,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'profile', 'email'],
    },
    'default',
    consentMode,
  );
  return { clientId: client.client_id, base, redirectUri };
}

function authorizeUrl(clientId: string, redirectUri: string, extra: Record<string, string> = {}): string {
  const url = new URL(`${anvilUrl()}/authorize`);
  url.search = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: redirectUri,
    state: randomBytes(12).toString('base64url'),
    nonce: randomBytes(12).toString('base64url'),
    code_challenge: createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url'),
    code_challenge_method: 'S256',
    ...extra,
  }).toString();
  return url.href;
}

/** A 6-digit code that is wrong for the steps around now (the server accepts +-1 step). */
function wrongCode(secret: string): string {
  const now = Date.now() / 1000;
  const valid = new Set([totp(secret, now - 30), totp(secret, now), totp(secret, now + 30)]);
  for (let n = 0; ; n += 1) {
    const candidate = String(n).padStart(6, '0');
    if (!valid.has(candidate)) return candidate;
  }
}

/** From the account security page: starts TOTP enrolment and returns the base32 secret. */
async function beginTotp(page: Page): Promise<string> {
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#totp-begin-submit').click();
  await expect(page.locator('#totp-qr svg')).toBeVisible();
  return ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
}

test('account security, TOTP enrolment and recovery codes', async ({ page, browser }) => {
  const user = await newUser(browser, 'a11y-sec');
  await signIn(page, user.email, user.password);

  await page.goto(`${anvilUrl()}/ui/account/security`);
  await expect(page.locator('#passkeys-empty')).toBeVisible();
  await expect(page.locator('#account-nav-security')).toHaveAttribute('aria-current', 'page');
  await auditPage(page);

  const secret = await beginTotp(page);
  await auditPage(page);

  // The QR code keeps a fixed, scannable size: not stretched to the card width.
  for (const width of [375, 1280]) {
    await page.setViewportSize({ width, height: 800 });
    const box = await page.locator('#totp-qr svg').boundingBox();
    expect(box, 'QR code rendered').not.toBeNull();
    expect(box!.width, `QR width at ${width} px`).toBeGreaterThanOrEqual(150);
    expect(box!.width, `QR width at ${width} px`).toBeLessThanOrEqual(220);
    expect(Math.abs(box!.width - box!.height)).toBeLessThanOrEqual(1);
  }

  // A wrong code: the error is linked to the field.
  await page.locator('#code').fill(wrongCode(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#code-msg-1')).toBeVisible();
  await expect(page.locator('#code')).toHaveAttribute('aria-invalid', 'true');
  await auditPage(page);

  await page.locator('#code').fill(totp(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#recovery-codes li')).toHaveCount(10);
  await auditPage(page);

  await page.locator('#link-account-security').click();
  await expect(page.locator('#recovery-codes-count')).toHaveText('10');
  await auditPage(page);
});

webauthnTest('account security with a passkey', async ({ page, browser, authenticator }) => {
  expect(authenticator).toBeTruthy();
  const user = await newUser(browser, 'a11y-pk');
  await signIn(page, user.email, user.password);
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#label').fill('Laptop');
  await page.locator('#passkey-register-submit').click();
  await expect(page.locator('#passkey-list tbody tr')).toHaveCount(1);
  await auditPage(page);
});

test('second factor: clean, wrong code, recovery-code disclosure open', async ({ page, browser }) => {
  const user = await newUser(browser, 'a11y-2fa');
  const setup = await browser.newContext();
  let secret: string;
  try {
    const p = await setup.newPage();
    await signIn(p, user.email, user.password);
    secret = await beginTotp(p);
    await p.locator('#code').fill(totp(secret));
    await p.locator('#totp-confirm-submit').click();
    await expect(p.locator('#recovery-codes li')).toHaveCount(10);
  } finally {
    await setup.close();
  }

  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('form#second-factor')).toBeVisible();
  await auditPage(page);

  await page.locator('#code').fill(wrongCode(secret));
  await page.locator('#second-factor-submit').click();
  await expect(page.locator('[data-message-key="login.second_factor_invalid"]')).toBeVisible();
  await expect(page.locator('#code')).toHaveAttribute('aria-invalid', 'true');
  await auditPage(page);

  await page.locator('#recovery-code-toggle > summary').click();
  await expect(page.locator('#recovery_code')).toBeVisible();
  await auditPage(page);
});

test('consent screen and connected apps', async ({ page, browser }) => {
  const user = await newUser(browser, 'a11y-consent');
  const rp = await loopbackClient(browser, 'a11y consent client', 'required');
  await signIn(page, user.email, user.password);

  await page.goto(`${anvilUrl()}/ui/account/apps`);
  await expect(page.locator('#apps-empty')).toBeVisible();
  await auditPage(page);

  await page.goto(authorizeUrl(rp.clientId, rp.redirectUri));
  await expect(page.locator('form#consent-form')).toBeVisible();
  await auditPage(page);

  // Allow redirects to the client's (unserved) redirect URI. Playwright routes do not see redirect
  // targets, so wait for the browser to request it instead.
  const redirected = page.waitForRequest((req) => req.url().startsWith(rp.redirectUri));
  await page.locator('#consent-allow').click();
  const callback = new URL((await redirected).url());
  expect(callback.searchParams.get('code') ?? '').not.toBe('');

  // The unserved target ends in a browser error page; continue in a second tab (same session).
  const apps = await page.context().newPage();
  await apps.goto(`${anvilUrl()}/ui/account/apps`);
  await expect(apps.locator(`#app-list li[data-client-id="${rp.clientId}"]`)).toBeVisible();
  await auditPage(apps);
});

test('form_post interstitial', async ({ page, browser }) => {
  const user = await newUser(browser, 'a11y-fp');
  const rp = await loopbackClient(browser, 'a11y form_post client', 'skip_first_party');
  await signIn(page, user.email, user.password);
  // Keep the interstitial on screen: without its script it waits (no-JS users press Continue).
  await page.route('**/form_post.js', (route) => route.abort());
  await page.route(`${rp.base}/**`, (route) => route.fulfill({ status: 200, body: 'posted' }));
  await page.goto(authorizeUrl(rp.clientId, rp.redirectUri, { response_mode: 'form_post' }));
  await expect(page.locator('form#form-post')).toBeAttached();
  await expect(page.locator('#form-post-status')).toBeVisible();
  await auditPage(page);
});

test('sessions page with two browsers', async ({ page, browser }) => {
  const user = await newUser(browser, 'a11y-sess');
  const other = await browser.newContext();
  try {
    await signIn(await other.newPage(), user.email, user.password);
    await signIn(page, user.email, user.password);
    await page.goto(`${anvilUrl()}/ui/account/sessions`);
    await expect(page.locator('#session-list tbody tr')).toHaveCount(2);
    await auditPage(page);

    // After signing out the other session: the confirmation message and a single row.
    await page.locator('#session-list tbody tr:not([data-current]) button').click();
    await expect(page.locator('[data-message-key="sessions.revoked"]')).toBeVisible();
    await auditPage(page);
  } finally {
    await other.close();
  }
});

// ---------------------------------------------------------------------------------------------
// 07.1 pages (plan 07.1-18): every new or changed end-user page and the changed console pages, in
// the light and the dark scheme. Journeys go through the fake RP (lib/ux-state.ts) where an app is
// involved; tenant settings are changed with withTenantSettings (restored afterwards) or in a
// tenant of the test's own.

/** Runs `fn` with the fake RP listening, then stops it. */
async function withFakeRp<T>(fn: () => Promise<T>): Promise<T> {
  const rp = await fakeRp();
  try {
    return await fn();
  } finally {
    await rp.close();
  }
}

test('signed in, root signed in, logout confirmation and signed out', async ({ page, browser }) => {
  const tok = await token(await uxState(browser));
  const user = await detourUser(tok, 'a11y-out');
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expect(page.locator('#link-account')).toBeVisible();
  await auditPage(page);

  await page.goto(`${anvilUrl()}/`);
  await expect(page.locator('#form-sign-out button')).toBeVisible();
  await auditPage(page);

  await page.goto(`${anvilUrl()}/ui/logout`);
  await expect(page.locator('#logout-confirm-submit')).toBeVisible();
  await auditPage(page);
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await expect(page.locator('#link-login')).toBeVisible();
  await auditPage(page);
});

test('request-bound pages: expired link, check-email with Continue, verification done, recovery sent', async ({
  page,
  browser,
}) => {
  const s = await uxState(browser);
  const tok = await token(s);
  await page.goto(`${anvilUrl()}/ui/login?request=0190a6d4-0000-7000-8000-0000000a11aa`);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'flow_expired');
  await auditPage(page);

  await withFakeRp(() =>
    withTenantSettings(tok, { require_verified_email: true }, async () => {
      await startAtLogin(page, s.clients.web);
      await page.locator('#link-registration').click();
      const email = randomEmail('a11y-verify');
      await register(page, email, randomPassword());
      await expect(page.locator('#message-sent-to')).toContainText(email);
      await expect(page.locator('#link-continue')).toBeVisible();
      await auditPage(page);

      const link = extractLink((await latestMessageTo(email)).Text, '/ui/verification');
      await page.goto(link);
      await page.locator('#verification-submit').click();
      await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'verification.done');
      await expect(page.locator('#link-continue')).toBeVisible();
      await auditPage(page);
      // The used link: notice plus a way forward, no button.
      await page.goto(link);
      await expect(page.locator('[data-message-key="links.expired"]')).toBeVisible();
      await auditPage(page);

      await startAtLogin(page, s.clients.web);
      await page.locator('#link-recovery').click();
      await page.locator('#email').fill(randomEmail('a11y-nobody'));
      await page.locator('#recovery-submit').click();
      await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.sent');
      await expect(page.locator('#link-continue')).toBeVisible();
      await auditPage(page);
    }),
  );
});

test('MFA enrolment with the otpauth link and the in-flow recovery codes page', async ({ page, browser }) => {
  const s = await uxState(browser);
  const tok = await token(s);
  const user = await detourUser(tok, 'a11y-mfa');
  await withFakeRp(() =>
    withTenantSettings(tok, { mfa_policy: 'required' }, async () => {
      await startAtLogin(page, s.clients.web);
      await login(page, user.email, user.password);
      await expect(page.locator('form#mfa-enroll')).toBeVisible();
      await expect(page.locator('#link-otpauth')).toBeVisible();
      await auditPage(page);
      const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
      await page.locator('#code').fill(totp(secret));
      await page.locator('#mfa-enroll-submit').click();
      await expect(page).toHaveURL(/\/ui\/login\/recovery-codes\?flow=/);
      await expect(page.locator('#recovery-codes li')).toHaveCount(10);
      await auditPage(page);
      await page.locator('#recovery-codes-confirm-submit').click();
      expect((await atRp(page)).get('code')).toBeTruthy();
    }),
  );
});

test('sign-in with email sign-in on and the email code page', async ({ page, browser }) => {
  const s = await uxState(browser);
  const tok = await token(s);
  const user = await detourUser(tok, 'a11y-email');
  await withFakeRp(() =>
    withTenantSettings(tok, { email_otp: true }, async () => {
      await startAtLogin(page, s.clients.web);
      await expect(page.locator('#email-code-request-submit')).toBeVisible();
      await auditPage(page);
      await page.locator('#identifier').fill(user.email);
      await page.locator('#email-code-request-submit').click();
      await expect(page.locator('form#email-code')).toBeVisible();
      await auditPage(page);
    }),
  );
});

test('account pages with the account header and the confirmation step', async ({ page, browser }) => {
  const tok = await token(await uxState(browser));
  const user = await detourUser(tok, 'a11y-acct');
  await signIn(page, user.email, user.password);
  for (const section of ['profile', 'email', 'password', 'linked', 'attributes']) {
    await page.goto(`${anvilUrl()}/ui/account/${section}`);
    await expect(page.locator('#account-identity')).toContainText(user.email);
    await expect(page.locator('#sign-out-submit')).toBeVisible();
    await auditPage(page);
  }

  // A destructive action asks first (07.1-21): the confirmation step.
  const secret = await beginTotp(page);
  await page.locator('#code').fill(totp(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#recovery-codes li')).toHaveCount(10);
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#recovery-codes-regenerate-submit').click();
  await expect(page.locator('form#form-confirm')).toBeVisible();
  await auditPage(page);
});

test('org chooser and the non-member page', async ({ page, browser }) => {
  const tok = await token(await uxState(browser));
  const tenant = await createOrgTenant(tok, 'a11y-org');
  try {
    const acme = await createOrg(tok, tenant.slug, { slug: 'acme', display_name: 'Acme Corp' });
    const beta = await createOrg(tok, tenant.slug, { slug: 'beta', display_name: 'Beta Labs' });
    await createOrg(tok, tenant.slug, { slug: 'gamma', display_name: 'Gamma Works' });
    const user = await detourUser(tok, 'a11y-org', tenant.slug);
    await addMember(tok, tenant.slug, acme.id, user.id);
    await addMember(tok, tenant.slug, beta.id, user.id);
    const client = await createOrgClient(tok, tenant.slug, `${fakeRpOrigin()}/a11y-org`, 'required');
    await withFakeRp(async () => {
      await page.goto(uxAuthorizeUrl(client, {}, tenant.issuer).url);
      await login(page, user.email, user.password);
      await expect(page.locator('form#select-organization-form')).toBeVisible();
      await auditPage(page);
      await page.locator('#organization-acme').check();
      await page.locator('#select-organization-form-submit').click();
      await atRp(page);

      await page.goto(uxAuthorizeUrl(client, { organization: 'gamma' }, tenant.issuer).url);
      await expect(page.locator('#org-not-member-email')).toHaveText(user.email);
      await auditPage(page);
    });
  } finally {
    await tenant.cleanup();
  }
});

test('upstream link confirmation page', async ({ page, browser }) => {
  const tok = await token(await uxState(browser));
  const tenant = randomSlug('a11y-link');
  await createTenant(tok, tenant, { auto_link: false });
  let stop: (() => Promise<void>) | undefined;
  try {
    const user = await detourUser(tok, 'a11y-link', tenant);
    const { mock } = await githubMockConnection(tok, tenant, 'github', [
      { sub: '8190001', id: 8190001, login: 'octo-a11y', name: 'Octo A11y', email: user.email },
    ]);
    stop = () => mock.stop();
    await page.goto(`${tenantIssuer(tenant)}/ui/login`);
    await page.locator('#upstream-github').click();
    await expect(page).toHaveURL((url) => url.origin === mock.url);
    await page.locator('#mock-continue').click();
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await auditPage(page);
  } finally {
    await stop?.();
    await deleteTenant(tok, tenant);
  }
});

/** axe on a console page in both schemes at 390px and desktop (the console has its own reflow checks). */
async function auditConsolePage(page: Page): Promise<void> {
  for (const scheme of SCHEMES) {
    await page.emulateMedia({ colorScheme: scheme });
    // The console's controls animate their colours (transition-*): audit the settled scheme, not a
    // colour halfway between light and dark.
    await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
    for (const vp of [
      { name: 'mobile', width: 390, height: 844 },
      { name: 'desktop', width: 1280, height: 800 },
    ]) {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await test.step(`console axe ${vp.name} ${scheme}`, async () => {
        await expectNoA11yViolations(page);
      });
    }
  }
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 1280, height: 800 });
}

test('changed console pages', async ({ page, browser }) => {
  const s = await uxState(browser);
  const tok = await token(s);
  const admin = { email: randomEmail('a11y-console'), password: randomPassword() };
  await createConsoleAdmin(tok, admin);
  const user = await detourUser(tok, 'a11y-console-user');
  await consoleSignIn(page, admin);
  const visits: Array<[string, () => Promise<void>]> = [
    ['t/default', () => expect(page.getByTestId('tenant-overview')).toBeVisible()],
    ['t/default/users', () => expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible()],
    [`t/default/users/${user.id}`, () => expect(page.getByRole('heading', { level: 1, name: user.email })).toBeVisible()],
    ['t/default/clients/new', () => expect(page.getByTestId('app-type-picker')).toBeVisible()],
    [`t/default/clients/${s.clients.web.client_id}`, () => expect(page.getByTestId('integration-card')).toBeVisible()],
    ['t/default/connections/new', () => expect(page.getByRole('heading', { level: 1, name: 'New connection' })).toBeVisible()],
    ['t/default/settings', () => expect(page.getByTestId('login-settings-form')).toBeVisible()],
    ['tenants/new', () => expect(page.getByTestId('tenant-form')).toBeVisible()],
  ];
  for (const [path, ready] of visits) {
    await page.goto(consoleUrl(path));
    await ready();
    await page.waitForLoadState('networkidle');
    await auditConsolePage(page);
  }
});
