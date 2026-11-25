// UI-02: every Phase 2 hosted page passes the axe WCAG 2.2 A/AA rules at a mobile and a desktop
// viewport, in the light and the dark colour scheme, and reflows without horizontal scrolling at
// 320 CSS px (WCAG 1.4.10).
//
// Pages: setup + setup done (only while the instance is not yet installed, i.e. when this spec runs
// first in a fresh run.sh instance), login (clean and with an error), registration (clean and with
// field errors), the registration "check your email" message, verification (via the Mailpit link),
// recovery request, the recovery "sent" message, recovery reset (via the Mailpit link) and error
// pages (unknown client, invalid setup token).
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  completeSetup,
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

  await page.goto(`${anvilUrl()}/setup?token=a11y-bogus`);
  await expect(page.locator('#error-message')).toBeVisible();
  await auditPage(page);
});
