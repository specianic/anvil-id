// AUTH-06 / UI-01: email sign-in works without JavaScript. The "Email me a sign-in code" disclosure
// is a native <details>, the code and magic link pages are plain forms.
//
// JavaScript is switched off in this file itself (test.use below): the nojs project of
// playwright.config.ts matches only `nojs.*.spec.ts` / `nojs.spec.ts`, which this name does not, so
// the file runs in the chromium project and must not rely on that project's settings.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import {
  adminToken,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import {
  codeFrom,
  createEmailSignInTenant,
  deleteTenant,
  expectSession,
  magicLinkFrom,
  requestEmailCode,
  signInEmail,
  submitEmailCode,
  type EmailSignInTenant,
} from '../lib/email-code';

test.use({ javaScriptEnabled: false });

let token: string;
let tenant: EmailSignInTenant;

test.beforeAll(async ({ browser }) => {
  token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createEmailSignInTenant(token, 'nojs-email');
});

test.afterAll(async () => {
  if (tenant) await deleteTenant(token, tenant.slug);
});

async function verifiedUser(prefix: string): Promise<string> {
  const email = randomEmail(prefix);
  await createUser(token, { email, password: randomPassword(), email_verified: true }, tenant.slug);
  return email;
}

test('JavaScript is off in this file', async ({ page }) => {
  await page.setContent('<p id="probe">off</p><script>document.getElementById("probe").textContent = "on";</script>');
  await expect(page.locator('#probe')).toHaveText('off');
});

test('sign in with the emailed code without JavaScript', async ({ page }) => {
  const email = await verifiedUser('nojs-otp');
  await page.goto(`${tenant.base}/ui/login`);
  await requestEmailCode(page, email);
  await submitEmailCode(page, codeFrom(await signInEmail(email)));
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expectSession(page, tenant);
});

test('sign in with the magic link without JavaScript', async ({ page }) => {
  const email = await verifiedUser('nojs-magic');
  await page.goto(`${tenant.base}/ui/login`);
  await requestEmailCode(page, email);
  await page.goto(magicLinkFrom(await signInEmail(email), tenant));
  await page.locator('#magic-link-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expectSession(page, tenant);
});
