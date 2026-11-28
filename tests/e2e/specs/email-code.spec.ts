// AUTH-06: passwordless sign-in by email in a real browser, over real SMTP (Mailpit).
//
// - At a relying party: "Email me a sign-in code", the code from the email, back at the client
//   with an ID token whose amr is [otp].
// - The magic link opened in the same browser: "Continue signing in" signs in.
// - The email says the link works only in the browser where the sign-in started and that the code
//   works anywhere (07.1-14, U-M8).
// - The magic link opened in another browser (a second context, without the flow cookie): the page
//   says so on opening, before any button (open it in the browser where you started, or type the
//   code there, or start again here), that context is not signed in, and nothing was used up (the
//   original browser still signs in with the code).
// - An unknown address and an unverified one get exactly the same confirmation and no email.
// - The sign-in page with the email form, the "Check your email" page and the magic link page
//   pass axe.
//
// The specs run in a tenant of their own with email_otp and magic_link on (lib/email-code.ts).
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  createClient,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { signInForIdToken, type CodeClient } from '../lib/account';
import {
  codeFrom,
  createEmailSignInTenant,
  deleteTenant,
  expectNoMailTo,
  expectNoSession,
  expectSession,
  magicLinkFrom,
  requestEmailCode,
  signInEmail,
  submitEmailCode,
  type EmailSignInTenant,
} from '../lib/email-code';

let token: string;
let tenant: EmailSignInTenant;

test.beforeAll(async ({ browser }) => {
  token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createEmailSignInTenant(token);
});

test.afterAll(async () => {
  if (tenant) await deleteTenant(token, tenant.slug);
});

/** A verified user of the email sign-in tenant (with a password they never use here). */
async function verifiedUser(prefix: string): Promise<{ id: string; email: string }> {
  const email = randomEmail(prefix);
  const user = await createUser(
    token,
    { email, password: randomPassword(), email_verified: true },
    tenant.slug,
  );
  expect(user.id).toBeTruthy();
  return { id: user.id ?? '', email };
}

test('relying party sign-in with an emailed one-time code (amr otp)', async ({ page }) => {
  const user = await verifiedUser('otp');
  const redirectUri = 'http://localhost:9/e2e-email-code/callback';
  const created = await createClient(
    token,
    {
      name: 'e2e email code client',
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scopes: ['openid', 'email'],
    },
    tenant.slug,
  );
  const client: CodeClient = {
    client_id: created.client_id,
    client_secret: created.client_secret ?? '',
    redirect_uri: redirectUri,
  };

  const claims = await signInForIdToken(
    page,
    client,
    async (p) => {
      await expect(p.locator('form#login')).toBeVisible();
      await requestEmailCode(p, user.email, () => expectNoA11yViolations(p));
      // "Check your email" page.
      await expect(p.locator('#code')).toHaveAttribute('autocomplete', 'one-time-code');
      await expect(p.locator('#code')).toHaveAttribute('inputmode', 'numeric');
      await expectNoA11yViolations(p);

      const message = await signInEmail(user.email);
      expect(message.Subject).toMatch(/sign-in code/i);
      await submitEmailCode(p, codeFrom(message));
    },
    tenant.base,
  );
  expect(claims.sub).toBe(user.id);
  expect(claims.amr).toEqual(expect.arrayContaining(['otp']));
  expect(claims.amr).not.toEqual(expect.arrayContaining(['pwd']));
});

test('a wrong code is refused, then the right one signs in', async ({ page }) => {
  const user = await verifiedUser('otp-wrong');
  await page.goto(`${tenant.base}/ui/login`);
  await requestEmailCode(page, user.email);
  const code = codeFrom(await signInEmail(user.email));

  const wrong = code === '000000' ? '111111' : '000000';
  await submitEmailCode(page, wrong);
  await expect(page.locator('form#email-code [data-message-key="email_code.invalid"]')).toBeVisible();
  await expect(page.locator('#code')).toHaveAttribute('aria-invalid', 'true');
  await expectNoA11yViolations(page);

  await submitEmailCode(page, code);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expectSession(page, tenant);
});

test('magic link opened in the same browser signs in after "Continue signing in"', async ({
  page,
}) => {
  const user = await verifiedUser('magic');
  await page.goto(`${tenant.base}/ui/login`);
  await requestEmailCode(page, user.email);
  const link = magicLinkFrom(await signInEmail(user.email), tenant);

  // Opening the link only shows a button; nothing is used yet.
  const res = await page.goto(link);
  expect(res?.headers()['cache-control']).toContain('no-store');
  expect(res?.headers()['referrer-policy']).toBe('no-referrer');
  await expect(page.locator('form#magic-link')).toBeVisible();
  await expect(page.locator('#magic-link-submit')).toHaveText('Continue signing in');
  await expectNoA11yViolations(page);

  await page.locator('#magic-link-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expectSession(page, tenant);
});

test('magic link opened in another browser does not sign that browser in', async ({
  page,
  browser,
}) => {
  const user = await verifiedUser('magic-other');
  await page.goto(`${tenant.base}/ui/login`);
  await requestEmailCode(page, user.email);
  const message = await signInEmail(user.email);
  const link = magicLinkFrom(message, tenant);

  // The email says where the link works, and that the code works on any device.
  expect(message.Text).toContain('The link works only in the browser where you started signing in.');
  expect(message.Text).toContain('The code works whichever device you read this email on');

  const other = await browser.newContext();
  try {
    const otherPage = await other.newPage();
    // A typed or pasted address would carry the flow cookie in the right browser: the page
    // explains on opening, with no button that could only fail.
    await otherPage.goto(link);
    const notice = otherPage.locator('#magic-link-other-browser');
    await expect(notice).toContainText('cannot sign you in here');
    await expect(otherPage.locator('#magic-link-code-hint')).toContainText('type the code');
    await expect(otherPage.locator('form#magic-link')).toHaveCount(0);
    await expect(otherPage.locator('#link-login')).toHaveText('Start signing in again here');
    await expectNoA11yViolations(otherPage);
    await expectNoSession(otherPage, tenant);
    // Start again leads to this tenant's sign-in page.
    await otherPage.locator('#link-login').click();
    await expect(otherPage.locator('form#login')).toBeVisible();
  } finally {
    await other.close();
  }

  // Nothing was used up: the browser where the sign-in started finishes with the code.
  await submitEmailCode(page, codeFrom(message));
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expectSession(page, tenant);
});

test('unknown and unverified addresses get the same confirmation and no email', async ({
  page,
}) => {
  const known = await verifiedUser('known');
  await page.goto(`${tenant.base}/ui/login`);
  const knownText = await requestEmailCode(page, known.email);
  await signInEmail(known.email);

  const unknown = randomEmail('nobody');
  await page.context().clearCookies();
  await page.goto(`${tenant.base}/ui/login`);
  const unknownText = await requestEmailCode(page, unknown);
  expect(unknownText).toBe(knownText);
  // The page offers the code form exactly as for a real account.
  await expect(page.locator('#code')).toBeVisible();

  const unverified = randomEmail('unverified');
  await createUser(
    token,
    { email: unverified, password: randomPassword(), email_verified: false },
    tenant.slug,
  );
  await page.context().clearCookies();
  await page.goto(`${tenant.base}/ui/login`);
  const unverifiedText = await requestEmailCode(page, unverified);
  expect(unverifiedText).toBe(knownText);

  await expectNoMailTo(unknown);
  await expectNoMailTo(unverified);
});
