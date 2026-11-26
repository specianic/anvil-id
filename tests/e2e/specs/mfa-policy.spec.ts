// AUTH-08 / OIDC-14 in a browser: the admin MFA policy and acr_values step-up.
//
// - Tenant policy `required`: a user without a second factor is sent to authenticator-app
//   enrolment right after the password, enrols (code computed from the displayed secret), gets
//   recovery codes and reaches the RP; the next sign-in asks for the second factor.
// - Tenant policy `off`: a user with TOTP signs in with the password alone (amr [pwd]); the same
//   browser session is then stepped up by acr_values=urn:anvilid:acr:mfa: only the second-factor
//   page (no password field), and the ID token has acr mfa with otp + mfa in amr, on the same
//   session.
// - Client override: tenant `optional`, one client `required`: only that client forces enrolment.
// - Tenant policy `required`, passkey choice: a fresh user picks "Add a passkey" on the enrolment
//   page, the CDP virtual authenticator (fixtures/webauthn.ts) registers it, and the RP's ID token
//   has acr mfa and mfa in amr; the next sign-in uses that passkey (usernameless, from the sign-in
//   page), which satisfies `required` on its own.
//
// The tenant policy is shared by every spec of the run (one worker, one instance), so each test
// sets it through withTenantSettings, which restores the previous value even on failure. ID token
// claims are read through a dedicated code client (the sample RP does not show its ID token).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { addVirtualAuthenticator, removeVirtualAuthenticator } from '../fixtures/webauthn';
import {
  adminToken,
  anvilUrl,
  createClient,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import {
  enrolTotp,
  freePort,
  signInDirect,
  signInForIdToken,
  startSampleRp,
  type CodeClient,
  type SampleRp,
} from '../lib/account';
import { userSessions, withTenantSettings } from '../lib/admin';
import { addAuthorizeParams } from '../lib/authorize';
import { totp } from '../lib/totp';

const ACR_MFA = 'urn:anvilid:acr:mfa';
const ACR_PWD = 'urn:anvilid:acr:pwd';

let creds: ManagementCredential;
/** Client without its own policy (follows the tenant). */
let rp: SampleRp;
/** Client with mfa_policy `required`. */
let strictRp: SampleRp;
let codeClient: CodeClient;

function rpClient(name: string, extra: Record<string, unknown> = {}) {
  return async (redirectUri: string) =>
    createClient(await adminToken(creds), {
      name,
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
      ...extra,
    });
}

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  rp = await startSampleRp(rpClient('e2e MFA policy sample RP'));
  strictRp = await startSampleRp(rpClient('e2e MFA required sample RP', { mfa_policy: 'required' }));
  const redirectUri = `http://localhost:${await freePort()}/cb`;
  const client = await createClient(await adminToken(creds), {
    name: 'e2e MFA policy id-token client',
    client_type: 'confidential',
    application_type: 'web',
    auth_method: 'client_secret_basic',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code'],
    scopes: ['openid', 'email'],
  });
  codeClient = { client_id: client.client_id, client_secret: client.client_secret ?? '', redirect_uri: redirectUri };
});

test.afterAll(async () => {
  await rp?.stop();
  await strictRp?.stop();
});

async function newUser(prefix: string): Promise<{ id: string; email: string; password: string }> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  const user = await createUser(await adminToken(creds), { email, password, email_verified: true });
  if (!user.id) throw new Error('created user has no id');
  return { id: user.id, email, password };
}

/** Fresh browser state, RP login, password; ends wherever the policy sends the user. */
async function passwordAtRp(page: Page, base: string, email: string, password: string): Promise<void> {
  await page.context().clearCookies();
  await page.goto(`${base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await login(page, email, password);
}

async function expectAtRp(page: Page, base: string, email: string): Promise<void> {
  await expect(page).toHaveURL(`${base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
}

async function expectEnrolmentPage(page: Page): Promise<void> {
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await expect(page.locator('form#mfa-enroll')).toBeVisible();
  await expect(page.locator('#mfa-enroll-required')).toBeVisible();
  await expect(page.locator('#totp-secret')).toBeVisible();
}

async function submitSecondFactor(page: Page, code: string): Promise<void> {
  await page.locator('#code').fill(code);
  await page.locator('#second-factor-submit').click();
}

test('policy required: enrolment during sign-in, then the second factor on the next sign-in', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const token = await adminToken(creds);
  const user = await newUser('mfa-required');

  await withTenantSettings(token, { mfa_policy: 'required' }, async () => {
    await passwordAtRp(page, rp.base, user.email, user.password);

    // The password alone does not reach the RP: the enrolment page, axe-clean.
    await expectEnrolmentPage(page);
    await expectNoA11yViolations(page);
    const shown = async () =>
      ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
    expect(await shown()).toMatch(/^[A-Z2-7]+$/);

    // A wrong code is refused on the enrolment page.
    const wrong = totp(await shown()) === '000000' ? '111111' : '000000';
    await page.locator('#code').fill(wrong);
    await page.locator('#mfa-enroll-submit').click();
    await expectEnrolmentPage(page);
    await expect(page.locator('[id^="mfa-enroll-msg-"]').first()).toBeVisible();

    // The secret on the page now (read again in case the refusal re-rendered it).
    const secret = await shown();
    const now = Date.now() / 1000;
    const step = Math.floor(now / 30);
    await page.locator('#code').fill(totp(secret, now));
    await page.locator('#mfa-enroll-submit').click();

    // Recovery codes, shown once, then on to the RP.
    await expect(page.locator('#recovery-codes li')).toHaveCount(10);
    await expectNoA11yViolations(page);
    await page.locator('#link-continue').click();
    await expectAtRp(page, rp.base, user.email);

    // The next sign-in asks for the enrolled factor (code of the next step: the enrolment step is
    // used up).
    await passwordAtRp(page, rp.base, user.email, user.password);
    await expect(page.locator('form#second-factor')).toBeVisible();
    await submitSecondFactor(page, totp(secret, (step + 1) * 30));
    await expectAtRp(page, rp.base, user.email);
  });
});

test('policy off skips the second factor; acr_values step-up asks only for it', async ({ page }) => {
  test.setTimeout(90_000);
  const token = await adminToken(creds);
  const user = await newUser('mfa-off');

  // Enrol TOTP on the account page (tenant policy as left by the run: optional by default).
  await signInDirect(page, user.email, user.password);
  const enrolment = await enrolTotp(page);

  await withTenantSettings(token, { mfa_policy: 'off' }, async () => {
    // Password only, although the user has TOTP: amr [pwd], acr pwd.
    await page.context().clearCookies();
    const first = await signInForIdToken(page, codeClient, async (p) => {
      await login(p, user.email, user.password);
    });
    expect(first.sub).toBe(user.id);
    expect(first.acr).toBe(ACR_PWD);
    expect(first.amr).toEqual(['pwd']);
    // The enrolment browser's session is still active too (clearing cookies does not end it), so
    // the sign-in session is found by the ID token's sid.
    const before = await userSessions(token, user.id);
    expect(before.map((s) => s.id)).toContain(first.sid);

    // Step-up in the same browser: acr_values=mfa -> only the second-factor page.
    const stop = await addAuthorizeParams(page, { acr_values: ACR_MFA });
    try {
      const stepped = await signInForIdToken(page, codeClient, async (p) => {
        await expect(p.locator('form#second-factor')).toBeVisible();
        await expect(p.locator('#password')).toHaveCount(0);
        await expect(p.locator('#identifier')).toHaveCount(0);
        await submitSecondFactor(p, totp(enrolment.secret, (enrolment.step + 1) * 30));
      });
      expect(stepped.sub).toBe(user.id);
      expect(stepped.acr).toBe(ACR_MFA);
      expect(stepped.amr).toEqual(expect.arrayContaining(['otp', 'mfa']));
      expect(stepped.sid).toBe(first.sid);
    } finally {
      await stop();
    }

    // Upgraded in place: no new session, and the signed-in session now records the second factor.
    const after = await userSessions(token, user.id);
    expect(after.map((s) => s.id).sort()).toEqual(before.map((s) => s.id).sort());
    const upgraded = after.find((s) => s.id === first.sid);
    expect(upgraded?.acr).toBe(ACR_MFA);
    expect(upgraded?.amr).toEqual(expect.arrayContaining(['otp', 'mfa']));
  });
});

test('a client override to required applies only to that client', async ({ page }) => {
  const token = await adminToken(creds);
  const user = await newUser('mfa-client');

  await withTenantSettings(token, { mfa_policy: 'optional' }, async () => {
    // The client without its own policy follows the tenant: no factor, no prompt.
    await passwordAtRp(page, rp.base, user.email, user.password);
    await expectAtRp(page, rp.base, user.email);

    // The client with mfa_policy required forces enrolment for the same user.
    await passwordAtRp(page, strictRp.base, user.email, user.password);
    await expectEnrolmentPage(page);
  });
});

test('policy required: a passkey chosen at enrolment signs in with mfa, then signs in again', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const token = await adminToken(creds);
  const user = await newUser('mfa-passkey');
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await withTenantSettings(token, { mfa_policy: 'required' }, async () => {
      await page.context().clearCookies();
      const enrolled = await signInForIdToken(page, codeClient, async (p) => {
        await login(p, user.email, user.password);
        // The enrolment page offers both choices; the passkey button appears once webauthn.js
        // finds WebAuthn support.
        await expectEnrolmentPage(p);
        await expect(p.locator('#mfa-enroll-passkey')).toBeVisible();
        await expectNoA11yViolations(p);
        const button = p.locator('#mfa-enroll-passkey-submit');
        await expect(button).toBeVisible();
        await button.click();
      });
      expect(enrolled.sub).toBe(user.id);
      expect(enrolled.acr).toBe(ACR_MFA);
      const amr = enrolled.amr as string[];
      expect(amr).toEqual(expect.arrayContaining(['user', 'mfa']));
      expect(amr.some((m) => m === 'hwk' || m === 'swk')).toBe(true);
      expect(amr).not.toContain('otp');

      const stored = await authenticator.getCredentials();
      expect(stored).toHaveLength(1);
      expect(stored[0].isResidentCredential).toBe(true);
      expect(stored[0].rpId).toBe(new URL(anvilUrl()).hostname);

      // Next sign-in: the enrolled passkey alone satisfies `required` (no password, no enrolment).
      await page.context().clearCookies();
      const again = await signInForIdToken(page, codeClient, async (p) => {
        const passkey = p.locator('#login-passkey-submit');
        await expect(passkey).toBeVisible();
        await passkey.click();
      });
      expect(again.sub).toBe(user.id);
      expect(again.acr).toBe(ACR_MFA);
      expect(again.amr).toEqual(expect.arrayContaining(['mfa']));
    });
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});
