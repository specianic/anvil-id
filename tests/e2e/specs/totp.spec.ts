// AUTH-05 in a browser: authenticator-app (TOTP) enrolment on /ui/account/security with the code
// computed from the displayed secret, password + TOTP sign-in through the sample relying party,
// replay rejection of a used code, single-use recovery codes with a notification email (Mailpit),
// and WCAG 2.2 AA checks on the enrolment, recovery-codes and second-factor pages.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
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
import { auditEvents, enrolTotp, signInDirect, startSampleRp, type SampleRp } from '../lib/account';
import { latestMessageTo } from '../lib/mailpit';
import { totp } from '../lib/totp';

let creds: ManagementCredential;
let rp: SampleRp;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  const token = await adminToken(creds);
  rp = await startSampleRp((redirectUri) =>
    createClient(token, {
      name: 'e2e TOTP sample RP',
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
    }),
  );
});

test.afterAll(async () => {
  await rp?.stop();
});

/** Signs out, starts at the RP and submits the right password; ends on the second-factor page. */
async function passwordStep(page: Page, email: string, password: string): Promise<void> {
  await page.context().clearCookies();
  await page.goto(`${rp.base}/login`);
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await login(page, email, password);
  await expect(page.locator('form#second-factor')).toBeVisible();
  await expect(page.locator('#factor_token')).toBeAttached();
}

async function submitCode(page: Page, code: string): Promise<void> {
  await page.locator('#code').fill(code);
  await page.locator('#second-factor-submit').click();
}

async function submitRecoveryCode(page: Page, code: string): Promise<void> {
  await page.locator('#recovery-code-toggle summary').click();
  await page.locator('#recovery_code').fill(code);
  await page.locator('#second-factor-submit').click();
}

async function expectSignedIn(page: Page, email: string): Promise<void> {
  await expect(page).toHaveURL(`${rp.base}/me`);
  await expect(page.locator('#email')).toHaveText(email);
}

async function expectSecondFactorRejected(page: Page): Promise<void> {
  await expect(page.locator('[data-message-key="login.second_factor_invalid"]')).toBeVisible();
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
}

test('TOTP enrolment, sign-in, replay rejection and single-use recovery codes', async ({ page }) => {
  // The last step may wait up to one 30-second TOTP step.
  test.setTimeout(120_000);
  const email = randomEmail('totp');
  const password = randomPassword();
  const user = await createUser(await adminToken(creds), { email, password, email_verified: true });

  // Enrol from the account security page; the code is computed from the displayed secret.
  await signInDirect(page, email, password);
  const enrolment = await enrolTotp(page, async () => {
    await expectNoA11yViolations(page);
  });
  await page.locator('#link-account-security').click();
  await expect(page.locator('#recovery-codes-count')).toHaveText('10');

  // The code that confirmed the enrolment cannot be used to sign in (its step is used up).
  const enrolmentCode = totp(enrolment.secret, enrolment.step * 30);
  await passwordStep(page, email, password);
  await expectNoA11yViolations(page);
  // The password alone does not sign in: no RP profile, no session.
  await expect(page).toHaveURL((url) => url.href.startsWith(anvilUrl()));
  await submitCode(page, enrolmentCode);
  await expectSecondFactorRejected(page);
  await expectNoA11yViolations(page);

  // Password + the code of the next time step (accepted within the one-step window).
  const code = totp(enrolment.secret, (enrolment.step + 1) * 30);
  await passwordStep(page, email, password);
  await submitCode(page, code);
  await expectSignedIn(page, email);

  // The same code again, still inside its time window: rejected as a replay.
  await passwordStep(page, email, password);
  await submitCode(page, code);
  await expectSecondFactorRejected(page);

  // A recovery code signs in once...
  const recoveryCode = enrolment.recoveryCodes[0];
  await passwordStep(page, email, password);
  await submitRecoveryCode(page, recoveryCode);
  await expectSignedIn(page, email);

  // ...and is rejected the second time.
  await passwordStep(page, email, password);
  await submitRecoveryCode(page, recoveryCode);
  await expectSecondFactorRejected(page);

  // The use was audited and the user was notified by email.
  const events = await auditEvents(await adminToken(creds), {
    action: 'recovery_code_used',
    target: user.id ?? '',
  });
  expect(events).toHaveLength(1);
  expect(events[0].details).toMatchObject({ remaining: 9 });

  const notice = await latestMessageTo(email, { timeoutMs: 30_000 });
  expect(notice.Subject).toMatch(/recovery code was used/i);
  expect(notice.Text).toContain('9');

  // The account page counts the remaining codes.
  await signInDirectWithTotp(page, email, password, enrolment.secret, enrolment.step + 2);
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await expect(page.locator('#recovery-codes-count')).toHaveText('9');
});

/**
 * Signs in on the hosted login page (no authorization request) with password + the TOTP code of
 * `step`, waiting for that step to be within the server's one-step window.
 */
async function signInDirectWithTotp(
  page: Page,
  email: string,
  password: string,
  secret: string,
  step: number,
): Promise<void> {
  const waitMs = (step - 1) * 30_000 - Date.now();
  if (waitMs > 0) await page.waitForTimeout(waitMs + 250);
  await page.context().clearCookies();
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, email, password);
  await submitCode(page, totp(secret, step * 30));
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
}
