// The end-user detours that need no JavaScript, with JavaScript disabled (07.1-18; UI-01 with
// U-H1, U-H2, U-H6, U-M10): password (create an account after a failed sign-in, forgot password),
// registration (sign in from a registration error, required verification), email code "Use another
// way" and second factor (TOTP) Start over each end at the fake RP with a code and the original
// state. Also: a stale request= stops on GET, and the Signed in page offers account and sign-out.
//
// Journeys: lib/detours.ts (shared with flow-detours.spec.ts).
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { anvilUrl } from '../lib/anvil';
import {
  createAccountAfterFailedSignIn,
  emailCodeUseAnotherWay,
  forgotPassword,
  registrationWithRequiredVerification,
  secondFactorStartOver,
  signedInPageWithoutClient,
  signInFromRegistrationError,
  staleRequestStopsOnGet,
  type DetourContext,
} from '../lib/detours';
import { fakeRp, token, uxState, type FakeRp } from '../lib/ux-state';

let rp: FakeRp | undefined;
let ctx: DetourContext;

test.beforeAll(async ({ browser }) => {
  rp = await fakeRp();
  const s = await uxState(browser);
  ctx = { token: await token(s), client: s.clients.web };
});

test.afterAll(async () => {
  await rp?.close();
});

test.use({ javaScriptEnabled: false });

test.beforeEach(async ({ page }) => {
  // Guard: scripts really do not run (webauthn.js would reveal the passkey button).
  await page.goto(`${anvilUrl()}/ui/login`);
  await expect(page.locator('form#login')).toBeVisible();
  await expect(page.locator('#login-passkey-submit')).toBeHidden();
});

test('no JS: create an account after a failed sign-in returns to the app', async ({ page }) => {
  await createAccountAfterFailedSignIn(page, ctx);
});

test('no JS: sign in from a registration error returns to the app', async ({ page }) => {
  await signInFromRegistrationError(page, ctx);
});

test('no JS: forgot password continues to the app', async ({ page }) => {
  await forgotPassword(page, ctx);
});

test('no JS: registration with required verification continues to the app', async ({ page }) => {
  await registrationWithRequiredVerification(page, ctx);
});

test('no JS: second factor Start over returns to the app', async ({ page }) => {
  await secondFactorStartOver(page, ctx, anvilUrl());
});

test('no JS: email code "Use another way" returns to the app', async ({ page }) => {
  await emailCodeUseAnotherWay(page, ctx);
});

test('no JS: a stale request= stops on GET', async ({ page }) => {
  await staleRequestStopsOnGet(page, anvilUrl());
});

test('no JS: the Signed in page links the account and signs out', async ({ page }) => {
  await signedInPageWithoutClient(page, ctx, anvilUrl());
});
