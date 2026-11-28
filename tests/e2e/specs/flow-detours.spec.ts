// Every end-user detour returns to the app (07.1-18; U-H1, U-H2, U-H6, U-M10, U-M11, U-H7, U-M7).
//
// Each test starts from an app's authorization URL (the cached first-party web client of
// lib/ux-state.ts, registered against the fake RP) and must end at the fake RP with a code and the
// original state, after one detour:
//   - create an account after a failed sign-in
//   - sign in from a registration error
//   - forgot password (the emailed link carries the request; reset; Continue to <app>)
//   - registration with required verification (the check-email page names the address; the
//     verification link continues to the app)
//   - second factor Start over
//   - MFA enrolment Start over (and the reload-safe recovery codes page)
//   - email code "Use another way"
//   - upstream link confirmation: Cancel after a wrong password
// plus: a stale or unknown `?request=` fails on GET with a way forward and no password field, the
// "Signed in" page (no app) links the account and offers sign-out, the consent step names the
// account and explains offline access (U-M15, U-L4), and a link confirmed during sign-in shows
// when it was last used (U-L7).
//
// The journeys live in lib/detours.ts; nojs-flow-detours.spec.ts runs the ones that need no
// JavaScript with JavaScript disabled.
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { anvilUrl, createClient, login } from '../lib/anvil';
import {
  createAccountAfterFailedSignIn,
  detourUser,
  emailCodeUseAnotherWay,
  expectCodeAtRp,
  expectKeepsRequest,
  forgotPassword,
  mfaEnrolmentStartOver,
  registrationWithRequiredVerification,
  secondFactorStartOver,
  signedInPageWithoutClient,
  signInFromRegistrationError,
  staleRequestStopsOnGet,
  startAtLogin,
  type DetourContext,
} from '../lib/detours';
import { deleteTenant } from '../lib/email-code';
import { expectWayForward } from '../lib/layout';
import { createTenant, githubMockConnection, randomSlug, tenantIssuer } from '../lib/upstream';
import { atRp, authorizeUrl, fakeRp, fakeRpOrigin, token, uxState, type FakeRp } from '../lib/ux-state';

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

test('create an account after a failed sign-in returns to the app', async ({ page }) => {
  await createAccountAfterFailedSignIn(page, ctx);
});

test('sign in from a registration error returns to the app', async ({ page }) => {
  await signInFromRegistrationError(page, ctx);
});

test('forgot password: the emailed link keeps the request and continues to the app', async ({ page }) => {
  await forgotPassword(page, ctx);
});

test('registration with required verification names the address and the link continues to the app', async ({
  page,
}) => {
  await registrationWithRequiredVerification(page, ctx);
});

test('second factor Start over keeps the request and returns to the app', async ({ page }) => {
  await secondFactorStartOver(page, ctx, anvilUrl());
});

test('MFA enrolment Start over keeps the request; the recovery codes page continues to the app', async ({
  page,
}) => {
  await mfaEnrolmentStartOver(page, ctx);
});

test('email code "Use another way" keeps the request and returns to the app', async ({ page }) => {
  await emailCodeUseAnotherWay(page, ctx);
});

test('upstream link: Cancel after a wrong password keeps the request and returns to the app', async ({
  page,
}) => {
  test.setTimeout(120_000);
  const tenant = randomSlug('detour-link');
  await createTenant(ctx.token, tenant, { auto_link: false });
  const mocks: Array<{ stop(): Promise<void> }> = [];
  try {
    const user = await detourUser(ctx.token, 'detour-link', tenant);
    const { mock } = await githubMockConnection(ctx.token, tenant, 'github', [
      { sub: '8180001', id: 8180001, login: 'octo-detour', name: 'Octo Detour', email: user.email },
    ]);
    mocks.push(mock);
    const created = await createClient(
      ctx.token,
      {
        name: 'Detour link app',
        client_type: 'public',
        application_type: 'web',
        auth_method: 'none',
        redirect_uris: [`${fakeRpOrigin()}/link-callback`],
        grant_types: ['authorization_code'],
        scopes: ['openid', 'profile', 'email'],
      },
      tenant,
      'skip_first_party',
    );
    const client = { client_id: created.client_id, redirect_uri: `${fakeRpOrigin()}/link-callback` };

    const started = await startAtLogin(page, client, tenantIssuer(tenant));
    await page.locator('#upstream-github').click();
    await expect(page).toHaveURL((url) => url.origin === mock.url);
    await page.locator('#mock-continue').click();
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await expectKeepsRequest(page, '#link-cancel', started);

    await page.locator('#identifier').fill(user.email);
    await page.locator('#password').fill(`${user.password}-wrong`);
    await page.locator('#upstream-link-submit').click();
    await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
    await expectKeepsRequest(page, '#link-cancel', started);

    await page.locator('#link-cancel').click();
    await expect(page.locator('form#login')).toBeVisible();
    expect(new URL(page.url()).searchParams.get('request')).toBe(started.requestId);
    await login(page, user.email, user.password);
    await expectCodeAtRp(page, started);
  } finally {
    for (const m of mocks) await m.stop();
    await deleteTenant(ctx.token, tenant);
  }
});

test('a stale or unknown request= stops on GET with a way forward and no password field', async ({ page }) => {
  await staleRequestStopsOnGet(page, anvilUrl());
});

test('the Signed in page without an app links the account and signs out', async ({ page }) => {
  await signedInPageWithoutClient(page, ctx, anvilUrl());
});

test('consent names the account and says what offline access means; Allow returns to the app', async ({
  page,
  browser,
}) => {
  // U-M15 and U-L4 on the journey: the consent step in the middle of an app sign-in.
  const s = await uxState(browser);
  const user = await detourUser(ctx.token, 'detour-consent');
  const req = authorizeUrl(s.clients.thirdParty, { scope: 'openid email offline_access', prompt: 'consent' });
  await page.goto(req.url);
  await login(page, user.email, user.password);
  await expect(page.locator('form#consent-form')).toBeVisible();
  await expect(page.locator('#consent-account-email')).toHaveText(user.email);
  await expect(page.locator('#consent-other')).toBeVisible();
  await expect(page.locator('[data-scope="offline_access"]')).toContainText('Stay signed in to UX journeys third-party app');
  await expect(page.locator('#consent-offline-note')).toBeVisible();
  await page.locator('#consent-allow').click();
  const params = await atRp(page);
  expect(params.get('code')).toBeTruthy();
  expect(params.get('state')).toBe(req.state);
});

test('upstream link confirmed with the password returns to the app; Linked shows when it was last used', async ({
  page,
}) => {
  // U-L7: a link created by a sign-in is "used" at that moment (not "Never").
  test.setTimeout(120_000);
  const tenant = randomSlug('detour-lastused');
  await createTenant(ctx.token, tenant, { auto_link: false });
  const mocks: Array<{ stop(): Promise<void> }> = [];
  try {
    const user = await detourUser(ctx.token, 'detour-lastused', tenant);
    const { mock } = await githubMockConnection(ctx.token, tenant, 'github', [
      { sub: '8180002', id: 8180002, login: 'octo-lastused', name: 'Octo Used', email: user.email },
    ]);
    mocks.push(mock);
    const created = await createClient(
      ctx.token,
      {
        name: 'Detour last used app',
        client_type: 'public',
        application_type: 'web',
        auth_method: 'none',
        redirect_uris: [`${fakeRpOrigin()}/lastused-callback`],
        grant_types: ['authorization_code'],
        scopes: ['openid', 'profile', 'email'],
      },
      tenant,
      'skip_first_party',
    );
    const client = { client_id: created.client_id, redirect_uri: `${fakeRpOrigin()}/lastused-callback` };
    const started = await startAtLogin(page, client, tenantIssuer(tenant));
    await page.locator('#upstream-github').click();
    await expect(page).toHaveURL((url) => url.origin === mock.url);
    await page.locator('#mock-continue').click();
    await expect(page.locator('form#upstream-link')).toBeVisible();
    await page.locator('#identifier').fill(user.email);
    await page.locator('#password').fill(user.password);
    await page.locator('#upstream-link-submit').click();
    await expectCodeAtRp(page, started);

    await page.goto(`${tenantIssuer(tenant)}/ui/account/linked`);
    const row = page.locator('tr[id^="linked-"]').first();
    await expect(row).toBeVisible();
    // Columns: provider, email, linked, last used, action.
    const lastUsed = row.locator('td').nth(3);
    await expect(lastUsed.locator('time')).toHaveAttribute('datetime', /\d{4}-\d{2}-\d{2}T/);
    await expect(lastUsed).not.toHaveText('Never');
  } finally {
    for (const m of mocks) await m.stop();
    await deleteTenant(ctx.token, tenant);
  }
});

test('consent, account chooser and org chooser opened without a request offer a way forward', async ({ page }) => {
  // U-H5: these pages used to be dead ends when opened without (or after) their request.
  for (const path of ['/ui/consent', '/ui/select-account', '/ui/select-organization']) {
    const resp = await page.goto(`${anvilUrl()}${path}`);
    expect(resp?.status() ?? 0, path).toBeGreaterThanOrEqual(400);
    await expect(page.locator('#error-message')).toBeVisible();
    await expectWayForward(page);
  }
});
