// End-user detour journeys (07.1-18, U-H1, U-H2, U-H6, U-M10, U-M11), shared by
// specs/flow-detours.spec.ts (JavaScript on) and specs/nojs-flow-detours.spec.ts (JavaScript off).
//
// Every journey starts from an app's authorization URL (lib/ux-state.ts authorizeUrl, the cached
// first-party web client registered against the fake RP), takes one detour (create an account,
// forgot password, Start over, Use another way, ...) and must end at the fake RP with a code and the
// original state. Links on the intermediate pages are checked for the app's `request=` where they
// are visible, so a detour that drops the app context fails here before it strands the user on the
// "Signed in" page.
//
// The fake RP must be running (fakeRp() in the spec's beforeAll). Specs that change tenant settings
// use withTenantSettings (lib/admin.ts), which restores them afterwards.

import { expect, type Page } from '@playwright/test';
import { withTenantSettings } from './admin';
import { createUser, login, randomEmail, randomPassword, register } from './anvil';
import { extractLink, latestMessageTo } from './mailpit';
import { totp } from './totp';
import { atRp, authorizeUrl, type AuthorizeRequest, type UxClient, type UxUser } from './ux-state';

/** An authorization request that landed on the sign-in page. */
export interface Started {
  req: AuthorizeRequest;
  /** The `request=` id the sign-in page was opened with. */
  requestId: string;
}

/** Context every journey needs: an admin token and the client the journey signs in to. */
export interface DetourContext {
  token: string;
  client: UxClient;
}

/** A verified user with a password, created with an existing admin token (one API call). */
export async function detourUser(token: string, prefix: string, tenant = 'default'): Promise<UxUser> {
  const email = randomEmail(prefix);
  const password = randomPassword();
  const user = await createUser(token, { email, password, email_verified: true }, tenant);
  if (!user.id) throw new Error(`POST /tenants/${tenant}/users returned no id`);
  return { id: user.id, email, password };
}

/** Opens the client's authorization URL (no session) and waits for the sign-in page with `request=`. */
export async function startAtLogin(page: Page, client: UxClient, issuer?: string): Promise<Started> {
  const req = authorizeUrl(client, {}, issuer);
  await page.goto(req.url);
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/login') && url.searchParams.has('request'));
  await expect(page.locator('form#login')).toBeVisible();
  const requestId = new URL(page.url()).searchParams.get('request') ?? '';
  expect(requestId).not.toBe('');
  return { req, requestId };
}

/** Asserts the link `selector` is visible and carries the app's request id. */
export async function expectKeepsRequest(page: Page, selector: string, started: Started): Promise<void> {
  const link = page.locator(selector);
  await expect(link).toBeVisible();
  const href = (await link.getAttribute('href')) ?? '';
  expect(new URL(href, page.url()).searchParams.get('request'), `${selector} keeps request= (${href})`).toBe(
    started.requestId,
  );
}

/** Waits for the fake RP and asserts it received a code and the original state, no error. */
export async function expectCodeAtRp(page: Page, started: Started): Promise<void> {
  const params = await atRp(page);
  expect(params.get('error'), `RP got error ${params.get('error_description')}`).toBeNull();
  expect(params.get('code')).toBeTruthy();
  expect(params.get('state')).toBe(started.req.state);
}

/**
 * Clicks a "Continue to <app>" link that must go back into the request, then signs in when the
 * link leads to the sign-in page (signed out) instead of straight to the app (signed in).
 */
async function continueToApp(page: Page, started: Started, user: { email: string; password: string }): Promise<void> {
  await expectKeepsRequest(page, '#link-continue', started);
  await page.locator('#link-continue').click();
  const signIn = page.locator('form#login');
  const rp = page.locator('#rp-params');
  await expect(signIn.or(rp)).toBeVisible();
  if (await signIn.isVisible()) {
    expect(new URL(page.url()).searchParams.get('request')).toBe(started.requestId);
    await login(page, user.email, user.password);
  }
  await expectCodeAtRp(page, started);
}

/** A failed sign-in, then "Create an account" (request kept): registering lands at the app. */
export async function createAccountAfterFailedSignIn(page: Page, ctx: DetourContext): Promise<void> {
  const started = await startAtLogin(page, ctx.client);
  await login(page, randomEmail('detour-nobody'), randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await expectKeepsRequest(page, '#link-registration', started);
  await expectKeepsRequest(page, '#link-recovery', started);
  await page.locator('#link-registration').click();
  await expect(page.locator('form#registration')).toBeVisible();
  await expectKeepsRequest(page, '#link-login', started);

  const email = randomEmail('detour-reg');
  await register(page, email, randomPassword());
  await expectCodeAtRp(page, started);
  // The address gets its verification email, and its link still names the request.
  const link = extractLink((await latestMessageTo(email)).Text, '/ui/verification');
  expect(new URL(link).searchParams.get('request')).toBe(started.requestId);
}

/** "Create an account", a refused registration, then "Sign in" (request kept): lands at the app. */
export async function signInFromRegistrationError(page: Page, ctx: DetourContext): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-regerr');
  const started = await startAtLogin(page, ctx.client);
  await page.locator('#link-registration').click();
  await register(page, randomEmail('detour-short'), 'short');
  await expect(page).toHaveURL(/\/ui\/registration\?flow=/);
  await expect(page.locator('#password-msg-1')).toBeVisible();
  await expectKeepsRequest(page, '#link-login', started);
  await page.locator('#link-login').click();
  await expect(page.locator('form#login')).toBeVisible();
  await login(page, user.email, user.password);
  await expectCodeAtRp(page, started);
}

/**
 * A failed sign-in, "Forgot password", the emailed link (it carries the request), a new password,
 * then "Continue to <app>": lands at the app.
 */
export async function forgotPassword(page: Page, ctx: DetourContext): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-rec');
  const started = await startAtLogin(page, ctx.client);
  await login(page, user.email, randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await expectKeepsRequest(page, '#link-recovery', started);
  await page.locator('#link-recovery').click();
  await expect(page.locator('form#recovery')).toBeVisible();
  await expectKeepsRequest(page, '#link-login', started);
  await page.locator('#email').fill(user.email);
  await page.locator('#recovery-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.sent');
  await expectKeepsRequest(page, '#link-continue', started);

  const link = extractLink((await latestMessageTo(user.email)).Text, '/ui/recovery');
  expect(new URL(link).searchParams.get('request'), 'the emailed reset link carries the request').toBe(
    started.requestId,
  );
  await page.goto(link);
  await expect(page.locator('form#recovery-reset')).toBeVisible();
  const newPassword = randomPassword();
  await page.locator('#password').fill(newPassword);
  await page.locator('#recovery-reset-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.done');
  await continueToApp(page, started, { email: user.email, password: newPassword });
}

/**
 * Registration while the tenant requires a verified email: the check-email page names the address
 * and already offers the way back; the emailed verification link continues to the app.
 */
export async function registrationWithRequiredVerification(page: Page, ctx: DetourContext): Promise<void> {
  await withTenantSettings(ctx.token, { require_verified_email: true }, async () => {
    const started = await startAtLogin(page, ctx.client);
    await page.locator('#link-registration').click();
    await expect(page.locator('form#registration')).toBeVisible();
    const email = randomEmail('detour-verify');
    const password = randomPassword();
    await register(page, email, password);
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'registration.check_email');
    await expect(page.locator('#message-sent-to')).toContainText(email);
    await expectKeepsRequest(page, '#link-continue', started);

    const link = extractLink((await latestMessageTo(email)).Text, '/ui/verification');
    expect(new URL(link).searchParams.get('request'), 'the verification link carries the request').toBe(
      started.requestId,
    );
    await page.goto(link);
    await page.locator('#verification-submit').click();
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'verification.done');
    await continueToApp(page, started, { email, password });
  });
}

/** From the account security page of a signed-in browser: enrols an authenticator app. */
async function enrolTotpHere(page: Page, anvil: string): Promise<{ secret: string; step: number }> {
  await page.goto(`${anvil}/ui/account/security`);
  await page.locator('#totp-begin-submit').click();
  await expect(page.locator('#totp-secret')).toBeVisible();
  const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  const now = Date.now() / 1000;
  await page.locator('#code').fill(totp(secret, now));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'account.totp_enrolled');
  return { secret, step: Math.floor(now / 30) };
}

/**
 * A user with an authenticator app: password, then "Start over" on the second-factor page (request
 * kept), password again and the code: lands at the app.
 */
export async function secondFactorStartOver(page: Page, ctx: DetourContext, anvil: string): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-2fa');
  await page.goto(`${anvil}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  const { secret, step } = await enrolTotpHere(page, anvil);
  await page.context().clearCookies();

  const started = await startAtLogin(page, ctx.client);
  await login(page, user.email, user.password);
  await expect(page.locator('form#second-factor')).toBeVisible();
  await expectKeepsRequest(page, '#link-login', started);
  await page.locator('#link-login').click();
  await expect(page.locator('form#login')).toBeVisible();
  expect(new URL(page.url()).searchParams.get('request')).toBe(started.requestId);

  await login(page, user.email, user.password);
  await expect(page.locator('form#second-factor')).toBeVisible();
  // The enrolment used up its step; the next step's code is inside the one-step window.
  await page.locator('#code').fill(totp(secret, (step + 1) * 30));
  await page.locator('#second-factor-submit').click();
  await expectCodeAtRp(page, started);
}

/**
 * Required two-step verification without a factor: "Start over" on the enrolment page (request
 * kept), then enrolment, the reload-safe recovery codes page and its confirm: lands at the app.
 */
export async function mfaEnrolmentStartOver(page: Page, ctx: DetourContext): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-mfa');
  await withTenantSettings(ctx.token, { mfa_policy: 'required' }, async () => {
    const started = await startAtLogin(page, ctx.client);
    await login(page, user.email, user.password);
    await expect(page.locator('form#mfa-enroll')).toBeVisible();
    await expect(page.locator('#mfa-enroll-required')).toBeVisible();
    await expectKeepsRequest(page, '#link-login', started);
    await page.locator('#link-login').click();
    await expect(page.locator('form#login')).toBeVisible();
    expect(new URL(page.url()).searchParams.get('request')).toBe(started.requestId);

    await login(page, user.email, user.password);
    await expect(page.locator('form#mfa-enroll')).toBeVisible();
    const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
    await page.locator('#code').fill(totp(secret));
    await page.locator('#mfa-enroll-submit').click();
    await expect(page).toHaveURL(/\/ui\/login\/recovery-codes\?flow=/);
    const codes = await page.locator('#recovery-codes li').allTextContents();
    expect(codes).toHaveLength(10);
    // U-H7: a reload shows the same codes (no-store GET, not a POST answer).
    await page.reload();
    expect(await page.locator('#recovery-codes li').allTextContents()).toEqual(codes);
    await page.locator('#recovery-codes-confirm-submit').click();
    await expectCodeAtRp(page, started);
  });
}

/**
 * Email sign-in on: the sign-in page has one address field; "Email me a way to sign in", then "Use
 * another way" (request kept) and the password: lands at the app.
 */
export async function emailCodeUseAnotherWay(page: Page, ctx: DetourContext): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-email');
  await withTenantSettings(ctx.token, { email_otp: true }, async () => {
    const started = await startAtLogin(page, ctx.client);
    // U-M7: one address field for both ways of signing in.
    await expect(page.locator('form#login input[type=email]')).toHaveCount(1);
    await page.locator('#identifier').fill(user.email);
    await page.locator('#email-code-request-submit').click();
    await expect(page.locator('form#email-code')).toBeVisible();
    await expectKeepsRequest(page, '#link-login', started);
    await page.locator('#link-login').click();
    await expect(page.locator('form#login')).toBeVisible();
    expect(new URL(page.url()).searchParams.get('request')).toBe(started.requestId);
    await login(page, user.email, user.password);
    await expectCodeAtRp(page, started);
  });
}

/** A stale or unknown `request=` stops on GET: expired page, a way forward, no password field. */
export async function staleRequestStopsOnGet(page: Page, anvil: string): Promise<void> {
  const unknown = '0190a6d4-0000-7000-8000-00000000d00d';
  for (const path of ['/ui/login', '/ui/registration', '/ui/recovery']) {
    const resp = await page.goto(`${anvil}${path}?request=${unknown}`);
    expect(resp?.status(), path).toBe(400);
    await expect(page.locator('h1')).toHaveText('This sign-in link has expired');
    await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'flow_expired');
    await expect(page.locator('input[type=password]')).toHaveCount(0);
    await expect(page.locator('input[type=email]')).toHaveCount(0);
    expect(await page.content()).not.toContain(unknown);
    await expect(page.locator('#link-login')).toBeVisible();
  }
  await page.locator('#link-login').click();
  await expect(page.locator('form#login')).toBeVisible();
  expect(new URL(page.url()).searchParams.has('request')).toBe(false);
}

/** Signing in without an app: the "Signed in" page links the account and offers sign-out. */
export async function signedInPageWithoutClient(page: Page, ctx: DetourContext, anvil: string): Promise<void> {
  const user = await detourUser(ctx.token, 'detour-signedin');
  await page.goto(`${anvil}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await expect(page.locator('#link-account')).toBeVisible();
  await expect(page.locator('#form-sign-out button')).toBeVisible();
  // The default tenant is not the system tenant: no console link here.
  await expect(page.locator('#link-console')).toHaveCount(0);

  // The account link opens the account area of this session (checked in a second tab of the same
  // browser, so the signed-in page itself stays put for the sign-out below).
  const accountHref = await page.locator('#link-account').getAttribute('href');
  const tab = await page.context().newPage();
  try {
    await tab.goto(new URL(accountHref ?? '', page.url()).href);
    await expect(tab.locator('#account-identity')).toContainText(user.email);
  } finally {
    await tab.close();
  }

  await page.locator('#form-sign-out button').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/logout'));
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await expect(page.locator('#logout-message')).toHaveAttribute('data-message-key', 'logout.signed_out');
  await expect(page.locator('#link-login')).toBeVisible();
}
