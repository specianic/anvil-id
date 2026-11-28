// 390px sweep (07.1-18; the review's "no overflow at 390px" and "no dead end" checks, C-L8): every
// changed end-user page and the changed console pages, reached through the real journeys, have no
// horizontal overflow at 390 CSS px (lib/layout.ts expectNoHorizontalOverflow) and a visible way
// forward (expectWayForward; pages whose way forward is a decision show its buttons instead). The
// console pages also open and close the mobile menu.
//
// End-user pages: sign-in (clean, failed), registration (clean, refused, check-email), recovery
// (request, sent, reset, done, used link), verification (page, done, used link), error pages (not
// found, unknown client, expired sign-in link), root (signed out, signed in), Signed in, logout
// confirmation, signed out, consent, org chooser, non-member page, every account page, the account
// confirmation step, both recovery codes pages, MFA enrolment and the second factor.
// Console pages: overview, users list and a user page, clients list, the new client picker, a
// client page, new connection, login settings, audit log, tenants list and new tenant; plus the
// console Low items C-L1 (plain tenant names in the switcher) and C-L5 (no empty role select).
//
// Env: ANVIL_URL, MAILPIT_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { withTenantSettings } from '../lib/admin';
import { anvilUrl, createConsoleAdmin, createUser, login, randomEmail, randomPassword, register } from '../lib/anvil';
import { consoleUrl } from '../lib/console';
import { consoleSignIn } from '../lib/console-ux';
import { detourUser, startAtLogin } from '../lib/detours';
import { deleteTenant } from '../lib/email-code';
import { expectNoHorizontalOverflow, expectWayForward } from '../lib/layout';
import { extractLink, latestMessageTo } from '../lib/mailpit';
import { addMember, createOrg, createOrgClient, createOrgTenant, type OrgTenant } from '../lib/org';
import { totp } from '../lib/totp';
import { createTenant, randomSlug } from '../lib/upstream';
import { atRp, authorizeUrl, fakeRp, fakeRpOrigin, token, uxState, type FakeRp, type UxState } from '../lib/ux-state';

const WIDTH = 390;

let rp: FakeRp | undefined;
let s: UxState;
let tok: string;

test.use({ viewport: { width: WIDTH, height: 844 } });
test.describe.configure({ timeout: 120_000 });

test.beforeAll(async ({ browser }) => {
  rp = await fakeRp();
  s = await uxState(browser);
  tok = await token(s);
});

test.afterAll(async () => {
  await rp?.close();
});

/** No overflow at 390px and a link, account, sign-in or sign-out way forward. */
async function sweep(page: Page, label: string): Promise<void> {
  await test.step(`390px: ${label}`, async () => {
    await expectNoHorizontalOverflow(page, WIDTH);
    await expectWayForward(page);
  });
}

/** No overflow at 390px; the way forward is a decision (visible submit buttons in main). */
async function sweepDecision(page: Page, label: string): Promise<void> {
  await test.step(`390px: ${label}`, async () => {
    await expectNoHorizontalOverflow(page, WIDTH);
    await expect(page.locator('main button[type=submit]').filter({ visible: true }).first()).toBeVisible();
  });
}

test('sign-in, registration and recovery pages', async ({ page }) => {
  const user = await detourUser(tok, 'l390-rec');
  await startAtLogin(page, s.clients.web);
  await sweep(page, 'sign-in');
  await login(page, user.email, randomPassword());
  await expect(page.locator('[data-message-key="login.invalid_credentials"]')).toBeVisible();
  await sweep(page, 'failed sign-in');

  await page.locator('#link-registration').click();
  await expect(page.locator('form#registration')).toBeVisible();
  await sweep(page, 'registration');
  await register(page, randomEmail('l390-short'), 'short');
  await expect(page.locator('#password-msg-1')).toBeVisible();
  await sweep(page, 'refused registration');

  await page.locator('#link-login').click();
  await page.locator('#link-recovery').click();
  await expect(page.locator('form#recovery')).toBeVisible();
  await sweep(page, 'recovery request');
  await page.locator('#email').fill(user.email);
  await page.locator('#recovery-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.sent');
  await sweep(page, 'recovery sent');

  const link = extractLink((await latestMessageTo(user.email)).Text, '/ui/recovery');
  await page.goto(link);
  await expect(page.locator('form#recovery-reset')).toBeVisible();
  await sweepDecision(page, 'recovery reset');
  await page.locator('#password').fill(randomPassword());
  await page.locator('#recovery-reset-submit').click();
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.done');
  await sweep(page, 'recovery done');
  await page.goto(link);
  await expect(page.locator('[data-message-key="links.expired"]')).toBeVisible();
  await sweep(page, 'used reset link');
});

test('registration check-email and verification pages', async ({ page }) => {
  await withTenantSettings(tok, { require_verified_email: true }, async () => {
    await startAtLogin(page, s.clients.web);
    await page.locator('#link-registration').click();
    const email = randomEmail('l390-verify');
    await register(page, email, randomPassword());
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'registration.check_email');
    await sweep(page, 'registration check-email');

    const link = extractLink((await latestMessageTo(email)).Text, '/ui/verification');
    await page.goto(link);
    await expect(page.locator('form#verification')).toBeVisible();
    await sweepDecision(page, 'verification');
    await page.locator('#verification-submit').click();
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'verification.done');
    await sweep(page, 'verification done');
    await page.goto(link);
    await expect(page.locator('[data-message-key="links.expired"]')).toBeVisible();
    await sweep(page, 'used verification link');
  });
});

test('error pages and the signed-out root page', async ({ page }) => {
  await page.goto(`${anvilUrl()}/l390-does-not-exist`);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'not_found');
  await sweep(page, 'not found');

  await page.goto(authorizeUrl({ client_id: 'l390-unknown-client', redirect_uri: `${fakeRpOrigin()}/x` }).url);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'unknown_client');
  await sweep(page, 'unknown client');

  await page.goto(`${anvilUrl()}/ui/login?request=0190a6d4-0000-7000-8000-0000000390aa`);
  await expect(page.locator('#error-message')).toHaveAttribute('data-error-key', 'flow_expired');
  await sweep(page, 'expired sign-in link');

  await page.goto(`${anvilUrl()}/`);
  await expect(page.locator('#link-login')).toBeVisible();
  await sweep(page, 'root, signed out');
});

test('signed in, root, logout confirmation and signed out', async ({ page }) => {
  const user = await detourUser(tok, 'l390-out');
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  await sweep(page, 'signed in');

  await page.goto(`${anvilUrl()}/`);
  await expect(page.locator('#link-account')).toBeVisible();
  await sweep(page, 'root, signed in');

  await page.goto(`${anvilUrl()}/ui/logout`);
  await expect(page.locator('#logout-confirm-submit')).toBeVisible();
  await sweep(page, 'logout confirmation');
  await page.locator('#logout-confirm-submit').click();
  await expect(page).toHaveURL((url) => url.pathname.endsWith('/ui/signed-out'));
  await sweep(page, 'signed out');
});

test('consent and the app access confirmation step', async ({ page }) => {
  const user = await detourUser(tok, 'l390-consent');
  const req = authorizeUrl(s.clients.thirdParty);
  await page.goto(req.url);
  await login(page, user.email, user.password);
  await expect(page.locator('form#consent-form')).toBeVisible();
  await expect(page.locator('#consent-account-email')).toContainText(user.email);
  await sweepDecision(page, 'consent');
  await page.locator('#consent-allow').click();
  expect((await atRp(page)).get('code')).toBeTruthy();

  await page.goto(`${anvilUrl()}/ui/account/apps`);
  await page.locator('#app-revoke-1-submit').click();
  await expect(page.locator('form#form-confirm')).toBeVisible();
  await sweep(page, 'account confirmation step (remove app access)');
});

test('account pages, recovery codes and their confirmation step', async ({ page }) => {
  const user = await detourUser(tok, 'l390-acct');
  await page.goto(`${anvilUrl()}/ui/login`);
  await login(page, user.email, user.password);
  await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'login.signed_in');
  for (const section of ['profile', 'email', 'password', 'security', 'sessions', 'linked', 'apps', 'attributes']) {
    await page.goto(`${anvilUrl()}/ui/account/${section}`);
    await expect(page.locator('#account-identity')).toContainText(user.email);
    await sweep(page, `account ${section}`);
  }
  // U-L5: the empty attributes page (still open) does not repeat its H1 as an H2.
  await expect(page.locator('#attributes-none')).toBeVisible();
  const h1 = ((await page.locator('h1').first().textContent()) ?? '').trim();
  const h2s = (await page.locator('main h2').allTextContents()).map((t) => t.trim());
  expect(h2s, 'no H2 repeats the H1').not.toContain(h1);

  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#totp-begin-submit').click();
  await expect(page.locator('#link-otpauth')).toBeVisible();
  await sweep(page, 'account TOTP enrolment');
  const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  await page.locator('#code').fill(totp(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#recovery-codes li')).toHaveCount(10);
  await sweep(page, 'account recovery codes');

  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#recovery-codes-regenerate-submit').click();
  await expect(page.locator('form#form-confirm')).toBeVisible();
  await sweep(page, 'account confirmation step (new recovery codes)');
});

test('MFA enrolment, the in-flow recovery codes page and the second factor', async ({ page, browser }) => {
  const user = await detourUser(tok, 'l390-mfa');
  let secret = '';
  await withTenantSettings(tok, { mfa_policy: 'required' }, async () => {
    await startAtLogin(page, s.clients.web);
    await login(page, user.email, user.password);
    await expect(page.locator('form#mfa-enroll')).toBeVisible();
    await sweep(page, 'MFA enrolment');
    secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
    const now = Date.now() / 1000;
    await page.locator('#code').fill(totp(secret, now));
    await page.locator('#mfa-enroll-submit').click();
    await expect(page.locator('#recovery-codes li')).toHaveCount(10);
    await sweepDecision(page, 'in-flow recovery codes');
    await page.locator('#recovery-codes-confirm-submit').click();
    expect((await atRp(page)).get('code')).toBeTruthy();
  });

  const other = await browser.newContext({ viewport: { width: WIDTH, height: 844 } });
  try {
    const p = await other.newPage();
    await startAtLogin(p, s.clients.web);
    await login(p, user.email, user.password);
    await expect(p.locator('form#second-factor')).toBeVisible();
    await sweep(p, 'second factor');
  } finally {
    await other.close();
  }
});

test('org chooser and the non-member page', async ({ page }) => {
  let tenant: OrgTenant | undefined;
  try {
    tenant = await createOrgTenant(tok, 'l390-org');
    const acme = await createOrg(tok, tenant.slug, { slug: 'acme', display_name: 'Acme Corporation International' });
    const beta = await createOrg(tok, tenant.slug, { slug: 'beta', display_name: 'Beta Laboratories' });
    await createOrg(tok, tenant.slug, { slug: 'gamma', display_name: 'Gamma Works' });
    const email = randomEmail('l390-org');
    const password = randomPassword();
    const user = await createUser(tok, { email, password, email_verified: true }, tenant.slug);
    await addMember(tok, tenant.slug, acme.id, user.id ?? '');
    await addMember(tok, tenant.slug, beta.id, user.id ?? '');
    const client = await createOrgClient(tok, tenant.slug, `${fakeRpOrigin()}/org-callback`, 'required');

    await page.goto(authorizeUrl(client, {}, tenant.issuer).url);
    await login(page, email, password);
    await expect(page.locator('form#select-organization-form')).toBeVisible();
    await sweepDecision(page, 'org chooser');
    await page.locator('#organization-beta').check();
    await page.locator('#select-organization-form-submit').click();
    expect((await atRp(page)).get('code')).toBeTruthy();

    await page.goto(authorizeUrl(client, { organization: 'gamma' }, tenant.issuer).url);
    await expect(page.locator('#org-not-member-email')).toHaveText(email);
    await sweepDecision(page, 'non-member page');
  } finally {
    await tenant?.cleanup();
  }
});

/** At 390px the console navigation sits behind Menu, which opens and closes. */
async function consoleSweep(page: Page, label: string): Promise<void> {
  await test.step(`390px console: ${label}`, async () => {
    await expectNoHorizontalOverflow(page, WIDTH);
    const menu = page.getByRole('button', { name: 'Menu' });
    const nav = page.getByRole('navigation', { name: 'Main' });
    await expect(menu).toBeVisible();
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(nav).toBeVisible();
    await expectNoHorizontalOverflow(page, WIDTH);
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(nav).toBeHidden();
  });
}

test('console pages with the mobile menu', async ({ page }) => {
  const admin = { email: randomEmail('l390-admin'), password: randomPassword() };
  await createConsoleAdmin(tok, admin);
  const user = await detourUser(tok, 'l390-console-user');
  await consoleSignIn(page, admin);

  const visits: Array<{ path: string; label: string; ready: () => Promise<void> }> = [
    { path: 't/default', label: 'overview', ready: () => expect(page.getByTestId('tenant-overview')).toBeVisible() },
    {
      path: 't/default/users',
      label: 'users list',
      ready: () => expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible(),
    },
    {
      path: `t/default/users/${user.id}`,
      label: 'user page',
      ready: () => expect(page.getByRole('heading', { level: 1, name: user.email })).toBeVisible(),
    },
    {
      path: 't/default/clients',
      label: 'clients list',
      ready: () => expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible(),
    },
    {
      path: 't/default/clients/new',
      label: 'new client picker',
      ready: () => expect(page.getByTestId('app-type-picker')).toBeVisible(),
    },
    {
      path: `t/default/clients/${s.clients.web.client_id}`,
      label: 'client page',
      ready: () => expect(page.getByTestId('integration-card')).toBeVisible(),
    },
    {
      path: 't/default/connections/new',
      label: 'new connection',
      ready: () => expect(page.getByRole('heading', { level: 1, name: 'New connection' })).toBeVisible(),
    },
    {
      path: 't/default/settings',
      label: 'login settings',
      ready: () => expect(page.getByTestId('login-settings-form')).toBeVisible(),
    },
    {
      path: 't/default/audit',
      label: 'audit log',
      ready: () => expect(page.getByRole('heading', { level: 1, name: /audit/i })).toBeVisible(),
    },
    {
      path: 'tenants',
      label: 'tenants list',
      ready: () => expect(page.getByRole('heading', { level: 1, name: 'Tenants' })).toBeVisible(),
    },
    {
      path: 'tenants/new',
      label: 'new tenant',
      ready: () => expect(page.getByTestId('tenant-form')).toBeVisible(),
    },
  ];
  for (const v of visits) {
    await page.goto(consoleUrl(v.path));
    await v.ready();
    await page.waitForLoadState('networkidle');
    await consoleSweep(page, v.label);
  }

  await test.step('console Low items: plain tenant names (C-L1), no empty role select (C-L5)', async () => {
    const slug = randomSlug('l390-noroles');
    await createTenant(tok, slug);
    try {
      const member = await detourUser(tok, 'l390-noroles', slug);
      await page.goto(consoleUrl(`t/${slug}/users/${member.id}?tab=roles`));
      await expect(page.getByTestId('no-assignable-roles')).toContainText('This tenant has no roles yet.');
      await expect(page.getByRole('tabpanel').getByRole('combobox')).toHaveCount(0);
      await expectNoHorizontalOverflow(page, WIDTH);
      const switcher = page.locator('#tenant-switcher-select');
      await expect(switcher.locator('option[value="system"]')).toHaveText('System');
      await expect(switcher.locator('option[value="default"]')).toHaveText('Default');
    } finally {
      await deleteTenant(tok, slug);
    }
  });
});
