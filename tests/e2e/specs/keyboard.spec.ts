// UI-02 checks axe cannot make (research Pitfall 15): keyboard operation, visible and unobscured
// focus (WCAG 2.4.7, 2.4.11), autocomplete purposes (1.3.5), paste allowed into credential fields
// (3.3.8 accessible authentication), target size (2.5.8) and errors that are programmatically
// linked and announced (3.3.1, 4.1.3).
//
// 0.2 pages (plan 03-27): second factor (one-time-code autocomplete, paste, recovery-code disclosure
// by keyboard), consent buttons, account security / TOTP enrolment / recovery codes, sessions and
// connected apps (tab order follows the DOM, visible unobscured focus, 24 px targets).
//
// 07.1-18: the console's keyboard order (skip link, tenant switcher, Sign out, navigation; C-L8).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { expect, test, type Browser, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createClient,
  createConsoleAdmin,
  createUser,
  login,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
} from '../lib/anvil';
import { consoleSignIn } from '../lib/console-ux';
import { totp } from '../lib/totp';

/** The account navigation, in DOM order (themes/default/templates/account_base.html). */
const ACCOUNT_NAV = [
  'account-nav-profile',
  'account-nav-email',
  'account-nav-password',
  'account-nav-security',
  'account-nav-sessions',
  'account-nav-apps',
  'account-nav-linked',
];

/** What every signed-in account page starts with, in DOM order: the account header's sign-out
 * button (#account-header, 07.1-12; no back-to-app link without a client_id), then the account
 * navigation. */
const ACCOUNT_CHROME = ['sign-out-submit', ...ACCOUNT_NAV];

test.beforeAll(async ({ browser }) => {
  // Make sure the instance is installed (setup completed once for the whole run).
  await sharedManagementCredential(browser);
});

/** The id of the focused element (or its tag name when it has no id). */
function focusedId(page: Page): Promise<string> {
  return page.evaluate(() => {
    const el = document.activeElement;
    return el ? el.id || el.tagName.toLowerCase() : '';
  });
}

/** Asserts the focused element shows a focus indicator and is not hidden behind other content. */
async function expectVisibleFocus(page: Page): Promise<void> {
  const info = await page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return null;
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const top = document.elementFromPoint(cx, cy);
    return {
      id: el.id,
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
      boxShadow: style.boxShadow,
      // A multi-line text field is the exception: on focus the browser scrolls its caret into
      // view, not the whole box, so a tall textarea near the bottom edge may extend past it. Its
      // top edge and first line (where the caret lands) must then be in view.
      inViewport:
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.right <= innerWidth &&
        (rect.bottom <= innerHeight ||
          (el instanceof HTMLTextAreaElement &&
            rect.top +
              Number.parseFloat(style.borderTopWidth) +
              Number.parseFloat(style.paddingTop) +
              (Number.parseFloat(style.lineHeight) || 1.2 * Number.parseFloat(style.fontSize)) <=
              innerHeight)),
      geometry: `rect ${JSON.stringify(rect)}, viewport ${innerWidth}x${innerHeight}, scrollY ${scrollY}, page height ${document.documentElement.scrollHeight}`,
      unobscured: top !== null && (top === el || el.contains(top)),
    };
  });
  expect(info, 'an element has focus').not.toBeNull();
  const indicator =
    (info!.outlineStyle !== 'none' && info!.outlineWidth > 0) || info!.boxShadow !== 'none';
  expect(indicator, `focus indicator on #${info!.id}`).toBe(true);
  expect(info!.inViewport, `#${info!.id} scrolled into view (${info!.geometry})`).toBe(true);
  expect(info!.unobscured, `#${info!.id} not obscured`).toBe(true);
}

/** The page loads with initial focus (autofocus) on `id`, shown with a visible indicator. */
async function expectInitialFocus(page: Page, id: string): Promise<void> {
  await expect.poll(() => focusedId(page), `initial focus on #${id}`).toBe(id);
  await expectVisibleFocus(page);
}

/** Tabs from the current focus and returns the ids of the next `n` focused elements. */
async function tabSequence(page: Page, n: number): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < n; i += 1) {
    await page.keyboard.press('Tab');
    await expectVisibleFocus(page);
    ids.push(await focusedId(page));
  }
  return ids;
}

/** Interactive controls are at least 24x24 CSS px (WCAG 2.5.8). */
async function expectTargetSizes(page: Page): Promise<void> {
  const small = await page.evaluate(() =>
    Array.from(
      document.querySelectorAll<HTMLElement>('main a, main button, main input:not([type=hidden])'),
    )
      .map((el) => ({ id: el.id || el.tagName, rect: el.getBoundingClientRect() }))
      .filter(({ rect }) => rect.width < 24 || rect.height < 24)
      .map(({ id, rect }) => `${id} ${rect.width}x${rect.height}`),
  );
  expect(small, 'controls smaller than 24x24 CSS px').toEqual([]);
}

/** Pasting into the field is not cancelled by the page. */
async function expectPasteAllowed(page: Page, selector: string): Promise<void> {
  const prevented = await page.locator(selector).evaluate((el) => {
    const data = new DataTransfer();
    data.setData('text/plain', 'pasted-secret');
    const event = new ClipboardEvent('paste', {
      clipboardData: data,
      bubbles: true,
      cancelable: true,
    });
    return !el.dispatchEvent(event);
  });
  expect(prevented, `paste into ${selector} is not prevented`).toBe(false);
  await expect(page.locator(selector)).not.toHaveAttribute('onpaste', /.*/);
}

for (const vp of [
  { name: 'desktop', width: 1280, height: 800 },
  { name: 'mobile', width: 375, height: 812 },
]) {
  test.describe(`${vp.name} viewport`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test('login: tab order, visible focus, autocomplete, paste, Enter submits, announced error', async ({
      page,
    }) => {
      await page.goto(`${anvilUrl()}/ui/login`);
      await expect(page.locator('form#login')).toBeVisible();

      const links = await page.locator('main nav a').evaluateAll((els) => els.map((e) => e.id));
      // The passkey button (03-20) is revealed only when webauthn.js finds WebAuthn support, so it
      // is in the tab order in the JS project and absent in the no-JS one.
      const passkey = (await page.locator('#login-passkey-submit').isVisible())
        ? ['login-passkey-submit']
        : [];
      // The first field has initial focus (U-L2); Tab then walks the rest in DOM order.
      await expectInitialFocus(page, 'identifier');
      const order = await tabSequence(page, 2 + passkey.length + links.length);
      expect(order).toEqual(['password', 'login-submit', ...passkey, ...links]);

      await expect(page.locator('#identifier')).toHaveAttribute('autocomplete', 'username');
      await expect(page.locator('#password')).toHaveAttribute('autocomplete', 'current-password');
      await expect(page.locator('label[for="identifier"]')).toBeVisible();
      await expect(page.locator('label[for="password"]')).toBeVisible();
      await expectPasteAllowed(page, '#identifier');
      await expectPasteAllowed(page, '#password');
      await expectTargetSizes(page);

      // Keyboard only: type into the fields and submit with Enter.
      await page.locator('#identifier').focus();
      await page.keyboard.type(randomEmail('kbd'));
      await page.keyboard.press('Tab');
      await page.keyboard.type(randomPassword());
      await page.keyboard.press('Enter');
      const error = page.locator('[data-message-key="login.invalid_credentials"]');
      await expect(error).toBeVisible();
      await expect(error).toHaveAttribute('role', 'alert');

      // After the round trip the form again starts focused and is operable by keyboard.
      await expectInitialFocus(page, 'identifier');
      const again = await tabSequence(page, 2);
      expect(again).toEqual(['password', 'login-submit']);
    });

    test('registration: tab order, autocomplete, paste, field errors linked and announced', async ({
      page,
    }) => {
      await page.goto(`${anvilUrl()}/ui/registration`);
      await expect(page.locator('form#registration')).toBeVisible();

      const links = await page.locator('main nav a').evaluateAll((els) => els.map((e) => e.id));
      const order = await tabSequence(page, 4 + links.length);
      expect(order).toEqual(['email', 'name', 'password', 'registration-submit', ...links]);

      await expect(page.locator('#email')).toHaveAttribute('autocomplete', 'email');
      await expect(page.locator('#name')).toHaveAttribute('autocomplete', 'name');
      await expect(page.locator('#password')).toHaveAttribute('autocomplete', 'new-password');
      await expectPasteAllowed(page, '#email');
      await expectPasteAllowed(page, '#password');
      await expectTargetSizes(page);

      // Submit the empty form with Enter from the email field: errors are linked to their fields.
      await page.locator('#email').focus();
      await page.keyboard.press('Enter');
      const invalid = page.locator('form#registration input[aria-invalid="true"]');
      await expect(invalid.first()).toBeVisible();
      for (const input of await invalid.all()) {
        const describedBy = (await input.getAttribute('aria-describedby')) ?? '';
        expect(describedBy, 'invalid input has aria-describedby').not.toBe('');
        for (const id of describedBy.split(/\s+/)) {
          const msg = page.locator(`[id="${id}"]`);
          await expect(msg).toBeVisible();
          await expect(msg).toHaveAttribute('role', 'alert');
        }
      }
      // Focus goes to the first invalid field when tabbing from the top.
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await page.locator('body').focus();
      const first = await tabSequence(page, 1);
      expect(first).toEqual(['email']);
    });

    test('recovery: autocomplete and keyboard submit', async ({ page }) => {
      await page.goto(`${anvilUrl()}/ui/recovery`);
      const order = await tabSequence(page, 2);
      expect(order).toEqual(['email', 'recovery-submit']);
      await expect(page.locator('#email')).toHaveAttribute('autocomplete', 'email');
      await expectTargetSizes(page);
      await page.locator('#email').focus();
      await page.keyboard.type(randomEmail('kbd-rec'));
      await page.keyboard.press('Enter');
      await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'recovery.sent');
      await expectTargetSizes(page);
    });
  });
}

// ---------------------------------------------------------------------------------------------
// Helpers for the 0.2 pages.

/** The ids (or tag names) of the visible focusable controls inside <main>, in DOM order. */
function domFocusOrder(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(
      document.querySelectorAll<HTMLElement>(
        'main a[href], main button, main input:not([type=hidden]), main textarea, main select, main summary',
      ),
    )
      .filter((el) => el.checkVisibility() && el.tabIndex >= 0)
      .map((el) => el.id || el.tagName.toLowerCase()),
  );
}

/** Tabbing from the top of the page visits exactly the visible controls, in DOM order. */
async function expectDomTabOrder(page: Page): Promise<string[]> {
  const expected = await domFocusOrder(page);
  expect(expected.length, 'page has focusable controls').toBeGreaterThan(0);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  const order = await tabSequence(page, expected.length);
  expect(order).toEqual(expected);
  return order;
}

/** <summary> disclosures are also targets of at least 24x24 CSS px. */
async function expectSummaryTargetSizes(page: Page): Promise<void> {
  const small = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('main summary'))
      .map((el) => el.getBoundingClientRect())
      .filter((r) => r.width < 24 || r.height < 24)
      .map((r) => `${r.width}x${r.height}`),
  );
  expect(small, 'summaries smaller than 24x24 CSS px').toEqual([]);
}

async function newUser(browser: Browser, prefix: string): Promise<{ email: string; password: string }> {
  const creds = await sharedManagementCredential(browser);
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

/** Enrols an authenticator app for the signed-in user of `page`; returns its base32 secret. */
async function enrolTotp(page: Page): Promise<string> {
  await page.goto(`${anvilUrl()}/ui/account/security`);
  await page.locator('#totp-begin-submit').click();
  const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
  await page.locator('#code').fill(totp(secret));
  await page.locator('#totp-confirm-submit').click();
  await expect(page.locator('#recovery-codes li')).toHaveCount(10);
  return secret;
}

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

const PHASE3_VIEWPORTS = [
  { name: 'desktop', width: 1280, height: 800 },
  { name: 'mobile', width: 375, height: 812 },
] as const;

for (const vp of PHASE3_VIEWPORTS) {
  test.describe(`${vp.name} viewport, 0.2 pages`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test('second factor: tab order, one-time-code, paste, disclosure by keyboard, announced error', async ({
      page,
      browser,
    }) => {
      const user = await newUser(browser, 'kbd-2fa');
      const setup = await browser.newContext();
      let secret = '';
      try {
        const p = await setup.newPage();
        await signIn(p, user.email, user.password);
        secret = await enrolTotp(p);
      } finally {
        await setup.close();
      }

      await page.goto(`${anvilUrl()}/ui/login`);
      await login(page, user.email, user.password);
      await expect(page.locator('form#second-factor')).toBeVisible();

      const order = await expectDomTabOrder(page);
      expect(order).toEqual(['code', 'summary', 'second-factor-submit', 'link-login']);
      // WCAG 3.3.8: the code field supports autofill of one-time codes and allows paste.
      await expect(page.locator('#code')).toHaveAttribute('autocomplete', 'one-time-code');
      await expect(page.locator('#code')).toHaveAttribute('inputmode', 'numeric');
      await expectPasteAllowed(page, '#code');
      await expectTargetSizes(page);
      await expectSummaryTargetSizes(page);

      // The recovery-code disclosure opens with the keyboard and its field joins the tab order.
      await page.locator('#recovery-code-toggle > summary').focus();
      await page.keyboard.press('Enter');
      await expect(page.locator('#recovery-code-toggle')).toHaveAttribute('open', '');
      await page.keyboard.press('Tab');
      expect(await focusedId(page)).toBe('recovery_code');
      await expectVisibleFocus(page);
      await expectPasteAllowed(page, '#recovery_code');
      await page.keyboard.press('Shift+Tab');
      await page.keyboard.press('Space');
      await expect(page.locator('#recovery-code-toggle')).not.toHaveAttribute('open', '');

      // A wrong code typed and submitted with Enter: the error is linked and announced.
      const now = Date.now() / 1000;
      const valid = new Set([totp(secret, now - 30), totp(secret, now), totp(secret, now + 30)]);
      let wrong = '000000';
      for (let n = 1; valid.has(wrong); n += 1) wrong = String(n).padStart(6, '0');
      await page.locator('#code').focus();
      await page.keyboard.type(wrong);
      await page.keyboard.press('Enter');
      const error = page.locator('[data-message-key="login.second_factor_invalid"]');
      await expect(error).toBeVisible();
      await expect(error).toHaveAttribute('role', 'alert');
      const describedBy = (await page.locator('#code').getAttribute('aria-describedby')) ?? '';
      expect(describedBy.split(/\s+/)).toContain((await error.getAttribute('id')) ?? '?');

      // The right code by keyboard signs in.
      await page.locator('#code').focus();
      await page.keyboard.type(totp(secret, Date.now() / 1000 + 30));
      await page.keyboard.press('Enter');
      await expect(page.locator('form#second-factor')).toHaveCount(0);
    });

    test('consent: Allow and Deny reachable in order, Enter submits', async ({ page, browser }) => {
      const user = await newUser(browser, 'kbd-consent');
      const creds = await sharedManagementCredential(browser);
      const redirectUri = `http://localhost:${await freePort()}/cb`;
      const client = await createClient(
        await adminToken(creds),
        {
          name: 'keyboard consent client',
          client_type: 'confidential',
          application_type: 'web',
          auth_method: 'client_secret_basic',
          redirect_uris: [redirectUri],
          grant_types: ['authorization_code'],
          scopes: ['openid', 'email'],
        },
        'default',
        'required',
      );
      await signIn(page, user.email, user.password);
      const authorize = new URL(`${anvilUrl()}/authorize`);
      authorize.search = new URLSearchParams({
        client_id: client.client_id,
        response_type: 'code',
        scope: 'openid email',
        redirect_uri: redirectUri,
        state: randomBytes(12).toString('base64url'),
        code_challenge: createHash('sha256').update(randomBytes(32)).digest('base64url'),
        code_challenge_method: 'S256',
      }).toString();
      await page.goto(authorize.href);
      await expect(page.locator('form#consent-form')).toBeVisible();

      const order = await expectDomTabOrder(page);
      expect(order).toEqual(['consent-other', 'consent-allow', 'consent-deny']);
      await expectTargetSizes(page);

      // Deny with the keyboard: the browser is sent to the redirect URI with access_denied.
      const redirected = page.waitForRequest((req) => req.url().startsWith(redirectUri));
      await page.locator('#consent-deny').focus();
      await page.keyboard.press('Enter');
      expect(new URL((await redirected).url()).searchParams.get('error')).toBe('access_denied');
    });

    test('account security, TOTP enrolment and recovery codes: tab order, focus, targets', async ({
      page,
      browser,
    }) => {
      const user = await newUser(browser, 'kbd-sec');
      await signIn(page, user.email, user.password);

      await page.goto(`${anvilUrl()}/ui/account/security`);
      const overview = await expectDomTabOrder(page);
      expect(overview.slice(0, ACCOUNT_CHROME.length)).toEqual(ACCOUNT_CHROME);
      expect(overview).toContain('totp-begin-submit');
      await expectTargetSizes(page);

      // Start enrolment by keyboard.
      await page.locator('#totp-begin-submit').focus();
      await page.keyboard.press('Enter');
      await expect(page.locator('#totp-qr')).toBeVisible();
      const enrol = await expectDomTabOrder(page);
      expect(enrol.slice(ACCOUNT_CHROME.length)).toEqual([
        'link-otpauth',
        'code',
        'totp-confirm-submit',
        'link-account-security',
      ]);
      await expect(page.locator('#code')).toHaveAttribute('autocomplete', 'one-time-code');
      await expectPasteAllowed(page, '#code');
      await expectTargetSizes(page);

      const secret = ((await page.locator('#totp-secret').textContent()) ?? '').replace(/\s+/g, '');
      await page.locator('#code').focus();
      await page.keyboard.type(totp(secret));
      await page.keyboard.press('Enter');
      await expect(page.locator('#recovery-codes li')).toHaveCount(10);
      const codes = await expectDomTabOrder(page);
      expect(codes.slice(ACCOUNT_CHROME.length)).toEqual(['recovery-codes-text', 'link-account-security']);
      await expectTargetSizes(page);

      await page.locator('#link-account-security').focus();
      await page.keyboard.press('Enter');
      await expect(page.locator('#recovery-codes-count')).toHaveText('10');
      const enrolled = await expectDomTabOrder(page);
      expect(enrolled).toContain('recovery-codes-regenerate-submit');
      await expectTargetSizes(page);
    });

    test('sessions and connected apps: table actions in order, visible focus, targets', async ({
      page,
      browser,
    }) => {
      const user = await newUser(browser, 'kbd-sess');
      const other = await browser.newContext();
      try {
        await signIn(await other.newPage(), user.email, user.password);
        await signIn(page, user.email, user.password);
        await page.goto(`${anvilUrl()}/ui/account/sessions`);
        await expect(page.locator('#session-list tbody tr')).toHaveCount(2);
        const order = await expectDomTabOrder(page);
        expect(order.slice(0, ACCOUNT_CHROME.length)).toEqual(ACCOUNT_CHROME);
        expect(order.at(-1)).toBe('sessions-revoke-others-submit');
        expect(order.filter((id) => /^session-revoke-.+-submit$/.test(id))).toHaveLength(2);
        await expectTargetSizes(page);

        // Sign out the other session with the keyboard.
        const otherButton = page.locator('#session-list tbody tr:not([data-current]) button');
        await otherButton.focus();
        await expectVisibleFocus(page);
        await page.keyboard.press('Enter');
        await expect(page.locator('[data-message-key="sessions.revoked"]')).toBeVisible();
        await expect(page.locator('#session-list tbody tr')).toHaveCount(1);
      } finally {
        await other.close();
      }

      await page.goto(`${anvilUrl()}/ui/account/apps`);
      await expect(page.locator('#apps-empty')).toBeVisible();
      await expectDomTabOrder(page);
      await expectTargetSizes(page);
    });
  });
}

// C-L8 (the admin review's "works well" list, kept): the console's keyboard order starts with the
// skip link, then the tenant switcher, then Sign out, then the main navigation.
test('console: skip link, tenant switcher, sign out, then the navigation', async ({ page, browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  const admin = { email: randomEmail('kbd-console'), password: randomPassword() };
  await createConsoleAdmin(token, admin);
  await page.setViewportSize({ width: 1280, height: 800 });
  await consoleSignIn(page, admin);
  await expect(page.getByTestId('tenant-overview')).toBeVisible();
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());

  const stops: string[] = [];
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab');
    stops.push(
      await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el) return '';
        if (el.id === 'tenant-switcher-select') return 'tenant-switcher';
        if (el.closest('nav[aria-label="Main"]')) return 'nav';
        return (el.textContent ?? '').trim() || el.tagName.toLowerCase();
      }),
    );
  }
  const at = (name: string) => stops.indexOf(name);
  expect(at('Skip to content'), `tab stops: ${stops.join(' > ')}`).toBe(0);
  expect(at('tenant-switcher')).toBeGreaterThan(at('Skip to content'));
  expect(at('Sign out')).toBeGreaterThan(at('tenant-switcher'));
  expect(at('nav')).toBeGreaterThan(at('Sign out'));
});
