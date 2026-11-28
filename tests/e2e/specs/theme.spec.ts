// UI-03: live theming from the admin console (plans 04-18, 04-22) in a real browser.
//
// An admin of the system tenant opens Console -> Branding (the default tenant's theme), changes the
// primary colour and the preview iframe follows within seconds (computed --anvil-primary and the
// sign-in button colour inside the frame). A small PNG logo is uploaded and appears in the preview.
// After Publish, the real sign-in page of the tenant has the same primary colour and logo, still
// passes axe (the theme keeps AA), and its CSP still has no 'unsafe-inline'. A low-contrast text
// colour shows a contrast warning, custom CSS with @import shows the line error and blocks Publish,
// and Reset restores the default theme on the sign-in page. A first test checks the default theme:
// the self-hosted fonts load under the page CSP and orange is never a text colour.
//
// The default tenant's branding is shared by every spec of the run, so it is deleted before and
// after this file through the admin API.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser, type FrameLocator, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createConsoleAdmin,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
  type ManagementCredential,
} from '../lib/anvil';
import { consoleLogin } from '../lib/console';

/** The built-in primary colour (themes/default/static/anvil.css, Specianic orange, both schemes). */
const DEFAULT_PRIMARY = '#ff5a1f';
/** Orange as a computed colour: a fill only, never the colour of text. */
const ORANGE_RGB = 'rgb(255, 90, 31)';
/** The new primary colour: 7.9:1 against white, the button text a lone customised primary is paired
 *  with (see themes/default/README.md), so AA holds. */
const PRIMARY = '#1b5e20';
const PRIMARY_RGB = 'rgb(27, 94, 32)';
/** Text colour between 3:1 and 4.5:1 on the default background and surface: accepted, warned. */
const LOW_CONTRAST_TEXT = '#777777';

/** A 1x1 PNG, generated for this test (not a secret). */
const LOGO_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);

let creds: ManagementCredential;

async function deleteDefaultBranding(): Promise<void> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1/tenants/default/branding`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${await adminToken(creds)}`, accept: 'application/json' },
  });
  if (res.status !== 204 && res.status !== 404) {
    throw new Error(`DELETE default branding: HTTP ${res.status} ${await res.text()}`);
  }
}

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
  await deleteDefaultBranding();
});

test.afterAll(async () => {
  await deleteDefaultBranding();
});

/** The value of a CSS custom property on the root element of a page or frame. */
async function rootVar(target: Page | FrameLocator, name: string): Promise<string> {
  return target
    .locator('html')
    .evaluate((el, prop) => getComputedStyle(el).getPropertyValue(prop).trim().toLowerCase(), name);
}

/** The preview has settled on the current draft. */
async function previewSettled(page: Page): Promise<void> {
  await expect(page.getByTestId('preview-status')).toHaveText('Preview is up to date.', {
    timeout: 10_000,
  });
}

/** Opens the default tenant's sign-in page in a fresh context and returns it with its CSP. */
async function openLoginPage(browser: Browser): Promise<{ page: Page; csp: string; close: () => Promise<void> }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const res = await page.goto(`${anvilUrl()}/ui/login`);
  expect(res?.status()).toBe(200);
  await expect(page.locator('form#login')).toBeVisible();
  return {
    page,
    csp: res?.headers()['content-security-policy'] ?? '',
    close: () => context.close(),
  };
}

/** The computed colour of a link in the page's main card (a link appended for the measurement, so the
 *  check does not depend on which links the tenant's settings show). */
async function linkColor(page: Page): Promise<string> {
  return page.locator('main').evaluate((main) => {
    const a = document.createElement('a');
    a.href = '#';
    a.textContent = 'link';
    main.append(a);
    const color = getComputedStyle(a).color;
    a.remove();
    return color;
  });
}

test('default theme: self-hosted fonts load and orange is never text', async ({ browser }) => {
  const login = await openLoginPage(browser);
  try {
    const fonts = await login.page.evaluate(async () => {
      await document.fonts.ready;
      // Plex is only used by code on some pages; ask for it so its file has to load too.
      await document.fonts.load('13px "IBM Plex Mono"');
      const faces: FontFace[] = [];
      document.fonts.forEach((f) => faces.push(f));
      const loaded = (family: string) =>
        faces.some((f) => f.family.replace(/["']/g, '') === family && f.status === 'loaded');
      return {
        hankenCheck: document.fonts.check('16px "Hanken Grotesk"'),
        hanken: loaded('Hanken Grotesk'),
        plex: loaded('IBM Plex Mono'),
        bodyFont: getComputedStyle(document.body).fontFamily,
      };
    });
    expect(fonts.hankenCheck).toBe(true);
    expect(fonts.hanken).toBe(true);
    expect(fonts.plex).toBe(true);
    expect(fonts.bodyFont).toContain('Hanken Grotesk');
    expect(login.csp).toContain("font-src 'self'");
    expect(login.csp).not.toMatch(/https?:/);

    await expect.poll(() => rootVar(login.page, '--anvil-primary')).toBe(DEFAULT_PRIMARY);
    // Orange fills the primary button (with ink text) but links use the darker signal-text colour.
    await expect(login.page.locator('#login-submit')).toHaveCSS('background-color', ORANGE_RGB);
    await expect(login.page.locator('#login-submit')).not.toHaveCSS('color', ORANGE_RGB);
    expect(await linkColor(login.page)).not.toBe(ORANGE_RGB);
    await expectNoA11yViolations(login.page);
  } finally {
    await login.close();
  }
});

test('console theme editor: live preview, publish to the sign-in page, warnings, errors, reset', async ({
  page,
  browser,
}) => {
  test.setTimeout(180_000);
  const admin: AdminAccount = { email: randomEmail('theme-admin'), password: randomPassword() };
  await createConsoleAdmin(await adminToken(creds), admin);

  await test.step('open Branding in the console', async () => {
    await consoleLogin(page, admin);
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Branding' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Branding' })).toBeVisible();
    await expect(page.getByTestId('theme-editor')).toBeVisible();
    await expect(page.getByTestId('branding-state')).toContainText('Not customised');
    await previewSettled(page);
    await expect(page.getByTestId('theme-preview-frame')).toHaveAttribute('title', 'Theme preview');
    await expectNoA11yViolations(page);
  });

  const frame = page.frameLocator('[data-testid="theme-preview-frame"]');

  await test.step('the preview starts on the default theme', async () => {
    await expect(frame.locator('#preview-login-submit')).toBeVisible();
    await expect.poll(() => rootVar(frame, '--anvil-primary')).toBe(DEFAULT_PRIMARY);
    await expect(frame.locator('.anvil-logo')).toBeHidden();
  });

  await test.step('changing the primary colour updates the preview', async () => {
    await page.getByTestId('color-colors.primary').fill(PRIMARY);
    await previewSettled(page);
    await expect.poll(() => rootVar(frame, '--anvil-primary'), { timeout: 5_000 }).toBe(PRIMARY);
    await expect(frame.locator('#preview-login-submit')).toHaveCSS('background-color', PRIMARY_RGB);
  });

  await test.step('uploading a logo shows it in the preview', async () => {
    await expect(page.getByTestId('logo-none')).toBeVisible();
    await page.getByTestId('logo-file').setInputFiles({
      name: 'logo.png',
      mimeType: 'image/png',
      buffer: LOGO_PNG,
    });
    await expect(page.getByTestId('logo-selected')).toBeVisible();
    await page.getByTestId('logo-upload').click();
    await expect(page.getByTestId('logo-current')).toBeVisible();
    await expect(page.getByText('Logo saved. It is live on the sign-in pages.')).toBeVisible();
    await previewSettled(page);
    await expect(frame.locator('.anvil-logo')).toBeVisible({ timeout: 5_000 });
    // The draft colour survives the preview reload.
    await expect.poll(() => rootVar(frame, '--anvil-primary')).toBe(PRIMARY);
  });

  await test.step('publish', async () => {
    const publish = page.getByTestId('publish-theme');
    await expect(publish).toBeEnabled();
    await publish.click();
    await expect(page.getByText('Theme published. The sign-in pages use it now.')).toBeVisible();
    await expect(page.getByTestId('branding-state')).toContainText('Customised');
    await expect(page.getByTestId('reset-theme')).toBeEnabled();
  });

  await test.step('the real sign-in page uses the published theme and keeps AA and the CSP', async () => {
    const login = await openLoginPage(browser);
    try {
      await expect.poll(() => rootVar(login.page, '--anvil-primary')).toBe(PRIMARY);
      await expect(login.page.locator('#login-submit')).toHaveCSS('background-color', PRIMARY_RGB);
      // Links follow the customised primary colour, as before the default theme had its own link
      // colour.
      expect(await linkColor(login.page)).toBe(PRIMARY_RGB);
      await expect(login.page.locator('.anvil-logo')).toBeVisible();
      await expect(login.page.locator('.anvil-logo')).toHaveAttribute('role', 'img');
      expect(login.csp).not.toBe('');
      expect(login.csp).not.toContain('unsafe-inline');
      expect(login.csp).toMatch(/style-src [^;]*'self'/);
      await expectNoA11yViolations(login.page);
    } finally {
      await login.close();
    }
  });

  await test.step('a low-contrast text colour shows a contrast warning', async () => {
    const text = page.getByTestId('color-colors.text');
    await text.fill(LOW_CONTRAST_TEXT);
    await previewSettled(page);
    const warnings = page.getByTestId('contrast-warnings-light');
    await expect(warnings).toBeVisible();
    await expect(warnings).toContainText(/Text on (background|surface)/);
    await expect(page.getByTestId('preview-warnings')).toBeVisible();
    await text.fill('');
    await previewSettled(page);
    await expect(page.getByTestId('contrast-warnings-light')).toHaveCount(0);
  });

  await test.step('custom CSS with @import shows the line error and blocks Publish', async () => {
    const css = page.getByTestId('custom-css');
    await css.fill('.anvil-muted { font-style: italic; }\n@import "https://example.test/x.css";');
    await expect(page.getByTestId('draft-invalid')).toBeVisible({ timeout: 10_000 });
    const fieldError = page.getByTestId('theme-custom-css').locator('[data-field-error]');
    await expect(fieldError).toContainText(/line 2/i);
    await expect(css).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByTestId('preview-errors')).toContainText('custom_css');
    await expect(page.getByTestId('publish-theme')).toBeDisabled();
    // The preview keeps the last valid draft.
    await expect.poll(() => rootVar(frame, '--anvil-primary')).toBe(PRIMARY);

    await css.fill('');
    await previewSettled(page);
    await expect(page.getByTestId('draft-invalid')).toHaveCount(0);
  });

  await test.step('reset restores the default theme', async () => {
    await page.getByTestId('reset-theme').click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Remove branding' }).click();
    await expect(dialog).toBeHidden();
    await expect(
      page.getByText('Branding removed. The sign-in pages use the default theme again.'),
    ).toBeVisible();
    await expect(page.getByTestId('branding-state')).toContainText('Not customised');
    await expect(page.getByTestId('color-colors.primary')).toHaveValue('');
    await expect(page.getByTestId('logo-none')).toBeVisible();

    const login = await openLoginPage(browser);
    try {
      await expect.poll(() => rootVar(login.page, '--anvil-primary')).toBe(DEFAULT_PRIMARY);
      await expect(login.page.locator('.anvil-logo')).toBeHidden();
    } finally {
      await login.close();
    }
  });
});
