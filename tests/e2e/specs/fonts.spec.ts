// Self-hosted fonts (07.1-02, 07.1-10, checked here by 07.1-18): an end-user page and the console
// load Hanken Grotesk from the instance itself, the body text actually uses it, and no request
// leaves the instance origin while the pages and their fonts load (no font CDN, no third-party
// request of any kind).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { adminToken, anvilUrl, createConsoleAdmin, randomEmail, randomPassword, sharedManagementCredential } from '../lib/anvil';
import { consoleSignIn } from '../lib/console-ux';

/** Records every request URL the page sends from now on. */
function recordRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on('request', (req) => urls.push(req.url()));
  return urls;
}

/** After document.fonts.ready: a loaded Hanken Grotesk face exists and the body asks for it. */
async function expectHankenLoaded(page: Page): Promise<void> {
  const fonts = await page.evaluate(async () => {
    await document.fonts.ready;
    // document.fonts.check() is also true when no face matches at all, so look at the faces too.
    const faces: string[] = [];
    document.fonts.forEach((f) => {
      if (f.family.replace(/["']/g, '') === 'Hanken Grotesk') faces.push(f.status);
    });
    return {
      faces,
      check: document.fonts.check('16px "Hanken Grotesk"'),
      body: getComputedStyle(document.body).fontFamily,
    };
  });
  expect(fonts.faces, `Hanken Grotesk faces on ${page.url()}`).toContain('loaded');
  expect(fonts.check).toBe(true);
  expect(fonts.body.split(',')[0].replace(/["']/g, '').trim()).toBe('Hanken Grotesk');
}

/** Every recorded request goes to the instance origin (data: and blob: URLs are local). */
function expectOnlyInstanceOrigin(urls: string[]): void {
  const origin = new URL(anvilUrl()).origin;
  const foreign = urls.filter((u) => {
    if (u.startsWith('data:') || u.startsWith('blob:')) return false;
    return new URL(u).origin !== origin;
  });
  expect(foreign, 'requests that left the instance origin').toEqual([]);
  expect(
    urls.some((u) => /HankenGrotesk.*\.ttf/.test(u)),
    'the Hanken Grotesk file was requested from the instance',
  ).toBe(true);
}

test('the sign-in page loads Hanken Grotesk from the instance only', async ({ page }) => {
  const urls = recordRequests(page);
  const fontResponse = page.waitForResponse((r) => /HankenGrotesk.*\.ttf/.test(r.url()));
  await page.goto(`${anvilUrl()}/ui/login`);
  await expect(page.locator('form#login')).toBeVisible();
  const font = await fontResponse;
  expect(font.status()).toBe(200);
  await expectHankenLoaded(page);
  expectOnlyInstanceOrigin(urls);
});

test('the console loads Hanken Grotesk from the instance only', async ({ page, browser }) => {
  const token = await adminToken(await sharedManagementCredential(browser));
  const admin = { email: randomEmail('fonts-admin'), password: randomPassword() };
  await createConsoleAdmin(token, admin);

  const urls = recordRequests(page);
  await consoleSignIn(page, admin);
  await expect(page.getByTestId('tenant-overview')).toBeVisible();
  await expectHankenLoaded(page);
  await page.waitForLoadState('networkidle');
  expectOnlyInstanceOrigin(urls.filter((u) => new URL(u).pathname.startsWith('/console/')));
  expectOnlyInstanceOrigin(urls);
});
