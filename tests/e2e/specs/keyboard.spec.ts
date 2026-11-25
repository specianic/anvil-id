// UI-02 checks axe cannot make (research Pitfall 15): keyboard operation, visible and unobscured
// focus (WCAG 2.4.7, 2.4.11), autocomplete purposes (1.3.5), paste allowed into credential fields
// (3.3.8 accessible authentication), target size (2.5.8) and errors that are programmatically
// linked and announced (3.3.1, 4.1.3).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { anvilUrl, randomEmail, randomPassword, sharedManagementCredential } from '../lib/anvil';

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
      inViewport:
        rect.top >= 0 && rect.left >= 0 && rect.bottom <= innerHeight && rect.right <= innerWidth,
      unobscured: top !== null && (top === el || el.contains(top)),
    };
  });
  expect(info, 'an element has focus').not.toBeNull();
  const indicator =
    (info!.outlineStyle !== 'none' && info!.outlineWidth > 0) || info!.boxShadow !== 'none';
  expect(indicator, `focus indicator on #${info!.id}`).toBe(true);
  expect(info!.inViewport, `#${info!.id} scrolled into view`).toBe(true);
  expect(info!.unobscured, `#${info!.id} not obscured`).toBe(true);
}

/** Tabs from the top of the page and returns the ids of the first `n` focused elements. */
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
      const order = await tabSequence(page, 3 + passkey.length + links.length);
      expect(order).toEqual(['identifier', 'password', 'login-submit', ...passkey, ...links]);

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

      // After the round trip the form is still operable by keyboard from the top.
      const again = await tabSequence(page, 3);
      expect(again).toEqual(['identifier', 'password', 'login-submit']);
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
