// Layout and navigation assertions shared by the hosted-page and console specs (07.1): no
// horizontal overflow on narrow screens, a visible focus indicator, and no dead-end pages.

import { expect, type Page } from '@playwright/test';

interface OverflowReport {
  scrollWidth: number;
  innerWidth: number;
  offenders: string[];
}

/**
 * Sets the viewport to `width` (default 390, a small phone) and asserts the document does not
 * scroll horizontally (`scrollWidth <= innerWidth`). The failure message lists the elements that
 * extend past the right edge.
 */
export async function expectNoHorizontalOverflow(page: Page, width = 390): Promise<void> {
  const height = page.viewportSize()?.height ?? 844;
  await page.setViewportSize({ width, height });
  const report = await page.evaluate(async (): Promise<OverflowReport> => {
    // Let the resize reflow settle before measuring.
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const innerWidth = window.innerWidth;
    const offenders = Array.from(document.body.querySelectorAll('*'))
      .filter((e) => e.getBoundingClientRect().right > innerWidth + 0.5)
      .slice(0, 10)
      .map((e) => {
        const id = e.id ? `#${e.id}` : '';
        const cls = typeof e.className === 'string' && e.className ? `.${e.className.trim().split(/\s+/).join('.')}` : '';
        return `${e.tagName.toLowerCase()}${id}${cls} (right ${Math.round(e.getBoundingClientRect().right)})`;
      });
    return { scrollWidth: document.documentElement.scrollWidth, innerWidth, offenders };
  });
  expect(
    report.scrollWidth,
    `horizontal overflow at ${width}px on ${page.url()}: scrollWidth ${report.scrollWidth} > ${report.innerWidth}\n` +
      report.offenders.join('\n'),
  ).toBeLessThanOrEqual(report.innerWidth);
}

/**
 * Asserts the focused element (after the caller moved focus, normally with Tab) is not the body
 * and shows a focus indicator: a non-zero outline or a box-shadow ring.
 */
export async function expectFocusVisible(page: Page): Promise<void> {
  const focus = await page.evaluate(() => {
    const e = document.activeElement;
    if (!e || e === document.body || e === document.documentElement) return { element: 'body', visible: false };
    const style = getComputedStyle(e);
    const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
    const ring = style.boxShadow !== '' && style.boxShadow !== 'none';
    return { element: `${e.tagName.toLowerCase()}${e.id ? `#${e.id}` : ''}`, visible: outline || ring };
  });
  expect(focus.element, 'focus is on the page body, not on a control').not.toBe('body');
  expect(focus.visible, `focused ${focus.element} on ${page.url()} has no visible focus indicator`).toBe(true);
}

/**
 * The "no dead end" assertion: the page offers at least one visible way forward inside `main`
 * (continue, account, sign-in or sign-out controls, or any link with an href).
 */
export async function expectWayForward(page: Page): Promise<void> {
  const ways = page.locator(
    [
      '#link-continue',
      '#link-account',
      '#link-login',
      '#form-sign-out button',
      '#form-sign-out [type=submit]',
      'main a[href]',
    ].join(', '),
  );
  await expect(ways.filter({ visible: true }).first(), `no way forward on ${page.url()}`).toBeVisible();
}
