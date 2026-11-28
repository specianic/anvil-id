// Console helpers for the admin-journey specs (07.1). lib/console.ts consoleLogin asserts the
// default landing page; consoleSignIn here only waits for the signed-in shell, so journeys keep
// working whatever the landing page is (Users, Overview, the last tenant used). Navigation goes
// through the grouped main navigation, opening the mobile menu first when it is collapsed.

import { expect, type Page } from '@playwright/test';
import { login, type AdminAccount } from './anvil';
import { consoleUrl } from './console';

/**
 * Opens /console/, signs in on the system tenant's hosted login page with `admin`'s email and
 * password, and waits until the console shell (main navigation or its menu button) is shown.
 */
export async function consoleSignIn(page: Page, admin: AdminAccount): Promise<void> {
  await page.goto(consoleUrl());
  await expect(page).toHaveURL((url) => url.pathname.startsWith('/t/system/ui/login'));
  await login(page, admin.email, admin.password);
  await expect(page).toHaveURL((url) => url.pathname.startsWith('/console/'));
  await expect(mainNav(page).or(menuButton(page)).first()).toBeVisible();
}

function mainNav(page: Page) {
  return page.getByRole('navigation', { name: 'Main' });
}

function menuButton(page: Page) {
  return page.getByRole('button', { name: /^menu$/i });
}

/**
 * Opens a console section by its navigation label (exact accessible name, e.g. `Clients`,
 * `Signing keys`). On narrow viewports the collapsed navigation is opened through its Menu button
 * first. Waits until the link is the current page and the network is idle.
 */
export async function nav(page: Page, label: string): Promise<void> {
  const menu = menuButton(page);
  if ((await menu.count()) > 0 && (await menu.first().isVisible())) {
    if ((await menu.first().getAttribute('aria-expanded')) !== 'true') await menu.first().click();
    await expect(menu.first()).toHaveAttribute('aria-expanded', 'true');
  }
  const link = mainNav(page).getByRole('link', { name: label, exact: true });
  await link.click();
  await expect(link).toHaveAttribute('aria-current', 'page');
  await page.waitForLoadState('networkidle');
}

/** The visible text of `<main>` (the whole body when the page has no main landmark). */
export async function mainText(page: Page): Promise<string> {
  const main = page.locator('main');
  return (await main.count()) > 0 ? main.first().innerText() : page.locator('body').innerText();
}
