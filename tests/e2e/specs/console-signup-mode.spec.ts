// C-H3 (07.1-17, review J5): the sign-up mode of an existing tenant is editable in the console.
// Login settings starts with a Sign-up section; choosing Disabled and saving removes "Create an
// account" from the tenant's sign-in page and makes /ui/registration refuse; choosing Open again
// restores both. Runs in a tenant of its own, deleted afterwards.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Browser } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { tenantSettings } from '../lib/admin';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v04';
import { tenantIssuer } from '../lib/upstream';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

/** Whether the tenant's sign-in page offers "Create an account" and /ui/registration shows its form. */
async function signUpOffered(browser: Browser, slug: string): Promise<{ link: boolean; form: boolean }> {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`${tenantIssuer(slug)}/ui/login`);
    await expect(page.locator('#identifier')).toBeVisible();
    const link = (await page.locator('#link-registration').count()) > 0;
    await page.goto(`${tenantIssuer(slug)}/ui/registration`);
    const form = (await page.locator('form#registration').count()) > 0;
    if (!form) {
      await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'registration.disabled');
    }
    return { link, form };
  } finally {
    await context.close();
  }
}

test('console: change the sign-up mode of an existing tenant', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'csignup');
  const { slug, token } = tenant;
  expect((await tenantSettings(token, slug)).registration).toBe('open');
  expect(await signUpOffered(browser, slug)).toEqual({ link: true, form: true });

  const section = page.getByTestId('sign-up-section');
  const save = page.getByTestId('save-login-settings');
  const saved = page.getByTestId('login-settings-save-bar').getByRole('status');

  await test.step('Login settings starts with the Sign-up section showing the current mode', async () => {
    await openTenantPage(page, slug, 'settings');
    await expect(section.getByRole('heading', { level: 2, name: 'Sign-up' })).toBeVisible();
    // The first section of the form.
    await expect(page.getByTestId('login-settings-form').locator('h2').first()).toHaveText('Sign-up');
    await expect(section.getByRole('radio', { name: 'Open' })).toBeChecked();
    await expect(section.getByRole('radio', { name: 'Invite only' })).not.toBeChecked();
    await expect(section.getByRole('radio', { name: 'Disabled' })).not.toBeChecked();
    // One Save for the whole page.
    await expect(page.getByTestId('login-settings-form').getByRole('button', { name: /^Save/ })).toHaveCount(1);
    await expectNoA11yViolations(page);
  });

  await test.step('Disabled: no "Create an account" and /ui/registration refuses', async () => {
    await section.getByRole('radio', { name: 'Disabled' }).check();
    await expect(page.getByTestId('login-settings-dirty')).toBeVisible();
    await save.click();
    await expect(saved).toHaveText('Login settings saved.');
    await expect(page.getByTestId('login-settings-dirty')).toHaveCount(0);
    expect((await tenantSettings(token, slug)).registration).toBe('disabled');
    expect(await signUpOffered(browser, slug)).toEqual({ link: false, form: false });

    await page.reload();
    await expect(section.getByRole('radio', { name: 'Disabled' })).toBeChecked();
  });

  await test.step('Invite only is stored as invite_only', async () => {
    await section.getByRole('radio', { name: 'Invite only' }).check();
    await save.click();
    await expect(saved).toHaveText('Login settings saved.');
    expect((await tenantSettings(token, slug)).registration).toBe('invite_only');
    expect((await signUpOffered(browser, slug)).link).toBe(false);
  });

  await test.step('Open restores the link and the registration form', async () => {
    await section.getByRole('radio', { name: 'Open' }).check();
    await save.click();
    await expect(saved).toHaveText('Login settings saved.');
    expect((await tenantSettings(token, slug)).registration).toBe('open');
    expect(await signUpOffered(browser, slug)).toEqual({ link: true, form: true });
  });
});
