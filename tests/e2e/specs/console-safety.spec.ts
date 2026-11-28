// Cross-cutting console safety (07.1-17, review section 4): leaving Login settings with unsaved
// changes asks first (Stay keeps the edit, Leave discards it); a saved form leaves freely; deleting
// a tenant requires typing its slug exactly (wrong text or case keeps the button disabled, Cancel
// keeps the tenant); the SMTP page states the instance's real SMTP state, read from /system/info
// first; unpublished branding edits ask before leaving too. Runs in a tenant of its own.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { tenantSettings } from '../lib/admin';
import { anvilUrl } from '../lib/anvil';
import { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v04';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

function navLink(page: Page, label: string) {
  return page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: label, exact: true });
}

test('console safety: unsaved-changes guard, typed tenant deletion, true SMTP state', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'csafe');
  const { slug, token } = tenant;
  const guard = page.getByRole('alertdialog', { name: 'Leave without saving?' });

  await test.step('Login settings: leaving with unsaved changes prompts; Stay keeps the edit', async () => {
    await openTenantPage(page, slug, 'settings');
    await expect(page.getByRole('heading', { level: 1, name: 'Login settings' })).toBeVisible();
    await expectNoA11yViolations(page);
    const mfa = page.getByLabel('MFA policy');
    await mfa.selectOption('optional');
    await expect(page.getByTestId('login-settings-dirty')).toBeVisible();

    await navLink(page, 'Users').click();
    await expect(guard).toBeVisible();
    await expectNoA11yViolations(page);
    await guard.getByRole('button', { name: 'Stay' }).click();
    await expect(guard).toBeHidden();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/settings`);
    await expect(mfa).toHaveValue('optional');

    // Leave discards the edit; nothing was stored.
    await navLink(page, 'Users').click();
    await guard.getByRole('button', { name: 'Leave' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
    expect((await tenantSettings(token, slug)).mfa_policy).toBe('off');
  });

  await test.step('a saved form leaves without a prompt; undoing an edit clears the guard', async () => {
    await openTenantPage(page, slug, 'settings');
    const mfa = page.getByLabel('MFA policy');
    await mfa.selectOption('optional');
    await page.getByTestId('save-login-settings').click();
    await expect(page.getByTestId('login-settings-save-bar').getByRole('status')).toHaveText('Login settings saved.');
    expect((await tenantSettings(token, slug)).mfa_policy).toBe('optional');

    await mfa.selectOption('required');
    await mfa.selectOption('optional');
    await expect(page.getByTestId('login-settings-dirty')).toHaveCount(0);
    await navLink(page, 'Users').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
    await expect(guard).toHaveCount(0);
  });

  await test.step('deleting a tenant requires typing its slug; Cancel keeps it', async () => {
    await openTenantPage(page, slug, 'settings');
    const zone = page.getByTestId('danger-zone');
    await zone.scrollIntoViewIfNeeded();
    await expect(zone.getByRole('heading', { name: 'Danger zone' })).toBeVisible();
    await zone.getByRole('button', { name: 'Delete tenant' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this tenant?' });
    await expect(dialog).toBeVisible();
    const confirm = dialog.getByRole('button', { name: 'Delete tenant' });
    const input = dialog.getByTestId('danger-zone-confirm-input');
    await expect(confirm).toBeDisabled();
    await input.fill('wrong');
    await expect(confirm).toBeDisabled();
    await input.fill(slug.toUpperCase());
    await expect(confirm).toBeDisabled();
    await input.fill(slug);
    await expect(confirm).toBeEnabled();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    const res = await fetch(`${anvilUrl()}/api/admin/v1/tenants/${slug}`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    await res.body?.cancel();
    expect(res.status).toBe(200);
  });

  await test.step('the SMTP page states the real SMTP state of the instance', async () => {
    const res = await fetch(`${anvilUrl()}/api/admin/v1/system/info`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    const { smtp_configured } = (await res.json()) as { smtp_configured: boolean };

    await openTenantPage(page, slug, 'email/smtp');
    await expect(page.getByRole('heading', { level: 1, name: 'SMTP settings' })).toBeVisible();
    const source = page.getByTestId('smtp-source');
    // The tenant has no SMTP settings of its own, so the installation decides.
    if (smtp_configured) {
      await expect(source).toHaveAttribute('data-state', 'installation');
      await expect(source).toContainText("uses the installation's SMTP server");
    } else {
      await expect(source).toHaveAttribute('data-state', 'none');
      await expect(source).toContainText(
        "No SMTP server configured — verification, recovery and invitation emails can't be sent",
      );
    }
    await expectNoA11yViolations(page);
  });

  await test.step('unpublished branding edits ask before leaving', async () => {
    await openTenantPage(page, slug, 'branding');
    await expect(page.getByTestId('theme-editor')).toBeVisible();
    await page.getByTestId('color-colors.primary').fill('#123456');
    await navLink(page, 'Users').click();
    await expect(guard).toBeVisible();
    await guard.getByRole('button', { name: 'Leave' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
  });

  await test.step('the Overview passes the axe audit', async () => {
    await openTenantPage(page, slug, '');
    await expect(page.getByTestId('getting-started')).toBeVisible();
    await expectNoA11yViolations(page);
  });
});
