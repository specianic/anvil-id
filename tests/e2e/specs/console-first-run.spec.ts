// J1 first run (07.1-17, review section 4): after setup, the used setup link says setup is complete
// and links to the console; signing in to the console lands on the default tenant's Overview with
// the getting-started checklist and the admin's email in the header; the Overview's issuer and
// discovery URL match the published discovery document; the checklist's "Create your first app"
// turns done once the tenant has an app, "Add your logo and colours" opens the Logo section of
// Branding, the SMTP item follows the instance's real SMTP state, and the system tenant lists
// "Add a second administrator". Every page visited passes the axe audit.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import {
  adminToken,
  anvilUrl,
  createClient,
  createConsoleAdmin,
  randomEmail,
  randomPassword,
  requireEnv,
  sharedManagementCredential,
  type AdminAccount,
} from '../lib/anvil';
import { consoleLogin, consoleUrl } from '../lib/console';
import { deleteTenant } from '../lib/email-code';
import { createTenant, randomSlug, tenantIssuer } from '../lib/upstream';

const slug = randomSlug('first-run');
let cleanupToken: string | undefined;

test.afterAll(async () => {
  if (cleanupToken) await deleteTenant(cleanupToken, slug);
});

function item(page: Page, id: string) {
  return page.getByTestId(`checklist-${id}`);
}

test('console first run: setup link, overview landing, checklist from real state', async ({ page, browser }) => {
  test.setTimeout(120_000);
  // Completes setup if no earlier spec did, so the setup link below is a used one.
  const token = await adminToken(await sharedManagementCredential(browser));
  cleanupToken = token;
  const admin: AdminAccount = { email: randomEmail('first-run-admin'), password: randomPassword() };
  await createConsoleAdmin(token, admin);
  await createTenant(token, slug);

  await test.step('the used setup link says setup is complete and links to the console', async () => {
    await page.goto(requireEnv('SETUP_URL'));
    await expect(page.locator('#message-body')).toHaveAttribute('data-message-key', 'errors_friendly.setup_used');
    const link = page.locator('#link-console');
    await expect(link).toBeVisible();
    expect(new URL((await link.getAttribute('href')) ?? '', anvilUrl()).pathname).toBe('/console/');
  });

  await test.step('signing in lands on the Overview with the checklist; the header shows the email', async () => {
    await consoleLogin(page, admin);
    await expect(page.getByTestId('console-admin')).toHaveText(admin.email);
    const nav = page.getByRole('navigation', { name: 'Main' });
    await expect(nav.getByRole('link', { name: 'Overview', exact: true })).toHaveAttribute('aria-current', 'page');
    for (const id of ['first-app', 'sign-up', 'logo', 'smtp', 'connection']) {
      await expect(item(page, id)).toBeVisible();
    }
    // The second-administrator step belongs to the system tenant only.
    await expect(item(page, 'second-admin')).toHaveCount(0);
    // The sign-up mode is a choice: shown with its current value, never as a fake "done".
    await expect(item(page, 'sign-up')).toHaveAttribute('data-state', 'info');
    await expect(item(page, 'sign-up')).toContainText('Currently:');
    await expectNoA11yViolations(page);
  });

  await test.step("the Overview's issuer and discovery URL match the discovery document", async () => {
    const issuer = await page.getByLabel('Issuer', { exact: true }).inputValue();
    const discovery = await page.getByLabel('Discovery URL', { exact: true }).inputValue();
    expect(issuer).toBe(tenantIssuer('default'));
    expect(discovery).toBe(`${issuer}/.well-known/openid-configuration`);
    const res = await fetch(discovery, { headers: { accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { issuer?: string }).issuer).toBe(issuer);
    await expect(page.getByRole('button', { name: 'Copy Issuer' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy Discovery URL' })).toBeVisible();
  });

  await test.step('the SMTP item follows the instance (tenant or installation SMTP, or none)', async () => {
    const res = await fetch(`${anvilUrl()}/api/admin/v1/system/info`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    const { smtp_configured } = (await res.json()) as { smtp_configured: boolean };
    await page.goto(consoleUrl(`t/${slug}`));
    const smtp = item(page, 'smtp');
    // A fresh tenant has no SMTP settings of its own: the installation decides.
    await expect(smtp).toHaveAttribute('data-state', smtp_configured ? 'done' : 'todo');
    await expect(smtp).toContainText(
      smtp_configured ? "uses the installation's SMTP server" : 'No SMTP server configured',
    );
  });

  await test.step('"Create your first app" turns done once the tenant has an app', async () => {
    await expect(page.getByRole('heading', { level: 1, name: `E2E ${slug}` })).toBeVisible();
    const firstApp = item(page, 'first-app');
    await expect(firstApp).toHaveAttribute('data-state', 'todo');
    await expect(firstApp.getByRole('link', { name: 'Create your first app' })).toHaveAttribute(
      'href',
      `/console/t/${slug}/clients/new`,
    );
    await expect(item(page, 'connection')).toHaveAttribute('data-state', 'todo');
    await expectNoA11yViolations(page);

    await createClient(
      token,
      {
        name: 'e2e first-run app',
        client_type: 'public',
        application_type: 'web',
        auth_method: 'none',
        redirect_uris: ['https://first-run.example.test/callback'],
        grant_types: ['authorization_code'],
        scopes: ['openid'],
      },
      slug,
    );
    await page.reload();
    await expect(firstApp).toHaveAttribute('data-state', 'done');
    await expect(item(page, 'first-app-detail')).toHaveText('1 app in this tenant.');
  });

  await test.step('"Add your logo and colours" opens the Logo section at the top of Branding', async () => {
    await item(page, 'logo').getByRole('link', { name: 'Add your logo and colours' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/branding` && url.hash === '#logo');
    const logo = page.locator('#logo');
    await expect(logo.getByRole('heading', { level: 2, name: 'Logo' })).toBeVisible();
    await expect(logo).toBeInViewport();
    // The logo control is the first section of the editor.
    await expect(page.getByTestId('theme-editor').locator('[data-testid^="theme-"]').first()).toHaveAttribute(
      'data-testid',
      'theme-logo',
    );
    await expect(page.getByTestId('logo-file')).toBeVisible();
  });

  await test.step('the system tenant lists "Add a second administrator" from the role holders', async () => {
    await page.goto(consoleUrl('t/system'));
    const second = item(page, 'second-admin');
    await expect(second).toBeVisible();
    // The setup administrator and this spec's administrator both hold the role.
    await expect(second).toHaveAttribute('data-state', 'done');
    await expect(second.getByRole('link', { name: 'Add a second administrator' })).toHaveAttribute(
      'href',
      '/console/t/system/roles/administrator',
    );
    await expectNoA11yViolations(page);
  });
});
