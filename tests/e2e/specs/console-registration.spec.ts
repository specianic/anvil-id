// OIDC-17 / AGT-02 from the console (05-24): an operator opens dynamic client registration,
// creates an initial access token (value shown once), switches the policy to allow-listed, and
// /register then refuses requests without the token and accepts one with it (single use). The
// registered client shows a Dynamic source badge in the clients list. The system tenant's
// registration settings are read-only.
//
// Runs in a tenant of its own, deleted afterwards.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { findInPagedTable } from '../lib/console';
import {
  allowClipboard,
  openTenantPage,
  registerClient,
  setUpConsoleTenant,
  takeOneTimeSecret,
  type ConsoleTenant,
} from '../lib/console-v04';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

const METADATA = {
  client_name: 'e2e console registration',
  redirect_uris: ['https://dcr-console.example.test/callback'],
  grant_types: ['authorization_code'],
  response_types: ['code'],
};

test('console: DCR policy, initial access token and dynamic client badge', async ({ page, browser }) => {
  test.setTimeout(120_000);
  tenant = await setUpConsoleTenant(browser, page, 'cdcr');
  const { slug } = tenant;
  await allowClipboard(page);

  await test.step('registration is disabled by default (/register answers 404)', async () => {
    const res = await registerClient(slug, METADATA);
    expect(res.status).toBe(404);
  });

  await test.step('open the registration settings from Login settings and set DCR open', async () => {
    await openTenantPage(page, slug, 'settings');
    await page.getByTestId('registration-settings-link').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/settings/registration`);
    await expect(page.getByRole('heading', { level: 1, name: 'Client registration' })).toBeVisible();
    await expect(page.getByTestId('dcr-policy')).toHaveValue('disabled');
    await expectNoA11yViolations(page);
    await page.getByTestId('dcr-policy').selectOption('open');
    await page.getByTestId('save-registration').click();
    await expect(page.getByTestId('registration-form').getByRole('status')).toHaveText('Registration settings saved.');
    const res = await registerClient(slug, METADATA);
    expect(res.status).toBe(201);
  });

  let iat = '';
  await test.step('create a single-use initial access token; its value is shown once', async () => {
    await page.getByTestId('iat-description').fill('e2e console token');
    await page.getByTestId('iat-uses').fill('1');
    await page.getByTestId('create-iat').click();
    await expectNoA11yViolations(page);
    iat = await takeOneTimeSecret(page, 'iat-value');
    const row = page.getByRole('row').filter({ hasText: 'e2e console token' });
    await expect(row).toContainText('Usable');
  });

  await test.step('switch to allow-listed: no token 401, the token 201 once, then 401', async () => {
    await page.getByTestId('dcr-policy').selectOption('allow_listed');
    await page.getByTestId('save-registration').click();
    await expect(page.getByTestId('registration-form').getByRole('status')).toHaveText('Registration settings saved.');

    expect((await registerClient(slug, METADATA)).status).toBe(401);
    expect((await registerClient(slug, METADATA, 'not-a-real-token')).status).toBe(401);
    const ok = await registerClient(slug, { ...METADATA, client_name: 'e2e allow-listed' }, iat);
    expect(ok.status).toBe(201);
    expect(typeof ok.body.client_id).toBe('string');
    expect((await registerClient(slug, METADATA, iat)).status).toBe(401);

    await page.reload();
    await expect(page.getByRole('row').filter({ hasText: 'e2e console token' })).toContainText('Expired or used up');

    await test.step('the clients list marks the registered client as dynamic', async () => {
      const clientId = ok.body.client_id as string;
      await openTenantPage(page, slug, 'clients');
      const badge = page.getByTestId(`client-source-${clientId}`);
      await findInPagedTable(page, badge);
      await expect(badge).toHaveText('Dynamic');
      await expectNoA11yViolations(page);
    });
  });

  await test.step('the system tenant keeps registration disabled and read-only', async () => {
    await openTenantPage(page, 'system', 'settings/registration');
    await expect(page.getByTestId('registration-read-only')).toBeVisible();
    await expect(page.getByTestId('dcr-policy')).toBeDisabled();
    await expect(page.getByTestId('dcr-policy')).toHaveValue('disabled');
    await expect(page.getByTestId('cimd-policy')).toHaveValue('disabled');
    await expect(page.getByTestId('iat-form')).toHaveCount(0);
  });
});
