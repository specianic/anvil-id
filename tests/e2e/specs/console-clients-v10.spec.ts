// OIDC-18 / AGT-03 / UI-05 from the console (07-20): an operator sets and persists the 1.0 client
// fields (require PAR, client kind, native headless), sees the API refuse an agent that skips
// consent on the consent field, sets the tenant's "Require PAR for all clients" and headless
// allowed origins (a wildcard origin refused next to the field), and creates and deletes a
// Firebase password hash profile whose signer key is never shown back.
//
// Runs in a tenant of its own, deleted afterwards, signed in as a console administrator created
// with createConsoleAdmin.
//
// Console test ids (admin-ui, plan 07-20):
// - client form: fieldset `client-v10-fields`, `client-require-par`, `client-kind`,
//   `client-headless-native` (the consent select is labelled "Consent"); since 07.1-16 these sit in
//   the collapsed Advanced section (`client-advanced-toggle`), opened before asserting
// - login settings: `par-headless-form`, `tenant-require-par`, `headless-origins`,
//   `headless-origin` rows (`data-origin`, button "Remove {origin}"), `headless-origin-input`,
//   `headless-origin-add`, `save-par-headless`, `password-profiles-link`
// - password hash profiles: `new-profile`, `profile-form`, `profile-name`, `profile-rounds`,
//   `profile-mem-cost`, `profile-salt-separator`, `profile-signer-key`, `profile-submit`,
//   `profile-row` (`data-name`, button "Delete {name}"), `profile-in-use`
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminCall, tenantPath } from '../lib/admin-api';
import { createClient } from '../lib/anvil';
import { openSectionFromNav, openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

interface ClientFields {
  client_id: string;
  consent_mode: string;
  require_pushed_authorization_requests: boolean;
  client_kind: 'application' | 'agent';
  headless_native: boolean;
}

interface TenantSettingsView {
  settings: {
    par: { require_pushed_authorization_requests: boolean };
    headless: { allowed_origins: string[] };
  };
}

interface HashProfile {
  id: string;
  name: string;
  [field: string]: unknown;
}

/** firebase/scrypt README parameters (public test vector; no real project's key). */
const FB_SIGNER_KEY =
  'jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==';

test('console: client PAR/agent/headless fields, tenant PAR and origins, hash profiles', async ({ page, browser }) => {
  test.setTimeout(150_000);
  tenant = await setUpConsoleTenant(browser, page, 'cv10');
  const { token, slug } = tenant;

  const created = await createClient(
    token,
    {
      name: 'e2e v10 fields',
      client_type: 'public',
      application_type: 'web',
      auth_method: 'none',
      redirect_uris: ['https://v10-console.example.test/callback'],
      grant_types: ['authorization_code'],
      scopes: ['openid'],
    },
    slug,
    'required',
  );
  const clientId = created.client_id;
  const readClient = () =>
    adminCall<ClientFields>(token, 'GET', tenantPath(slug, `/clients/${encodeURIComponent(clientId)}`));
  const editForm = () => page.getByRole('form', { name: 'Edit client' });
  /** Opens the collapsed Advanced section of the edit form (closed again after a reload). */
  const openAdvanced = async () => {
    const toggle = editForm().getByTestId('client-advanced-toggle');
    if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  };

  await test.step('the client form shows the 1.0 fields with their defaults', async () => {
    await openTenantPage(page, slug, `clients/${encodeURIComponent(clientId)}`);
    const form = editForm();
    await expect(form.getByTestId('client-v10-fields')).toHaveCount(0);
    await openAdvanced();
    await expect(form.getByTestId('client-v10-fields')).toBeVisible();
    await expect(form.getByTestId('client-require-par')).not.toBeChecked();
    await expect(form.getByTestId('client-kind')).toHaveValue('application');
    await expect(form.getByTestId('client-headless-native')).not.toBeChecked();
    await expectNoA11yViolations(page);
  });

  await test.step('an agent that skips consent is refused on the consent field', async () => {
    const form = editForm();
    await form.getByTestId('client-kind').selectOption('agent');
    await expect(form).toContainText('Agents always see the consent screen');
    await form.getByLabel('Consent', { exact: true }).selectOption('skip_first_party');
    await form.getByRole('button', { name: 'Save changes' }).click();
    await expect(form.getByText('The client was not saved. Fix the errors below.')).toBeVisible();
    await expect(form.getByLabel('Consent', { exact: true })).toHaveAttribute('aria-invalid', 'true');
    const stored = await readClient();
    expect(stored.client_kind).toBe('application');
    expect(stored.consent_mode).toBe('required');
  });

  await test.step('require PAR and the agent kind are saved and persist', async () => {
    const form = editForm();
    await form.getByLabel('Consent', { exact: true }).selectOption('required');
    await form.getByTestId('client-require-par').check();
    await form.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Client saved.' })).toBeVisible();
    const stored = await readClient();
    expect(stored.require_pushed_authorization_requests).toBe(true);
    expect(stored.client_kind).toBe('agent');
    expect(stored.headless_native).toBe(false);

    await page.reload();
    await openAdvanced();
    await expect(editForm().getByTestId('client-require-par')).toBeChecked();
    await expect(editForm().getByTestId('client-kind')).toHaveValue('agent');
  });

  await test.step('a first-party application becomes a native headless client', async () => {
    const form = editForm();
    await form.getByTestId('client-kind').selectOption('application');
    await form.getByLabel('Consent', { exact: true }).selectOption('skip_first_party');
    await form.getByTestId('client-headless-native').check();
    await form.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Client saved.' })).toBeVisible();
    const stored = await readClient();
    expect(stored.headless_native).toBe(true);
    expect(stored.client_kind).toBe('application');
    expect(stored.consent_mode).toBe('skip_first_party');

    await page.reload();
    await openAdvanced();
    await expect(editForm().getByTestId('client-headless-native')).toBeChecked();
  });

  const origin = `https://spa-${randomBytes(4).toString('hex')}.example.test`;
  const readTenant = () => adminCall<TenantSettingsView>(token, 'GET', tenantPath(slug));

  await test.step('tenant: require PAR for all clients and an allowed origin; a wildcard is refused', async () => {
    await openTenantPage(page, slug, 'settings');
    const form = page.getByTestId('par-headless-form');
    await expect(form).toBeVisible();
    await expect(form.getByTestId('tenant-require-par')).not.toBeChecked();
    await form.getByTestId('tenant-require-par').check();
    await form.getByTestId('headless-origin-input').fill(origin);
    await form.getByTestId('headless-origin-add').click();
    await form.getByTestId('headless-origin-input').fill('https://*.example.test');
    await form.getByTestId('headless-origin-add').click();
    await expect(form.getByTestId('headless-origin')).toHaveCount(2);
    await form.getByTestId('save-par-headless').click();
    await expect(form.getByText('The settings were not saved. Fix the errors below.')).toBeVisible();
    await expect(form.getByTestId('headless-origin-input')).toHaveAttribute('aria-invalid', 'true');
    const unchanged = await readTenant();
    expect(unchanged.settings.par.require_pushed_authorization_requests).toBe(false);
    expect(unchanged.settings.headless.allowed_origins).toEqual([]);

    await form.getByRole('button', { name: 'Remove https://*.example.test' }).click();
    await form.getByTestId('save-par-headless').click();
    await expect(page.getByRole('status').filter({ hasText: 'headless settings saved' })).toBeVisible();
    const saved = await readTenant();
    expect(saved.settings.par.require_pushed_authorization_requests).toBe(true);
    expect(saved.settings.headless.allowed_origins).toEqual([origin]);
    await expectNoA11yViolations(page);
  });

  await test.step('tenant: removing the origin and the PAR requirement is saved', async () => {
    await page.reload();
    const form = page.getByTestId('par-headless-form');
    await expect(form.locator(`[data-testid="headless-origin"][data-origin="${origin}"]`)).toBeVisible();
    await expect(form.getByTestId('tenant-require-par')).toBeChecked();
    await form.getByRole('button', { name: `Remove ${origin}` }).click();
    await form.getByTestId('tenant-require-par').uncheck();
    await form.getByTestId('save-par-headless').click();
    await expect(page.getByRole('status').filter({ hasText: 'headless settings saved' })).toBeVisible();
    const saved = await readTenant();
    expect(saved.settings.par.require_pushed_authorization_requests).toBe(false);
    expect(saved.settings.headless.allowed_origins).toEqual([]);
  });

  const profileName = `fb-${randomBytes(3).toString('hex')}`;

  await test.step('password hash profiles: create one; the signer key is never shown back', async () => {
    await openTenantPage(page, slug, 'users');
    await openSectionFromNav(page, slug, 'Password hash profiles', 'password-profiles');
    await page.getByTestId('new-profile').click();
    const dialog = page.getByRole('dialog', { name: 'New Firebase hash profile' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId('profile-signer-key')).toHaveAttribute('type', 'password');
    await expectNoA11yViolations(page);
    await dialog.getByTestId('profile-name').fill(profileName);
    await dialog.getByTestId('profile-rounds').fill('8');
    await dialog.getByTestId('profile-mem-cost').fill('14');
    await dialog.getByTestId('profile-salt-separator').fill('Bw==');
    await dialog.getByTestId('profile-signer-key').fill(FB_SIGNER_KEY);
    await dialog.getByTestId('profile-submit').click();
    await expect(dialog).toBeHidden();
    await expect(page.locator(`[data-testid="profile-row"][data-name="${profileName}"]`)).toBeVisible();
    expect(await page.content()).not.toContain(FB_SIGNER_KEY);

    const list = await adminCall<{ items: HashProfile[] }>(token, 'GET', tenantPath(slug, '/password-hash-profiles'));
    expect(list.items.map((p) => p.name)).toContain(profileName);
    expect(JSON.stringify(list)).not.toContain(FB_SIGNER_KEY);
  });

  await test.step('password hash profiles: delete it after confirming', async () => {
    await page.getByRole('button', { name: `Delete ${profileName}` }).click();
    const confirm = page.getByRole('alertdialog', { name: 'Delete this profile?' });
    await confirm.getByRole('button', { name: 'Delete profile' }).click();
    await expect(confirm).toBeHidden();
    await expect(page.locator(`[data-testid="profile-row"][data-name="${profileName}"]`)).toHaveCount(0);
    const list = await adminCall<{ items: HashProfile[] }>(token, 'GET', tenantPath(slug, '/password-hash-profiles'));
    expect(list.items.map((p) => p.name)).not.toContain(profileName);
  });
});
