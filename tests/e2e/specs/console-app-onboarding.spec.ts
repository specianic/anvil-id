// J2 "Add login to my app" (07.1-16: C-H5, C-H7, C-M1..M4, C-M13, C-L3): creating a client starts
// with "What are you building?" and each app type preselects working defaults (SPA and native are
// public with PKCE, web is confidential, machine-to-machine has no sign-in fields, agents always ask
// for consent). A native or single-page app switched to Confidential gets a warning. The created
// page and the client page show an Integration card whose Issuer and Discovery URL match the
// tenant's discovery document, each with a Copy button. Redirect URI and home page refusals show
// the server's message at the field. The built-in console client offers no Delete; deleting another
// client needs its name typed.
//
// Runs in a tenant of its own (deleted afterwards). After consoleLogin the spec goes to the client
// pages by URL and never asserts the console landing page.
//
// Console test ids (admin-ui, plan 07.1-16): picker `app-type-picker` (radios named after the app
// type), `confidential-warning`, `client-advanced-toggle`, `integration-card` with
// `integration-issuer`, `integration-discovery-url`, `integration-client-id`,
// `integration-client-secret`, `integration-env`; `built-in-client`; `danger-zone`,
// `danger-zone-confirm-input`; `created-client-id`, `created-client-secret`.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminCall, tenantPath } from '../lib/admin-api';
import { openTenantPage, setUpConsoleTenant, takeOneTimeSecret, type ConsoleTenant } from '../lib/console-v04';
import { expectNoHorizontalOverflow } from '../lib/layout';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

interface TenantView {
  issuer: string;
  discovery_url: string;
}

interface StoredClient {
  client_id: string;
  name: string;
  client_type: 'public' | 'confidential';
  application_type: 'web' | 'native';
  auth_method: string;
  grant_types: string[];
  scopes: string[];
  require_pkce: boolean;
  consent_mode: 'required' | 'skip_first_party';
  client_kind: 'application' | 'agent';
  redirect_uris: string[];
  registration_source: string;
}

type AppTypeTitle = 'Web app' | 'Single-page app' | 'Native or mobile app' | 'Machine-to-machine' | 'AI agent';

const newForm = (page: Page) => page.getByRole('form', { name: 'New client' });

async function openNewClient(page: Page, slug: string): Promise<void> {
  await openTenantPage(page, slug, 'clients/new');
  await expect(page.getByRole('heading', { level: 1, name: 'New client' })).toBeVisible();
  await expect(page.getByTestId('app-type-picker')).toBeVisible();
}

async function pick(page: Page, title: AppTypeTitle): Promise<void> {
  const radio = page.getByTestId('app-type-picker').getByRole('radio', { name: title });
  await radio.check();
  await expect(radio).toBeChecked();
}

async function openAdvanced(page: Page): Promise<void> {
  const toggle = newForm(page).getByTestId('client-advanced-toggle');
  if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
}

/** The Integration card shows the tenant's issuer and discovery URL, each with a Copy button. */
async function expectIntegrationCard(page: Page, view: TenantView, clientId: string): Promise<void> {
  const card = page.getByTestId('integration-card');
  await expect(card).toBeVisible();
  await expect(card.getByTestId('integration-issuer').getByRole('textbox', { name: 'Issuer' })).toHaveValue(view.issuer);
  await expect(card.getByTestId('integration-discovery-url').getByRole('textbox', { name: 'Discovery URL' })).toHaveValue(
    view.discovery_url,
  );
  await expect(card.getByTestId('integration-client-id').getByRole('textbox', { name: 'Client ID' })).toHaveValue(clientId);
  await expect(card.getByRole('button', { name: 'Copy Issuer' })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Copy Discovery URL' })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Copy Client ID' })).toBeVisible();
  await expect(card.getByTestId('integration-env')).toContainText(`ANVILID_ISSUER=${view.issuer}`);
  await expect(card.getByTestId('integration-env')).toContainText(`ANVILID_CLIENT_ID=${clientId}`);
}

test('console: guided app creation by type, integration values, safe client deletion', async ({ page, browser }) => {
  test.setTimeout(240_000);
  tenant = await setUpConsoleTenant(browser, page, 'onb');
  const { token, slug } = tenant;
  const readClient = (clientId: string) =>
    adminCall<StoredClient>(token, 'GET', tenantPath(slug, `/clients/${encodeURIComponent(clientId)}`));

  const view = await adminCall<TenantView>(token, 'GET', tenantPath(slug));
  await test.step("the tenant view's issuer and discovery URL are the discovery document's", async () => {
    expect(view.discovery_url).toBe(`${view.issuer}/.well-known/openid-configuration`);
    const res = await fetch(`${view.issuer}/.well-known/openid-configuration`, { headers: { accept: 'application/json' } });
    expect(res.status).toBe(200);
    const doc = (await res.json()) as { issuer: string };
    expect(doc.issuer).toBe(view.issuer);
  });

  await test.step('the new client page starts with the type picker (Web preselected); axe and narrow layout', async () => {
    await openNewClient(page, slug);
    await expect(page.getByRole('radio', { name: 'Web app' })).toBeChecked();
    await expectNoA11yViolations(page);
    const size = page.viewportSize();
    await expectNoHorizontalOverflow(page);
    if (size) await page.setViewportSize(size);
  });

  const created: Partial<Record<AppTypeTitle, string>> = {};

  /** Fills the name (and a redirect URI), creates, checks the Integration card; returns the client id. */
  async function createAndCheck(title: AppTypeTitle, redirect: string | null, confidential: boolean): Promise<string> {
    const form = newForm(page);
    await form.getByLabel('Name', { exact: true }).fill(`e2e ${title}`);
    if (redirect !== null) await form.getByLabel('Redirect URIs', { exact: true }).fill(redirect);
    await form.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Client created' })).toBeVisible();
    const clientId = ((await page.getByTestId('created-client-id').textContent()) ?? '').trim();
    expect(clientId).not.toBe('');
    await expectIntegrationCard(page, view, clientId);
    if (confidential) {
      await expect(page.getByTestId('integration-client-secret')).toBeVisible();
      await expect(page.getByTestId('integration-env')).toContainText('ANVILID_CLIENT_SECRET=');
      await expectNoA11yViolations(page);
      // Dismissing the one-time secret removes it everywhere, the Integration card included.
      await takeOneTimeSecret(page, 'created-client-secret', false);
      await expect(page.getByTestId('integration-client-secret')).toHaveCount(0);
      await expect(page.getByTestId('integration-env')).not.toContainText('ANVILID_CLIENT_SECRET=');
    } else {
      await expect(page.getByTestId('integration-client-secret')).toHaveCount(0);
      await expect(page.getByTestId('integration-env')).not.toContainText('ANVILID_CLIENT_SECRET=');
      await expectNoA11yViolations(page);
    }
    created[title] = clientId;
    return clientId;
  }

  await test.step('Web app: confidential, client secret (HTTP Basic), code + refresh, PKCE, consent skipped', async () => {
    const form = newForm(page);
    await pick(page, 'Web app');
    await expect(form.getByLabel('Client type')).toHaveValue('confidential');
    await expect(form.getByLabel('Token endpoint authentication')).toHaveValue('client_secret_basic');
    await expect(form.getByLabel('Token endpoint authentication').locator('option:checked')).toHaveText(
      'Client secret (HTTP Basic)',
    );
    await expect(form.getByRole('checkbox', { name: 'User sign-in (authorization code)' })).toBeChecked();
    await expect(form.getByRole('checkbox', { name: 'Stay signed in (refresh token)' })).toBeChecked();
    await expect(form.getByRole('checkbox', { name: 'Service credentials (client credentials)' })).not.toBeChecked();
    await expect(form.getByLabel('Require PKCE')).toBeChecked();
    await expect(form.getByLabel('Consent', { exact: true })).toHaveValue('skip_first_party');
    await expect(form.getByTestId('confidential-warning')).toHaveCount(0);

    const id = await createAndCheck('Web app', 'https://onboarding-web.example.test/callback', true);
    const stored = await readClient(id);
    expect(stored).toMatchObject({
      client_type: 'confidential',
      application_type: 'web',
      auth_method: 'client_secret_basic',
      require_pkce: true,
      consent_mode: 'skip_first_party',
      client_kind: 'application',
      registration_source: 'static',
    });
    expect([...stored.grant_types].sort()).toEqual(['authorization_code', 'refresh_token']);
  });

  await test.step('Single-page app: public, no secret, PKCE forced, consent skipped', async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await pick(page, 'Single-page app');
    await expect(form.getByLabel('Client type')).toHaveValue('public');
    await expect(form.getByLabel('Token endpoint authentication')).toHaveCount(0);
    await expect(form.getByLabel('Require PKCE')).toBeChecked();
    await expect(form.getByLabel('Require PKCE')).toBeDisabled();
    await expect(form.getByLabel('Consent', { exact: true })).toHaveValue('skip_first_party');
    await expect(form.getByLabel('Redirect URIs', { exact: true })).toHaveAttribute('placeholder', /localhost:5173/);

    const id = await createAndCheck('Single-page app', 'http://localhost:5173/callback', false);
    const stored = await readClient(id);
    expect(stored).toMatchObject({
      client_type: 'public',
      application_type: 'web',
      auth_method: 'none',
      require_pkce: true,
      consent_mode: 'skip_first_party',
    });
  });

  await test.step('Native app: public, application type native; Confidential triggers the shipped-secret warning', async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await pick(page, 'Native or mobile app');
    await expect(form.getByLabel('Client type')).toHaveValue('public');
    await expect(form.getByLabel('Require PKCE')).toBeChecked();
    await expect(form.getByLabel('Consent', { exact: true })).toHaveValue('skip_first_party');
    await expect(form.getByLabel('Redirect URIs', { exact: true })).toHaveAttribute('placeholder', /com\.example\.app:\/callback/);
    await openAdvanced(page);
    await expect(form.getByLabel('Application type')).toHaveValue('native');

    await form.getByLabel('Client type').selectOption('confidential');
    const warning = form.getByTestId('confidential-warning');
    await expect(warning).toBeVisible();
    await expect(warning).toContainText('A secret in a shipped app is not secret');
    await expectNoA11yViolations(page);
    await form.getByLabel('Client type').selectOption('public');
    await expect(warning).toHaveCount(0);

    const id = await createAndCheck('Native or mobile app', 'com.example.onboarding:/callback', false);
    const stored = await readClient(id);
    expect(stored).toMatchObject({
      client_type: 'public',
      application_type: 'native',
      auth_method: 'none',
      require_pkce: true,
      consent_mode: 'skip_first_party',
    });
  });

  await test.step('Single-page app switched to Confidential also warns', async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await pick(page, 'Single-page app');
    await form.getByLabel('Client type').selectOption('confidential');
    await expect(form.getByTestId('confidential-warning')).toBeVisible();
    // Back to Web (the page's starting values): the form is clean again for the next navigation.
    await pick(page, 'Web app');
    await expect(form.getByTestId('confidential-warning')).toHaveCount(0);
  });

  await test.step('Machine-to-machine: client credentials only, no sign-in fields, API scopes', async () => {
    const form = newForm(page);
    await pick(page, 'Machine-to-machine');
    await expect(form.getByLabel('Client type')).toHaveValue('confidential');
    await expect(form.getByRole('checkbox', { name: 'Service credentials (client credentials)' })).toBeChecked();
    await expect(form.getByRole('checkbox', { name: 'User sign-in (authorization code)' })).not.toBeChecked();
    await expect(form.getByRole('checkbox', { name: 'Stay signed in (refresh token)' })).not.toBeChecked();
    await expect(form.getByLabel('Redirect URIs', { exact: true })).toHaveCount(0);
    await expect(form.getByLabel('Post-logout redirect URIs')).toHaveCount(0);
    await expect(form.getByLabel('Consent', { exact: true })).toHaveCount(0);
    await expect(form.getByLabel('Require PKCE')).toHaveCount(0);
    await expect(form.getByLabel('Scopes')).toHaveValue('');
    await expect(form.getByLabel('Scopes')).not.toHaveAttribute('placeholder', /openid/);
    await openAdvanced(page);
    await expect(form.getByLabel('ID token signing algorithm')).toHaveCount(0);
    await expectNoA11yViolations(page);
    await form.getByLabel('Scopes').fill('orders:read');

    const id = await createAndCheck('Machine-to-machine', null, true);
    const stored = await readClient(id);
    expect(stored).toMatchObject({ client_type: 'confidential', auth_method: 'client_secret_basic', redirect_uris: [] });
    expect(stored.grant_types).toEqual(['client_credentials']);
    expect(stored.scopes).toEqual(['orders:read']);
  });

  await test.step('AI agent: client kind agent, consent required', async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await pick(page, 'AI agent');
    await expect(form.getByLabel('Consent', { exact: true })).toHaveValue('required');
    await openAdvanced(page);
    await expect(form.getByTestId('client-kind')).toHaveValue('agent');

    const id = await createAndCheck('AI agent', 'https://onboarding-agent.example.test/callback', true);
    const stored = await readClient(id);
    expect(stored).toMatchObject({ client_kind: 'agent', consent_mode: 'required' });
  });

  await test.step('the client page shows the Integration card too (no secret)', async () => {
    const id = created['Single-page app'] ?? '';
    await openTenantPage(page, slug, `clients/${encodeURIComponent(id)}`);
    await expect(page.getByRole('heading', { level: 1, name: 'e2e Single-page app' })).toBeVisible();
    await expectIntegrationCard(page, view, id);
    await expect(page.getByTestId('integration-card').getByRole('textbox', { name: 'Redirect URI' })).toHaveValue(
      'http://localhost:5173/callback',
    );
    await expect(page.getByTestId('integration-client-secret')).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  await test.step('a redirect URI without a scheme names the missing scheme; http on localhost is accepted', async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await form.getByLabel('Name', { exact: true }).fill('e2e redirect message');
    const redirect = form.getByLabel('Redirect URIs', { exact: true });
    await redirect.fill('localhost:5173/cb');
    await form.getByRole('button', { name: 'Create client' }).click();
    await expect(form.getByText('The client was not saved. Fix the errors below.')).toBeVisible();
    await expect(redirect).toHaveAttribute('aria-invalid', 'true');
    await expect(form.locator('[data-field-error]')).toContainText('missing its scheme');

    await redirect.fill('http://localhost:5173/cb');
    await form.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Client created' })).toBeVisible();
    await takeOneTimeSecret(page, 'created-client-secret', false);
  });

  await test.step("an unsafe App home page is refused with the server's message", async () => {
    await openNewClient(page, slug);
    const form = newForm(page);
    await form.getByLabel('Name', { exact: true }).fill('e2e home page');
    await form.getByLabel('Redirect URIs', { exact: true }).fill('https://onboarding-home.example.test/callback');
    const home = form.getByLabel('App home page');
    await home.fill('javascript:alert(1)');
    await form.getByRole('button', { name: 'Create client' }).click();
    await expect(form.getByText('The client was not saved. Fix the errors below.')).toBeVisible();
    await expect(home).toHaveAttribute('aria-invalid', 'true');
    await expect(form.locator('[data-field-error]')).toContainText('absolute https URL');

    await home.fill('https://onboarding-home.example.test/');
    await form.getByLabel('Sign-in start URL').fill('https://onboarding-home.example.test/login');
    await form.getByRole('button', { name: 'Create client' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Client created' })).toBeVisible();
    const clientId = ((await page.getByTestId('created-client-id').textContent()) ?? '').trim();
    await takeOneTimeSecret(page, 'created-client-secret', false);
    const stored = await adminCall<{ client_uri: string | null; initiate_login_uri: string | null }>(
      token,
      'GET',
      tenantPath(slug, `/clients/${encodeURIComponent(clientId)}`),
    );
    expect(stored.client_uri).toBe('https://onboarding-home.example.test/');
    expect(stored.initiate_login_uri).toBe('https://onboarding-home.example.test/login');
  });

  await test.step('the clients list links names, shows ids in mono and who created each client', async () => {
    await openTenantPage(page, slug, 'clients');
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible();
    const id = created['Web app'] ?? '';
    const link = page.getByRole('link', { name: 'e2e Web app' });
    await expect(link).toBeVisible();
    await expect(link).toContainText(id);
    await expect(page.getByRole('columnheader', { name: 'Created by' })).toBeVisible();
    await expect(page.getByTestId(`client-source-${id}`)).toHaveText('Admin');
    await expectNoA11yViolations(page);
  });

  await test.step('the built-in console client has no Delete', async () => {
    await openTenantPage(page, 'system', 'clients/anvil-console');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByTestId('built-in-client')).toBeVisible();
    await expect(page.getByTestId('danger-zone')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Delete/ })).toHaveCount(0);
  });

  await test.step('deleting a client requires typing its name', async () => {
    const id = created['Native or mobile app'] ?? '';
    await openTenantPage(page, slug, `clients/${encodeURIComponent(id)}`);
    await expect(page.getByRole('heading', { level: 1, name: 'e2e Native or mobile app' })).toBeVisible();
    await page.getByTestId('danger-zone').getByRole('button', { name: 'Delete client' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this client?' });
    await expect(dialog).toBeVisible();
    const confirm = dialog.getByRole('button', { name: 'Delete client' });
    await expect(confirm).toBeDisabled();
    await dialog.getByTestId('danger-zone-confirm-input').fill('e2e native or mobile app');
    await expect(confirm).toBeDisabled();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    await readClient(id);

    await page.getByTestId('danger-zone').getByRole('button', { name: 'Delete client' }).click();
    await dialog.getByTestId('danger-zone-confirm-input').fill('e2e Native or mobile app');
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/clients`);
    await adminCall(token, 'GET', tenantPath(slug, `/clients/${encodeURIComponent(id)}`), undefined, 404);
  });
});
