// ADM-02 "connections, branding" / ORG-03 / ORG-04 from the console (06-23): in an organization an
// operator creates a SAML connection from the mock IdP's metadata (the server refuses the mock's
// plain-http sign-in location, at import and at save, shown next to the field; the spec switches the
// location to https because it never signs in through the connection), copies the SP values, adds a domain and verifies it through
// the suite's mock DNS (publishTxt), routes the domain to the SAML connection with passwords still
// allowed (allowed for a connection without sign-ins), sees that turning passwords off is refused
// with the API's explanation (nobody has signed in through the connection yet), creates an org OIDC
// connection against the mock OIDC IdP (write-only secret), brands the organization and finds both
// connections read-only in the tenant's connection list. axe runs on every tab and dialog.
//
// Runs in a fresh tenant of its own, deleted afterwards, signed in as a console administrator
// created with createConsoleAdmin. The default tenant never gets a routed domain (its sign-in page
// stays the combined form for every other spec).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE, E2E_DNS_CONTROL_URL (see tests/e2e/run.sh).

import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { anvilUrl, randomPassword } from '../lib/anvil';
import { allowClipboard } from '../lib/console-v04';
import {
  createOrg,
  openSectionFromNav,
  openTenantPage,
  orgBrandingPrimary,
  orgConnections,
  orgDomains,
  randomOrgDomain,
  setUpConsoleTenant,
  type ConsoleTenant,
} from '../lib/console-v10';
import { publishTxt, removeTxt } from '../lib/mock-dns';
import { mockIdpRedirectUri, startMockIdp, type MockIdp } from '../lib/mock-idp';
import { startMockSamlIdp, type MockSamlIdp } from '../lib/mock-saml-idp';
import { tenantIssuer } from '../lib/upstream';

let tenant: ConsoleTenant | undefined;
let samlIdp: MockSamlIdp | undefined;
let oidcIdp: MockIdp | undefined;
let publishedRecord: string | undefined;

test.afterAll(async () => {
  if (publishedRecord) await removeTxt(publishedRecord).catch(() => undefined);
  await samlIdp?.close();
  await oidcIdp?.stop();
  await tenant?.cleanup();
});

test('console: org SAML/OIDC connections, verified domain with routing, org branding', async ({ page, browser }) => {
  test.setTimeout(180_000);
  tenant = await setUpConsoleTenant(browser, page, 'csso');
  const { token, slug } = tenant;
  expect(slug).not.toBe('default');
  await allowClipboard(page);

  const org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  samlIdp = await startMockSamlIdp();
  const issuer = tenantIssuer(slug);
  const sectionNav = page.getByRole('navigation', { name: 'Organization sections' });

  await test.step('the organization has Connections, Domains and Branding sections', async () => {
    await openTenantPage(page, slug, `organizations/${org.id}`);
    await expect(page.getByRole('heading', { level: 1, name: 'Acme Corp' })).toBeVisible();
    for (const name of ['Connections', 'Domains', 'Branding']) {
      await expect(sectionNav.getByRole('link', { name, exact: true })).toBeVisible();
    }
    await sectionNav.getByRole('link', { name: 'Connections', exact: true }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${org.id}/connections`);
    await expect(sectionNav.getByRole('link', { name: 'Connections', exact: true })).toHaveAttribute('aria-current', 'page');
    await expect(page.getByText('No connections yet.')).toBeVisible();
    // The suite runs with ANVILID_SAML_EXPERIMENTAL=true: SAML is offered, marked experimental.
    await expect(page.getByTestId('org-connection-kind-saml')).toBeEnabled();
    await expect(page.getByTestId('saml-unavailable')).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  let samlId = '';
  await test.step('create a SAML connection from the mock IdP metadata', async () => {
    const idp = samlIdp;
    if (!idp) throw new Error('mock SAML IdP not started');
    await page.getByTestId('org-connection-kind-saml').check();
    await expect(page.getByTestId('saml-experimental').first()).toBeVisible();

    // The mock serves plain http on loopback. AnvilID requires an https sign-in URL, so the
    // metadata as served is refused, with the reason next to the XML field and nothing filled in.
    await page.getByTestId('saml-metadata-xml').fill(idp.metadataXml);
    await page.getByTestId('saml-import-metadata').click();
    const importForm = page.getByTestId('saml-metadata-form');
    await expect(importForm).toContainText('is not usable SAML IdP metadata');
    await expect(page.getByTestId('saml-metadata-xml')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByTestId('saml-idp-entity-id')).toHaveValue('');
    await expectNoA11yViolations(page);

    // The same metadata with an https sign-in location (this spec never signs in through the
    // connection; the SAML sign-in journey is the saml spec's) imports: entity ID, sign-in URL and
    // the signing certificate are filled in.
    const httpsSsoUrl = idp.ssoUrl.replace(/^http:/, 'https:');
    const metadata = idp.metadataXml.replace(`Location="${idp.ssoUrl}"`, `Location="${httpsSsoUrl}"`);
    expect(metadata).not.toBe(idp.metadataXml);
    await page.getByTestId('saml-metadata-xml').fill(metadata);
    await page.getByTestId('saml-import-metadata').click();
    await expect(importForm).toContainText('Metadata imported');
    await expect(page.getByTestId('saml-idp-entity-id')).toHaveValue(idp.entityId);
    await expect(page.getByTestId('saml-sso-url')).toHaveValue(httpsSsoUrl);
    await expect(page.getByTestId('saml-cert-1')).toHaveValue(/BEGIN CERTIFICATE/);
    // Certificates are public: subject and expiry are shown (the mock's cert is valid for 7 days).
    await expect(page.getByTestId('saml-cert-info')).toContainText('AnvilID e2e mock SAML IdP');
    await expect(page.getByTestId('saml-cert-expired')).toHaveCount(0);
    await expectNoA11yViolations(page);

    await page.getByTestId('saml-display-name').fill('Acme SAML');
    await page.getByTestId('saml-slug').fill('acme-saml');
    await page.getByTestId('saml-attr-email').fill('email');
    // A plain-http sign-in URL entered by hand is refused by the API, shown next to the field.
    await page.getByTestId('saml-sso-url').fill(idp.ssoUrl);
    await page.getByTestId('saml-submit').click();
    const form = page.getByTestId('saml-connection-form');
    await expect(form).toContainText('The connection was not saved');
    await expect(form).toContainText('must be an https URL');
    await expect(page.getByTestId('saml-sso-url')).toHaveAttribute('aria-invalid', 'true');
    expect(await orgConnections(token, slug, org.id)).toHaveLength(0);
    await expectNoA11yViolations(page);

    await page.getByTestId('saml-sso-url').fill(httpsSsoUrl);
    await page.getByTestId('saml-submit').click();

    const panel = page.getByRole('dialog', { name: 'Connection Acme SAML' });
    await expect(panel).toBeVisible();
    await expect(panel.getByTestId('saml-experimental').first()).toBeVisible();
    await expect(panel.getByTestId('saml-sp-entity-id')).toHaveText(`${issuer}/saml/acme-saml`);
    await expect(panel.getByTestId('saml-sp-acs-url')).toHaveText(`${issuer}/ui/login/saml/acme-saml/acs`);
    await expect(panel.getByTestId('saml-sp-metadata-url')).toHaveText(`${issuer}/saml/acme-saml/metadata`);
    await panel.getByTestId('copy-saml-sp-acs-url').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`${issuer}/ui/login/saml/acme-saml/acs`);
    await expectNoA11yViolations(page);

    const stored = (await orgConnections(token, slug, org.id)).find((c) => c.slug === 'acme-saml');
    expect(stored?.kind).toBe('saml');
    expect(stored?.organization).toBe(org.id);
    expect(stored?.config.idp_entity_id).toBe(idp.entityId);
    samlId = stored?.id ?? '';
    await panel.getByTestId('close-org-connection').click();
    await expect(panel).toBeHidden();
    await expect(page.getByTestId('org-connection-acme-saml')).toBeVisible();
  });

  const domain = randomOrgDomain();
  await test.step('add a domain and verify it through the mock DNS', async () => {
    await sectionNav.getByRole('link', { name: 'Domains', exact: true }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${org.id}/domains`);
    await expect(page.getByText('No domains yet.')).toBeVisible();
    await page.getByTestId('add-domain-input').fill(domain);
    await page.getByTestId('add-domain').click();

    const card = page.locator(`[data-testid="domain-card"][data-domain="${domain}"]`);
    await expect(card).toHaveAttribute('data-status', 'pending');
    await expect(card.getByTestId('domain-status')).toHaveText('Pending');
    const recordName = (await card.getByTestId('domain-record-name').textContent()) ?? '';
    const recordValue = (await card.getByTestId('domain-record-value').textContent()) ?? '';
    expect(recordName).toBe(`_anvilid-challenge.${domain}.`);
    expect(recordValue).toMatch(/^anvilid-domain-verification=\S+$/);
    await card.getByTestId('copy-domain-record-value').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(recordValue);
    // Before the record exists the claim stays pending (one answer for every failure).
    await card.getByTestId('verify-domain').click();
    await expect(card).toContainText('not found yet');
    await expect(card).toHaveAttribute('data-status', 'pending');
    await expectNoA11yViolations(page);

    publishedRecord = recordName;
    await publishTxt(recordName, [recordValue]);
    await card.getByTestId('verify-domain').click();
    await expect(card).toHaveAttribute('data-status', 'verified');
    await expect(card.getByTestId('domain-status')).toHaveText('Verified');
    await expect(card.getByTestId('verify-domain')).toHaveCount(0);
    await expect(card.getByTestId('domain-checks')).toContainText('Verified');
    const stored = (await orgDomains(token, slug, org.id)).find((d) => d.domain === domain);
    expect(stored?.status).toBe('verified');
    expect(stored?.allow_local_password).toBe(true);
    await expectNoA11yViolations(page);
  });

  await test.step('route the domain to the SAML connection with passwords allowed', async () => {
    const card = page.locator(`[data-testid="domain-card"][data-domain="${domain}"]`);
    await card.getByTestId('domain-connection').selectOption({ label: 'Acme SAML' });
    await card.getByTestId('domain-routing').check();
    // Default on, with the trade-off explained.
    await expect(card.getByTestId('domain-allow-password')).toBeChecked();
    await expect(card.getByTestId('domain-routing-form')).toContainText('cannot lock them out');
    await card.getByTestId('save-domain-routing').click();
    await expect(card).toContainText('Routing saved.');
    const stored = (await orgDomains(token, slug, org.id)).find((d) => d.domain === domain);
    expect(stored?.routing).toBe(true);
    expect(stored?.connection_id).toBe(samlId);
    expect(stored?.allow_local_password).toBe(true);
    await expectNoA11yViolations(page);
  });

  await test.step('turning passwords off is refused while nobody signed in through the connection', async () => {
    const card = page.locator(`[data-testid="domain-card"][data-domain="${domain}"]`);
    await card.getByTestId('domain-allow-password').uncheck();
    await card.getByTestId('save-domain-routing').click();
    const error = card.getByTestId('domain-routing-error');
    await expect(error).toBeVisible();
    await expect(error).toContainText('at least one sign-in');
    const stored = (await orgDomains(token, slug, org.id)).find((d) => d.domain === domain);
    expect(stored?.allow_local_password).toBe(true);
    expect(stored?.routing).toBe(true);
    await expectNoA11yViolations(page);
  });

  await test.step('create an org OIDC connection against the mock OIDC IdP', async () => {
    const clientId = `csso-${randomBytes(4).toString('hex')}`;
    oidcIdp = await startMockIdp({
      kind: 'apple',
      clientId,
      redirectUri: mockIdpRedirectUri(anvilUrl(), slug, 'acme-oidc'),
    });
    const secret = randomPassword();
    await sectionNav.getByRole('link', { name: 'Connections', exact: true }).click();
    await page.getByTestId('org-connection-kind-oidc').check();
    const form = page.getByTestId('connection-form');
    await form.getByLabel('Display name').fill('Acme OIDC');
    await form.getByLabel('Slug').fill('acme-oidc');
    await form.getByLabel('Issuer').fill(oidcIdp.url);
    await form.getByLabel('Client ID').fill(clientId);
    await page.getByTestId('connection-secret-input').fill(secret);
    await expectNoA11yViolations(page);
    await page.getByTestId('connection-submit').click();

    const panel = page.getByRole('dialog', { name: 'Connection Acme OIDC' });
    await expect(panel).toBeVisible();
    await expect(panel.getByTestId('connection-redirect-uri')).toHaveText(mockIdpRedirectUri(anvilUrl(), slug, 'acme-oidc'));
    await expect(panel.getByTestId('connection-secret-status')).toContainText('Configured');
    await expect(panel.getByTestId('saml-sp-values')).toHaveCount(0);
    // Write-only: the secret is never rendered.
    expect(await page.content()).not.toContain(secret);
    await expectNoA11yViolations(page);
    const stored = (await orgConnections(token, slug, org.id)).find((c) => c.slug === 'acme-oidc');
    expect(stored?.kind).toBe('oidc');
    expect(stored?.secret_configured).toBe(true);
    await panel.getByTestId('close-org-connection').click();
    await expect(panel).toBeHidden();
  });

  await test.step('brand the organization', async () => {
    await sectionNav.getByRole('link', { name: 'Branding', exact: true }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${org.id}/branding`);
    await expect(page.getByTestId('branding-state')).toContainText('Not customised: this organization uses the tenant theme.');
    await page.getByTestId('color-colors.primary').fill('#7a1fa2');
    await expect(page.getByTestId('publish-theme')).toBeEnabled({ timeout: 10_000 });
    await page.getByTestId('publish-theme').click();
    await expect(page.getByText('Theme published.')).toBeVisible();
    expect(await orgBrandingPrimary(token, slug, org.id)).toBe('#7a1fa2');
    await expectNoA11yViolations(page);
  });

  await test.step('the tenant connection list shows both org connections read-only', async () => {
    await openSectionFromNav(page, slug, 'Connections', 'connections');
    for (const name of ['Acme SAML', 'Acme OIDC']) {
      const row = page.getByRole('row').filter({ hasText: name });
      await expect(row.getByTestId('connection-organization')).toContainText('Acme Corp');
      await expect(row.getByTestId('connection-organization')).toContainText('Read-only here');
    }
    await expectNoA11yViolations(page);
    await page.getByRole('row').filter({ hasText: 'Acme SAML' }).getByRole('link', { name: 'Acme SAML' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${org.id}/connections`);
  });
});
