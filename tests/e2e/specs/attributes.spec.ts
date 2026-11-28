// Custom user attributes (AUTH-14, plans 05-19/05-23): an administrator defines a user-editable
// enum attribute and an admin-only attribute through the admin API; the user edits the editable
// one on /ui/account/attributes (with and without JavaScript), an invalid value is refused with a
// field error, and the value reaches the relying party's ID token through the attribute's claim
// rule.
//
// Each test runs in a tenant of its own, deleted afterwards.
//
// Selectors (themes/default/templates/account_attributes.html): form attributes-form, inputs
// attr-{name}, field errors attr-{name}-error, submit attributes-form-submit, messages
// account-msg-N (data-message-key), nav entry account-nav-attributes (on every account page).
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import {
  adminToken,
  createClient,
  createUser,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type ManagementCredential,
} from '../lib/anvil';
import { adminCall, tenantPath } from '../lib/admin-api';
import { authorizationCodeFlow, jwtClaims } from '../lib/code-flow';
import { deleteTenant } from '../lib/email-code';
import { createTenant, randomSlug, signInAtTenant, tenantIssuer } from '../lib/upstream';

let creds: ManagementCredential;

test.beforeAll(async ({ browser }) => {
  creds = await sharedManagementCredential(browser);
});

const DEPARTMENTS = ['engineering', 'sales', 'support'];

interface AttributeTenant {
  slug: string;
  userId: string;
  email: string;
  password: string;
}

/**
 * A tenant with `department` (user-editable enum, mapped to the `department` ID-token claim) and
 * `cost_center` (admin-only), and one verified user whose cost center the administrator set.
 */
async function attributeTenant(token: string): Promise<AttributeTenant> {
  const slug = randomSlug('attr');
  await createTenant(token, slug);
  await adminCall(token, 'PUT', tenantPath(slug, '/attributes/department'), {
    schema: { type: 'string', title: 'Department', enum: DEPARTMENTS },
    required: false,
    user_editable: true,
    claim: { claim: 'department', tokens: ['id_token'], scope: null },
    position: 0,
  });
  await adminCall(token, 'PUT', tenantPath(slug, '/attributes/cost_center'), {
    schema: { type: 'string', title: 'Cost center', maxLength: 32 },
    required: false,
    user_editable: false,
    position: 1,
  });
  const email = randomEmail('attr');
  const password = randomPassword();
  const user = await createUser(token, { email, password, email_verified: true }, slug);
  if (!user.id) throw new Error('created user has no id');
  await adminCall(token, 'PUT', tenantPath(slug, `/users/${user.id}/attributes`), {
    values: { cost_center: 'CC-1042' },
  });
  return { slug, userId: user.id, email, password };
}

async function storedValues(token: string, t: AttributeTenant): Promise<Record<string, unknown>> {
  const body = await adminCall<{ values: Record<string, unknown> }>(
    token,
    'GET',
    tenantPath(t.slug, `/users/${t.userId}/attributes`),
  );
  return body.values;
}

async function openAttributes(page: Page, slug: string): Promise<void> {
  await page.goto(`${tenantIssuer(slug)}/ui/account/attributes`);
  await expect(page.locator('#attributes-form')).toBeVisible();
}

async function save(page: Page): Promise<void> {
  await page.locator('#attributes-form-submit').click();
}

test('the user edits an editable attribute, invalid values are refused and the claim reaches the ID token', async ({
  page,
}) => {
  const token = await adminToken(creds);
  const t = await attributeTenant(token);
  try {
    await signInAtTenant(page, t.slug, t.email, t.password);

    // Every account page carries the Attributes entry (05-33): from the profile page it opens the
    // attributes page.
    await page.goto(`${tenantIssuer(t.slug)}/ui/account/profile`);
    const navEntry = page.locator('#account-nav-attributes');
    await expect(navEntry).toBeVisible();
    await navEntry.click();
    await expect(page).toHaveURL(/\/ui\/account\/attributes$/);
    await expect(page.locator('#attributes-form')).toBeVisible();
    await expect(page.locator('#account-nav-attributes')).toHaveAttribute('aria-current', 'page');

    await openAttributes(page, t.slug);

    // Only the user-editable attribute is offered; the admin-only one is not shown at all.
    await expect(page.locator('#account-nav-attributes')).toBeVisible();
    await expect(page.locator('#attr-department')).toBeVisible();
    await expect(page.locator('#attr-cost_center')).toHaveCount(0);
    await expect(page.locator('#attr-cost_center-value')).toHaveCount(0);

    await page.locator('#attr-department').selectOption('sales');
    await save(page);
    await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'attributes.saved');
    await expect(page.locator('#attr-department')).toHaveValue('sales');
    expect(await storedValues(token, t)).toEqual({ cost_center: 'CC-1042', department: 'sales' });

    // A value outside the enum (an option added to the page, as a tampered form would send) is
    // refused with a field error, and nothing changes.
    await page.locator('#attr-department').evaluate((el) => {
      const select = el as HTMLSelectElement;
      const option = document.createElement('option');
      option.value = 'marketing';
      option.textContent = 'marketing';
      select.append(option);
      select.value = 'marketing';
    });
    await save(page);
    await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'attributes.invalid');
    await expect(page.locator('#attr-department-error')).toBeVisible();
    await expect(page.locator('#attr-department')).toHaveAttribute('aria-invalid', 'true');
    expect((await storedValues(token, t)).department).toBe('sales');
    // Post/Redirect/Get (07.1-21): the refusal is a GET; reloading it shows the plain form.
    await expect(page).toHaveURL(
      (url) => url.pathname.endsWith('/ui/account/attributes') && url.searchParams.has('flow'),
    );
    await page.reload();
    await expect(page.locator('#attr-department-error')).toHaveCount(0);
    await expect(page.locator('#attr-department')).toHaveValue('sales');

    // The mapped claim is in the relying party's ID token (the session already exists).
    const redirectUri = 'https://attributes-rp.example.test/callback';
    const client = await createClient(
      token,
      {
        name: 'attributes RP',
        client_type: 'confidential',
        application_type: 'web',
        auth_method: 'client_secret_basic',
        redirect_uris: [redirectUri],
        grant_types: ['authorization_code'],
        scopes: ['openid', 'email'],
      },
      t.slug,
    );
    if (!client.client_secret) throw new Error('client created without a secret');
    const tokens = await authorizationCodeFlow(
      page,
      { client_id: client.client_id, client_secret: client.client_secret, redirect_uri: redirectUri },
      'openid email',
      async () => {},
      tenantIssuer(t.slug),
    );
    if (!tokens.id_token) throw new Error('no id_token');
    const claims = jwtClaims(tokens.id_token);
    expect(claims.department).toBe('sales');
    expect(claims).not.toHaveProperty('cost_center');
  } finally {
    await deleteTenant(token, t.slug);
  }
});

test('the attributes page works without JavaScript', async ({ browser }) => {
  const token = await adminToken(creds);
  const t = await attributeTenant(token);
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await signInAtTenant(page, t.slug, t.email, t.password);
    await openAttributes(page, t.slug);
    await page.locator('#attr-department').selectOption('support');
    await save(page);
    await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'attributes.saved');
    await expect(page.locator('#attr-department')).toHaveValue('support');
    expect((await storedValues(token, t)).department).toBe('support');

    // Clearing the optional value removes it.
    await page.locator('#attr-department').selectOption('');
    await save(page);
    await expect(page.locator('#account-msg-1')).toHaveAttribute('data-message-key', 'attributes.saved');
    expect(await storedValues(token, t)).toEqual({ cost_center: 'CC-1042' });
  } finally {
    await context.close();
    await deleteTenant(token, t.slug);
  }
});
