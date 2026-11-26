// ADM-02 "organizations" / ORG-02 from the console (06-21): an operator creates an organization,
// defines an org role, adds a tenant user as a member and gives them the role within the org,
// invites a new address (listed as pending; the console never shows a token), revokes another
// invitation, sees the membership on the user's page, sets a client's organization policy and
// deletes a throwaway organization. Every new page and dialog passes the axe audit. Delivery of the
// invitation email is asserted by the invitations spec (06-24).
//
// Each lookup is one admin API request (06-29): "add member by email" asks
// `listUsers?email=`, and the user's Organizations card asks
// `/users/{id}/organizations` (no per-org role scan, no user list paging).
//
// Runs in a fresh tenant of its own, deleted afterwards, signed in as a console administrator
// created with createConsoleAdmin.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminCall, tenantPath } from '../lib/admin-api';
import { createClient, createUser, randomEmail, randomPassword } from '../lib/anvil';
import {
  createOrg,
  findOrg,
  openSectionFromNav,
  openTenantPage,
  orgInvitations,
  orgMemberRoles,
  setUpConsoleTenant,
  type ConsoleTenant,
} from '../lib/console-v10';

let tenant: ConsoleTenant | undefined;

/** Records the path and query of every admin API GET the console sends. */
function recordAdminGets(page: Page): URL[] {
  const urls: URL[] = [];
  page.on('request', (req) => {
    const url = new URL(req.url());
    if (req.method() === 'GET' && url.pathname.startsWith('/api/admin/')) urls.push(url);
  });
  return urls;
}

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('console: organizations with members, org roles, invitations and client policy', async ({ page, browser }) => {
  test.setTimeout(180_000);
  tenant = await setUpConsoleTenant(browser, page, 'corgs');
  const { token, slug } = tenant;
  expect(slug).not.toBe('default');

  const memberEmail = randomEmail('corgs-member');
  const member = await createUser(token, { email: memberEmail, password: randomPassword(), email_verified: true }, slug);
  if (!member.id) throw new Error('created user has no id');
  const memberId = member.id;
  const sectionNav = page.getByRole('navigation', { name: 'Organization sections' });
  const adminGets = recordAdminGets(page);

  await test.step('the Organizations page is in the navigation and starts empty', async () => {
    await openTenantPage(page, slug, 'users');
    await openSectionFromNav(page, slug, 'Organizations', 'organizations');
    await expect(page.getByText('No organizations yet.')).toBeVisible();
    await expectNoA11yViolations(page);
  });

  let orgId = '';
  await test.step('create the organization acme', async () => {
    await page.getByTestId('new-org').click();
    await expect(page.getByRole('heading', { level: 1, name: 'New organization' })).toBeVisible();
    // A bad slug is refused before anything is sent.
    await page.getByTestId('org-display-name').fill('Acme Corp');
    await page.getByTestId('org-slug').fill('Acme!');
    await page.getByTestId('org-submit').click();
    await expect(page.getByTestId('org-form')).toContainText('starting with a letter or digit');
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/new`);
    await expectNoA11yViolations(page);

    await page.getByTestId('org-slug').fill('acme');
    await page.getByTestId('org-mfa-policy').selectOption('optional');
    await page.getByTestId('org-submit').click();
    await expect(page.getByRole('heading', { level: 1, name: 'Acme Corp' })).toBeVisible();
    const match = /\/organizations\/([0-9a-f-]{36})$/.exec(new URL(page.url()).pathname);
    if (!match) throw new Error(`unexpected URL after create: ${page.url()}`);
    orgId = match[1];
    const stored = await findOrg(token, slug, 'acme');
    expect(stored?.id).toBe(orgId);
    expect(stored?.mfa_policy).toBe('optional');
    await expect(sectionNav.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    await expectNoA11yViolations(page);
  });

  await test.step('the list shows the organization', async () => {
    await openTenantPage(page, slug, 'organizations');
    await expect(page.getByTestId('open-org-acme')).toHaveText('Acme Corp');
    await page.getByTestId('open-org-acme').click();
    await expect(page.getByRole('heading', { level: 1, name: 'Acme Corp' })).toBeVisible();
  });

  await test.step('create the org role billing with permissions', async () => {
    await sectionNav.getByRole('link', { name: 'Roles' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${orgId}/roles`);
    await expect(page.getByText('No organization roles yet.')).toBeVisible();
    await expectNoA11yViolations(page);

    await page.getByTestId('new-org-role').click();
    const dialog = page.getByRole('dialog', { name: 'New organization role' });
    await expect(dialog).toBeVisible();
    await dialog.getByTestId('org-role-name').fill('billing');
    // Admin permissions are refused inside organizations (also by the API).
    await dialog.getByTestId('org-role-permissions').fill('invoices:read admin:write');
    await dialog.getByTestId('org-role-submit').click();
    await expect(dialog.getByTestId('org-role-form')).toContainText('Admin permissions');
    await expectNoA11yViolations(page);

    await dialog.getByTestId('org-role-permissions').fill('invoices:read invoices:pay');
    await dialog.getByTestId('org-role-submit').click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('status').filter({ hasText: 'Role billing created.' })).toBeVisible();
    await expect(page.getByTestId('org-role-billing')).toContainText('invoices:pay invoices:read');
    await expectNoA11yViolations(page);
  });

  await test.step('add the tenant user as a member (unknown emails are refused)', async () => {
    await sectionNav.getByRole('link', { name: 'Members' }).click();
    await expect(page.getByText('No members yet.')).toBeVisible();

    const usersPath = `/api/admin/v1/tenants/${slug}/users`;
    const userListGets = () => adminGets.filter((u) => u.pathname === usersPath);
    const before = userListGets().length;
    await page.getByTestId('add-member-email').fill(randomEmail('corgs-nobody'));
    await page.getByTestId('add-member').click();
    await expect(page.getByTestId('add-member-form')).toContainText('No user of this tenant has this email.');

    // A malformed address is the API's 422, shown next to the field.
    await page.getByTestId('add-member-email').fill('not an address');
    await page.getByTestId('add-member').click();
    await expect(page.getByTestId('add-member-form')).toContainText('whitespace');

    await page.getByTestId('add-member-email').fill(memberEmail.toUpperCase());
    await page.getByTestId('add-member').click();
    await expect(page.getByRole('status').filter({ hasText: 'added.' })).toBeVisible();
    // One `?email=` request per lookup, never a page of the user list.
    const lookups = userListGets().slice(before);
    expect(lookups).toHaveLength(3);
    for (const u of lookups) {
      expect(u.searchParams.get('email')).not.toBeNull();
      expect(u.searchParams.get('after')).toBeNull();
    }
    expect(lookups[2]?.searchParams.get('email')).toBe(memberEmail.toUpperCase());
    const table = page.getByRole('table', { name: 'Members' });
    await expect(table.getByRole('link', { name: memberEmail })).toBeVisible();
    await expectNoA11yViolations(page);
  });

  await test.step('assign the org role billing to the member', async () => {
    await page.getByRole('button', { name: `Roles of ${memberEmail}` }).click();
    const dialog = page.getByRole('dialog', { name: `Roles of ${memberEmail}` });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('No roles in this organization.')).toBeVisible();
    await expectNoA11yViolations(page);

    await dialog.getByTestId('org-assign-role-select').selectOption('org:billing');
    await dialog.getByTestId('org-assign-role').click();
    await expect(dialog.getByRole('status').filter({ hasText: 'Role billing assigned.' })).toBeVisible();
    const held = dialog.getByTestId('member-role-billing');
    await expect(held).toContainText('invoices:pay');
    await expect(held.getByTestId('role-scope')).toHaveText('Org role');
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Close' }).click();
    await expect(dialog).toBeHidden();

    expect(await orgMemberRoles(token, slug, orgId, memberId)).toEqual([
      expect.objectContaining({ name: 'billing', scope: 'org' }),
    ]);
  });

  const invitedEmail = randomEmail('corgs-invited');
  const revokedEmail = randomEmail('corgs-revoked');
  await test.step('invite a new address with the billing role; it is pending and shows no token', async () => {
    await sectionNav.getByRole('link', { name: 'Invitations' }).click();
    await expect(page.getByText('No invitations.')).toBeVisible();
    await expectNoA11yViolations(page);

    await page.getByTestId('invite-email').fill(invitedEmail);
    await page.getByTestId('invite-roles').locator('input[data-role="org:billing"]').check();
    await page.getByTestId('send-invitation').click();
    await expect(page.getByRole('status').filter({ hasText: `Invitation sent to ${invitedEmail}` })).toBeVisible();
    const row = page.locator(`[data-testid="invitation-row"][data-email="${invitedEmail}"]`);
    await expect(row).toHaveAttribute('data-status', 'open');
    await expect(row.getByTestId('invitation-status')).toHaveText('Pending');
    await expect(row).toContainText('billing');
    await expectNoA11yViolations(page);

    const stored = await orgInvitations(token, slug, orgId);
    const invitation = stored.find((i) => i.email === invitedEmail);
    expect(invitation?.status).toBe('open');
    // Neither the API nor the console carries the token or its hash.
    expect(Object.keys(invitation ?? {}).some((k) => /token|hash/i.test(k))).toBe(false);
    const html = await page.content();
    expect(html).not.toContain('token=');
    expect(html).not.toContain('/ui/invitation');
  });

  await test.step('revoke another invitation after confirming', async () => {
    await page.getByTestId('invite-email').fill(revokedEmail);
    await page.getByTestId('send-invitation').click();
    const row = page.locator(`[data-testid="invitation-row"][data-email="${revokedEmail}"]`);
    await expect(row).toHaveAttribute('data-status', 'open');

    await page.getByRole('button', { name: `Revoke invitation for ${revokedEmail}` }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Revoke invitation?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Revoke invitation' }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('status').filter({ hasText: `Invitation for ${revokedEmail} revoked.` })).toBeVisible();
    // Closed invitations are hidden by default and listed on request.
    await expect(row).toHaveCount(0);
    await page.getByTestId('invitations-include-closed').check();
    await expect(row).toHaveAttribute('data-status', 'revoked');
    await expect(row.getByTestId('invitation-status')).toHaveText('Revoked');
    await expect(page.locator(`[data-testid="invitation-row"][data-email="${invitedEmail}"]`)).toHaveAttribute(
      'data-status',
      'open',
    );

    const stored = await orgInvitations(token, slug, orgId);
    expect(stored.find((i) => i.email === revokedEmail)?.status).toBe('revoked');
    expect(stored.find((i) => i.email === invitedEmail)?.status).toBe('open');
  });

  await test.step("the user's page lists the membership with a link to the organization", async () => {
    const before = adminGets.length;
    await openTenantPage(page, slug, `users/${memberId}`);
    const card = page.getByTestId('user-organizations');
    await expect(card.getByRole('link', { name: 'Acme Corp' })).toBeVisible();
    await expect(card).toContainText('billing');
    // The card is one request: no organization paging and no per-org member role scan.
    const gets = adminGets.slice(before);
    expect(gets.filter((u) => u.pathname === `/api/admin/v1/tenants/${slug}/users/${memberId}/organizations`)).toHaveLength(1);
    expect(gets.some((u) => /\/members\/[^/]+\/roles$/.test(u.pathname))).toBe(false);
    expect(gets.some((u) => u.pathname === `/api/admin/v1/tenants/${slug}/organizations`)).toBe(false);
    await expectNoA11yViolations(page);
    await card.getByRole('link', { name: 'Acme Corp' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${orgId}/members`);
    await expect(page.getByRole('heading', { level: 1, name: 'Acme Corp' })).toBeVisible();
  });

  await test.step("set a client's organization policy to optional", async () => {
    const client = await createClient(
      token,
      {
        name: 'console orgs RP',
        client_type: 'confidential',
        application_type: 'web',
        auth_method: 'client_secret_basic',
        redirect_uris: ['https://corgs-rp.example.test/callback'],
        grant_types: ['authorization_code'],
        scopes: ['openid', 'email'],
      },
      slug,
    );
    await openTenantPage(page, slug, `clients/${client.client_id}`);
    await expect(page.getByTestId('client-organization')).toHaveText('Off');
    const policy = page.getByTestId('client-organization-policy');
    await expect(policy).toHaveValue('off');
    await policy.selectOption('optional');
    await expect(page.getByText('users without organizations still sign in')).toBeVisible();
    await expectNoA11yViolations(page);
    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Client saved.' })).toBeVisible();
    await expect(page.getByTestId('client-organization')).toHaveText('Optional');

    const stored = await adminCall<{ organization: string }>(
      token,
      'GET',
      tenantPath(slug, `/clients/${encodeURIComponent(client.client_id)}`),
    );
    expect(stored.organization).toBe('optional');
  });

  await test.step('delete a throwaway organization after confirming', async () => {
    const temp = await createOrg(token, slug, { slug: 'temp-org', display_name: 'Temp Org' });
    await openTenantPage(page, slug, `organizations/${temp.id}`);
    await expect(page.getByRole('heading', { level: 1, name: 'Temp Org' })).toBeVisible();
    await page.getByTestId('delete-org').click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete Temp Org?' });
    await expect(dialog).toBeVisible();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Delete organization' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations`);
    await expect(page.getByTestId('open-org-acme')).toBeVisible();
    await expect(page.getByTestId('open-org-temp-org')).toHaveCount(0);
    expect(await findOrg(token, slug, temp.id)).toBeNull();
    expect(await findOrg(token, slug, 'acme')).not.toBeNull();
  });
});
