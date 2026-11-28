// Console form safety (07.1-10, C-M11/M12/M13/L2): the organization slug follows the display name
// until edited; deleting an organization happens in the danger zone and needs the typed slug; the
// organization, role, attribute and webhook forms hold navigation while they have unsaved changes
// (in-app: "Leave without saving?" with Stay/Leave; closing the tab: the browser's beforeunload
// prompt); /attributes/new opens the create form instead of an attribute named "new".
//
// Runs in a fresh tenant of its own, deleted afterwards, signed in as a console administrator.
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, test, type Page } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { findOrg, openTenantPage, setUpConsoleTenant, type ConsoleTenant } from '../lib/console-v10';

let tenant: ConsoleTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

function mainNavLink(page: Page, name: string) {
  return page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true });
}

function leaveDialog(page: Page) {
  return page.getByRole('alertdialog', { name: 'Leave without saving?' });
}

test('console: slug fill, typed organization delete, unsaved-changes guards, attributes/new', async ({ page, browser }) => {
  test.setTimeout(180_000);
  tenant = await setUpConsoleTenant(browser, page, 'cforms');
  const { token, slug } = tenant;

  let orgId = '';
  await test.step('the organization slug follows the display name until it is edited', async () => {
    await openTenantPage(page, slug, 'organizations/new');
    await expect(page.getByRole('heading', { level: 1, name: 'New organization' })).toBeVisible();
    const name = page.getByTestId('org-display-name');
    const orgSlug = page.getByTestId('org-slug');
    await name.fill('Globex Holdings Ltd.');
    await expect(orgSlug).toHaveValue('globex-holdings-ltd');
    await name.fill('Glöbex Straße');
    await expect(orgSlug).toHaveValue('globex-strasse');
    // Once the admin edits the slug, the name no longer changes it.
    await orgSlug.fill('globex');
    await name.fill('Globex Corporation');
    await expect(orgSlug).toHaveValue('globex');
    await expectNoA11yViolations(page);

    // A successful create navigates without an unsaved-changes prompt.
    await page.getByTestId('org-submit').click();
    await expect(page.getByRole('heading', { level: 1, name: 'Globex Corporation' })).toBeVisible();
    await expect(leaveDialog(page)).toHaveCount(0);
    const stored = await findOrg(token, slug, 'globex');
    expect(stored?.display_name).toBe('Globex Corporation');
    orgId = stored?.id ?? '';
  });

  await test.step('the organization settings form guards unsaved changes', async () => {
    const sectionNav = page.getByRole('navigation', { name: 'Organization sections' });
    await page.getByTestId('org-display-name').fill('Globex Unsaved');
    await sectionNav.getByRole('link', { name: 'Members' }).click();
    const dialog = leaveDialog(page);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Stay' })).toBeFocused();
    await expectNoA11yViolations(page);
    await dialog.getByRole('button', { name: 'Stay' }).click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${orgId}`);
    await expect(page.getByTestId('org-display-name')).toHaveValue('Globex Unsaved');

    // Saving clears the dirty state: navigating afterwards is not held.
    await page.getByTestId('org-submit').click();
    await expect(page.getByRole('status').filter({ hasText: 'Organization saved.' })).toBeVisible();
    await sectionNav.getByRole('link', { name: 'Members' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations/${orgId}/members`);
    await expect(leaveDialog(page)).toHaveCount(0);
  });

  await test.step('deleting the organization needs its slug typed in the danger zone', async () => {
    await openTenantPage(page, slug, `organizations/${orgId}`);
    await expect(page.getByRole('heading', { level: 1, name: 'Globex Unsaved' })).toBeVisible();
    const zone = page.getByTestId('danger-zone');
    await expect(zone.getByRole('heading', { name: 'Danger zone' })).toBeVisible();
    await zone.getByRole('button', { name: 'Delete organization' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Delete this organization?' });
    await expect(dialog).toBeVisible();
    const confirm = dialog.getByRole('button', { name: 'Delete organization' });
    const input = dialog.getByTestId('danger-zone-confirm-input');
    await expect(confirm).toBeDisabled();
    await input.fill('Globex Unsaved');
    await expect(confirm).toBeDisabled();
    await input.fill('GLOBEX');
    await expect(confirm).toBeDisabled();
    await expectNoA11yViolations(page);
    // Cancel keeps the organization.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(await findOrg(token, slug, orgId)).not.toBeNull();

    await zone.getByRole('button', { name: 'Delete organization' }).click();
    await expect(confirm).toBeDisabled();
    await input.fill('globex');
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/organizations`);
    expect(await findOrg(token, slug, orgId)).toBeNull();
  });

  await test.step('/attributes/new opens the create form, which guards unsaved changes', async () => {
    await openTenantPage(page, slug, 'attributes');
    await page.getByTestId('new-attribute').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/attributes/new`);
    await expect(page.getByRole('heading', { level: 1, name: 'New attribute' })).toBeVisible();
    await expect(page.getByTestId('attribute-form')).toBeVisible();
    await expect(page.getByTestId('attribute-name')).toBeEnabled();

    // Opened directly too, not as an attribute named "new".
    await openTenantPage(page, slug, 'attributes/new');
    await expect(page.getByRole('heading', { level: 1, name: 'New attribute' })).toBeVisible();
    await expect(page.getByTestId('attribute-form')).toBeVisible();
    await expect(page.getByRole('heading', { level: 1, name: 'new', exact: true })).toHaveCount(0);
    await expectNoA11yViolations(page);

    await page.getByTestId('attribute-name').fill('employee_id');
    await mainNavLink(page, 'Users').click();
    const dialog = leaveDialog(page);
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Leave' }).click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
  });

  await test.step('a dirty role form asks before leaving; Stay keeps the input', async () => {
    await openTenantPage(page, slug, 'roles/new');
    await expect(page.getByRole('heading', { level: 1, name: 'New role' })).toBeVisible();
    await expect(page.getByTestId('role-submit')).toHaveCount(1);
    await page.getByTestId('role-name').fill('draft-role');
    await mainNavLink(page, 'Users').click();
    const dialog = leaveDialog(page);
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Stay' }).click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/roles/new`);
    await expect(page.getByTestId('role-name')).toHaveValue('draft-role');

    // Undoing the edit makes the form clean again: no prompt.
    await page.getByTestId('role-name').fill('');
    await mainNavLink(page, 'Users').click();
    await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/users`);
    await expect(dialog).toHaveCount(0);
  });

  await test.step('a dirty webhook form triggers the browser prompt when the tab closes', async () => {
    await openTenantPage(page, slug, 'webhooks/new');
    await expect(page.getByRole('heading', { level: 1, name: 'New webhook endpoint' })).toBeVisible();
    await expect(page.getByTestId('webhook-submit')).toHaveCount(1);
    // Real key presses: browsers only show beforeunload prompts after a user gesture.
    await page.getByTestId('webhook-name').click();
    await page.keyboard.type('draft-hook');

    // In-app navigation is held by the console's own dialog.
    await mainNavLink(page, 'Webhooks').click();
    await expect(leaveDialog(page)).toBeVisible();
    await leaveDialog(page).getByRole('button', { name: 'Stay' }).click();
    await expect(leaveDialog(page)).toBeHidden();

    // Closing the tab asks the browser's beforeunload question; dismissing it keeps the page.
    const prompted = new Promise<string>((resolve) => {
      page.once('dialog', (dialog) => {
        resolve(dialog.type());
        void dialog.dismiss();
      });
    });
    await page.close({ runBeforeUnload: true });
    expect(await prompted).toBe('beforeunload');
    expect(page.isClosed()).toBe(false);
    await expect(page.getByTestId('webhook-name')).toHaveValue('draft-hook');
  });
});
