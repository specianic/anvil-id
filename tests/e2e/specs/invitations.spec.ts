// ORG-02 invitations in a browser (06-20): an administrator invites a new address to an
// organization; the org_invitation email arrives in Mailpit; the invitee opens the link (the GET
// only shows the offer, nothing is used), accepts, registers through the signed-out form (the
// address comes from the invitation and is verified) and is a member of the org; the same link
// then shows the one invalid page. The new account signs in with its password. axe runs on the
// offer, registration, registered and invalid pages.
//
// Runs in a tenant of its own (deleted afterwards). Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE,
// MAILPIT_URL (see tests/e2e/run.sh).

import { expect, test } from '@playwright/test';
import { expectNoA11yViolations } from '../fixtures/axe';
import { adminToken, findUserByEmail, randomEmail, randomPassword, sharedManagementCredential } from '../lib/anvil';
import { extractLink, latestMessageTo } from '../lib/mailpit';
import { createInvitation, createOrg, createOrgTenant, orgInvitations, orgMembers, type OrgTenant } from '../lib/org';
import { signInAtTenant } from '../lib/upstream';

let tenant: OrgTenant | undefined;

test.afterAll(async () => {
  await tenant?.cleanup();
});

test('an invited address registers through the emailed link and joins the org', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const token = await adminToken(await sharedManagementCredential(browser));
  tenant = await createOrgTenant(token, 'invite');
  const { slug } = tenant;
  expect(slug).not.toBe('default');
  const org = await createOrg(token, slug, { slug: 'acme', display_name: 'Acme Corp' });
  const invitee = randomEmail('invitee');
  const password = randomPassword();

  let link = '';
  await test.step('the invitation email arrives in Mailpit', async () => {
    const invitation = await createInvitation(token, slug, org.id, invitee);
    expect(invitation.status).toBe('open');
    expect(JSON.stringify(invitation)).not.toMatch(/token/i);
    const message = await latestMessageTo(invitee);
    expect(message.Subject).toContain('Acme Corp');
    expect(message.Text).toContain(invitee);
    link = extractLink(message.Text, `/t/${slug}/ui/invitation`);
    expect(new URL(link).searchParams.get('token')).toBeTruthy();
  });

  await test.step('the link shows the offer; accepting while signed out offers registration', async () => {
    await page.goto(link);
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.offer');
    await expect(page.locator('#invitation-message')).toContainText('Acme Corp');
    await expectNoA11yViolations(page);
    // Opening the link used nothing.
    expect((await orgInvitations(token, slug, org.id)).find((i) => i.email === invitee)?.status).toBe('open');

    await page.locator('#invitation-accept-submit').click();
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.signed_out');
    await expect(page.locator('form#invitation-register-form')).toBeVisible();
    // The address comes from the invitation, read-only and not a form field.
    await expect(page.locator('#invitation-email')).toHaveValue(invitee);
    await expect(page.locator('#invitation-email')).toHaveAttribute('readonly', '');
    await expect(page.locator('#invitation-email')).not.toHaveAttribute('name');
    await expectNoA11yViolations(page);
  });

  await test.step('registering creates a verified account that is a member of the org', async () => {
    await page.locator('#password').fill(password);
    await page.locator('#name').fill('Ivy Invitee');
    await page.locator('#invitation-register-submit').click();
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.registered');
    await expect(page.locator('#invitation-sign-in')).toBeVisible();
    await expectNoA11yViolations(page);

    const user = await findUserByEmail(token, invitee, slug);
    expect(user).toBeDefined();
    expect(user?.email_verified).toBe(true);
    const members = await orgMembers(token, slug, org.id);
    expect(members.map((m) => m.user_id)).toContain(user?.id);
    const invitation = (await orgInvitations(token, slug, org.id)).find((i) => i.email === invitee);
    expect(invitation?.status).toBe('accepted');
  });

  await test.step('a second use of the link shows the invalid page', async () => {
    await page.goto(link);
    await expect(page.locator('#invitation-message')).toHaveAttribute('data-message-key', 'invitation.invalid');
    await expect(page.locator('#invitation-accept-submit')).toHaveCount(0);
    await expect(page.locator('form#invitation-register-form')).toHaveCount(0);
    await expectNoA11yViolations(page);
  });

  await test.step('the new account signs in with its password', async () => {
    await signInAtTenant(page, slug, invitee, password);
  });
});
