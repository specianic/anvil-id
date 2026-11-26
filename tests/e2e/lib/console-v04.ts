// Helpers for the 0.4 console specs (05-24): console-roles, console-webhooks and
// console-registration. Each spec works in a tenant of its own (created through the admin API and
// deleted afterwards), signed in as a console administrator created at runtime.
//
// Console test ids used here (admin-ui, plan 05-24):
// - one-time secrets: `{id}` (the value), `{id}-panel`, `{id}-copy`, `{id}-done` with id
//   `webhook-secret` or `iat-value`
// - roles: `new-role`, `role-form`, `role-name`, `role-permission-input`, `role-permission-add`,
//   `role-permissions`, `role-submit`, `delete-role`, `last-administrator`; user page tab "Roles":
//   `assign-role-select`, `assign-role`, `user-role-{name}`
// - claim mapping (Login settings): `claim-mapping-form`, `claim-rule-roles`, `save-claim-mapping`
// - webhooks: `new-webhook`, `webhook-form`, `webhook-name`, `webhook-url`, `webhook-submit`,
//   `open-webhook`, `webhook-status`, `send-webhook-test`, `toggle-webhook`, `rotate-webhook-secret`,
//   `delete-webhook`, `delivery-log` (rows: `tr[data-event][data-status]`), `refresh-deliveries`
// - registration: `registration-settings-link`, `registration-form`, `registration-read-only`,
//   `dcr-policy`, `cimd-policy`, `save-registration`, `iat-form`, `iat-description`, `iat-uses`,
//   `create-iat`; clients list: `client-source-{client_id}`
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, type Browser, type Page } from '@playwright/test';
import {
  adminToken,
  anvilUrl,
  createConsoleAdmin,
  randomEmail,
  randomPassword,
  sharedManagementCredential,
  type AdminAccount,
} from './anvil';
import { consoleLogin, consoleUrl } from './console';
import { deleteTenant } from './email-code';
import { createTenant, randomSlug, tenantIssuer } from './upstream';

/** A tenant of the spec's own and the management token that created it. */
export interface ConsoleTenant {
  token: string;
  slug: string;
  admin: AdminAccount;
  /** Deletes the tenant (best effort). */
  cleanup(): Promise<void>;
}

/**
 * Creates a tenant `{prefix}-xxxxxxxx` and a console administrator (system user with the
 * `administrator` role), signs `page` in to the console and returns the tenant.
 */
export async function setUpConsoleTenant(browser: Browser, page: Page, prefix: string): Promise<ConsoleTenant> {
  const token = await adminToken(await sharedManagementCredential(browser));
  const slug = randomSlug(prefix);
  await createTenant(token, slug);
  const admin: AdminAccount = { email: randomEmail(`${prefix}-admin`), password: randomPassword() };
  await createConsoleAdmin(token, admin);
  await consoleLogin(page, admin);
  return { token, slug, admin, cleanup: () => deleteTenant(token, slug) };
}

/** Opens a page of the tenant in the console (`roles`, `webhooks/new`, ...). */
export async function openTenantPage(page: Page, slug: string, path: string): Promise<void> {
  await page.goto(consoleUrl(`t/${slug}/${path.replace(/^\/+/, '')}`));
}

/**
 * Reads a secret shown once (`testId` = `webhook-secret` or `iat-value`), checks that its Copy
 * button puts exactly that value on the clipboard (needs clipboard permissions on the context),
 * dismisses it and checks that it is gone from the page.
 */
export async function takeOneTimeSecret(page: Page, testId: string, checkClipboard = true): Promise<string> {
  const valueLocator = page.getByTestId(testId);
  await expect(valueLocator).toBeVisible();
  const value = ((await valueLocator.textContent()) ?? '').trim();
  expect(value).not.toBe('');
  if (checkClipboard) {
    await page.getByTestId(`${testId}-copy`).click();
    await expect(page.getByTestId(`${testId}-panel`)).toContainText('Copied.');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(value);
  }
  await page.getByTestId(`${testId}-done`).click();
  await expect(page.getByTestId(`${testId}-panel`)).toHaveCount(0);
  expect(await page.content()).not.toContain(value);
  return value;
}

/** Grants clipboard access to the console origin (for the Copy buttons). */
export async function allowClipboard(page: Page): Promise<void> {
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: anvilUrl() });
}

/**
 * POSTs an RFC 7591 registration to the tenant's `/register` (optionally with an initial access
 * token) and returns the status and the parsed body.
 */
export async function registerClient(
  slug: string,
  metadata: Record<string, unknown>,
  initialAccessToken?: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json' };
  if (initialAccessToken) headers.authorization = `Bearer ${initialAccessToken}`;
  const res = await fetch(`${tenantIssuer(slug)}/register`, {
    method: 'POST',
    headers,
    body: JSON.stringify(metadata),
  });
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = { raw: text };
  }
  return { status: res.status, body };
}
