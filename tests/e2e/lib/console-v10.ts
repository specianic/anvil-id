// Shared helpers for the 1.0 console specs (Phase 6: console-keys, and the org/SSO console specs
// of later plans). Tenant set-up and sign-in reuse lib/console-v04.ts: each spec works in a tenant
// of its own, created through the admin API and deleted afterwards, signed in as a console
// administrator created at runtime with createConsoleAdmin. Specs never change the default
// tenant's signing keys or settings (other specs and the sample RP depend on them).
//
// Console test ids used here (admin-ui, plan 06-16):
// - signing keys page: `rotate-key` (opens the dialog), `rotate-key-dialog`, `rotate-key-alg`,
//   `rotate-key-immediate`; the state badge in each row is `key-state` (find a row by its kid text)
//
// Env: ANVIL_URL, SETUP_URL, E2E_STATE_FILE (see tests/e2e/run.sh).

import { expect, type Page } from '@playwright/test';
import { adminCall, tenantPath } from './admin-api';
import { tenantIssuer } from './upstream';

export { openTenantPage, setUpConsoleTenant, type ConsoleTenant } from './console-v04';

/**
 * Opens a tenant section through the main navigation (as a user would) from any tenant page and
 * waits for its heading. `label` is the TENANT_PAGES label, `path` its route segment.
 */
export async function openSectionFromNav(
  page: Page,
  slug: string,
  label: string,
  path: string,
  heading = label,
): Promise<void> {
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: label, exact: true }).click();
  await expect(page).toHaveURL((url) => url.pathname === `/console/t/${slug}/${path}`);
  await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
}

/** A signing key as the admin API lists it (06-11 KeyView). */
export interface KeyView {
  kid: string;
  alg: string;
  state: 'next' | 'active' | 'retired';
  created_at: string;
  activated_at?: string | null;
  retired_at?: string | null;
  expires_at?: string | null;
}

/** The tenant's signing keys through the admin API (newest first). */
export async function listTenantKeys(token: string, slug: string): Promise<KeyView[]> {
  const body = await adminCall<{ items: KeyView[] }>(token, 'GET', tenantPath(slug, '/keys'));
  return body.items;
}

/** The kids published in the tenant's JWKS (located through its discovery document). */
export async function tenantJwksKids(slug: string): Promise<string[]> {
  const discovery = await fetch(`${tenantIssuer(slug)}/.well-known/openid-configuration`);
  expect(discovery.status).toBe(200);
  const { jwks_uri: jwksUri } = (await discovery.json()) as { jwks_uri: string };
  const jwks = await fetch(jwksUri, { headers: { accept: 'application/json' } });
  expect(jwks.status).toBe(200);
  const { keys } = (await jwks.json()) as { keys: Array<{ kid?: string }> };
  return keys.map((k) => k.kid ?? '');
}
