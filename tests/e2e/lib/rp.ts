// Helpers for driving the sample relying party in examples/node-rp.
// The RP base URL comes from the environment (RP_URL).

import { expect, type Page } from '@playwright/test';
import { requireEnv } from './anvil';

export function rpUrl(): string {
  return requireEnv('RP_URL');
}

export interface RpProfile {
  sub: string;
  email: string;
  refreshCount: number;
}

/**
 * Starts a login at the RP. The browser ends up on AnvilID's hosted login page
 * (or straight back at the RP when an AnvilID session already exists).
 */
export async function rpLogin(page: Page): Promise<void> {
  await page.goto(`${rpUrl()}/login`);
}

/** Reads the signed-in profile from the RP's /me page (navigates there if needed). */
export async function rpMe(page: Page): Promise<RpProfile> {
  const me = `${rpUrl()}/me`;
  if (page.url() !== me && !page.url().startsWith(`${rpUrl()}/refresh`)) {
    await page.goto(me);
  }
  return readProfile(page);
}

/** Runs a refresh-token grant at the RP and returns the updated profile. */
export async function rpRefresh(page: Page): Promise<RpProfile> {
  await page.goto(`${rpUrl()}/refresh`);
  return readProfile(page);
}

async function readProfile(page: Page): Promise<RpProfile> {
  const sub = page.locator('#sub');
  await expect(sub).toBeVisible();
  const email = (await page.locator('#email').textContent())?.trim() ?? '';
  const count = (await page.locator('#refresh-count').textContent())?.trim() ?? '';
  const refreshCount = Number.parseInt(count, 10);
  if (Number.isNaN(refreshCount)) {
    throw new Error(`RP refresh count is not a number: ${count}`);
  }
  return { sub: (await sub.textContent())?.trim() ?? '', email, refreshCount };
}
