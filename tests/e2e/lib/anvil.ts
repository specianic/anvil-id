// Helpers for driving AnvilID: first-run setup, the management credential,
// the admin API and the hosted login/registration pages.
//
// Every endpoint comes from the environment (ANVIL_URL); nothing here holds a
// credential. Credentials are created at runtime by completeSetup().

import { randomBytes } from 'node:crypto';
import { expect, type Page } from '@playwright/test';

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`environment variable ${name} is required for the e2e tests`);
  }
  return value.replace(/\/+$/, '');
}

export function anvilUrl(): string {
  return requireEnv('ANVIL_URL');
}

export interface AdminAccount {
  email: string;
  password: string;
}

export interface ManagementCredential {
  clientId: string;
  clientSecret: string;
}

/** Extracts the first-run setup URL from AnvilID's log output (`Setup URL: …`). */
export function parseSetupUrl(log: string): string | undefined {
  const match = /Setup URL:\s*(https?:\/\/\S+\/setup\?token=\S+)/.exec(log);
  return match?.[1];
}

/**
 * Completes the /setup page with the given admin account and returns the
 * management client credential shown once on the success page.
 */
export async function completeSetup(
  page: Page,
  setupUrl: string,
  admin: AdminAccount,
): Promise<ManagementCredential> {
  await page.goto(setupUrl);
  const form = page.locator('form#setup');
  await expect(form).toBeVisible();
  await form.locator('#email').fill(admin.email);
  await form.locator('#password').fill(admin.password);
  await page.locator('#setup-submit').click();

  const idLocator = page.locator('#mgmt-client-id');
  const secretLocator = page.locator('#mgmt-client-secret');
  await expect(idLocator).toBeVisible();
  await expect(secretLocator).toBeVisible();
  const clientId = (await idLocator.textContent())?.trim() ?? '';
  const clientSecret = (await secretLocator.textContent())?.trim() ?? '';
  if (!clientId || !clientSecret) {
    throw new Error('setup success page did not show the management credential');
  }
  return { clientId, clientSecret };
}

/** Obtains an admin API access token via client_credentials on the system tenant. */
export async function adminToken(creds: ManagementCredential): Promise<string> {
  const basic = Buffer.from(
    `${encodeURIComponent(creds.clientId)}:${encodeURIComponent(creds.clientSecret)}`,
  ).toString('base64');
  const res = await fetch(`${anvilUrl()}/t/system/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basic}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'admin:read admin:write',
    }).toString(),
  });
  if (res.status !== 200) {
    throw new Error(`management token request failed: HTTP ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) {
    throw new Error('management token response has no access_token');
  }
  return body.access_token;
}

export interface CreateClientBody {
  name: string;
  client_type: 'confidential' | 'public';
  application_type: 'web' | 'native';
  auth_method: 'client_secret_basic' | 'client_secret_post' | 'none';
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  [extra: string]: unknown;
}

export interface CreatedClient {
  client_id: string;
  client_secret?: string;
  [extra: string]: unknown;
}

export interface CreateUserBody {
  email: string;
  password?: string;
  email_verified?: boolean;
  claims?: Record<string, unknown>;
  [extra: string]: unknown;
}

export interface CreatedUser {
  id?: string;
  email?: string;
  [extra: string]: unknown;
}

async function adminPost<T>(token: string, path: string, body: unknown): Promise<T> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (res.status !== 201) {
    throw new Error(`POST ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as T;
}

/** Creates an OAuth client in the given tenant (default `default`). */
export function createClient(
  token: string,
  body: CreateClientBody,
  tenant = 'default',
): Promise<CreatedClient> {
  return adminPost<CreatedClient>(token, `/tenants/${encodeURIComponent(tenant)}/clients`, body);
}

/** Creates a user in the given tenant (default `default`). */
export function createUser(
  token: string,
  body: CreateUserBody,
  tenant = 'default',
): Promise<CreatedUser> {
  return adminPost<CreatedUser>(token, `/tenants/${encodeURIComponent(tenant)}/users`, body);
}

/** Fills the hosted login page the browser is currently on and submits it. */
export async function login(page: Page, identifier: string, password: string): Promise<void> {
  await page.locator('#identifier').fill(identifier);
  await page.locator('#password').fill(password);
  await page.locator('#login-submit').click();
}

/** Fills the hosted registration page the browser is currently on and submits it. */
export async function register(page: Page, email: string, password: string): Promise<void> {
  await page.locator('#email').fill(email);
  await page.locator('#password').fill(password);
  await page.locator('#registration-submit').click();
}

/** A unique address per call, so tests never collide on user identity. */
export function randomEmail(prefix = 'user'): string {
  return `${prefix}-${randomBytes(6).toString('hex')}@example.test`;
}

/** A random password that satisfies a length-based policy. */
export function randomPassword(): string {
  return `pw-${randomBytes(18).toString('base64url')}`;
}
