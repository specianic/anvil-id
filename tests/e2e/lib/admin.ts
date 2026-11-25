// Admin API helpers for tenant settings and user sessions, shared by the logout, MFA policy and
// prompt specs. Nothing here holds a credential; callers pass an admin token (lib/anvil.ts
// adminToken).

import { anvilUrl } from './anvil';

export type MfaPolicy = 'off' | 'optional' | 'required';
export type RegistrationMode = 'open' | 'invite_only' | 'disabled';

/** The tenant settings fields the specs read or change (the API returns more). */
export interface TenantSettings {
  registration: RegistrationMode;
  require_verified_email: boolean;
  mfa_policy: MfaPolicy;
  email_otp: boolean;
  magic_link: boolean;
  [extra: string]: unknown;
}

export type TenantSettingsPatch = Partial<
  Pick<TenantSettings, 'registration' | 'require_verified_email' | 'mfa_policy' | 'email_otp' | 'magic_link'>
>;

async function adminFetch<T>(
  token: string,
  method: 'GET' | 'PATCH',
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${anvilUrl()}/api/admin/v1${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status !== 200) {
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as T;
}

/** The current settings of `tenant` (GET /tenants/{slug}). */
export async function tenantSettings(token: string, tenant = 'default'): Promise<TenantSettings> {
  const view = await adminFetch<{ settings: TenantSettings }>(
    token,
    'GET',
    `/tenants/${encodeURIComponent(tenant)}`,
  );
  return view.settings;
}

/** Merges `patch` into the settings of `tenant` (PATCH /tenants/{slug}); returns the result. */
export async function updateTenantSettings(
  token: string,
  patch: TenantSettingsPatch,
  tenant = 'default',
): Promise<TenantSettings> {
  const view = await adminFetch<{ settings: TenantSettings }>(
    token,
    'PATCH',
    `/tenants/${encodeURIComponent(tenant)}`,
    { settings: patch },
  );
  return view.settings;
}

/**
 * Applies `patch` to `tenant`, runs `fn` and restores the previous value of every patched field,
 * also when `fn` throws. Tenant settings are shared by every spec of a run (one worker, one
 * instance), so specs that change them must put them back.
 */
export async function withTenantSettings<T>(
  token: string,
  patch: TenantSettingsPatch,
  fn: () => Promise<T>,
  tenant = 'default',
): Promise<T> {
  const before = await tenantSettings(token, tenant);
  const restore: Record<string, unknown> = {};
  for (const key of Object.keys(patch)) restore[key] = before[key];
  await updateTenantSettings(token, patch, tenant);
  try {
    return await fn();
  } finally {
    await updateTenantSettings(token, restore as TenantSettingsPatch, tenant);
  }
}

/** One active browser session as listed by the admin API. */
export interface SessionView {
  id: string;
  user_id: string;
  auth_time: string;
  acr?: string;
  amr?: string[];
  [extra: string]: unknown;
}

/** The active sessions of a user (GET /tenants/{slug}/users/{id}/sessions). */
export async function userSessions(
  token: string,
  userId: string,
  tenant = 'default',
): Promise<SessionView[]> {
  const list = await adminFetch<{ items: SessionView[] }>(
    token,
    'GET',
    `/tenants/${encodeURIComponent(tenant)}/users/${encodeURIComponent(userId)}/sessions`,
  );
  return list.items;
}
