// A generic admin API call for the 0.4 resources (attributes, webhooks, roles, initial access
// tokens, registration settings) that have no dedicated helper. Nothing here holds a credential;
// callers pass an admin token (lib/anvil.ts adminToken).

import { anvilUrl } from './anvil';

export type AdminMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * Sends `method path` (relative to /api/admin/v1) with an optional JSON body and returns the
 * parsed JSON response (undefined for 204). Throws unless the status is one of `expected`.
 */
export async function adminCall<T = unknown>(
  token: string,
  method: AdminMethod,
  path: string,
  body?: unknown,
  expected: number | number[] = 200,
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
  const allowed = Array.isArray(expected) ? expected : [expected];
  if (!allowed.includes(res.status)) {
    throw new Error(`${method} ${path} failed: HTTP ${res.status} ${await res.text()}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** `/tenants/{slug}` plus `rest`, with the slug encoded. */
export function tenantPath(slug: string, rest = ''): string {
  return `/tenants/${encodeURIComponent(slug)}${rest}`;
}
