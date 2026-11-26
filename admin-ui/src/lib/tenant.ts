// The tenant the console works on comes from the route (`/console/t/$tenant/...`, 05-04). Every
// tenant-scoped page and component reads it through useTenant(); nothing hardcodes a tenant.
import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";

/** The tenant opened when nothing was used before in this browser tab (and the target of pre-0.4 links). */
export const FALLBACK_TENANT = "default";
/** The installation's own tenant: its users are the console admins. It cannot be deleted. */
export const SYSTEM_TENANT = "system";
/** Tenants the API refuses to delete (403). */
export const UNDELETABLE_TENANTS: readonly string[] = [SYSTEM_TENANT, FALLBACK_TENANT];

/** Client-side mirror of the API's slug rule: 2-63 characters of a-z, 0-9 and '-'. The API decides. */
export const SLUG_PATTERN = /^[a-z0-9-]{2,63}$/;

const LAST_TENANT_KEY = "anvilid.console.tenant";

/** The slug of the tenant in the current route. Only valid below the `/t/$tenant` layout route. */
export function useTenant(): string {
  return useParams({ from: "/t/$tenant", select: (p) => p.tenant });
}

/** The tenant of the current route, or undefined outside tenant pages (tenant list, create page). */
export function useOptionalTenant(): string | undefined {
  return useParams({ strict: false, select: (p) => p.tenant });
}

/** The tenant used last in this browser tab, or `default`. */
export function lastTenant(): string {
  try {
    const stored = window.sessionStorage.getItem(LAST_TENANT_KEY);
    if (stored && SLUG_PATTERN.test(stored)) return stored;
  } catch {
    // Storage unavailable (privacy mode): fall back.
  }
  return FALLBACK_TENANT;
}

export function rememberTenant(slug: string): void {
  try {
    window.sessionStorage.setItem(LAST_TENANT_KEY, slug);
  } catch {
    // Storage unavailable: the console still works, it just opens `default` next time.
  }
}

/** Forget the remembered tenant if it is `slug` (after the tenant was deleted). */
export function forgetTenant(slug: string): void {
  try {
    if (window.sessionStorage.getItem(LAST_TENANT_KEY) === slug) window.sessionStorage.removeItem(LAST_TENANT_KEY);
  } catch {
    // Storage unavailable: nothing remembered.
  }
}

/** The path-based discovery document of a tenant (served by this installation, same origin). */
export function discoveryPath(slug: string): string {
  return `/t/${encodeURIComponent(slug)}/.well-known/openid-configuration`;
}

/** Absolute discovery URL to copy into a relying party's configuration. */
export function discoveryUrl(slug: string): string {
  return `${window.location.origin}${discoveryPath(slug)}`;
}

/**
 * The issuer a host-based tenant uses on its custom host: the public URL's scheme + `://` + host
 * (anvil_core::model::issuer, TenantBase::Host). The scheme is taken from the tenant's path issuer,
 * which the server computed from the public URL.
 */
export function hostIssuer(pathIssuer: string, host: string): string {
  const scheme = pathIssuer.startsWith("http://") ? "http" : "https";
  return `${scheme}://${host.replace(/\/+$/, "")}`;
}

/**
 * The OpenID discovery document of a tenant. The admin API's tenant view has no issuer field
 * (yet), so the issuer shown in the console is the one the server publishes in discovery.
 */
export interface Discovery {
  issuer: string;
  ui_locales_supported?: string[];
}

export function discoveryQueryKey(slug: string) {
  return ["discovery", slug] as const;
}

async function fetchDiscovery(slug: string, signal: AbortSignal): Promise<Discovery> {
  const response = await fetch(discoveryPath(slug), { signal, headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Discovery answered ${response.status}.`);
  const body: unknown = await response.json();
  if (typeof body !== "object" || body === null || typeof (body as { issuer?: unknown }).issuer !== "string") {
    throw new Error("Discovery returned no issuer.");
  }
  return body as Discovery;
}

export function useDiscovery(slug: string) {
  return useQuery({
    queryKey: discoveryQueryKey(slug),
    queryFn: ({ signal }) => fetchDiscovery(slug, signal),
    staleTime: 5 * 60_000,
  });
}

/** Query key of one tenant's view (GET /tenants/{slug}); shared by the layout route and the pages. */
export function tenantQueryKey(slug: string) {
  return ["tenant", slug] as const;
}

export function useTenantView(slug: string) {
  return useQuery({
    queryKey: tenantQueryKey(slug),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}", { params: { path: { slug } }, signal })),
  });
}
