// The tenant the console works on comes from the route (`/console/t/$tenant/...`, 05-04). Every
// tenant-scoped page and component reads it through useTenant(); nothing hardcodes a tenant.
import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";

/**
 * The installation's default tenant: opened when no tenant was used before in this browser tab,
 * and served at the public URL itself (no /t/{slug} prefix needed).
 */
export const DEFAULT_TENANT = "default";
/** The installation's own tenant: its users are the console admins. It cannot be deleted. */
export const SYSTEM_TENANT = "system";
/** Tenants the API refuses to delete (403). */
export const UNDELETABLE_TENANTS: readonly string[] = [SYSTEM_TENANT, DEFAULT_TENANT];

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
  return DEFAULT_TENANT;
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

/**
 * The discovery document of a tenant on this installation (same origin). The default tenant is
 * served at the public URL itself (issuer = public URL, TenantBase::Root); every other tenant
 * under /t/{slug} (issuer = public URL + /t/{slug}).
 */
export function discoveryPath(slug: string): string {
  if (slug === DEFAULT_TENANT) return "/.well-known/openid-configuration";
  return `/t/${encodeURIComponent(slug)}/.well-known/openid-configuration`;
}

/**
 * The OpenID discovery document of a tenant (read for `ui_locales_supported`). The issuer and the
 * discovery URL shown in the console come from the tenant view (`issuer`, `discovery_url`, 05-23).
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

/** Headings of the main navigation, in display order. */
export const NAV_GROUPS = [
  "Applications",
  "Users and access",
  "Branding and email",
  "Security",
  "Advanced",
] as const;

export type NavGroup = (typeof NAV_GROUPS)[number];

/**
 * The tenant-scoped console sections: the single source of the main navigation (grouped by `group`)
 * and of the tenant switcher's "keep the section" logic. `systemTenant: false` hides a section in
 * the system tenant; only sections the API refuses there are hidden (organizations do not exist in
 * the system tenant), working features stay visible.
 */
export const TENANT_PAGES = [
  { to: "/t/$tenant", label: "Overview", group: "Applications", systemTenant: true },
  { to: "/t/$tenant/clients", label: "Clients", group: "Applications", systemTenant: true },
  { to: "/t/$tenant/connections", label: "Connections", group: "Applications", systemTenant: true },
  { to: "/t/$tenant/users", label: "Users", group: "Users and access", systemTenant: true },
  { to: "/t/$tenant/organizations", label: "Organizations", group: "Users and access", systemTenant: false },
  { to: "/t/$tenant/roles", label: "Roles", group: "Users and access", systemTenant: true },
  { to: "/t/$tenant/attributes", label: "Attributes", group: "Users and access", systemTenant: true },
  { to: "/t/$tenant/sessions", label: "Sessions", group: "Users and access", systemTenant: true },
  { to: "/t/$tenant/branding", label: "Branding", group: "Branding and email", systemTenant: true },
  { to: "/t/$tenant/email", label: "Email", group: "Branding and email", systemTenant: true },
  { to: "/t/$tenant/keys", label: "Signing keys", group: "Security", systemTenant: true },
  { to: "/t/$tenant/password-profiles", label: "Password hash profiles", group: "Security", systemTenant: true },
  { to: "/t/$tenant/audit", label: "Audit log", group: "Security", systemTenant: true },
  { to: "/t/$tenant/settings", label: "Login settings", group: "Advanced", systemTenant: true },
  { to: "/t/$tenant/webhooks", label: "Webhooks", group: "Advanced", systemTenant: true },
] as const satisfies readonly { to: string; label: string; group: NavGroup; systemTenant: boolean }[];

export type TenantPage = (typeof TENANT_PAGES)[number]["to"];

/** The sections shown for `tenant`, grouped under NAV_GROUPS (empty groups are dropped). */
export function navGroupsFor(tenant: string) {
  const visible = TENANT_PAGES.filter((p) => tenant !== SYSTEM_TENANT || p.systemTenant);
  return NAV_GROUPS.map((group) => ({ group, pages: visible.filter((p) => p.group === group) })).filter(
    (g) => g.pages.length > 0,
  );
}

/** Whether a section exists in `tenant` (sections refused by the API in the system tenant do not). */
export function pageAvailableIn(page: TenantPage, tenant: string): boolean {
  return tenant !== SYSTEM_TENANT || TENANT_PAGES.some((p) => p.to === page && p.systemTenant);
}
