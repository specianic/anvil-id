// Tenant switcher of the console header: a native select (keyboard and screen reader friendly)
// listing every tenant from /api/admin/v1/tenants. Switching keeps the current section (Users,
// Clients, ...) and opens its list page in the other tenant.
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { type TenantView, api, unwrap } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import {
  DEFAULT_TENANT,
  SYSTEM_TENANT,
  TENANT_PAGES,
  type TenantPage,
  pageAvailableIn,
  useOptionalTenant,
} from "@/lib/tenant";

const PAGE_LIMIT = 200;
/** Upper bound on pages fetched for the switcher (2000 tenants); the tenant list page pages through all. */
const MAX_PAGES = 10;

export const ALL_TENANTS_KEY = ["tenants", "all"] as const;

async function fetchAllTenants(signal: AbortSignal): Promise<{ items: TenantView[]; truncated: boolean }> {
  const items: TenantView[] = [];
  let after: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const data = unwrap(
      await api.GET("/api/admin/v1/tenants", { params: { query: { limit: PAGE_LIMIT, after } }, signal }),
    );
    items.push(...data.items);
    if (!data.next_cursor) return { items, truncated: false };
    after = data.next_cursor;
  }
  return { items, truncated: true };
}

/**
 * The section (main navigation entry) of the current page, so a switch can stay in it: the path
 * segment after `/t/{tenant}/` (router paths exclude the /console basepath).
 */
function useCurrentSection(): TenantPage {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const segments = pathname.split("/").filter(Boolean);
  const section = segments[0] === "t" ? segments[2] : undefined;
  const page = TENANT_PAGES.find((p) => p.to.split("/")[3] === section);
  return page ? page.to : TENANT_PAGES[0].to;
}

/**
 * Option text of a tenant (C-L1): "System" and "Default" for the built-in tenants, otherwise
 * "<display name> (slug)", or just the slug when the display name adds nothing.
 */
export function tenantOptionLabel(slug: string, displayName: string | undefined): string {
  if (slug === SYSTEM_TENANT) return "System";
  if (slug === DEFAULT_TENANT) return "Default";
  if (!displayName || displayName.trim() === "" || displayName === slug) return slug;
  return `${displayName} (${slug})`;
}

const focusRing = "focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

export function TenantSwitcher() {
  const current = useOptionalTenant();
  const section = useCurrentSection();
  const navigate = useNavigate();
  const query = useQuery({ queryKey: ALL_TENANTS_KEY, queryFn: ({ signal }) => fetchAllTenants(signal) });

  const tenants = query.data?.items ?? [];
  // The current tenant stays selectable even before the list arrives (or beyond its bound).
  const options =
    current && !tenants.some((t) => t.slug === current)
      ? [current, ...tenants.map((t) => t.slug)]
      : tenants.map((t) => t.slug);
  const label = (slug: string) => tenantOptionLabel(slug, tenants.find((x) => x.slug === slug)?.display_name);

  return (
    <div className="flex items-center gap-2" data-testid="tenant-switcher">
      <label htmlFor="tenant-switcher-select" className="text-muted-foreground text-sm">
        Tenant
      </label>
      <select
        id="tenant-switcher-select"
        className={`border-input bg-background h-8 max-w-56 rounded-md border px-2 text-sm ${focusRing}`}
        value={current ?? ""}
        aria-busy={query.isPending}
        onChange={(e) => {
          const slug = e.target.value;
          if (!slug || slug === current) return;
          // A section the target tenant does not have (organizations in the system tenant) opens its overview.
          const to = pageAvailableIn(section, slug) ? section : TENANT_PAGES[0].to;
          void navigate({ to, params: { tenant: slug } });
        }}
      >
        {!current && (
          <option value="" disabled>
            Choose a tenant
          </option>
        )}
        {options.map((slug) => (
          <option key={slug} value={slug}>
            {label(slug)}
          </option>
        ))}
      </select>
      {current === SYSTEM_TENANT && (
        <Badge
          variant="outline"
          data-testid="system-tenant-badge"
          title="The installation's own tenant: its users are the console admins"
        >
          System tenant
        </Badge>
      )}
      {query.isError && (
        <span role="alert" className="text-destructive text-xs">
          Tenants could not be loaded.
        </span>
      )}
      <Link
        to="/tenants"
        className={`text-link rounded-md px-2 py-1 text-sm underline-offset-4 hover:underline ${focusRing}`}
        activeProps={{ "aria-current": "page", className: "text-foreground" }}
        activeOptions={{ exact: true }}
        data-testid="all-tenants-link"
      >
        All tenants
      </Link>
    </div>
  );
}
