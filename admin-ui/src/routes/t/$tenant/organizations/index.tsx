// Organizations of the tenant (ORG-02): business customers with their own members, roles and
// invitations. The system tenant has none (the API refuses them there), so it explains instead.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { api, unwrap } from "@/api/client";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { type OrganizationView, orgMfaLabel } from "@/components/OrgForm";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, OrganizationView>();

function columnsFor(tenant: string) {
  return col.columns([
    col.accessor("display_name", {
      header: "Name",
      cell: (info) => (
        <Link
          to="/t/$tenant/organizations/$orgId"
          params={{ tenant, orgId: info.row.original.id }}
          className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
          data-testid={`open-org-${info.row.original.slug}`}
        >
          {info.getValue()}
        </Link>
      ),
    }),
    col.accessor("slug", { header: "Slug", cell: (info) => <code className="text-xs">{info.getValue()}</code> }),
    col.accessor("mfa_policy", { header: "MFA", cell: (info) => orgMfaLabel(info.getValue()) }),
    col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
  ]);
}

function SystemTenantNotice() {
  return (
    <div className="text-muted-foreground rounded-md border p-6 text-sm" data-testid="orgs-system-tenant">
      <p>
        The system tenant holds the console administrators and has no organizations. Switch to a tenant of your
        applications to manage its organizations.
      </p>
      <Link to="/tenants" className="text-foreground mt-2 inline-block underline underline-offset-4">
        All tenants
      </Link>
    </div>
  );
}

function OrganizationsList({ tenant }: { tenant: string }) {
  const columns = useMemo(() => columnsFor(tenant), [tenant]);
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["organizations", tenant, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations", {
          params: { path: { slug: tenant }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <DataTable
      caption="Organizations"
      columns={columns}
      data={query.data?.items}
      getRowId={(o) => o.id}
      isPending={query.isPending}
      isFetching={query.isFetching}
      error={query.error}
      emptyMessage="No organizations yet."
      pager={pager}
      nextCursor={query.data?.next_cursor}
    />
  );
}

function OrganizationsPage() {
  const tenant = useTenant();
  const system = tenant === SYSTEM_TENANT;
  return (
    <section aria-labelledby="orgs-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="orgs-heading" className="text-xl font-semibold">
          Organizations
        </h1>
        {!system && (
          <Button asChild size="sm">
            <Link to="/t/$tenant/organizations/new" params={{ tenant }} data-testid="new-org">
              New organization
            </Link>
          </Button>
        )}
      </div>
      {system ? (
        <SystemTenantNotice />
      ) : (
        <>
          <p className="text-muted-foreground text-sm">
            Business customers of this tenant. Members sign in to an organization; its roles, MFA policy and enterprise
            connections then apply.
          </p>
          <OrganizationsList tenant={tenant} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/")({ component: OrganizationsPage });
