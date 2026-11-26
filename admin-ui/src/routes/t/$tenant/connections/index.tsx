import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import { type ConnectionView, KIND_LABELS } from "@/components/ConnectionForm";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const ORG_PAGE = 200;
const MAX_ORG_PAGES = 10;

const col = createColumnHelper<DataTableFeatures, ConnectionView>();

const linkClass =
  "font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

/** Display names of the tenant's organizations by id (for the organization column). */
type OrgNames = ReadonlyMap<string, string>;

function columnsFor(tenant: string, orgNames: OrgNames) {
  return col.columns([
  col.accessor("display_name", {
    header: "Name",
    cell: (info) => {
      const org = info.row.original.organization;
      // An organization's connection is changed only under that organization.
      return org ? (
        <Link to="/t/$tenant/organizations/$orgId/connections" params={{ tenant, orgId: org }} className={linkClass}>
          {info.getValue()}
        </Link>
      ) : (
        <Link
          to="/t/$tenant/connections/$connectionId"
          params={{ tenant, connectionId: info.row.original.id }}
          className={linkClass}
        >
          {info.getValue()}
        </Link>
      );
    },
  }),
  col.accessor("organization", {
    header: "Organization",
    cell: (info) => {
      const org = info.getValue();
      if (!org) return <span className="text-muted-foreground">Tenant</span>;
      return (
        <span className="flex flex-wrap items-center gap-1" data-testid="connection-organization">
          <Link to="/t/$tenant/organizations/$orgId" params={{ tenant, orgId: org }} className={linkClass}>
            {orgNames.get(org) ?? org}
          </Link>
          <Badge variant="outline">Read-only here</Badge>
        </span>
      );
    },
  }),
  col.accessor("slug", {
    header: "Slug",
    cell: (info) => <code className="text-xs">{info.getValue()}</code>,
  }),
  col.accessor("kind", {
    header: "Kind",
    cell: (info) => <Badge variant="secondary">{KIND_LABELS[info.getValue()]}</Badge>,
  }),
  col.accessor("enabled", {
    header: "Status",
    cell: (info) =>
      info.getValue() ? <Badge>Enabled</Badge> : <Badge variant="outline">Disabled</Badge>,
  }),
  col.accessor("secret_configured", {
    header: "Secret",
    cell: (info) =>
      info.row.original.kind === "saml" ? (
        <span className="text-muted-foreground">None (SAML)</span>
      ) : info.getValue() ? (
        <Badge variant="secondary">Configured</Badge>
      ) : (
        <Badge variant="outline">Not set</Badge>
      ),
  }),
  ]);
}

function ConnectionsPage() {
  const tenant = useTenant();
  // The API returns every connection of the tenant in one list (no cursor).
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["connections", tenant],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/connections", {
          params: { path: { slug: tenant } },
          signal,
        }),
      ),
  });
  const hasOrgConnections = query.data?.items.some((c) => c.organization) ?? false;
  // Names for the organization column; only loaded when an organization owns a connection. Without
  // them the column shows the organization's id.
  const orgs = useQuery({
    queryKey: ["organizations", tenant, "names"],
    enabled: hasOrgConnections,
    queryFn: async ({ signal }) => {
      const names = new Map<string, string>();
      let after: string | undefined;
      for (let page = 0; page < MAX_ORG_PAGES; page++) {
        const result = unwrap(
          await api.GET("/api/admin/v1/tenants/{slug}/organizations", {
            params: { path: { slug: tenant }, query: { limit: ORG_PAGE, after } },
            signal,
          }),
        );
        for (const o of result.items) names.set(o.id, o.display_name);
        if (!result.next_cursor) break;
        after = result.next_cursor;
      }
      return names;
    },
  });
  const orgNames = orgs.data;
  const columns = useMemo(() => columnsFor(tenant, orgNames ?? new Map()), [tenant, orgNames]);

  return (
    <section aria-labelledby="connections-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="connections-heading" className="text-xl font-semibold">
          Connections
        </h1>
        <Button asChild size="sm">
          <Link to="/t/$tenant/connections/new" params={{ tenant }} data-testid="new-connection">
            New connection
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Upstream identity providers users can sign in with (Google, Apple, Microsoft, GitHub, OpenID Connect, OAuth2).
        Connections of an organization (OpenID Connect, SAML) are listed with their organization and are managed on
        the organization's page.
      </p>
      <DataTable
        caption="Connections"
        columns={columns}
        data={query.data?.items}
        getRowId={(c) => c.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No connections configured yet."
        pager={pager}
        nextCursor={null}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/connections/")({ component: ConnectionsPage });
