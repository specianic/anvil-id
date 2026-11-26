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

const col = createColumnHelper<DataTableFeatures, ConnectionView>();

function columnsFor(tenant: string) {
  return col.columns([
  col.accessor("display_name", {
    header: "Name",
    cell: (info) => (
      <Link
        to="/t/$tenant/connections/$connectionId"
        params={{ tenant, connectionId: info.row.original.id }}
        className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        {info.getValue()}
      </Link>
    ),
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
      info.getValue() ? (
        <Badge variant="secondary">Configured</Badge>
      ) : (
        <Badge variant="outline">Not set</Badge>
      ),
  }),
  ]);
}

function ConnectionsPage() {
  const tenant = useTenant();
  const columns = useMemo(() => columnsFor(tenant), [tenant]);
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
