import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { type ClientView, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, ClientView>();

function columnsFor(tenant: string) {
  return col.columns([
    col.accessor("client_id", {
      header: "Client ID",
      cell: (info) => (
        <Link
          to="/t/$tenant/clients/$clientId"
          params={{ tenant, clientId: info.getValue() }}
          className="font-mono font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {info.getValue()}
        </Link>
      ),
    }),
    col.accessor("name", { header: "Name" }),
    col.accessor("client_type", {
      header: "Type",
      cell: (info) => <Badge variant="secondary">{info.getValue()}</Badge>,
    }),
    col.accessor("auth_method", {
      header: "Auth method",
      cell: (info) => <code className="text-xs">{info.getValue()}</code>,
    }),
  ]);
}

function ClientsPage() {
  const tenant = useTenant();
  const columns = useMemo(() => columnsFor(tenant), [tenant]);
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["clients", tenant, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients", {
          params: { path: { slug: tenant }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <section aria-labelledby="clients-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="clients-heading" className="text-xl font-semibold">
          Clients
        </h1>
        <Button asChild size="sm">
          <Link to="/t/$tenant/clients/new" params={{ tenant }}>
            New client
          </Link>
        </Button>
      </div>
      <DataTable
        caption="Clients"
        columns={columns}
        data={query.data?.items}
        getRowId={(c) => c.client_id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No clients registered yet."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/clients/")({ component: ClientsPage });
