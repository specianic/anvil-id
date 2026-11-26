// Users of a tenant. Since 1.0 also the entry to the import page and the bulk NDJSON export.
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { type UserView, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EXPORT_SCOPE_HINT, saveBlob, useCanExportUsers } from "@/lib/export";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, UserView>();

function columnsFor(tenant: string) {
  return col.columns([
    col.accessor("email", {
      header: "Email",
      cell: (info) => (
        <Link
          to="/t/$tenant/users/$userId"
          params={{ tenant, userId: info.row.original.id }}
          className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {info.getValue()}
        </Link>
      ),
    }),
    col.accessor("email_verified", {
      header: "Verified",
      cell: (info) => (info.getValue() ? "Yes" : "No"),
    }),
    col.accessor("status", {
      header: "Status",
      cell: (info) => (
        <Badge variant={info.getValue() === "blocked" ? "destructive" : "secondary"}>{info.getValue()}</Badge>
      ),
    }),
    col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
    col.accessor("last_login_at", { header: "Last login", cell: (info) => formatDateTime(info.getValue()) }),
  ]);
}

/** The failure marker the server appends when a bulk export breaks off mid-stream. */
const EXPORT_FAILED_MARKER = '{"error":"export_failed"}';

/** "Export all (NDJSON)": downloads every user (never password hashes) through the typed client. */
function ExportAll({ tenant }: { tenant: string }) {
  const canExport = useCanExportUsers();
  const [status, setStatus] = useState<string | null>(null);
  const exportAll = useMutation({
    mutationFn: async () => {
      const blob = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/export", {
          params: { path: { slug: tenant } },
          parseAs: "blob",
        }),
      );
      const tail = (await blob.slice(Math.max(0, blob.size - 64)).text()).trim();
      if (tail.endsWith(EXPORT_FAILED_MARKER)) {
        throw new Error("The export broke off on the server before every user was written. Try again.");
      }
      const filename = `${tenant}.users.ndjson`;
      saveBlob(new Blob([blob], { type: "application/x-ndjson" }), filename);
      return filename;
    },
    onMutate: () => setStatus(null),
    onSuccess: (filename) => setStatus(`Downloaded ${filename}.`),
  });
  const hintId = `export-all-hint-${tenant}`;
  return (
    <div className="space-y-2">
      <Button
        variant="outline"
        size="sm"
        onClick={() => exportAll.mutate()}
        disabled={!canExport || exportAll.isPending}
        aria-describedby={canExport ? undefined : hintId}
        data-testid="export-all-users"
      >
        {exportAll.isPending ? "Exporting…" : "Export all (NDJSON)"}
      </Button>
      {!canExport && (
        <p id={hintId} className="text-muted-foreground text-xs" data-testid="export-scope-missing">
          {EXPORT_SCOPE_HINT}
        </p>
      )}
      {exportAll.error ? <ProblemAlert error={exportAll.error} /> : null}
      <StatusMessage message={status} />
    </div>
  );
}

function UsersPage() {
  const tenant = useTenant();
  const columns = useMemo(() => columnsFor(tenant), [tenant]);
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["users", tenant, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users", {
          params: { path: { slug: tenant }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <section aria-labelledby="users-heading" className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h1 id="users-heading" className="text-xl font-semibold">
          Users
        </h1>
        <div className="flex flex-wrap items-start gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/t/$tenant/users/import" params={{ tenant }} data-testid="import-users-link">
              Import users
            </Link>
          </Button>
          <ExportAll tenant={tenant} />
        </div>
      </div>
      <DataTable
        caption="Users"
        columns={columns}
        data={query.data?.items}
        getRowId={(u) => u.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No users yet."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/users/")({ component: UsersPage });
