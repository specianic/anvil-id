import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { CONSOLE_TENANT, type UserView, api, unwrap } from "@/api/client";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, UserView>();

const columns = col.columns([
  col.accessor("email", {
    header: "Email",
    cell: (info) => (
      <Link
        to="/users/$userId"
        params={{ userId: info.row.original.id }}
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

function UsersPage() {
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["users", CONSOLE_TENANT, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users", {
          params: { path: { slug: CONSOLE_TENANT }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <section aria-labelledby="users-heading" className="space-y-4">
      <h1 id="users-heading" className="text-xl font-semibold">
        Users
      </h1>
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

export const Route = createFileRoute("/users/")({ component: UsersPage });
