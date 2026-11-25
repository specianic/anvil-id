import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { CONSOLE_TENANT, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";

type SessionView = components["schemas"]["SessionView"];

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, SessionView>();

function SessionsPage() {
  const pager = useCursorPager();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState<SessionView | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["sessions", CONSOLE_TENANT, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/sessions", {
          params: { path: { slug: CONSOLE_TENANT }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  const revoke = useMutation({
    mutationFn: async (session: SessionView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/sessions/{session_id}", {
        params: { path: { slug: CONSOLE_TENANT, session_id: session.id } },
      });
      return session;
    },
    onSuccess: async (session) => {
      setTarget(null);
      setStatus(`Session ${session.id} revoked.`);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["sessions"] }),
        queryClient.invalidateQueries({ queryKey: ["user-sessions", CONSOLE_TENANT, session.user_id] }),
      ]);
    },
  });

  const columns = useMemo(
    () =>
      col.columns([
        col.accessor("user_id", {
          header: "User",
          cell: (info) => (
            <Link
              to="/users/$userId"
              params={{ userId: info.getValue() }}
              search={{ tab: "sessions" }}
              className="font-mono text-xs underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
            >
              {info.getValue()}
            </Link>
          ),
        }),
        col.accessor("ip", { header: "IP address", cell: (info) => info.getValue() ?? "—" }),
        col.accessor("user_agent", {
          header: "User agent",
          cell: (info) => <span className="line-clamp-2 max-w-xs break-all text-xs">{info.getValue() ?? "—"}</span>,
        }),
        col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
        col.accessor("last_seen_at", { header: "Last seen", cell: (info) => formatDateTime(info.getValue()) }),
        col.display({
          id: "actions",
          header: () => <span className="sr-only">Actions</span>,
          cell: (info) => (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setTarget(info.row.original)}
              aria-label={`Revoke session ${info.row.original.id}`}
            >
              Revoke
            </Button>
          ),
        }),
      ]),
    [],
  );

  return (
    <section aria-labelledby="sessions-heading" className="space-y-4">
      <h1 id="sessions-heading" className="text-xl font-semibold">
        Sessions
      </h1>
      <p className="text-muted-foreground text-sm">
        Active browser sessions in this tenant. Revoking a session signs the user out and revokes the tokens issued
        from it.
      </p>
      <StatusMessage message={status} />
      <DataTable
        caption="Active sessions"
        columns={columns}
        data={query.data?.items}
        getRowId={(s) => s.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No active sessions."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
      <ConfirmDialog
        open={target !== null}
        title="Revoke session?"
        description={
          <p>
            The user is signed out on that device and its refresh tokens stop working. Session{" "}
            <code>{target?.id}</code>.
          </p>
        }
        confirmLabel="Revoke session"
        onConfirm={() => target && revoke.mutate(target)}
        onCancel={() => {
          revoke.reset();
          setTarget(null);
        }}
        pending={revoke.isPending}
        error={revoke.error}
      />
    </section>
  );
}

export const Route = createFileRoute("/sessions/")({ component: SessionsPage });
