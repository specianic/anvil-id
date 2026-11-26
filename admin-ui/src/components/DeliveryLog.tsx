// Delivery log of one webhook endpoint (newest first, cursor pages) with redelivery. Refreshes on
// its own while a delivery is pending, so a test send shows its outcome without a reload.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { useCursorPager } from "@/components/DataTable";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";

type Delivery = components["schemas"]["WebhookDeliveryDto"];
type DeliveryStatus = components["schemas"]["DeliveryStatus"];

const PAGE_SIZE = 25;
const PENDING_REFRESH_MS = 2_000;

const STATUS_LABELS: Record<DeliveryStatus, string> = {
  pending: "Pending",
  delivered: "Delivered",
  failed: "Failed",
};

function StatusBadge({ status }: { status: DeliveryStatus }) {
  const variant = status === "delivered" ? "secondary" : status === "failed" ? "destructive" : "outline";
  return <Badge variant={variant}>{STATUS_LABELS[status]}</Badge>;
}

export function deliveriesQueryKey(tenant: string, endpointId: string) {
  return ["webhook-deliveries", tenant, endpointId] as const;
}

export function DeliveryLog({ tenant, endpointId }: { tenant: string; endpointId: string }) {
  const queryClient = useQueryClient();
  const pager = useCursorPager();
  const [status, setStatus] = useState<string | null>(null);
  const query = useQuery({
    queryKey: [...deliveriesQueryKey(tenant, endpointId), pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/webhooks/{id}/deliveries", {
          params: { path: { slug: tenant, id: endpointId }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data?.items.some((d) => d.status === "pending") ? PENDING_REFRESH_MS : false),
  });

  const redeliver = useMutation({
    mutationFn: async (delivery: Delivery) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/webhooks/deliveries/{delivery_id}/redeliver", {
          params: { path: { slug: tenant, delivery_id: delivery.id } },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async () => {
      setStatus("Redelivery queued.");
      await queryClient.invalidateQueries({ queryKey: deliveriesQueryKey(tenant, endpointId) });
    },
  });

  const items = query.data?.items ?? [];
  return (
    <div className="space-y-3" data-testid="delivery-log">
      <div className="flex items-center justify-between gap-2">
        <StatusMessage message={status} />
        <Button
          variant="outline"
          size="sm"
          className="ml-auto"
          onClick={() => void query.refetch()}
          disabled={query.isFetching}
          data-testid="refresh-deliveries"
        >
          Refresh
        </Button>
      </div>
      {redeliver.error ? <ProblemAlert error={redeliver.error} /> : null}
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Deliveries, newest first</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Created</TableHead>
                <TableHead scope="col">Event</TableHead>
                <TableHead scope="col">Status</TableHead>
                <TableHead scope="col">Attempts</TableHead>
                <TableHead scope="col">Last response</TableHead>
                <TableHead scope="col">Next attempt / completed</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isPending ? (
                <TableRow>
                  <TableCell colSpan={7}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground h-20 text-center">
                    No deliveries yet.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((d) => (
                  <TableRow key={d.id} data-testid={`delivery-${d.id}`} data-status={d.status} data-event={d.event_type}>
                    <TableCell>{formatDateTime(d.created_at)}</TableCell>
                    <TableCell>
                      <code className="text-xs">{d.event_type}</code>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={d.status} />
                    </TableCell>
                    <TableCell>{d.attempts}</TableCell>
                    <TableCell>
                      {d.last_http_status ? <code className="text-xs">HTTP {d.last_http_status}</code> : null}
                      {d.error_class ? <code className="text-destructive block text-xs">{d.error_class}</code> : null}
                      {!d.last_http_status && !d.error_class ? "—" : null}
                    </TableCell>
                    <TableCell>
                      {d.status === "pending" ? formatDateTime(d.next_attempt_at) : formatDateTime(d.completed_at)}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={redeliver.isPending}
                        onClick={() => redeliver.mutate(d)}
                        aria-label={`Redeliver ${d.event_type} from ${formatDateTime(d.created_at)}`}
                      >
                        Redeliver
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
      <nav aria-label="Delivery pages" className="flex items-center justify-end gap-2">
        <span className="text-muted-foreground mr-auto text-sm" aria-live="polite">
          Page {pager.page}
        </span>
        <Button variant="outline" size="sm" onClick={pager.previous} disabled={!pager.hasPrevious || query.isFetching}>
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => query.data?.next_cursor && pager.next(query.data.next_cursor)}
          disabled={!query.data?.next_cursor || query.isFetching}
        >
          Next
        </Button>
      </nav>
    </div>
  );
}
