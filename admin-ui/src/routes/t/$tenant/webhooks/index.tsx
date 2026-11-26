// Webhook endpoints of the tenant (ADM-05): signed (Standard Webhooks) deliveries of lifecycle events.
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTenant } from "@/lib/tenant";

function WebhooksPage() {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: ["webhooks", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/webhooks", { params: { path: { slug: tenant } }, signal })),
  });
  const items = query.data?.items ?? [];

  return (
    <section aria-labelledby="webhooks-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="webhooks-heading" className="text-xl font-semibold">
          Webhooks
        </h1>
        <Button asChild size="sm">
          <Link to="/t/$tenant/webhooks/new" params={{ tenant }} data-testid="new-webhook">
            New endpoint
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Each endpoint receives the events it subscribes to, signed with its own secret (Standard Webhooks). Payloads
        carry ids only; fetch details through the admin API.
      </p>
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Webhook endpoints</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Name</TableHead>
                <TableHead scope="col">URL</TableHead>
                <TableHead scope="col">Events</TableHead>
                <TableHead scope="col">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isPending ? (
                <TableRow>
                  <TableCell colSpan={4}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground h-20 text-center">
                    No webhook endpoints yet.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((w) => (
                  <TableRow key={w.id}>
                    <TableCell>
                      <Link
                        to="/t/$tenant/webhooks/$webhookId"
                        params={{ tenant, webhookId: w.id }}
                        className="font-mono font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                      >
                        {w.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs break-all">{w.url}</code>
                    </TableCell>
                    <TableCell>{w.events.length}</TableCell>
                    <TableCell>
                      {w.enabled ? (
                        <Badge>Enabled</Badge>
                      ) : (
                        <Badge variant="outline">{w.disabled_reason ? `Disabled (${w.disabled_reason})` : "Disabled"}</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/webhooks/")({ component: WebhooksPage });
