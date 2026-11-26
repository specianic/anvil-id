import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EMAIL_KIND_LABELS } from "@/lib/email";
import { formatDateTime } from "@/lib/format";

const linkClass =
  "font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function EmailPage() {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: ["email-templates", tenant],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/email-templates", {
          params: { path: { slug: tenant } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="email-heading" className="space-y-6">
      <h1 id="email-heading" className="text-xl font-semibold">
        Email
      </h1>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Delivery</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            Configure the SMTP server this tenant sends mail through, and send a test email.
          </p>
          <Link to="/t/$tenant/email/smtp" params={{ tenant }} className={linkClass}>
            SMTP settings
          </Link>
        </CardContent>
      </Card>
      <div className="space-y-2">
        <h2 className="text-lg font-semibold">Templates</h2>
        {query.isError ? (
          <ProblemAlert error={query.error} />
        ) : (
          <div className="rounded-md border">
            <Table aria-busy={query.isFetching}>
              <TableCaption className="sr-only">Email templates</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Template</TableHead>
                  <TableHead scope="col">Status</TableHead>
                  <TableHead scope="col">Last changed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {query.isPending ? (
                  [0, 1, 2].map((i) => (
                    <TableRow key={`loading-${i}`}>
                      <TableCell colSpan={3}>
                        <Skeleton className="h-5 w-full" />
                      </TableCell>
                    </TableRow>
                  ))
                ) : query.data.items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground h-20 text-center">
                      No email templates.
                    </TableCell>
                  </TableRow>
                ) : (
                  query.data.items.map((t) => (
                    <TableRow key={t.kind} data-kind={t.kind}>
                      <TableCell>
                        <Link to="/t/$tenant/email/$kind" params={{ tenant, kind: t.kind }} className={linkClass}>
                          {EMAIL_KIND_LABELS[t.kind]}
                        </Link>
                      </TableCell>
                      <TableCell>
                        {t.customized ? (
                          <Badge>Customized</Badge>
                        ) : (
                          <Badge variant="secondary">Default</Badge>
                        )}
                      </TableCell>
                      <TableCell>{formatDateTime(t.updated_at)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/email/")({ component: EmailPage });
