// Custom attribute definitions of the tenant (AUTH-14): the list; New attribute opens attributes/new. Values are edited on the
// user page (Attributes tab) and, for user-editable simple shapes, by users on the account page.
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { attributeShape, shapeLabel } from "@/components/AttributeForm";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTenant } from "@/lib/tenant";

function AttributesPage() {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: ["attributes", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/attributes", { params: { path: { slug: tenant } }, signal })),
  });
  const items = query.data?.items ?? [];

  return (
    <section aria-labelledby="attributes-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="attributes-heading" className="text-xl font-semibold">
          Attributes
        </h1>
        <Button asChild size="sm">
          <Link to="/t/$tenant/attributes/new" params={{ tenant }} data-testid="new-attribute">
            New attribute
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Custom user attributes, each validated by a JSON Schema. Edit a user's values on the user's page.
      </p>
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Attributes</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Name</TableHead>
                <TableHead scope="col">Input</TableHead>
                <TableHead scope="col">Flags</TableHead>
                <TableHead scope="col">Claim</TableHead>
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
                    No attributes defined yet.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((a) => (
                  <TableRow key={a.name}>
                    <TableCell>
                      <Link
                        to="/t/$tenant/attributes/$attributeName"
                        params={{ tenant, attributeName: a.name }}
                        className="font-mono font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                      >
                        {a.name}
                      </Link>
                    </TableCell>
                    <TableCell>{shapeLabel(attributeShape(a.schema))}</TableCell>
                    <TableCell>
                      <span className="flex flex-wrap gap-1">
                        {a.required && <Badge variant="secondary">Required</Badge>}
                        {a.user_editable && <Badge variant="outline">User editable</Badge>}
                        {!a.required && !a.user_editable && <span className="text-muted-foreground">—</span>}
                      </span>
                    </TableCell>
                    <TableCell>
                      {a.claim ? <code className="text-xs">{a.claim.claim}</code> : <span className="text-muted-foreground">Not in tokens</span>}
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

export const Route = createFileRoute("/t/$tenant/attributes/")({ component: AttributesPage });
