// Roles of the tenant (ORG-05): name, description and permissions. Roles reach tokens through the
// tenant's claim mapping (Login settings > Token claims); in the system tenant their admin scopes
// bound what console users may do.
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";

function rolesQueryKey(tenant: string) {
  return ["roles", tenant] as const;
}

function RolesPage() {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: rolesQueryKey(tenant),
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/roles", { params: { path: { slug: tenant } }, signal })),
  });
  const items = query.data?.items ?? [];

  return (
    <section aria-labelledby="roles-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="roles-heading" className="text-xl font-semibold">
          Roles
        </h1>
        <Button asChild size="sm">
          <Link to="/t/$tenant/roles/new" params={{ tenant }} data-testid="new-role">
            New role
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        {tenant === SYSTEM_TENANT
          ? "Roles of console users. Admin scopes among a role's permissions decide what its holders may do here."
          : "Assign roles to users on the user's page. Tokens carry them as configured under Login settings, Token claims."}
      </p>
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Roles</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Name</TableHead>
                <TableHead scope="col">Description</TableHead>
                <TableHead scope="col">Permissions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isPending ? (
                <TableRow>
                  <TableCell colSpan={3}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground h-20 text-center">
                    No roles defined yet.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <Link
                        to="/t/$tenant/roles/$roleName"
                        params={{ tenant, roleName: r.name }}
                        className="font-mono font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                      >
                        {r.name}
                      </Link>
                    </TableCell>
                    <TableCell className="max-w-xs break-words">{r.description || "—"}</TableCell>
                    <TableCell>
                      {r.permissions.length === 0 ? (
                        <span className="text-muted-foreground">None</span>
                      ) : (
                        <code className="text-xs break-all">{r.permissions.join(" ")}</code>
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

export const Route = createFileRoute("/t/$tenant/roles/")({ component: RolesPage });
