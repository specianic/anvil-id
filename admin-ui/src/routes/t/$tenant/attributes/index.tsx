// Custom attribute definitions of the tenant (AUTH-14): list and create. Values are edited on the
// user page (Attributes tab) and, for user-editable simple shapes, by users on the account page.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import {
  AttributeForm,
  type AttributeBody,
  NEW_ATTRIBUTE,
  attributeShape,
  shapeLabel,
} from "@/components/AttributeForm";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTenant } from "@/lib/tenant";

function NewAttribute({ onCancel }: { onCancel: () => void }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const create = useMutation({
    mutationFn: async ({ name, body }: { name: string; body: AttributeBody }) =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/attributes/{name}", {
          params: { path: { slug: tenant, name } },
          body,
        }),
      ),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["attribute", tenant, saved.name], saved);
      await queryClient.invalidateQueries({ queryKey: ["attributes", tenant] });
      await navigate({ to: "/t/$tenant/attributes/$attributeName", params: { tenant, attributeName: saved.name } });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>New attribute</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <AttributeForm
          mode="create"
          initial={NEW_ATTRIBUTE}
          submitLabel="Create attribute"
          pending={create.isPending}
          error={create.error}
          onSubmit={(name, body) => create.mutate({ name, body })}
        />
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </CardContent>
    </Card>
  );
}

function AttributesPage() {
  const tenant = useTenant();
  const [creating, setCreating] = useState(false);
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
        {!creating && (
          <Button size="sm" onClick={() => setCreating(true)} data-testid="new-attribute">
            New attribute
          </Button>
        )}
      </div>
      <p className="text-muted-foreground text-sm">
        Custom user attributes, each validated by a JSON Schema. Edit a user's values on the user's page.
      </p>
      {creating && <NewAttribute onCancel={() => setCreating(false)} />}
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
