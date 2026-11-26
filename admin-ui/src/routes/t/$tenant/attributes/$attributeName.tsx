// One attribute definition: replace it (PUT) or delete it. Stored user values are kept when the
// schema changes or the definition is deleted; values that no longer validate are left out of tokens.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import {
  type AttributeBody,
  type AttributeDefinition,
  AttributeForm,
  valuesFromDefinition,
} from "@/components/AttributeForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useTenant } from "@/lib/tenant";

function EditAttribute({ definition }: { definition: AttributeDefinition }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async (body: AttributeBody) =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/attributes/{name}", {
          params: { path: { slug: tenant, name: definition.name } },
          body,
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["attribute", tenant, saved.name], saved);
      setStatus("Attribute saved.");
      await queryClient.invalidateQueries({ queryKey: ["attributes", tenant] });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Definition</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <AttributeForm
          mode="edit"
          initial={valuesFromDefinition(definition)}
          submitLabel="Save changes"
          pending={save.isPending}
          error={save.error}
          onSubmit={(_name, body) => save.mutate(body)}
        />
        <StatusMessage message={status} />
      </CardContent>
    </Card>
  );
}

function DeleteAttribute({ definition }: { definition: AttributeDefinition }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/attributes/{name}", {
        params: { path: { slug: tenant, name: definition.name } },
      });
    },
    onSuccess: async () => {
      setConfirm(false);
      queryClient.removeQueries({ queryKey: ["attribute", tenant, definition.name] });
      await queryClient.invalidateQueries({ queryKey: ["attributes", tenant] });
      await navigate({ to: "/t/$tenant/attributes", params: { tenant } });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Delete attribute</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-sm">
          The definition is removed. Users' stored values are kept (shown as undefined keys) but no longer validated or
          put into tokens.
        </p>
        <Button variant="destructive" onClick={() => setConfirm(true)} data-testid="delete-attribute">
          Delete attribute
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Delete this attribute?"
        description={<p>{`The definition of ${definition.name} is removed.`}</p>}
        confirmLabel="Delete attribute"
        onConfirm={() => remove.mutate()}
        onCancel={() => {
          setConfirm(false);
          remove.reset();
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </Card>
  );
}

function AttributePage() {
  const tenant = useTenant();
  const { attributeName } = Route.useParams();
  const query = useQuery({
    queryKey: ["attribute", tenant, attributeName],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/attributes/{name}", {
          params: { path: { slug: tenant, name: attributeName } },
          signal,
        }),
      ),
  });
  return (
    <section aria-labelledby="attribute-heading" className="space-y-4">
      <Link
        to="/t/$tenant/attributes"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Attributes
      </Link>
      <h1 id="attribute-heading" className="font-mono text-xl font-semibold break-all">
        {attributeName}
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading attribute" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <EditAttribute definition={query.data} />
          <DeleteAttribute definition={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/attributes/$attributeName")({ component: AttributePage });
