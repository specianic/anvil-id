import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { CONSOLE_TENANT, type ClientView, api, unwrap } from "@/api/client";
import { ClientForm, type ClientFormValues, SecretOnce, updateBody, valuesFromClient } from "@/components/ClientForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 py-2">
      <dt className="text-muted-foreground text-sm">{label}</dt>
      <dd className="col-span-2 text-sm break-all">{children}</dd>
    </div>
  );
}

function List({ items, empty }: { items: readonly string[]; empty: string }) {
  if (items.length === 0) return <span className="text-muted-foreground">{empty}</span>;
  return (
    <ul className="space-y-1">
      {items.map((item) => (
        <li key={item}>
          <code className="text-xs">{item}</code>
        </li>
      ))}
    </ul>
  );
}

function ClientDetails({ client }: { client: ClientView }) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y">
            <Field label="Client ID">
              <code>{client.client_id}</code>
            </Field>
            <Field label="Name">{client.name}</Field>
            <Field label="Client type">{client.client_type}</Field>
            <Field label="Application type">{client.application_type}</Field>
            <Field label="Auth method">
              <code className="text-xs">{client.auth_method}</code>
            </Field>
            <Field label="PKCE required">{client.require_pkce ? "Yes" : "No"}</Field>
            <Field label="Access token format">{client.token_format}</Field>
            <Field label="Consent">{client.consent_mode === "required" ? "Required" : "Skipped (first party)"}</Field>
            <Field label="ID token signing">{client.id_token_signed_response_alg}</Field>
            <Field label="Tenant-wide introspection">{client.can_introspect ? "Yes" : "No"}</Field>
            <Field label="Created">{formatDateTime(client.created_at)}</Field>
            <Field label="Updated">{formatDateTime(client.updated_at)}</Field>
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Authorization</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y">
            <Field label="Redirect URIs">
              <List items={client.redirect_uris} empty="None" />
            </Field>
            <Field label="Grant types">
              <List items={client.grant_types} empty="None" />
            </Field>
            <Field label="Scopes">
              <List items={client.scopes} empty="None" />
            </Field>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}

function EditClient({ client }: { client: ClientView }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: ClientFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
          params: { path: { slug: CONSOLE_TENANT, client_id: client.client_id } },
          body: updateBody(values),
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["client", CONSOLE_TENANT, client.client_id], saved);
      setStatus("Client saved.");
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Edit client</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <ClientForm
          mode="edit"
          initial={valuesFromClient(client)}
          submitLabel="Save changes"
          pending={update.isPending}
          error={update.error}
          onSubmit={(values) => update.mutate(values)}
        />
        <StatusMessage message={status} />
      </CardContent>
    </Card>
  );
}

function DangerZone({ client }: { client: ClientView }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState<"rotate" | "delete" | null>(null);
  const hasSecret = client.auth_method === "client_secret_basic" || client.auth_method === "client_secret_post";

  const rotate = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/clients/{client_id}/secret", {
          params: { path: { slug: CONSOLE_TENANT, client_id: client.client_id } },
        }),
      ),
    onSuccess: () => setConfirm(null),
  });

  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
        params: { path: { slug: CONSOLE_TENANT, client_id: client.client_id } },
      });
    },
    onSuccess: async () => {
      setConfirm(null);
      queryClient.removeQueries({ queryKey: ["client", CONSOLE_TENANT, client.client_id] });
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
      await navigate({ to: "/clients" });
    },
  });

  const active = confirm === "rotate" ? rotate : remove;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Credentials and removal</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {rotate.data && <SecretOnce clientId={rotate.data.client_id} secret={rotate.data.client_secret} />}
        <div className="flex flex-wrap gap-2">
          {hasSecret && (
            <Button variant="outline" onClick={() => setConfirm("rotate")}>
              Rotate secret
            </Button>
          )}
          <Button variant="destructive" onClick={() => setConfirm("delete")}>
            Delete client
          </Button>
        </div>
      </CardContent>
      <ConfirmDialog
        open={confirm !== null}
        title={confirm === "rotate" ? "Rotate the client secret?" : "Delete this client?"}
        description={
          <p>
            {confirm === "rotate"
              ? "A new secret is generated and the current one stops working immediately."
              : "The client is removed and every token issued to it is revoked. This cannot be undone."}
          </p>
        }
        confirmLabel={confirm === "rotate" ? "Rotate secret" : "Delete client"}
        onConfirm={() => active.mutate()}
        onCancel={() => {
          rotate.reset();
          remove.reset();
          setConfirm(null);
        }}
        pending={active.isPending}
        error={active.error}
      />
    </Card>
  );
}

function ClientPage() {
  const { clientId } = Route.useParams();
  const query = useQuery({
    queryKey: ["client", CONSOLE_TENANT, clientId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
          params: { path: { slug: CONSOLE_TENANT, client_id: clientId } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="client-heading" className="space-y-4">
      <Link to="/clients" className="text-muted-foreground text-sm underline-offset-4 hover:underline">
        ← Clients
      </Link>
      <h1 id="client-heading" className="text-xl font-semibold break-all">
        {query.data?.name ?? "Client"}
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading client" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-6 w-1/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <ClientDetails client={query.data} />
          <EditClient client={query.data} />
          <DangerZone client={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/clients/$clientId")({ component: ClientPage });
