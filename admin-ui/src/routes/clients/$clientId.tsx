import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { CONSOLE_TENANT, type ClientView, api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
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
        <ClientDetails client={query.data} />
      )}
    </section>
  );
}

export const Route = createFileRoute("/clients/$clientId")({ component: ClientPage });
