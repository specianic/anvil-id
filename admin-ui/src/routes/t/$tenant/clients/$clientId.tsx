// One client: its integration values (issuer, discovery URL, client id, redirect URIs) with copy
// buttons, the edit form (one Save), secret rotation and, in a danger zone, deletion. The built-in
// console client of the system tenant cannot be deleted (the server refuses with 409), so the page
// offers no Delete for it.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { KeyRound, ShieldCheck } from "lucide-react";
import { type ReactNode, useState } from "react";
import { type ClientView, api, unwrap } from "@/api/client";
import { CONSOLE_CLIENT_ID } from "@/auth/oidc";
import { SYSTEM_TENANT, useTenant, useTenantView } from "@/lib/tenant";
import {
  AUTH_METHOD_LABELS,
  CLIENT_TYPE_LABELS,
  CREATED_BY_HINTS,
  CREATED_BY_LABELS,
  ClientForm,
  type ClientFormValues,
  updateBody,
  valuesFromClient,
} from "@/components/ClientForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DangerZone } from "@/components/DangerZone";
import { IntegrationCard } from "@/components/IntegrationCard";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { OneTimeSecret } from "@/components/WebhookForm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

/** The anvil-console client of the system tenant: built in, not deletable. */
function isBuiltInConsoleClient(tenant: string, client: ClientView): boolean {
  return tenant === SYSTEM_TENANT && client.client_id === CONSOLE_CLIENT_ID;
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

/** Facts the form cannot change: type, authentication, origin and dates. */
function ClientFacts({ client }: { client: ClientView }) {
  return (
    <dl className="grid gap-4 sm:grid-cols-3 lg:grid-cols-5" data-testid="client-facts">
      <Meta label="Client type">{CLIENT_TYPE_LABELS[client.client_type]}</Meta>
      <Meta label="Authentication">
        {AUTH_METHOD_LABELS[client.auth_method]}{" "}
        <code className="text-muted-foreground font-mono text-xs">{client.auth_method}</code>
      </Meta>
      <Meta label="Created by">
        <span title={CREATED_BY_HINTS[client.registration_source]}>{CREATED_BY_LABELS[client.registration_source]}</span>
      </Meta>
      <Meta label="Created">{formatDateTime(client.created_at)}</Meta>
      <Meta label="Updated">{formatDateTime(client.updated_at)}</Meta>
    </dl>
  );
}

function Integration({ client }: { client: ClientView }) {
  const tenant = useTenant();
  const view = useTenantView(tenant);
  if (view.isError) return <ProblemAlert error={view.error} />;
  if (!view.data) return <Skeleton className="h-24 w-full" />;
  return (
    <IntegrationCard
      issuer={view.data.issuer}
      discoveryUrl={view.data.discovery_url}
      clientId={client.client_id}
      redirectUris={client.redirect_uris}
    />
  );
}

function EditClient({ client }: { client: ClientView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: ClientFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
          params: { path: { slug: tenant, client_id: client.client_id } },
          body: updateBody(values),
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["client", tenant, client.client_id], saved);
      setStatus("Client saved.");
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Settings</h2>
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

/**
 * Secret rotation. The old secret stops working at once: a grace period with two valid secrets
 * needs dual-secret support on the server, which does not exist (C-L7, deferred).
 */
function ClientSecret({ client }: { client: ClientView }) {
  const tenant = useTenant();
  const [confirm, setConfirm] = useState(false);
  // The rotated secret lives only in component state; the cached mutation result has none.
  const [secret, setSecret] = useState<string | null>(null);
  const rotate = useMutation({
    mutationFn: async () => {
      const rotated = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/clients/{client_id}/secret", {
          params: { path: { slug: tenant, client_id: client.client_id } },
        }),
      );
      setSecret(rotated.client_secret);
      return { client_id: rotated.client_id };
    },
    onSuccess: () => setConfirm(false),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Client secret</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {secret && (
          <OneTimeSecret
            title="Copy the new client secret now. It is not shown again."
            label="Client secret"
            value={secret}
            testId="rotated-client-secret"
            onDone={() => setSecret(null)}
          />
        )}
        <p className="text-muted-foreground text-sm">
          Rotating generates a new secret. The old secret stops working immediately, so update the app right away.
        </p>
        <Button variant="outline" onClick={() => setConfirm(true)}>
          <KeyRound aria-hidden="true" />
          Rotate secret
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Rotate the client secret?"
        description={
          <p>
            A new secret is generated and the old secret stops working immediately. Apps using it fail to sign in
            until they are updated with the new one.
          </p>
        }
        confirmLabel="Rotate secret"
        onConfirm={() => rotate.mutate()}
        onCancel={() => {
          rotate.reset();
          setConfirm(false);
        }}
        pending={rotate.isPending}
        error={rotate.error}
      />
    </Card>
  );
}

function DeleteClient({ client }: { client: ClientView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
        params: { path: { slug: tenant, client_id: client.client_id } },
      });
    },
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: ["client", tenant, client.client_id] });
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
      await navigate({ to: "/t/$tenant/clients", params: { tenant } });
    },
  });
  return (
    <DangerZone
      title="Delete this client"
      description="The client is removed and every token issued to it is revoked. Apps using it can no longer sign users in. This cannot be undone."
      confirmText={client.name}
      actionLabel="Delete client"
      onConfirm={() => remove.mutate()}
      pending={remove.isPending}
      error={remove.error}
    />
  );
}

function ClientPage() {
  const tenant = useTenant();
  const { clientId } = Route.useParams();
  const query = useQuery({
    queryKey: ["client", tenant, clientId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
          params: { path: { slug: tenant, client_id: clientId } },
          signal,
        }),
      ),
  });
  const client = query.data;
  const builtIn = client ? isBuiltInConsoleClient(tenant, client) : false;
  const hasSecret = client?.auth_method === "client_secret_basic" || client?.auth_method === "client_secret_post";

  return (
    <section aria-labelledby="client-heading" className="space-y-4">
      <Link
        to="/t/$tenant/clients"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Clients
      </Link>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 id="client-heading" className="text-xl font-semibold break-all">
            {client?.name ?? "Client"}
          </h1>
          {builtIn ? (
            <Badge variant="outline" data-testid="built-in-client">
              <ShieldCheck aria-hidden="true" />
              Built-in client
            </Badge>
          ) : null}
        </div>
        <Link
          to="/t/$tenant/branding/$clientId"
          params={{ tenant, clientId }}
          className="text-sm underline underline-offset-4"
          data-testid="client-branding-link"
        >
          Branding
        </Link>
      </div>
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
          <ClientFacts client={query.data} />
          {builtIn ? (
            <p className="text-muted-foreground text-sm" data-testid="built-in-client-note">
              The console signs in with this client. It is part of AnvilID and cannot be deleted.
            </p>
          ) : null}
          <Integration client={query.data} />
          <EditClient client={query.data} />
          {hasSecret ? <ClientSecret client={query.data} /> : null}
          {builtIn ? null : <DeleteClient client={query.data} />}
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/clients/$clientId")({ component: ClientPage });
