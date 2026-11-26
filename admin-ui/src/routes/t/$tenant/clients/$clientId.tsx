import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { type ClientView, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import { ClientForm, type ClientFormValues, updateBody, valuesFromClient } from "@/components/ClientForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { OneTimeSecret } from "@/components/WebhookForm";
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

const MFA_LABELS: Record<NonNullable<ClientView["mfa_policy"]>, string> = {
  off: "Off",
  optional: "Optional",
  required: "Required",
};

const ORG_POLICY_LABELS: Record<ClientView["organization"], string> = {
  off: "Off",
  optional: "Optional",
  required: "Required",
};

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
      <Card data-testid="client-logout-security">
        <CardHeader>
          <CardTitle>Logout and security</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y">
            <Field label="Post-logout redirect URIs">
              <List items={client.post_logout_redirect_uris} empty="None" />
            </Field>
            <Field label="Back-channel logout URI">
              {client.backchannel_logout_uri ? (
                <code className="text-xs">{client.backchannel_logout_uri}</code>
              ) : (
                <span className="text-muted-foreground">None</span>
              )}
            </Field>
            {client.backchannel_logout_uri && (
              <Field label="Back-channel session required">
                {client.backchannel_logout_session_required ? "Yes" : "No"}
              </Field>
            )}
            <Field label="Allowed resources">
              <List items={client.allowed_resources} empty="None: tokens are for this client" />
            </Field>
            <Field label="MFA policy">{client.mfa_policy ? MFA_LABELS[client.mfa_policy] : "Tenant default"}</Field>
            <Field label="Organizations">
              <span data-testid="client-organization">{ORG_POLICY_LABELS[client.organization]}</span>
            </Field>
          </dl>
        </CardContent>
      </Card>
    </div>
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
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState<"rotate" | "delete" | null>(null);
  const hasSecret = client.auth_method === "client_secret_basic" || client.auth_method === "client_secret_post";

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
    onSuccess: () => setConfirm(null),
  });

  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
        params: { path: { slug: tenant, client_id: client.client_id } },
      });
    },
    onSuccess: async () => {
      setConfirm(null);
      queryClient.removeQueries({ queryKey: ["client", tenant, client.client_id] });
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
      await navigate({ to: "/t/$tenant/clients", params: { tenant } });
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
        {secret && (
          <OneTimeSecret
            title="Copy the new client secret now. It is not shown again."
            label="Client secret"
            value={secret}
            testId="rotated-client-secret"
            onDone={() => setSecret(null)}
          />
        )}
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
        <h1 id="client-heading" className="text-xl font-semibold break-all">
          {query.data?.name ?? "Client"}
        </h1>
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
          <ClientDetails client={query.data} />
          <EditClient client={query.data} />
          <DangerZone client={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/clients/$clientId")({ component: ClientPage });
