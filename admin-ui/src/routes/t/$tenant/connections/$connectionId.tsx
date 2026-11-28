import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { AlertTriangle, CircleOff, CirclePower } from "lucide-react";
import { useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { useTenant, useTenantView } from "@/lib/tenant";
import {
  ConnectionForm,
  type ConnectionFormValues,
  ConnectionStatusBadges,
  type ConnectionView,
  ENABLE_FIELD_LABELS,
  ENABLE_HINT,
  KIND_LABELS,
  SecretRotation,
  redirectUriFor,
  updateBody,
  valuesFromConnection,
} from "@/components/ConnectionForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

const queryKey = (tenant: string, id: string) => ["connection", tenant, id] as const;

function RedirectUri({ connection }: { connection: ConnectionView }) {
  const [status, setStatus] = useState<string | null>(null);
  // The URI the console showed before saving, computed from the tenant's issuer and the slug: the
  // saved view must carry the same one, or what the admin registered at the provider is wrong.
  const issuer = useTenantView(useTenant()).data?.issuer;
  const expected = issuer ? redirectUriFor(issuer, connection.slug) : null;
  const mismatch = expected !== null && expected !== connection.redirect_uri;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(connection.redirect_uri);
      setStatus("Redirect URI copied.");
    } catch {
      setStatus("Copying failed; select the URI and copy it manually.");
    }
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Redirect URI</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-sm">
          Register this callback URL at {KIND_LABELS[connection.kind]} (authorized redirect URI / callback URL).
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <code className="bg-muted rounded px-2 py-1 text-sm break-all" data-testid="connection-redirect-uri">
            {connection.redirect_uri}
          </code>
          <Button type="button" variant="outline" size="sm" onClick={() => void copy()} data-testid="copy-redirect-uri">
            Copy
          </Button>
        </div>
        <StatusMessage message={status} />
        {mismatch && (
          <p role="alert" className="text-destructive flex items-start gap-2 text-sm" data-testid="redirect-uri-mismatch">
            <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span>
              This differs from the redirect URI shown before saving ({expected}). Register the URI above at the
              provider, and check the tenant's issuer settings.
            </span>
          </p>
        )}
        <dl className="text-muted-foreground grid grid-cols-3 gap-2 text-sm">
          <dt>Created</dt>
          <dd className="col-span-2">{formatDateTime(connection.created_at)}</dd>
          <dt>Updated</dt>
          <dd className="col-span-2">{formatDateTime(connection.updated_at)}</dd>
        </dl>
      </CardContent>
    </Card>
  );
}

function EditConnection({ connection }: { connection: ConnectionView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: ConnectionFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/connections/{id}", {
          params: { path: { slug: tenant, id: connection.id } },
          // Enabling is the separate Enable action (EnableConnection).
          body: updateBody(values, false),
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(queryKey(tenant, connection.id), saved);
      setStatus("Connection saved.");
      await queryClient.invalidateQueries({ queryKey: ["connections"] });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Settings</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ConnectionForm
          mode="edit"
          initial={valuesFromConnection(connection)}
          submitLabel="Save changes"
          pending={update.isPending}
          error={update.error}
          onSubmit={(values) => update.mutate(values)}
          status={status}
          showEnabled={false}
        />
      </CardContent>
    </Card>
  );
}

/**
 * Enable / disable. The server refuses to enable an incomplete connection (or a generic OIDC one whose
 * issuer fails discovery) with 422 naming the field; the reason is shown here.
 */
function EnableConnection({ connection }: { connection: ConnectionView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const toggle = useMutation({
    mutationFn: async (enabled: boolean) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/connections/{id}", {
          params: { path: { slug: tenant, id: connection.id } },
          body: { enabled },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(queryKey(tenant, connection.id), saved);
      setStatus(saved.enabled ? "Connection enabled." : "Connection disabled.");
      await queryClient.invalidateQueries({ queryKey: ["connections"] });
    },
  });
  const refusal =
    toggle.error instanceof ApiError && toggle.error.status === 422 && toggle.error.problem.errors.length > 0
      ? toggle.error.problem.errors
      : null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Status</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm" data-testid="connection-enabled-status">
          {connection.enabled ? (
            <>
              <strong>Enabled.</strong>{" "}
              <span className="text-muted-foreground">The sign-in page offers this connection.</span>
            </>
          ) : (
            <>
              <strong>Disabled.</strong> <span className="text-muted-foreground">{ENABLE_HINT}</span>
            </>
          )}
        </p>
        {connection.enabled ? (
          <Button
            type="button"
            variant="outline"
            disabled={toggle.isPending}
            onClick={() => toggle.mutate(false)}
            data-testid="disable-connection"
          >
            <CircleOff aria-hidden="true" />
            {toggle.isPending ? "Disabling…" : "Disable"}
          </Button>
        ) : (
          <Button
            type="button"
            disabled={toggle.isPending}
            onClick={() => toggle.mutate(true)}
            data-testid="enable-connection"
          >
            <CirclePower aria-hidden="true" />
            {toggle.isPending ? "Checking…" : "Enable"}
          </Button>
        )}
        {refusal ? (
          <div role="alert" className="text-destructive space-y-1 text-sm" data-testid="enable-connection-error">
            <p>The connection was not enabled:</p>
            <ul className="list-disc space-y-0.5 pl-5">
              {refusal.map((e) => (
                <li key={`${e.field}:${e.message}`}>
                  {ENABLE_FIELD_LABELS[e.field] ?? e.field}: {e.message}
                </li>
              ))}
            </ul>
          </div>
        ) : toggle.error ? (
          <ProblemAlert error={toggle.error} />
        ) : null}
        <StatusMessage message={status} />
      </CardContent>
    </Card>
  );
}

/** The connection's write-only secret: the shared `SecretRotation` (one implementation). */
function ConnectionSecret({ connection }: { connection: ConnectionView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>{connection.kind === "apple" ? "Private key" : "Client secret"}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <SecretRotation
          kind={connection.kind}
          configured={connection.secret_configured}
          put={async (secret) =>
            unwrap(
              await api.PUT("/api/admin/v1/tenants/{slug}/connections/{id}/secret", {
                params: { path: { slug: tenant, id: connection.id } },
                body: { secret },
              }),
            )
          }
          onSaved={async (saved) => {
            queryClient.setQueryData(queryKey(tenant, connection.id), saved);
            await queryClient.invalidateQueries({ queryKey: ["connections"] });
          }}
        />
      </CardContent>
    </Card>
  );
}

function DangerZone({ connection }: { connection: ConnectionView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/connections/{id}", {
        params: { path: { slug: tenant, id: connection.id } },
      });
    },
    onSuccess: async () => {
      setConfirm(false);
      queryClient.removeQueries({ queryKey: queryKey(tenant, connection.id) });
      await queryClient.invalidateQueries({ queryKey: ["connections"] });
      await navigate({ to: "/t/$tenant/connections", params: { tenant } });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Removal</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Button variant="destructive" onClick={() => setConfirm(true)} data-testid="delete-connection">
          Delete connection
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Delete this connection?"
        description={
          <p>
            The connection is removed and every account link to it is deleted. Users who signed in only through it
            can no longer sign in with it. This cannot be undone.
          </p>
        }
        confirmLabel="Delete connection"
        onConfirm={() => remove.mutate()}
        onCancel={() => {
          remove.reset();
          setConfirm(false);
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </Card>
  );
}

function ConnectionPage() {
  const tenant = useTenant();
  const { connectionId } = Route.useParams();
  const query = useQuery({
    queryKey: queryKey(tenant, connectionId),
    // Edits live in the form's local state; a background refetch must not reset them.
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/connections/{id}", {
          params: { path: { slug: tenant, id: connectionId } },
          signal,
        }),
      ),
  });
  const connection = query.data;

  return (
    <section aria-labelledby="connection-heading" className="space-y-4">
      <Link
        to="/t/$tenant/connections"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Connections
      </Link>
      <div className="flex flex-wrap items-center gap-2">
        <h1 id="connection-heading" className="text-xl font-semibold break-all">
          {connection?.display_name ?? "Connection"}
        </h1>
        {connection && (
          <>
            <Badge variant="secondary">{KIND_LABELS[connection.kind]}</Badge>
            <ConnectionStatusBadges connection={connection} />
          </>
        )}
      </div>
      {query.isPending ? (
        <div role="status" aria-label="Loading connection" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-6 w-1/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <RedirectUri connection={query.data} />
          <EnableConnection connection={query.data} />
          <EditConnection connection={query.data} />
          <ConnectionSecret connection={query.data} />
          <DangerZone connection={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/connections/$connectionId")({ component: ConnectionPage });
