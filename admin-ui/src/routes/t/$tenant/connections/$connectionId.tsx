import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useRef, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import {
  ConnectionForm,
  type ConnectionFormValues,
  type ConnectionView,
  KIND_LABELS,
  LocalFieldError,
  SecretInput,
  readSecret,
  updateBody,
  valuesFromConnection,
} from "@/components/ConnectionForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage, fieldErrors } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

const queryKey = (tenant: string, id: string) => ["connection", tenant, id] as const;

function RedirectUri({ connection }: { connection: ConnectionView }) {
  const [status, setStatus] = useState<string | null>(null);
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
          body: updateBody(values),
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
        />
      </CardContent>
    </Card>
  );
}

function SecretCard({ connection }: { connection: ConnectionView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const apple = connection.kind === "apple";
  const [password, setPassword] = useState("");
  const [localError, setLocalError] = useState<LocalFieldError | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  // Handed to the request through a ref so the secret never lands in the mutation cache.
  const secretRef = useRef<string | null>(null);

  const put = useMutation({
    mutationFn: async (_action: "set" | "clear") => {
      const secret = secretRef.current;
      secretRef.current = null;
      return unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/connections/{id}/secret", {
          params: { path: { slug: tenant, id: connection.id } },
          body: { secret },
        }),
      );
    },
    onMutate: () => setStatus(null),
    onSuccess: async (saved, action) => {
      setPassword("");
      if (fileInput.current) fileInput.current.value = "";
      setConfirmClear(false);
      queryClient.setQueryData(queryKey(tenant, connection.id), saved);
      setStatus(action === "clear" ? "Secret removed." : "Secret saved.");
      await queryClient.invalidateQueries({ queryKey: ["connections"] });
    },
  });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    let secret: string | null;
    try {
      secret = await readSecret(connection.kind, password, fileInput);
    } catch (err) {
      if (err instanceof LocalFieldError) {
        setLocalError(err);
        return;
      }
      throw err;
    }
    if (secret === null) {
      setLocalError(new LocalFieldError("secret", apple ? "Choose a .p8 key file." : "Enter the new secret."));
      return;
    }
    secretRef.current = secret;
    put.mutate("set");
  };

  const formError = put.variables === "set" ? put.error : null;
  const errors = fieldErrors(formError);
  if (localError) errors.secret = [{ message: localError.message }];
  const otherError =
    formError && !(formError instanceof ApiError && formError.problem.errors.every((e) => e.field === "secret"))
      ? formError
      : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>{apple ? "Private key" : "Client secret"}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm" data-testid="connection-secret-status">
          {connection.secret_configured ? (
            <Badge variant="secondary">Configured</Badge>
          ) : (
            <Badge variant="outline">Not set</Badge>
          )}{" "}
          <span className="text-muted-foreground">
            The {apple ? "key" : "secret"} is stored encrypted and never shown. Enter a new one to replace it.
          </span>
        </p>
        <form
          onSubmit={(e) => void submit(e)}
          aria-label={apple ? "Replace private key" : "Rotate secret"}
          className="space-y-4"
          noValidate
        >
          {otherError ? <ProblemAlert error={otherError} /> : null}
          <SecretInput
            kind={connection.kind}
            label={apple ? "New key file (.p8)" : "New client secret"}
            hint={apple ? "The .p8 key downloaded from Apple." : "Replaces the current secret immediately."}
            password={password}
            onPasswordChange={setPassword}
            fileInput={fileInput}
            errors={errors.secret}
          />
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={put.isPending} data-testid="rotate-connection-secret">
              {put.isPending && put.variables === "set" ? "Saving…" : apple ? "Replace key" : "Rotate secret"}
            </Button>
            {connection.secret_configured && (
              <Button type="button" variant="outline" onClick={() => setConfirmClear(true)}>
                Remove {apple ? "key" : "secret"}
              </Button>
            )}
          </div>
          <StatusMessage message={status} />
        </form>
        <ConfirmDialog
          open={confirmClear}
          title={apple ? "Remove the private key?" : "Remove the client secret?"}
          description={<p>Sign-in through this connection fails until a new one is set.</p>}
          confirmLabel={apple ? "Remove key" : "Remove secret"}
          onConfirm={() => {
            secretRef.current = null;
            put.mutate("clear");
          }}
          onCancel={() => {
            put.reset();
            setConfirmClear(false);
          }}
          pending={put.isPending}
          error={put.variables === "clear" ? put.error : null}
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
            {connection.enabled ? <Badge>Enabled</Badge> : <Badge variant="outline">Disabled</Badge>}
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
          <EditConnection connection={query.data} />
          <SecretCard connection={query.data} />
          <DangerZone connection={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/connections/$connectionId")({ component: ConnectionPage });
