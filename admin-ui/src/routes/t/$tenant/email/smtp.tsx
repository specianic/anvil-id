import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { type SmtpState, fetchTenantSmtp, smtpQueryKey, smtpState, useSystemInfo } from "@/lib/smtp";
import { useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { SelectField, StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

type SmtpSettingsView = components["schemas"]["SmtpSettingsView"];
type SmtpTls = components["schemas"]["SmtpTls"];

const TLS_OPTIONS: readonly { value: SmtpTls; label: string }[] = [
  { value: "starttls", label: "STARTTLS (port 587)" },
  { value: "implicit", label: "Implicit TLS (port 465)" },
  { value: "none", label: "None (plain text, local relays only)" },
];

const smtpKey = smtpQueryKey;

/**
 * Where this tenant's mail goes right now (C-M14), from the tenant settings and the installation's
 * `smtp_configured`; never assumed.
 */
function SmtpSource({ state }: { state: SmtpState }) {
  if (state === "none") {
    return (
      <Alert variant="destructive" data-testid="smtp-source" data-state={state}>
        <AlertTitle>No SMTP server configured</AlertTitle>
        <AlertDescription>
          <p>
            No SMTP server configured — verification, recovery and invitation emails can't be sent. Enter a server
            below, or ask the operator to configure the installation's SMTP server.
          </p>
        </AlertDescription>
      </Alert>
    );
  }
  const text: Record<Exclude<SmtpState, "none">, string> = {
    tenant: "This tenant sends email through its own SMTP server (below).",
    installation:
      "This tenant uses the installation's SMTP server, configured by the operator. Save settings here to use a different server.",
    unknown:
      "This tenant has no SMTP settings of its own. Whether the installation has an SMTP server could not be read.",
  };
  return (
    <p className="text-muted-foreground text-sm" data-testid="smtp-source" data-state={state}>
      {text[state]}
    </p>
  );
}

function SmtpForm({ current, state }: { current: SmtpSettingsView | null; state: SmtpState }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [host, setHost] = useState(current?.host ?? "");
  const [port, setPort] = useState(String(current?.port ?? 587));
  const [tls, setTls] = useState<SmtpTls>(current?.tls ?? "starttls");
  const [username, setUsername] = useState(current?.username ?? "");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState(current?.from ?? "");
  const [status, setStatus] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const installationConfigured = useSystemInfo().data?.smtp_configured;

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/smtp", {
          params: { path: { slug: tenant } },
          body: {
            host: host.trim(),
            port: Number.parseInt(port, 10) || 0,
            tls,
            username: username.trim() || null,
            // Empty keeps the stored password.
            password: password === "" ? null : password,
            from: from.trim(),
          },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      setPassword("");
      queryClient.setQueryData(smtpKey(tenant), saved);
      setStatus("SMTP settings saved.");
      await queryClient.invalidateQueries({ queryKey: smtpKey(tenant) });
    },
  });

  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/smtp", { params: { path: { slug: tenant } } });
    },
    onSuccess: async () => {
      setConfirmRemove(false);
      queryClient.setQueryData(smtpKey(tenant), null);
      setStatus(
        installationConfigured === false
          ? "Tenant SMTP settings removed. No SMTP server is configured now: emails can't be sent."
          : "Tenant SMTP settings removed; the installation's SMTP server is used.",
      );
      await queryClient.invalidateQueries({ queryKey: smtpKey(tenant) });
    },
  });

  const errors = fieldErrors(save.error);
  const known = new Set(["host", "port", "tls", "username", "password", "from"]);
  const otherError =
    save.error && !(save.error instanceof ApiError && save.error.problem.errors.every((e) => known.has(e.field)))
      ? save.error
      : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Server</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <SmtpSource state={state} />
        <form onSubmit={submit} aria-label="SMTP settings" className="grid gap-4 sm:grid-cols-2" noValidate>
          {otherError ? (
            <div className="sm:col-span-2">
              <ProblemAlert error={otherError} />
            </div>
          ) : null}
          <TextField
            label="Host"
            name="host"
            autoComplete="off"
            required
            value={host}
            onChange={(e) => setHost(e.target.value)}
            errors={errors.host}
          />
          <TextField
            label="Port"
            name="port"
            type="number"
            inputMode="numeric"
            min={1}
            max={65535}
            required
            value={port}
            onChange={(e) => setPort(e.target.value)}
            errors={errors.port}
          />
          <SelectField
            label="TLS"
            name="tls"
            value={tls}
            onChange={(e) => setTls(e.target.value as SmtpTls)}
            options={TLS_OPTIONS}
            errors={errors.tls}
          />
          <TextField
            label="From address"
            name="from"
            required
            hint="addr@example.com or Name <addr@example.com>"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            errors={errors.from}
          />
          <TextField
            label="Username"
            name="username"
            autoComplete="off"
            optional
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            errors={errors.username}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            autoComplete="new-password"
            optional
            hint={
              current?.password_set
                ? "A password is set. Leave empty to keep it."
                : "Stored encrypted; it is never shown again."
            }
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            errors={errors.password}
          />
          <div className="flex flex-wrap gap-2 sm:col-span-2">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save SMTP settings"}
            </Button>
            {current !== null && (
              <Button type="button" variant="outline" onClick={() => setConfirmRemove(true)}>
                {installationConfigured === false ? "Remove tenant SMTP settings" : "Use installation SMTP"}
              </Button>
            )}
          </div>
          <div className="sm:col-span-2">
            <StatusMessage message={status} />
          </div>
        </form>
        <ConfirmDialog
          open={confirmRemove}
          title="Remove tenant SMTP settings?"
          description={
            <p>
              {installationConfigured === false
                ? "The installation has no SMTP server: this tenant can't send email until a server is configured again."
                : "Mail for this tenant is sent through the installation's SMTP server again."}
            </p>
          }
          confirmLabel="Remove settings"
          onConfirm={() => remove.mutate()}
          onCancel={() => {
            remove.reset();
            setConfirmRemove(false);
          }}
          pending={remove.isPending}
          error={remove.error}
        />
      </CardContent>
    </Card>
  );
}

function TestSend() {
  const tenant = useTenant();
  const [to, setTo] = useState("");
  const send = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/smtp/test", {
          params: { path: { slug: tenant } },
          body: { to: to.trim() },
        }),
      ),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    send.mutate();
  };

  const errors = fieldErrors(send.error);
  const result = send.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Send a test email</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="Send a test email" className="space-y-4" noValidate>
          <TextField
            label="Recipient"
            name="to"
            type="email"
            autoComplete="email"
            required
            value={to}
            onChange={(e) => setTo(e.target.value)}
            errors={errors.to}
          />
          <Button type="submit" disabled={send.isPending}>
            {send.isPending ? "Sending…" : "Send test email"}
          </Button>
          <div aria-live="polite" role="status" data-testid="smtp-test-result">
            {send.isSuccess && result?.delivered && (
              <p className="rounded-md border px-3 py-2 text-sm">Test email delivered to the SMTP server.</p>
            )}
            {send.isSuccess && result && !result.delivered && (
              <p className="border-destructive text-destructive rounded-md border px-3 py-2 text-sm">
                Delivery failed: {result.error ?? "unknown error"}
              </p>
            )}
          </div>
          {send.isError && !errors.to ? <ProblemAlert error={send.error} /> : null}
        </form>
      </CardContent>
    </Card>
  );
}

function SmtpPage() {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: smtpKey(tenant),
    // Edits live in local state; a background refetch must not overwrite them.
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: ({ signal }) => fetchTenantSmtp(tenant, signal),
  });
  const info = useSystemInfo();

  return (
    <section aria-labelledby="smtp-heading" className="space-y-4">
      <Link
        to="/t/$tenant/email"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Email
      </Link>
      <h1 id="smtp-heading" className="text-xl font-semibold">
        SMTP settings
      </h1>
      {query.isPending || info.isPending ? (
        <div role="status" aria-label="Loading SMTP settings" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <SmtpForm
            current={query.data}
            state={smtpState(query.data, info.data?.smtp_configured)}
          />
          <TestSend />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/email/smtp")({ component: SmtpPage });
