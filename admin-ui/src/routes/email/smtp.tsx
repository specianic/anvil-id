import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, CONSOLE_TENANT, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { SelectField, StatusMessage, TextField, fieldErrors } from "@/components/form";
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

const SMTP_KEY = ["smtp", CONSOLE_TENANT] as const;

/** Tenant SMTP settings, or null when the tenant uses the installation's SMTP server (404). */
async function fetchSmtp(signal: AbortSignal): Promise<SmtpSettingsView | null> {
  try {
    return unwrap(
      await api.GET("/api/admin/v1/tenants/{slug}/smtp", { params: { path: { slug: CONSOLE_TENANT } }, signal }),
    );
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

function SmtpForm({ current }: { current: SmtpSettingsView | null }) {
  const queryClient = useQueryClient();
  const [host, setHost] = useState(current?.host ?? "");
  const [port, setPort] = useState(String(current?.port ?? 587));
  const [tls, setTls] = useState<SmtpTls>(current?.tls ?? "starttls");
  const [username, setUsername] = useState(current?.username ?? "");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState(current?.from ?? "");
  const [status, setStatus] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/smtp", {
          params: { path: { slug: CONSOLE_TENANT } },
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
      queryClient.setQueryData(SMTP_KEY, saved);
      setStatus("SMTP settings saved.");
      await queryClient.invalidateQueries({ queryKey: SMTP_KEY });
    },
  });

  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/smtp", { params: { path: { slug: CONSOLE_TENANT } } });
    },
    onSuccess: async () => {
      setConfirmRemove(false);
      queryClient.setQueryData(SMTP_KEY, null);
      setStatus("Tenant SMTP settings removed; the installation's SMTP server is used.");
      await queryClient.invalidateQueries({ queryKey: SMTP_KEY });
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
        {current === null && (
          <p className="text-muted-foreground text-sm" data-testid="smtp-source">
            This tenant uses the installation's SMTP server. Save settings here to use a different server.
          </p>
        )}
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
                Use installation SMTP
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
          description={<p>Mail for this tenant is sent through the installation's SMTP server again.</p>}
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
  const [to, setTo] = useState("");
  const send = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/smtp/test", {
          params: { path: { slug: CONSOLE_TENANT } },
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
  const query = useQuery({
    queryKey: SMTP_KEY,
    // Edits live in local state; a background refetch must not overwrite them.
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: ({ signal }) => fetchSmtp(signal),
  });

  return (
    <section aria-labelledby="smtp-heading" className="space-y-4">
      <Link to="/email" className="text-muted-foreground text-sm underline-offset-4 hover:underline">
        ← Email
      </Link>
      <h1 id="smtp-heading" className="text-xl font-semibold">
        SMTP settings
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading SMTP settings" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <SmtpForm current={query.data} />
          <TestSend />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/email/smtp")({ component: SmtpPage });
