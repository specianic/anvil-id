// One webhook endpoint: settings, enable/disable, secret rotation (new secret shown once), test
// send and the delivery log with redelivery.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { api, unwrap } from "@/api/client";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DeliveryLog, deliveriesQueryKey } from "@/components/DeliveryLog";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  OneTimeSecret,
  type WebhookEndpoint,
  WebhookForm,
  type WebhookFormValues,
  valuesFromEndpoint,
} from "@/components/WebhookForm";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 py-2">
      <dt className="text-muted-foreground text-sm">{label}</dt>
      <dd className="col-span-2 text-sm break-all">{children}</dd>
    </div>
  );
}

function Overview({ endpoint }: { endpoint: WebhookEndpoint }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const toggle = useMutation({
    mutationFn: async (enabled: boolean) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/webhooks/{id}", {
          params: { path: { slug: tenant, id: endpoint.id } },
          body: { enabled },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["webhook", tenant, endpoint.id], saved);
      setStatus(saved.enabled ? "Endpoint enabled." : "Endpoint disabled.");
      await queryClient.invalidateQueries({ queryKey: ["webhooks", tenant] });
    },
  });
  const test = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/webhooks/{id}/test", {
          params: { path: { slug: tenant, id: endpoint.id } },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async () => {
      setStatus("Test event queued. Its delivery appears in the log below.");
      await queryClient.invalidateQueries({ queryKey: deliveriesQueryKey(tenant, endpoint.id) });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Endpoint</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="divide-y">
          <Field label="Status">
            <span data-testid="webhook-status">
              {endpoint.enabled ? (
                <Badge>Enabled</Badge>
              ) : (
                <Badge variant="outline">
                  {endpoint.disabled_reason ? `Disabled (${endpoint.disabled_reason})` : "Disabled"}
                </Badge>
              )}
            </span>
          </Field>
          <Field label="URL">
            <code className="text-xs">{endpoint.url}</code>
          </Field>
          <Field label="Events">
            <code className="text-xs">{endpoint.events.join(" ")}</code>
          </Field>
          <Field label="Signing secret">
            {endpoint.secret_configured ? "Configured (cannot be shown)" : "Not set"}
            {endpoint.previous_secret_expires_at && (
              <span className="text-muted-foreground block text-xs">
                The previous secret also signs until {formatDateTime(endpoint.previous_secret_expires_at)}.
              </span>
            )}
          </Field>
          <Field label="Created">{formatDateTime(endpoint.created_at)}</Field>
          <Field label="Updated">{formatDateTime(endpoint.updated_at)}</Field>
        </dl>
        {toggle.error ? <ProblemAlert error={toggle.error} /> : null}
        {test.error ? <ProblemAlert error={test.error} /> : null}
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => test.mutate()} disabled={test.isPending} data-testid="send-webhook-test">
            {test.isPending ? "Sending…" : "Send test event"}
          </Button>
          <Button
            variant="outline"
            onClick={() => toggle.mutate(!endpoint.enabled)}
            disabled={toggle.isPending}
            data-testid="toggle-webhook"
          >
            {endpoint.enabled ? "Disable" : "Enable"}
          </Button>
        </div>
        <StatusMessage message={status} />
      </CardContent>
    </Card>
  );
}

function EditEndpoint({ endpoint }: { endpoint: WebhookEndpoint }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: WebhookFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/webhooks/{id}", {
          params: { path: { slug: tenant, id: endpoint.id } },
          body: { name: values.name, url: values.url, events: values.events, enabled: values.enabled },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["webhook", tenant, endpoint.id], saved);
      setStatus("Endpoint saved.");
      await queryClient.invalidateQueries({ queryKey: ["webhooks", tenant] });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Edit endpoint</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Keyed by the enabled flag so the toggle above and this form stay in step. */}
        <WebhookForm
          key={String(endpoint.enabled)}
          mode="edit"
          initial={valuesFromEndpoint(endpoint)}
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

function Credentials({ endpoint }: { endpoint: WebhookEndpoint }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState<"rotate" | "delete" | null>(null);
  const [secret, setSecret] = useState<string | null>(null);

  const rotate = useMutation({
    mutationFn: async () => {
      const rotated = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/webhooks/{id}/secret", {
          params: { path: { slug: tenant, id: endpoint.id } },
        }),
      );
      // The new secret stays in component state; the cache only gets the endpoint.
      setSecret(rotated.secret);
      return rotated.endpoint;
    },
    onSuccess: (saved) => {
      setConfirm(null);
      queryClient.setQueryData(["webhook", tenant, endpoint.id], saved);
    },
  });
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/webhooks/{id}", {
        params: { path: { slug: tenant, id: endpoint.id } },
      });
    },
    onSuccess: async () => {
      setConfirm(null);
      queryClient.removeQueries({ queryKey: ["webhook", tenant, endpoint.id] });
      queryClient.removeQueries({ queryKey: deliveriesQueryKey(tenant, endpoint.id) });
      await queryClient.invalidateQueries({ queryKey: ["webhooks", tenant] });
      await navigate({ to: "/t/$tenant/webhooks", params: { tenant } });
    },
  });
  const active = confirm === "rotate" ? rotate : remove;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Secret and removal</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {secret && (
          <OneTimeSecret
            title="Copy the new signing secret now. It is not shown again."
            label="Signing secret"
            value={secret}
            testId="webhook-secret"
            onDone={() => setSecret(null)}
          >
            <p className="text-muted-foreground">
              The previous secret keeps signing deliveries for 24 hours, so receivers can switch without dropping
              events.
            </p>
          </OneTimeSecret>
        )}
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setConfirm("rotate")} data-testid="rotate-webhook-secret">
            Rotate secret
          </Button>
          <Button variant="destructive" onClick={() => setConfirm("delete")} data-testid="delete-webhook">
            Delete endpoint
          </Button>
        </div>
      </CardContent>
      <ConfirmDialog
        open={confirm !== null}
        title={confirm === "rotate" ? "Rotate the signing secret?" : "Delete this endpoint?"}
        description={
          <p>
            {confirm === "rotate"
              ? "A new secret is generated. Deliveries are signed with both secrets for 24 hours."
              : "The endpoint and its delivery log are removed. Pending deliveries are dropped."}
          </p>
        }
        confirmLabel={confirm === "rotate" ? "Rotate secret" : "Delete endpoint"}
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

function WebhookPage() {
  const tenant = useTenant();
  const { webhookId } = Route.useParams();
  const query = useQuery({
    queryKey: ["webhook", tenant, webhookId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/webhooks/{id}", {
          params: { path: { slug: tenant, id: webhookId } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="webhook-heading" className="space-y-4">
      <Link
        to="/t/$tenant/webhooks"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Webhooks
      </Link>
      <h1 id="webhook-heading" className="font-mono text-xl font-semibold break-all">
        {query.data?.name ?? "Webhook endpoint"}
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading endpoint" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <Overview endpoint={query.data} />
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Delivery log</h2>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <DeliveryLog tenant={tenant} endpointId={query.data.id} />
            </CardContent>
          </Card>
          <EditEndpoint endpoint={query.data} />
          <Credentials endpoint={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/webhooks/$webhookId")({ component: WebhookPage });
