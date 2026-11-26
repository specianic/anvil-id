// Create a webhook endpoint. The server generates the signing secret; it is shown once here and
// kept only in this page's state (the mutation result holds the endpoint without the secret).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import { NEW_WEBHOOK, OneTimeSecret, WebhookForm, type WebhookFormValues } from "@/components/WebhookForm";
import { useTenant } from "@/lib/tenant";

const linkClass =
  "text-sm underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function NewWebhookPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [secret, setSecret] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async (values: WebhookFormValues) => {
      const created = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/webhooks", {
          params: { path: { slug: tenant } },
          body: { name: values.name, url: values.url, events: values.events, enabled: values.enabled },
        }),
      );
      // The secret goes to component state only; the cached mutation result is the endpoint.
      setSecret(created.secret);
      return created.endpoint;
    },
    onSuccess: async (endpoint) => {
      queryClient.setQueryData(["webhook", tenant, endpoint.id], endpoint);
      await queryClient.invalidateQueries({ queryKey: ["webhooks", tenant] });
    },
  });
  const created = create.data;

  return (
    <section aria-labelledby="new-webhook-heading" className="space-y-4">
      <Link to="/t/$tenant/webhooks" params={{ tenant }} className={`text-muted-foreground ${linkClass}`}>
        ← Webhooks
      </Link>
      <h1 id="new-webhook-heading" className="text-xl font-semibold">
        {created ? "Endpoint created" : "New webhook endpoint"}
      </h1>
      {created ? (
        <div className="space-y-4">
          {secret ? (
            <OneTimeSecret
              title="Copy the signing secret now. It is not shown again."
              label="Signing secret"
              value={secret}
              testId="webhook-secret"
              onDone={() => setSecret(null)}
            >
              <p className="text-muted-foreground">
                Verify each delivery's <code>webhook-signature</code> header with it (Standard Webhooks).
              </p>
            </OneTimeSecret>
          ) : (
            <p role="status" className="text-sm">
              The secret is no longer shown. Rotate it on the endpoint page if it was lost.
            </p>
          )}
          <div className="flex gap-4">
            <Link
              to="/t/$tenant/webhooks/$webhookId"
              params={{ tenant, webhookId: created.id }}
              className={linkClass}
              data-testid="open-webhook"
            >
              Open {created.name}
            </Link>
            <Link to="/t/$tenant/webhooks" params={{ tenant }} className={linkClass}>
              Back to webhooks
            </Link>
          </div>
        </div>
      ) : (
        <WebhookForm
          mode="create"
          initial={NEW_WEBHOOK}
          submitLabel="Create endpoint"
          pending={create.isPending}
          error={create.error}
          onSubmit={(values) => create.mutate(values)}
        />
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/webhooks/new")({ component: NewWebhookPage });
