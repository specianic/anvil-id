import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { CONSOLE_TENANT, api, unwrap } from "@/api/client";
import { ClientForm, type ClientFormValues, NEW_CLIENT, SecretOnce, createBody } from "@/components/ClientForm";

const linkClass =
  "text-sm underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function NewClientPage() {
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: async (values: ClientFormValues) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/clients", {
          params: { path: { slug: CONSOLE_TENANT } },
          body: createBody(values),
        }),
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
    },
  });

  const created = create.data;

  return (
    <section aria-labelledby="new-client-heading" className="space-y-4">
      <Link to="/clients" className={`text-muted-foreground ${linkClass}`}>
        ← Clients
      </Link>
      <h1 id="new-client-heading" className="text-xl font-semibold">
        {created ? "Client created" : "New client"}
      </h1>
      {created ? (
        <div className="space-y-4">
          {created.client_secret ? (
            <SecretOnce clientId={created.client_id} secret={created.client_secret} />
          ) : (
            <p role="status" className="text-sm">
              Client <code data-testid="created-client-id">{created.client_id}</code> created. It has no secret.
            </p>
          )}
          <div className="flex gap-4">
            <Link to="/clients/$clientId" params={{ clientId: created.client_id }} className={linkClass}>
              Open {created.name}
            </Link>
            <Link to="/clients" className={linkClass}>
              Back to clients
            </Link>
          </div>
        </div>
      ) : (
        <ClientForm
          mode="create"
          initial={NEW_CLIENT}
          submitLabel="Create client"
          pending={create.isPending}
          error={create.error}
          onSubmit={(values) => create.mutate(values)}
        />
      )}
    </section>
  );
}

export const Route = createFileRoute("/clients/new")({ component: NewClientPage });
