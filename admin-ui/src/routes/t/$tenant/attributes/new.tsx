// Create a custom attribute definition (C-L2: /attributes/new is its own page, not an attribute
// named "new"). After the definition is saved, its page opens.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { type AttributeBody, AttributeForm, NEW_ATTRIBUTE } from "@/components/AttributeForm";
import { useTenant } from "@/lib/tenant";

function NewAttributePage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const create = useMutation({
    mutationFn: async ({ name, body }: { name: string; body: AttributeBody }) =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/attributes/{name}", {
          params: { path: { slug: tenant, name } },
          body,
        }),
      ),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["attribute", tenant, saved.name], saved);
      await queryClient.invalidateQueries({ queryKey: ["attributes", tenant] });
      await navigate({ to: "/t/$tenant/attributes/$attributeName", params: { tenant, attributeName: saved.name } });
    },
  });

  return (
    <section aria-labelledby="new-attribute-heading" className="space-y-4">
      <Link
        to="/t/$tenant/attributes"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Attributes
      </Link>
      <h1 id="new-attribute-heading" className="text-xl font-semibold">
        New attribute
      </h1>
      <AttributeForm
        mode="create"
        initial={NEW_ATTRIBUTE}
        submitLabel="Create attribute"
        pending={create.isPending}
        error={create.error}
        onSubmit={(name, body) => create.mutate({ name, body })}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/attributes/new")({ component: NewAttributePage });
