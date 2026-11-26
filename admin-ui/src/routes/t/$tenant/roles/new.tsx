import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { NEW_ROLE, RoleForm, type RoleFormValues } from "@/components/RoleForm";
import { useTenant } from "@/lib/tenant";

function NewRolePage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const create = useMutation({
    mutationFn: async (values: RoleFormValues) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/roles", {
          params: { path: { slug: tenant } },
          body: { name: values.name, description: values.description, permissions: values.permissions },
        }),
      ),
    onSuccess: async (role) => {
      queryClient.setQueryData(["role", tenant, role.name], role);
      await queryClient.invalidateQueries({ queryKey: ["roles", tenant] });
      await navigate({ to: "/t/$tenant/roles/$roleName", params: { tenant, roleName: role.name } });
    },
  });

  return (
    <section aria-labelledby="new-role-heading" className="space-y-4">
      <Link
        to="/t/$tenant/roles"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Roles
      </Link>
      <h1 id="new-role-heading" className="text-xl font-semibold">
        New role
      </h1>
      <RoleForm
        initial={NEW_ROLE}
        submitLabel="Create role"
        pending={create.isPending}
        error={create.error}
        onSubmit={(values) => create.mutate(values)}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/roles/new")({ component: NewRolePage });
