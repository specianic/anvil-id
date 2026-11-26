import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, unwrap } from "@/api/client";
import { NEW_ORG, OrgForm, type OrgFormValues, createOrgBody } from "@/components/OrgForm";
import { useTenant } from "@/lib/tenant";

function NewOrganizationPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const create = useMutation({
    mutationFn: async (values: OrgFormValues) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations", {
          params: { path: { slug: tenant } },
          body: createOrgBody(values),
        }),
      ),
    onSuccess: async (org) => {
      queryClient.setQueryData(["organization", tenant, org.id], org);
      await queryClient.invalidateQueries({ queryKey: ["organizations", tenant] });
      await navigate({ to: "/t/$tenant/organizations/$orgId", params: { tenant, orgId: org.id } });
    },
  });

  return (
    <section aria-labelledby="new-org-heading" className="space-y-4">
      <Link
        to="/t/$tenant/organizations"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Organizations
      </Link>
      <h1 id="new-org-heading" className="text-xl font-semibold">
        New organization
      </h1>
      <OrgForm
        initial={NEW_ORG}
        submitLabel="Create organization"
        pending={create.isPending}
        error={create.error}
        onSubmit={(values) => create.mutate(values)}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/new")({ component: NewOrganizationPage });
