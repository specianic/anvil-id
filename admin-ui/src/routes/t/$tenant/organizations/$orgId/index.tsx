// Organization overview: edit slug, display name, MFA policy and default roles; delete in the danger
// zone at the bottom (the admin types the organization slug to confirm).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import { DangerZone } from "@/components/DangerZone";
import {
  OrgForm,
  type OrgFormValues,
  type OrganizationView,
  orgQueryKey,
  patchOrgBody,
  useOrganization,
  valuesFromOrg,
} from "@/components/OrgForm";
import { StatusMessage } from "@/components/form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

function EditOrganization({ org }: { org: OrganizationView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: OrgFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/organizations/{org}", {
          params: { path: { slug: tenant, org: org.id } },
          body: patchOrgBody(values),
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(orgQueryKey(tenant, org.id), saved);
      setStatus("Organization saved.");
      await queryClient.invalidateQueries({ queryKey: ["organizations", tenant] });
      // The route may address the org by slug; follow a slug change.
      await navigate({ to: "/t/$tenant/organizations/$orgId", params: { tenant, orgId: saved.id }, replace: true });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Settings</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <OrgForm
          editing={{ tenant, org: org.id }}
          initial={valuesFromOrg(org)}
          submitLabel="Save changes"
          pending={update.isPending}
          error={update.error}
          onSubmit={(values) => update.mutate(values)}
        />
        <StatusMessage message={status} />
        <p className="text-muted-foreground text-xs">
          Id <code>{org.id}</code> · created {formatDateTime(org.created_at)} · updated {formatDateTime(org.updated_at)}
        </p>
      </CardContent>
    </Card>
  );
}

function DeleteOrganization({ org }: { org: OrganizationView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const remove = useMutation({
    mutationFn: async () => {
      // Errors are thrown by the client middleware; a 204 has no body to unwrap.
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: org.id } },
      });
    },
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: orgQueryKey(tenant, org.id) });
      await queryClient.invalidateQueries({ queryKey: ["organizations", tenant] });
      await navigate({ to: "/t/$tenant/organizations", params: { tenant } });
    },
  });
  return (
    <DangerZone
      title="Delete this organization"
      description={
        <p>
          Removes the memberships, organization roles and their assignments, connections, domains and invitations of{" "}
          <strong>{org.display_name}</strong>. Members' sign-ins bound to this organization end. The users themselves
          stay in the tenant. This cannot be undone.
        </p>
      }
      confirmText={org.slug}
      actionLabel="Delete organization"
      onConfirm={() => remove.mutate()}
      pending={remove.isPending}
      error={remove.error}
    />
  );
}

function OrganizationOverview() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const query = useOrganization(tenant, orgId);
  // The layout renders this only once the organization loaded.
  if (!query.data) return null;
  return (
    <div className="space-y-4">
      <EditOrganization org={query.data} />
      <DeleteOrganization org={query.data} />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/")({ component: OrganizationOverview });
