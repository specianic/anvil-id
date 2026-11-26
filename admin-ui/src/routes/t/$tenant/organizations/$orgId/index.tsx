// Organization overview: edit slug, display name, MFA policy and default roles; delete.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import { ConfirmDialog } from "@/components/ConfirmDialog";
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
import { Button } from "@/components/ui/button";
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
  const [open, setOpen] = useState(false);
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: org.id } },
      });
    },
    onSuccess: async () => {
      setOpen(false);
      queryClient.removeQueries({ queryKey: orgQueryKey(tenant, org.id) });
      await queryClient.invalidateQueries({ queryKey: ["organizations", tenant] });
      await navigate({ to: "/t/$tenant/organizations", params: { tenant } });
    },
  });
  return (
    <Card className="border-destructive/50">
      <CardHeader>
        <CardTitle>
          <h2>Delete organization</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-sm">
          Removes the memberships, organization roles and their assignments, connections, domains and invitations.
          Members' sign-ins bound to this organization end. The users themselves stay in the tenant.
        </p>
        <Button variant="destructive" onClick={() => setOpen(true)} data-testid="delete-org">
          Delete organization
        </Button>
        <ConfirmDialog
          open={open}
          title={`Delete ${org.display_name}?`}
          description={
            <p>
              The organization <code>{org.slug}</code> and everything that belongs to it are removed. This cannot be
              undone.
            </p>
          }
          confirmLabel="Delete organization"
          onConfirm={() => remove.mutate()}
          onCancel={() => {
            setOpen(false);
            remove.reset();
          }}
          pending={remove.isPending}
          error={remove.error}
        />
      </CardContent>
    </Card>
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
