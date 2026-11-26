// Invitations of an organization: invite an address with roles, list them with status and expiry,
// revoke an open one. The invitation link (its token) only ever goes to the invited address by
// email: the API returns no token, and the console has nothing to show or cache.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { type AssignableRole, RolePicker, useAssignableRoles } from "@/components/OrgRoleAssignments";
import { ProblemAlert } from "@/components/ProblemAlert";
import { CheckboxField, StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

type InvitationView = components["schemas"]["InvitationView"];
type InvitationStatus = components["schemas"]["InvitationStatus"];

const STATUS_LABELS: Record<InvitationStatus, string> = {
  open: "Pending",
  accepted: "Accepted",
  revoked: "Revoked",
  expired: "Expired",
};

function invitationsQueryKey(tenant: string, org: string) {
  return ["org-invitations", tenant, org] as const;
}

function InviteForm({ tenant, org, roles }: { tenant: string; org: string; roles: ReturnType<typeof useAssignableRoles> }) {
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/invitations", {
          params: { path: { slug: tenant, org } },
          body: { email: email.trim(), role_ids: roleIds },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (invitation) => {
      setStatus(`Invitation sent to ${invitation.email}. It expires ${formatDateTime(invitation.expires_at)}.`);
      setEmail("");
      setRoleIds([]);
      await queryClient.invalidateQueries({ queryKey: invitationsQueryKey(tenant, org) });
    },
  });
  const server = fieldErrors(create.error);
  const otherError = create.error && !server.email && !server.role_ids ? create.error : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (email.trim() === "") return;
    create.mutate();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Invite someone</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4" noValidate aria-label="Invite someone" data-testid="invite-form">
          {otherError ? <ProblemAlert error={otherError} /> : null}
          <TextField
            label="Email"
            name="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            hint="The address receives a link valid for 7 days. Accepting it adds the membership."
            errors={server.email}
            autoComplete="off"
            data-testid="invite-email"
          />
          <RolePicker
            legend="Roles on acceptance"
            roles={roles.roles}
            value={roleIds}
            onChange={setRoleIds}
            isPending={roles.isPending}
            error={roles.error}
            testId="invite-roles"
          />
          {server.role_ids && (
            <ul className="text-destructive space-y-0.5 text-sm" data-field-error>
              {server.role_ids.map((m) => (
                <li key={m.message}>{m.message}</li>
              ))}
            </ul>
          )}
          <Button type="submit" disabled={create.isPending || email.trim() === ""} data-testid="send-invitation">
            {create.isPending ? "Sending…" : "Send invitation"}
          </Button>
          <StatusMessage message={status} />
        </form>
      </CardContent>
    </Card>
  );
}

function roleNames(ids: string[], roles: AssignableRole[]): string {
  if (ids.length === 0) return "None";
  return ids.map((id) => roles.find((r) => r.id === id)?.name ?? id).join(", ");
}

function InvitationsPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const queryClient = useQueryClient();
  const roles = useAssignableRoles(tenant, orgId);
  const [includeClosed, setIncludeClosed] = useState(false);
  const [revoking, setRevoking] = useState<InvitationView | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const query = useQuery({
    queryKey: [...invitationsQueryKey(tenant, orgId), includeClosed],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/invitations", {
          params: { path: { slug: tenant, org: orgId }, query: { include_closed: includeClosed } },
          signal,
        }),
      ),
  });
  const revoke = useMutation({
    mutationFn: async (invitation: InvitationView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/invitations/{id}", {
        params: { path: { slug: tenant, org: orgId, id: invitation.id } },
      });
      return `Invitation for ${invitation.email} revoked.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setRevoking(null);
      setStatus(message);
      await queryClient.invalidateQueries({ queryKey: invitationsQueryKey(tenant, orgId) });
    },
  });
  const items = query.data?.items ?? [];

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Invitations</h2>
      <CheckboxField
        label="Show accepted and revoked invitations"
        checked={includeClosed}
        onChange={(e) => setIncludeClosed(e.target.checked)}
        data-testid="invitations-include-closed"
      />
      <StatusMessage message={status} />
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Invitations</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Email</TableHead>
                <TableHead scope="col">Status</TableHead>
                <TableHead scope="col">Roles</TableHead>
                <TableHead scope="col">Sent</TableHead>
                <TableHead scope="col">Expires</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isPending ? (
                <TableRow>
                  <TableCell colSpan={6}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground h-20 text-center">
                    No invitations.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((inv) => (
                  <TableRow key={inv.id} data-testid="invitation-row" data-email={inv.email} data-status={inv.status}>
                    <TableCell className="break-all">{inv.email}</TableCell>
                    <TableCell>
                      <Badge
                        variant={inv.status === "open" ? "default" : inv.status === "accepted" ? "secondary" : "outline"}
                        data-testid="invitation-status"
                      >
                        {STATUS_LABELS[inv.status]}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{roleNames(inv.role_ids, roles.roles)}</TableCell>
                    <TableCell>{formatDateTime(inv.created_at)}</TableCell>
                    <TableCell>
                      {inv.status === "accepted"
                        ? `Accepted ${formatDateTime(inv.accepted_at)}`
                        : inv.status === "revoked"
                          ? `Revoked ${formatDateTime(inv.revoked_at)}`
                          : formatDateTime(inv.expires_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      {inv.status === "open" && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRevoking(inv)}
                          aria-label={`Revoke invitation for ${inv.email}`}
                        >
                          Revoke
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
      <InviteForm tenant={tenant} org={orgId} roles={roles} />
      <ConfirmDialog
        open={revoking !== null}
        title="Revoke invitation?"
        description={<p>The link sent to {revoking?.email} stops working. You can invite the address again later.</p>}
        confirmLabel="Revoke invitation"
        onConfirm={() => revoking && revoke.mutate(revoking)}
        onCancel={() => {
          setRevoking(null);
          revoke.reset();
        }}
        pending={revoke.isPending}
        error={revoke.error}
      />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/invitations")({ component: InvitationsPage });
