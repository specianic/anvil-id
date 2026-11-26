// Members of an organization: add a user of the tenant (found by email) with roles, manage a
// member's roles within the org, remove a member (their sign-ins bound to the org end).
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { type FormEvent, useMemo, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog, Modal } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { OrgRoleAssignments, RolePicker, useAssignableRoles } from "@/components/OrgRoleAssignments";
import { ProblemAlert } from "@/components/ProblemAlert";
import { type FieldErrors, StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

type MemberView = components["schemas"]["MemberView"];

const PAGE_SIZE = 50;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Thrown when the email names no user of the tenant; shown next to the field. */
class UserLookupError extends Error {}

/**
 * The id of the tenant user with `email` (one `listUsers?email=` request; the API compares
 * case-insensitively). A user id is accepted as is.
 */
async function findUserId(tenant: string, input: string): Promise<string> {
  const wanted = input.trim();
  if (UUID_PATTERN.test(wanted)) return wanted.toLowerCase();
  const result = unwrap(
    await api.GET("/api/admin/v1/tenants/{slug}/users", {
      params: { path: { slug: tenant }, query: { email: wanted } },
    }),
  );
  const match = result.items[0];
  if (!match) throw new UserLookupError("No user of this tenant has this email.");
  return match.id;
}

function membersQueryKey(tenant: string, org: string) {
  return ["org-members", tenant, org] as const;
}

function AddMember({ tenant, org }: { tenant: string; org: string }) {
  const queryClient = useQueryClient();
  const assignable = useAssignableRoles(tenant, org);
  const [email, setEmail] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const add = useMutation({
    mutationFn: async () => {
      const userId = await findUserId(tenant, email);
      const result = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/members", {
          params: { path: { slug: tenant, org } },
          body: { user_id: userId, role_ids: roleIds },
        }),
      );
      return result.added ? `${email.trim()} added.` : `${email.trim()} already is a member; nothing changed.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setStatus(message);
      setEmail("");
      setRoleIds([]);
      await queryClient.invalidateQueries({ queryKey: membersQueryKey(tenant, org) });
      await queryClient.invalidateQueries({ queryKey: ["user-orgs", tenant] });
    },
  });
  const apiEmailErrors = fieldErrors(add.error).email;
  const fieldIssue: FieldErrors =
    add.error instanceof UserLookupError
      ? { email: [{ message: add.error.message }] }
      : apiEmailErrors
        ? { email: apiEmailErrors }
        : add.error instanceof ApiError && add.error.status === 404
          ? { email: [{ message: "No user of this tenant has this id." }] }
          : {};
  const otherError = add.error && Object.keys(fieldIssue).length === 0 ? add.error : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (email.trim() === "") return;
    add.mutate();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Add a member</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4" noValidate aria-label="Add a member" data-testid="add-member-form">
          {otherError ? <ProblemAlert error={otherError} /> : null}
          <TextField
            label="User"
            name="email"
            type="text"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            hint="The email (or id) of an existing user of this tenant. To bring in someone without an account, send an invitation."
            errors={fieldIssue.email}
            autoComplete="off"
            data-testid="add-member-email"
          />
          <RolePicker
            legend="Roles in this organization"
            roles={assignable.roles}
            value={roleIds}
            onChange={setRoleIds}
            isPending={assignable.isPending}
            error={assignable.error}
            testId="add-member-roles"
          />
          <Button type="submit" disabled={add.isPending || email.trim() === ""} data-testid="add-member">
            {add.isPending ? "Adding…" : "Add member"}
          </Button>
          <StatusMessage message={status} />
        </form>
      </CardContent>
    </Card>
  );
}

const col = createColumnHelper<DataTableFeatures, MemberView>();

function MembersPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const queryClient = useQueryClient();
  const pager = useCursorPager();
  const [rolesOf, setRolesOf] = useState<MemberView | null>(null);
  const [removing, setRemoving] = useState<MemberView | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const query = useQuery({
    queryKey: [...membersQueryKey(tenant, orgId), pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/members", {
          params: { path: { slug: tenant, org: orgId }, query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  const remove = useMutation({
    mutationFn: async (member: MemberView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}", {
        params: { path: { slug: tenant, org: orgId, user_id: member.user_id } },
      });
      return `${member.email ?? member.user_id} removed from the organization.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setRemoving(null);
      setStatus(message);
      await queryClient.invalidateQueries({ queryKey: membersQueryKey(tenant, orgId) });
      await queryClient.invalidateQueries({ queryKey: ["user-orgs", tenant] });
    },
  });

  const columns = useMemo(
    () =>
      col.columns([
        col.accessor("email", {
          header: "Member",
          cell: (info) => (
            <Link
              to="/t/$tenant/users/$userId"
              params={{ tenant, userId: info.row.original.user_id }}
              className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
            >
              {info.getValue() ?? info.row.original.user_id}
            </Link>
          ),
        }),
        col.accessor("created_at", { header: "Member since", cell: (info) => formatDateTime(info.getValue()) }),
        col.display({
          id: "actions",
          header: () => <span className="sr-only">Actions</span>,
          cell: (info) => {
            const m = info.row.original;
            const who = m.email ?? m.user_id;
            return (
              <div className="flex justify-end gap-2" data-testid={`member-${who}`}>
                <Button variant="outline" size="sm" onClick={() => setRolesOf(m)} aria-label={`Roles of ${who}`}>
                  Roles
                </Button>
                <Button variant="outline" size="sm" onClick={() => setRemoving(m)} aria-label={`Remove ${who}`}>
                  Remove
                </Button>
              </div>
            );
          },
        }),
      ]),
    [tenant],
  );

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Members</h2>
      <StatusMessage message={status} />
      <DataTable
        caption="Members"
        columns={columns}
        data={query.data?.items}
        getRowId={(m) => m.user_id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No members yet."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
      <AddMember tenant={tenant} org={orgId} />
      <Modal
        open={rolesOf !== null}
        onClose={() => setRolesOf(null)}
        title={`Roles of ${rolesOf?.email ?? rolesOf?.user_id ?? ""}`}
        placement="side"
      >
        {rolesOf && <OrgRoleAssignments tenant={tenant} org={orgId} userId={rolesOf.user_id} />}
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setRolesOf(null)}>
            Close
          </Button>
        </div>
      </Modal>
      <ConfirmDialog
        open={removing !== null}
        title="Remove member?"
        description={
          <p>
            {removing?.email ?? removing?.user_id} loses the membership and the roles in this organization, and their
            sign-ins to this organization end. The account itself stays.
          </p>
        }
        confirmLabel="Remove member"
        onConfirm={() => removing && remove.mutate(removing)}
        onCancel={() => {
          setRemoving(null);
          remove.reset();
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/members")({ component: MembersPage });
