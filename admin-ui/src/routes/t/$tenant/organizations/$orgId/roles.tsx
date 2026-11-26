// Roles owned by an organization: create, edit and delete. Members get them (and tenant roles)
// on the Members tab; `org:admin` makes holders administrators of the organization.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import { ConfirmDialog, Modal } from "@/components/ConfirmDialog";
import { NEW_ORG_ROLE, OrgRoleForm, type OrgRoleSubmit } from "@/components/OrgForm";
import { type OrgRoleView, orgRolesQueryKey, useOrgRoles } from "@/components/OrgRoleAssignments";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTenant } from "@/lib/tenant";

function OrgRolesPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const queryClient = useQueryClient();
  const query = useOrgRoles(tenant, orgId);
  /** `new` for the create dialog, a role for the edit dialog. */
  const [editing, setEditing] = useState<OrgRoleView | "new" | null>(null);
  const [deleting, setDeleting] = useState<OrgRoleView | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: orgRolesQueryKey(tenant, orgId) });
    await queryClient.invalidateQueries({ queryKey: ["org-member-roles", tenant, orgId] });
  };

  const save = useMutation({
    mutationFn: async ({ target, values }: { target: OrgRoleView | "new"; values: OrgRoleSubmit }) => {
      if (target === "new") {
        const role = unwrap(
          await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/roles", {
            params: { path: { slug: tenant, org: orgId } },
            body: values,
          }),
        );
        return `Role ${role.name} created.`;
      }
      const role = unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/organizations/{org}/roles/{name}", {
          params: { path: { slug: tenant, org: orgId, name: target.name } },
          body: values,
        }),
      );
      return `Role ${role.name} saved.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setEditing(null);
      setStatus(message);
      await invalidate();
    },
  });

  const remove = useMutation({
    mutationFn: async (role: OrgRoleView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/roles/{name}", {
        params: { path: { slug: tenant, org: orgId, name: role.name } },
      });
      return `Role ${role.name} deleted.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setDeleting(null);
      setStatus(message);
      await invalidate();
    },
  });

  const openEditor = (target: OrgRoleView | "new") => {
    save.reset();
    setEditing(target);
  };
  const items = query.data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Organization roles</h2>
        <Button size="sm" onClick={() => openEditor("new")} data-testid="new-org-role">
          New role
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Roles defined only for this organization. Members can also hold the tenant's{" "}
        <Link to="/t/$tenant/roles" params={{ tenant }} className="underline underline-offset-4">
          roles
        </Link>{" "}
        within the organization; assign both on the Members tab.
      </p>
      <StatusMessage message={status} />
      {query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <div className="rounded-md border">
          <Table aria-busy={query.isFetching}>
            <TableCaption className="sr-only">Organization roles</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Name</TableHead>
                <TableHead scope="col">Description</TableHead>
                <TableHead scope="col">Permissions</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isPending ? (
                <TableRow>
                  <TableCell colSpan={4}>
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground h-20 text-center">
                    No organization roles yet.
                  </TableCell>
                </TableRow>
              ) : (
                items.map((r) => (
                  <TableRow key={r.id} data-testid={`org-role-${r.name}`}>
                    <TableCell className="font-mono font-medium">{r.name}</TableCell>
                    <TableCell className="max-w-xs break-words">{r.description || "—"}</TableCell>
                    <TableCell>
                      {r.permissions.length === 0 ? (
                        <span className="text-muted-foreground">None</span>
                      ) : (
                        <code className="text-xs break-all">{r.permissions.join(" ")}</code>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Button variant="outline" size="sm" onClick={() => openEditor(r)} aria-label={`Edit role ${r.name}`}>
                          Edit
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            remove.reset();
                            setDeleting(r);
                          }}
                          aria-label={`Delete role ${r.name}`}
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "New organization role" : `Edit role ${editing?.name ?? ""}`}
      >
        {editing !== null && (
          <OrgRoleForm
            key={editing === "new" ? "new" : editing.id}
            initial={
              editing === "new"
                ? NEW_ORG_ROLE
                : { name: editing.name, description: editing.description, permissions: editing.permissions.join(" ") }
            }
            submitLabel={editing === "new" ? "Create role" : "Save role"}
            pending={save.isPending}
            error={save.error}
            onSubmit={(values) => save.mutate({ target: editing, values })}
            onCancel={() => setEditing(null)}
          />
        )}
      </Modal>
      <ConfirmDialog
        open={deleting !== null}
        title={`Delete role ${deleting?.name ?? ""}?`}
        description={<p>Members holding it lose it in this organization. This cannot be undone.</p>}
        confirmLabel="Delete role"
        onConfirm={() => deleting && remove.mutate(deleting)}
        onCancel={() => {
          setDeleting(null);
          remove.reset();
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/roles")({ component: OrgRolesPage });
