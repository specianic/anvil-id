// One role: edit name, description and permissions, see who holds it, delete it. Changes that
// would leave the system tenant without an administrator are refused (409) and explained.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { type UserView, api, unwrap } from "@/api/client";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { ProblemAlert } from "@/components/ProblemAlert";
import { type RoleDto, RoleForm, type RoleFormValues, RoleProblem, valuesFromRole } from "@/components/RoleForm";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useTenant } from "@/lib/tenant";

const col = createColumnHelper<DataTableFeatures, UserView>();

function holderColumns(tenant: string) {
  return col.columns([
    col.accessor("email", {
      header: "Email",
      cell: (info) => (
        <Link
          to="/t/$tenant/users/$userId"
          params={{ tenant, userId: info.row.original.id }}
          className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {info.getValue()}
        </Link>
      ),
    }),
    col.accessor("status", {
      header: "Status",
      cell: (info) => (
        <Badge variant={info.getValue() === "blocked" ? "destructive" : "secondary"}>{info.getValue()}</Badge>
      ),
    }),
  ]);
}

function Holders({ role }: { role: RoleDto }) {
  const tenant = useTenant();
  const pager = useCursorPager();
  const columns = useMemo(() => holderColumns(tenant), [tenant]);
  const query = useQuery({
    queryKey: ["role-users", tenant, role.name, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/roles/{name}/users", {
          params: { path: { slug: tenant, name: role.name }, query: { limit: 50, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Users with this role</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-muted-foreground text-sm">Assign or remove the role on a user's page (Roles tab).</p>
        <DataTable
          caption="Users with this role"
          columns={columns}
          data={query.data?.items}
          getRowId={(u) => u.id}
          isPending={query.isPending}
          isFetching={query.isFetching}
          error={query.error}
          emptyMessage="No user holds this role."
          pager={pager}
          nextCursor={query.data?.next_cursor}
        />
      </CardContent>
    </Card>
  );
}

function EditRole({ role }: { role: RoleDto }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (values: RoleFormValues) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/roles/{name}", {
          params: { path: { slug: tenant, name: role.name } },
          body: {
            name: values.name !== role.name ? values.name : undefined,
            description: values.description,
            permissions: values.permissions,
          },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["role", tenant, saved.name], saved);
      setStatus("Role saved.");
      await queryClient.invalidateQueries({ queryKey: ["roles", tenant] });
      await queryClient.invalidateQueries({ queryKey: ["user-roles", tenant] });
      if (saved.name !== role.name) {
        queryClient.removeQueries({ queryKey: ["role", tenant, role.name] });
        await navigate({ to: "/t/$tenant/roles/$roleName", params: { tenant, roleName: saved.name }, replace: true });
      }
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Edit role</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <RoleForm
          initial={valuesFromRole(role)}
          submitLabel="Save changes"
          pending={update.isPending}
          error={update.error}
          onSubmit={(values) => update.mutate(values)}
        />
        <StatusMessage message={status} />
      </CardContent>
    </Card>
  );
}

function DeleteRole({ role }: { role: RoleDto }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/roles/{name}", {
        params: { path: { slug: tenant, name: role.name } },
      });
    },
    onSuccess: async () => {
      setConfirm(false);
      queryClient.removeQueries({ queryKey: ["role", tenant, role.name] });
      await queryClient.invalidateQueries({ queryKey: ["roles", tenant] });
      await queryClient.invalidateQueries({ queryKey: ["user-roles", tenant] });
      await navigate({ to: "/t/$tenant/roles", params: { tenant } });
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Delete role</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-sm">
          Every assignment of the role is removed. Tokens issued from now on no longer carry it.
        </p>
        <Button variant="destructive" onClick={() => setConfirm(true)} data-testid="delete-role">
          Delete role
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Delete this role?"
        description={
          <div className="space-y-3">
            <p>{`The role ${role.name} and all its assignments are removed.`}</p>
            {remove.error ? <RoleProblem error={remove.error} /> : null}
          </div>
        }
        confirmLabel="Delete role"
        onConfirm={() => remove.mutate()}
        onCancel={() => {
          setConfirm(false);
          remove.reset();
        }}
        pending={remove.isPending}
      />
    </Card>
  );
}

function RolePage() {
  const tenant = useTenant();
  const { roleName } = Route.useParams();
  const query = useQuery({
    queryKey: ["role", tenant, roleName],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/roles/{name}", {
          params: { path: { slug: tenant, name: roleName } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="role-heading" className="space-y-4">
      <Link
        to="/t/$tenant/roles"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Roles
      </Link>
      <h1 id="role-heading" className="text-xl font-semibold break-all">
        {query.data?.name ?? roleName}
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading role" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <EditRole role={query.data} />
          <Holders role={query.data} />
          <DeleteRole role={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/roles/$roleName")({ component: RolePage });
