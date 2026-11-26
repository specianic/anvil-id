// Roles inside an organization (06-12): the roles that may be given in an org (the tenant's roles
// and the org's own roles, none carrying an admin permission), a picker for role ids (default roles,
// invitations, direct member adds) and the per-member assignment panel. The API decides
// eligibility; the console only hides roles it would refuse anyway (admin permissions).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage, controlClass } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export type OrgRoleView = components["schemas"]["OrgRoleView"];
export type OrgRoleScope = components["schemas"]["OrgRoleScope"];
type RoleDto = components["schemas"]["RoleDto"];

/** A role that can be given within an organization. */
export interface AssignableRole {
  id: string;
  name: string;
  scope: OrgRoleScope;
  description: string;
  permissions: string[];
}

/** `admin` and `admin:*` are installation permissions; the API refuses them inside organizations. */
export function isAdminPermission(permission: string): boolean {
  return permission === "admin" || permission.startsWith("admin:");
}

export function orgRolesQueryKey(tenant: string, org: string) {
  return ["org-roles", tenant, org] as const;
}

export function memberRolesQueryKey(tenant: string, org: string, userId: string) {
  return ["org-member-roles", tenant, org, userId] as const;
}

/** The roles owned by the organization (name order). */
export function useOrgRoles(tenant: string, org: string) {
  return useQuery({
    queryKey: orgRolesQueryKey(tenant, org),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/roles", {
          params: { path: { slug: tenant, org } },
          signal,
        }),
      ),
  });
}

/** Tenant roles and the org's roles that may be given in the org, org roles first. */
export function useAssignableRoles(tenant: string, org: string) {
  const tenantRoles = useQuery({
    queryKey: ["roles", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/roles", { params: { path: { slug: tenant } }, signal })),
  });
  const orgRoles = useOrgRoles(tenant, org);
  const fromTenant = (r: RoleDto): AssignableRole => ({
    id: r.id,
    name: r.name,
    scope: "tenant",
    description: r.description,
    permissions: r.permissions,
  });
  const roles: AssignableRole[] = [
    ...(orgRoles.data?.items ?? []).map((r) => ({ ...r, scope: "org" as const })),
    ...(tenantRoles.data?.items ?? []).map(fromTenant),
  ].filter((r) => !r.permissions.some(isAdminPermission));
  return {
    roles,
    isPending: tenantRoles.isPending || orgRoles.isPending,
    error: tenantRoles.error ?? orgRoles.error,
  };
}

export function ScopeBadge({ scope }: { scope: OrgRoleScope }) {
  return (
    <Badge variant={scope === "org" ? "default" : "outline"} data-testid="role-scope">
      {scope === "org" ? "Org role" : "Tenant role"}
    </Badge>
  );
}

/** Checkboxes over the assignable roles; `value` holds role ids. */
export function RolePicker({
  legend,
  hint,
  roles,
  value,
  onChange,
  isPending,
  error,
  testId,
}: {
  legend: string;
  hint?: string;
  roles: AssignableRole[];
  value: readonly string[];
  onChange: (next: string[]) => void;
  isPending: boolean;
  error: unknown;
  testId: string;
}) {
  const hintId = useId();
  return (
    <fieldset className="space-y-2" aria-describedby={hint ? hintId : undefined} data-testid={testId}>
      <legend className="text-sm font-medium">{legend}</legend>
      {hint && (
        <p id={hintId} className="text-muted-foreground text-xs">
          {hint}
        </p>
      )}
      {error ? (
        <ProblemAlert error={error} />
      ) : isPending ? (
        <Skeleton className="h-5 w-1/2" />
      ) : roles.length === 0 ? (
        <p className="text-muted-foreground text-sm">No roles can be given in this organization yet.</p>
      ) : (
        <ul className="space-y-1">
          {roles.map((r) => (
            <li key={r.id}>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 rounded border focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                  checked={value.includes(r.id)}
                  onChange={(e) => onChange(e.target.checked ? [...value, r.id] : value.filter((v) => v !== r.id))}
                  data-role={`${r.scope}:${r.name}`}
                />
                <span className="font-mono">{r.name}</span>
                <ScopeBadge scope={r.scope} />
              </label>
            </li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/** Option value of a role in the assignment select: scope and name (the API addresses roles that way). */
function optionValue(r: { scope: OrgRoleScope; name: string }): string {
  return `${r.scope}:${r.name}`;
}

/** The roles one member holds in the org, with assign and remove. */
export function OrgRoleAssignments({ tenant, org, userId }: { tenant: string; org: string; userId: string }) {
  const queryClient = useQueryClient();
  const selectId = useId();
  const [selected, setSelected] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const assignable = useAssignableRoles(tenant, org);
  const held = useQuery({
    queryKey: memberRolesQueryKey(tenant, org, userId),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles", {
          params: { path: { slug: tenant, org, user_id: userId } },
          signal,
        }),
      ),
  });
  const heldKeys = new Set((held.data?.items ?? []).map(optionValue));
  const options = assignable.roles.filter((r) => !heldKeys.has(optionValue(r)));

  const change = useMutation({
    mutationFn: async ({ action, role }: { action: "assign" | "remove"; role: { scope: OrgRoleScope; name: string } }) => {
      const params = { path: { slug: tenant, org, user_id: userId, role: role.name }, query: { scope: role.scope } };
      if (action === "assign") {
        unwrap(await api.PUT("/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role}", { params }));
        return `Role ${role.name} assigned.`;
      }
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role}", { params });
      return `Role ${role.name} removed.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setStatus(message);
      setSelected("");
      await queryClient.invalidateQueries({ queryKey: memberRolesQueryKey(tenant, org, userId) });
    },
  });

  const assign = () => {
    const role = options.find((r) => optionValue(r) === selected);
    if (role) change.mutate({ action: "assign", role });
  };

  return (
    <div className="space-y-4" data-testid="org-role-assignments">
      {held.isError ? (
        <ProblemAlert error={held.error} />
      ) : held.isPending ? (
        <Skeleton className="h-5 w-2/3" />
      ) : held.data.items.length === 0 ? (
        <p className="text-muted-foreground text-sm">No roles in this organization.</p>
      ) : (
        <ul className="divide-y rounded-md border" aria-label="Roles in this organization">
          {held.data.items.map((r) => (
            <li
              key={optionValue(r)}
              className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm"
              data-testid={`member-role-${r.name}`}
            >
              <span className="font-mono font-medium">{r.name}</span>
              <ScopeBadge scope={r.scope} />
              {r.permissions.length > 0 && <code className="text-muted-foreground text-xs break-all">{r.permissions.join(" ")}</code>}
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="ml-auto"
                disabled={change.isPending}
                aria-label={`Remove role ${r.name}`}
                onClick={() => change.mutate({ action: "remove", role: r })}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
      {assignable.error ? <ProblemAlert error={assignable.error} /> : null}
      <div className="space-y-1.5">
        <label htmlFor={selectId} className="block text-sm font-medium">
          Assign a role
        </label>
        <div className="flex gap-2">
          <select
            id={selectId}
            className={controlClass}
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={assignable.isPending || options.length === 0}
            data-testid="org-assign-role-select"
          >
            <option value="">{options.length === 0 ? "No further roles" : "Choose a role…"}</option>
            {options.map((r) => (
              <option key={optionValue(r)} value={optionValue(r)}>
                {r.name} ({r.scope === "org" ? "org role" : "tenant role"})
              </option>
            ))}
          </select>
          <Button type="button" onClick={assign} disabled={!selected || change.isPending} data-testid="org-assign-role">
            Assign
          </Button>
        </div>
        <p className="text-muted-foreground text-xs">
          Roles given here apply only while the member signs in to this organization. Roles with admin permissions
          cannot be given in an organization.
        </p>
      </div>
      {change.error ? <ProblemAlert error={change.error} /> : null}
      <StatusMessage message={status} />
    </div>
  );
}
