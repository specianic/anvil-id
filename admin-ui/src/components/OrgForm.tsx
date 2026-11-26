// Organization forms (06-12 API): the organization itself (slug, display name, MFA policy and, once
// it exists, the default roles for just-in-time members) and an org-owned role. Client-side rules
// mirror the API's; the API decides.
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { RolePicker, isAdminPermission, useAssignableRoles } from "@/components/OrgRoleAssignments";
import { ProblemAlert } from "@/components/ProblemAlert";
import { MAX_PERMISSIONS, PERMISSION_PATTERN, ROLE_NAME_PATTERN } from "@/components/RoleForm";
import { type FieldErrors, SelectField, TextField, TextareaField, fieldErrors, tokens } from "@/components/form";
import { Button } from "@/components/ui/button";
import { SLUG_PATTERN } from "@/lib/tenant";

export type OrganizationView = components["schemas"]["OrganizationView"];
type MfaPolicy = components["schemas"]["MfaPolicy"];
export type NewOrganization = components["schemas"]["NewOrganizationDto"];
export type OrganizationPatch = components["schemas"]["OrganizationPatchDto"];

export function orgQueryKey(tenant: string, org: string) {
  return ["organization", tenant, org] as const;
}

/** One organization (`org` is its id or slug); shared by the detail layout and its tabs. */
export function useOrganization(tenant: string, org: string) {
  return useQuery({
    queryKey: orgQueryKey(tenant, org),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}", {
          params: { path: { slug: tenant, org } },
          signal,
        }),
      ),
  });
}

export interface OrgFormValues {
  slug: string;
  display_name: string;
  /** `inherit` = no organization requirement (tenant and client policy apply). */
  mfa_policy: MfaPolicy | "inherit";
  default_role_ids: string[];
}

export const NEW_ORG: OrgFormValues = { slug: "", display_name: "", mfa_policy: "inherit", default_role_ids: [] };

export function valuesFromOrg(org: OrganizationView): OrgFormValues {
  return {
    slug: org.slug,
    display_name: org.display_name,
    mfa_policy: org.mfa_policy ?? "inherit",
    default_role_ids: [...org.default_role_ids],
  };
}

export function createOrgBody(values: OrgFormValues): NewOrganization {
  return {
    slug: values.slug.trim(),
    display_name: values.display_name.trim(),
    mfa_policy: values.mfa_policy === "inherit" ? null : values.mfa_policy,
  };
}

export function patchOrgBody(values: OrgFormValues): OrganizationPatch {
  return {
    slug: values.slug.trim(),
    display_name: values.display_name.trim(),
    // `null` removes the organization's MFA requirement.
    mfa_policy: values.mfa_policy === "inherit" ? null : values.mfa_policy,
    default_role_ids: values.default_role_ids,
  };
}

export const ORG_MFA_OPTIONS: readonly { value: MfaPolicy | "inherit"; label: string }[] = [
  { value: "inherit", label: "No organization requirement (tenant and client policy)" },
  { value: "off", label: "Off" },
  { value: "optional", label: "Optional (members who enrolled a second factor)" },
  { value: "required", label: "Required" },
];

export function orgMfaLabel(policy: MfaPolicy | null | undefined): string {
  return ORG_MFA_OPTIONS.find((o) => o.value === (policy ?? "inherit"))?.label ?? String(policy);
}

const ORG_FIELDS = new Set(["slug", "display_name", "mfa_policy", "default_role_ids", "metadata"]);

/** True if every problem field is shown next to a control of a form with `fields`. */
function onlyFieldErrors(error: unknown, fields: Set<string>): boolean {
  return error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => fields.has(e.field));
}

interface OrgFormProps {
  /** Org id or slug for the default-roles picker (edit only: org roles exist after the org). */
  editing?: { tenant: string; org: string };
  initial: OrgFormValues;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: OrgFormValues) => void;
}

function DefaultRoles({
  tenant,
  org,
  value,
  onChange,
}: {
  tenant: string;
  org: string;
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const assignable = useAssignableRoles(tenant, org);
  return (
    <RolePicker
      legend="Default roles"
      hint="Given in this organization to members created by just-in-time provisioning (enterprise sign-in)."
      roles={assignable.roles}
      value={value}
      onChange={onChange}
      isPending={assignable.isPending}
      error={assignable.error}
      testId="org-default-roles"
    />
  );
}

export function OrgForm({ editing, initial, submitLabel, pending, error, onSubmit }: OrgFormProps) {
  const [values, setValues] = useState<OrgFormValues>(initial);
  const [local, setLocal] = useState<FieldErrors>({});
  const server = fieldErrors(error);
  const otherError = error && !onlyFieldErrors(error, ORG_FIELDS) ? error : null;
  const set = <K extends keyof OrgFormValues>(key: K, value: OrgFormValues[K]) => setValues((v) => ({ ...v, [key]: value }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const issues: FieldErrors = {};
    if (!SLUG_PATTERN.test(values.slug.trim()) || values.slug.trim().startsWith("-")) {
      issues.slug = [{ message: "2-63 characters of a-z, 0-9 and '-', starting with a letter or digit." }];
    }
    const name = values.display_name.trim();
    if (name.length < 1 || name.length > 200) issues.display_name = [{ message: "1-200 characters." }];
    setLocal(issues);
    if (Object.keys(issues).length > 0) return;
    onSubmit(values);
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate aria-label="Organization" data-testid="org-form">
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <TextField
        label="Display name"
        name="display_name"
        value={values.display_name}
        maxLength={200}
        onChange={(e) => set("display_name", e.target.value)}
        hint="Shown to members, for example on the organization switcher at sign-in."
        errors={local.display_name ?? server.display_name}
        autoComplete="off"
        data-testid="org-display-name"
      />
      <TextField
        label="Slug"
        name="slug"
        value={values.slug}
        onChange={(e) => set("slug", e.target.value)}
        hint="Unique in the tenant. Applications may pass it as the organization authorization parameter."
        errors={local.slug ?? server.slug}
        autoComplete="off"
        data-testid="org-slug"
      />
      <SelectField
        label="Multi-factor authentication"
        name="mfa_policy"
        value={values.mfa_policy}
        onChange={(e) => set("mfa_policy", e.target.value as MfaPolicy | "inherit")}
        options={ORG_MFA_OPTIONS}
        hint="Applies when a member signs in to this organization; the strictest policy wins."
        errors={server.mfa_policy}
        data-testid="org-mfa-policy"
      />
      {editing ? (
        <>
          <DefaultRoles
            tenant={editing.tenant}
            org={editing.org}
            value={values.default_role_ids}
            onChange={(next) => set("default_role_ids", next)}
          />
          {server.default_role_ids && (
            <ul className="text-destructive space-y-0.5 text-sm" data-field-error>
              {server.default_role_ids.map((m) => (
                <li key={m.message}>{m.message}</li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p className="text-muted-foreground text-sm">
          Default roles for just-in-time members can be chosen once the organization exists.
        </p>
      )}
      <Button type="submit" disabled={pending} data-testid="org-submit">
        {pending ? "Saving…" : submitLabel}
      </Button>
    </form>
  );
}

// ---- org-owned roles ----

export interface OrgRoleFormValues {
  name: string;
  description: string;
  permissions: string;
}

export const NEW_ORG_ROLE: OrgRoleFormValues = { name: "", description: "", permissions: "" };

const ORG_ROLE_FIELDS = new Set(["name", "description", "permissions"]);

export interface OrgRoleSubmit {
  name: string;
  description: string;
  permissions: string[];
}

export function OrgRoleForm({
  initial,
  submitLabel,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  initial: OrgRoleFormValues;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: OrgRoleSubmit) => void;
  onCancel: () => void;
}) {
  const [values, setValues] = useState<OrgRoleFormValues>(initial);
  const [local, setLocal] = useState<FieldErrors>({});
  const server = fieldErrors(error);
  const otherError = error && !onlyFieldErrors(error, ORG_ROLE_FIELDS) ? error : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const issues: FieldErrors = {};
    if (!ROLE_NAME_PATTERN.test(values.name)) {
      issues.name = [{ message: "1-64 characters of a-z, 0-9, '_', '.' or '-', starting with a letter or digit." }];
    }
    const permissions = [...new Set(tokens(values.permissions))].sort();
    const bad = permissions.find((p) => !PERMISSION_PATTERN.test(p));
    if (bad) {
      issues.permissions = [{ message: `“${bad}” is not a valid permission: 1-128 characters of A-Z, a-z, 0-9, ':', '.', '_', '/', '-'.` }];
    } else if (permissions.some(isAdminPermission)) {
      issues.permissions = [{ message: "Admin permissions (admin, admin:…) cannot be given in an organization." }];
    } else if (permissions.length > MAX_PERMISSIONS) {
      issues.permissions = [{ message: `A role holds at most ${MAX_PERMISSIONS} permissions.` }];
    }
    setLocal(issues);
    if (Object.keys(issues).length > 0) return;
    onSubmit({ name: values.name, description: values.description.trim(), permissions });
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate aria-label="Organization role" data-testid="org-role-form">
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <TextField
        label="Name"
        name="name"
        value={values.name}
        onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))}
        hint="Unique in the organization."
        errors={local.name ?? server.name}
        autoComplete="off"
        data-testid="org-role-name"
      />
      <TextareaField
        label="Description"
        name="description"
        optional
        rows={2}
        maxLength={500}
        value={values.description}
        onChange={(e) => setValues((v) => ({ ...v, description: e.target.value }))}
        errors={server.description}
        className="font-sans"
      />
      <TextField
        label="Permissions"
        name="permissions"
        optional
        value={values.permissions}
        onChange={(e) => setValues((v) => ({ ...v, permissions: e.target.value }))}
        hint={
          <>
            Separated by spaces, for example <code>invoices:read invoices:pay</code>. <code>org:admin</code> makes
            holders administrators of this organization.
          </>
        }
        errors={local.permissions ?? server.permissions}
        autoComplete="off"
        data-testid="org-role-permissions"
      />
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending} data-testid="org-role-submit">
          {pending ? "Saving…" : submitLabel}
        </Button>
      </div>
    </form>
  );
}
