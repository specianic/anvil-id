// Role form (create and edit): name, description and the permission set as a tag input. The
// name and permission rules mirror the API's (it decides); the last-administrator conflict (409)
// is explained, because it is the one refusal an operator cannot fix by editing the form.
import { type FormEvent, type KeyboardEvent, useId, useState } from "react";
import { ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";
import { TextField, TextareaField, controlClass, fieldErrors } from "@/components/form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useFormState } from "@/lib/formState";
import { useUnsavedChanges } from "@/lib/unsaved";

export type RoleDto = components["schemas"]["RoleDto"];

/** `NewRoleDto.name`: 1-64 characters of a-z, 0-9, '_', '.' or '-', starting with a letter or digit. */
export const ROLE_NAME_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
/** One permission: 1-128 characters of A-Z, a-z, 0-9, ':', '.', '_', '/', '-'. */
export const PERMISSION_PATTERN = /^[A-Za-z0-9:._/-]{1,128}$/;
export const MAX_PERMISSIONS = 100;

export interface RoleFormValues {
  name: string;
  description: string;
  permissions: string[];
}

export const NEW_ROLE: RoleFormValues = { name: "", description: "", permissions: [] };

export function valuesFromRole(role: RoleDto): RoleFormValues {
  return { name: role.name, description: role.description, permissions: [...role.permissions] };
}

/** True for the 409 the API answers when a change would leave the system tenant without an administrator. */
export function isLastAdministrator(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && /administrator/i.test(error.problem.detail);
}

/** A problem from a role or assignment change, with the last-administrator conflict spelled out. */
export function RoleProblem({ error }: { error: unknown }) {
  if (isLastAdministrator(error)) {
    return (
      <Alert variant="destructive" data-testid="last-administrator">
        <AlertTitle>The system tenant would lose its last administrator</AlertTitle>
        <AlertDescription>
          <p>
            At least one active user must keep a role granting <code>admin:write</code>. Give that permission to
            another active user first, then retry. (<code>anvilid admin recover</code> restores access if every
            administrator is lost.)
          </p>
        </AlertDescription>
      </Alert>
    );
  }
  return <ProblemAlert error={error} />;
}

/** Tag input for permissions: Enter or "Add" adds the typed permission; each tag has a remove button. */
function PermissionsInput({
  value,
  onChange,
  serverErrors,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  serverErrors?: { message: string }[];
}) {
  const id = useId();
  const [draft, setDraft] = useState("");
  const [issue, setIssue] = useState<string | null>(null);
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const messages = [...(issue ? [issue] : []), ...(serverErrors ?? []).map((e) => e.message)];

  const add = () => {
    const tokens = draft
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    if (tokens.length === 0) return;
    const bad = tokens.find((t) => !PERMISSION_PATTERN.test(t));
    if (bad) {
      setIssue(`“${bad}” is not a valid permission: 1-128 characters of A-Z, a-z, 0-9, ':', '.', '_', '/', '-'.`);
      return;
    }
    const next = [...value];
    for (const t of tokens) if (!next.includes(t)) next.push(t);
    if (next.length > MAX_PERMISSIONS) {
      setIssue(`A role holds at most ${MAX_PERMISSIONS} permissions.`);
      return;
    }
    setIssue(null);
    setDraft("");
    onChange(next.sort());
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      add();
    }
  };

  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">Permissions</legend>
      {value.length === 0 ? (
        <p className="text-muted-foreground text-sm">No permissions.</p>
      ) : (
        <ul className="flex flex-wrap gap-2" aria-label="Permissions of this role" data-testid="role-permissions">
          {value.map((p) => (
            <li key={p} className="flex items-center gap-1 rounded-full border py-0.5 pr-1 pl-3 text-xs">
              <code>{p}</code>
              <button
                type="button"
                className="hover:bg-accent rounded-full px-1.5 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                aria-label={`Remove permission ${p}`}
                onClick={() => onChange(value.filter((v) => v !== p))}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex gap-2">
        <label htmlFor={id} className="sr-only">
          Add permission
        </label>
        <input
          id={id}
          className={controlClass}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="e.g. invoices:read"
          aria-describedby={[hintId, messages.length ? errorId : ""].filter(Boolean).join(" ")}
          aria-invalid={messages.length > 0 || undefined}
          autoComplete="off"
          data-testid="role-permission-input"
        />
        <Button type="button" variant="outline" onClick={add} data-testid="role-permission-add">
          Add
        </Button>
      </div>
      <p id={hintId} className="text-muted-foreground text-xs">
        Free-form strings your applications check (separate several with spaces). In the system tenant, admin scopes
        such as <code>admin:read</code> or <code>admin:users:write</code> decide what the role's holders may do in this
        console.
      </p>
      {messages.length > 0 && (
        <ul id={errorId} className="text-destructive space-y-0.5 text-sm" data-field-error>
          {messages.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

interface RoleFormProps {
  initial: RoleFormValues;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: RoleFormValues) => void;
}

export function RoleForm({ initial, submitLabel, pending, error, onSubmit }: RoleFormProps) {
  const form = useFormState<RoleFormValues>(initial);
  const { values, setValues } = form;
  const blocker = useUnsavedChanges(form.isDirty && !pending);
  const [nameIssue, setNameIssue] = useState<string | null>(null);
  const server = fieldErrors(error);
  const known = ["name", "description", "permissions"];
  const otherError =
    error &&
    !(error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => known.includes(e.field)))
      ? error
      : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ROLE_NAME_PATTERN.test(values.name)) {
      setNameIssue("1-64 characters of a-z, 0-9, '_', '.' or '-', starting with a letter or digit.");
      return;
    }
    setNameIssue(null);
    form.markSubmitted();
    onSubmit({ ...values, description: values.description.trim() });
  };

  return (
    <>
      {/* Outside the form: the guard's buttons must not submit it. */}
      <UnsavedChangesGuard blocker={blocker} />
      <form onSubmit={submit} className="space-y-4" noValidate aria-label="Role" data-testid="role-form">
        {otherError ? <RoleProblem error={otherError} /> : null}
        <TextField
          label="Name"
          name="name"
          value={values.name}
          onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))}
          hint="Unique in the tenant. Tokens carry role names in the roles claim."
          errors={nameIssue ? [{ message: nameIssue }] : server.name}
          autoComplete="off"
          data-testid="role-name"
        />
        <TextareaField
          label="Description"
          name="description"
          optional
          rows={2}
          value={values.description}
          maxLength={500}
          onChange={(e) => setValues((v) => ({ ...v, description: e.target.value }))}
          errors={server.description}
          className="font-sans"
        />
        <PermissionsInput
          value={values.permissions}
          onChange={(permissions) => setValues((v) => ({ ...v, permissions }))}
          serverErrors={server.permissions}
        />
        <Button type="submit" disabled={pending} data-testid="role-submit">
          {pending ? "Saving…" : submitLabel}
        </Button>
      </form>
    </>
  );
}
