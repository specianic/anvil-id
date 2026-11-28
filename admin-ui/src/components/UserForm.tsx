// User form (C-H1): create a user with a password or by invitation, or edit a user's email and
// username. One Save button; unsaved edits are guarded (lib/formState.ts + lib/unsaved.ts). The
// API decides every rule (password policy, email syntax, uniqueness); its field errors show next to
// the fields and anything else in a problem alert, with the server's own text.
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useId } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";
import { CheckboxField, TextField, fieldErrors } from "@/components/form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useFormState } from "@/lib/formState";
import { useUnsavedChanges } from "@/lib/unsaved";

export type UserFormMode = "create" | "edit";
export type UserCreateMethod = "password" | "invite";

export interface UserFormValues {
  email: string;
  username: string;
  /** Create only: how the user gets a password. */
  method: UserCreateMethod;
  /** Create only, with method "password". */
  password: string;
  /** Create only. */
  emailVerified: boolean;
}

export const NEW_USER: UserFormValues = { email: "", username: "", method: "password", password: "", emailVerified: false };

/**
 * Whether this tenant can send email: its own SMTP settings, or the installation SMTP server
 * (`smtp_configured` of system info). `undefined` while unknown (loading, or the token may not read
 * one of the two), so callers warn only when both are known to be missing.
 */
export function useSmtpAvailable(tenant: string): boolean | undefined {
  const info = useQuery({
    queryKey: ["system", "info"],
    queryFn: async ({ signal }) => unwrap(await api.GET("/api/admin/v1/system/info", { signal })),
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
  });
  // Same key and value as the SMTP settings page: the settings, or null when the tenant has none.
  const smtp = useQuery({
    queryKey: ["smtp", tenant],
    queryFn: async ({ signal }) => {
      try {
        return unwrap(await api.GET("/api/admin/v1/tenants/{slug}/smtp", { params: { path: { slug: tenant } }, signal }));
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    retry: false,
  });
  if (info.data?.smtp_configured || smtp.data) return true;
  if (info.isSuccess && smtp.isSuccess) return false;
  return undefined;
}

/** Shown where an action sends email and the tenant has no way to send it. */
export function NoSmtpWarning({ action }: { action: string }) {
  return (
    <Alert data-testid="no-smtp-warning">
      <AlertTitle>No email server is configured</AlertTitle>
      <AlertDescription>
        <p>
          {action} needs SMTP: set up this tenant's SMTP settings under Email, or configure the installation SMTP server
          (<code>smtp_url</code>). Until then the email is queued but not delivered.
        </p>
      </AlertDescription>
    </Alert>
  );
}

interface UserFormProps {
  mode: UserFormMode;
  initial: UserFormValues;
  pending: boolean;
  error: unknown;
  onSubmit: (values: UserFormValues) => void;
  /** Create mode: whether the tenant can send email (undefined = unknown, no warning). */
  smtpAvailable?: boolean;
}

const KNOWN_FIELDS = ["email", "username", "password", "email_verified", "invite"];

export function UserForm({ mode, initial, pending, error, onSubmit, smtpAvailable }: UserFormProps) {
  const form = useFormState<UserFormValues>(initial);
  const { values, setValues } = form;
  const blocker = useUnsavedChanges(form.isDirty && !pending);
  const methodName = useId();
  const server = fieldErrors(error);
  // "invite" errors belong to the method choice; show them with the password field.
  const passwordErrors = [...(server.password ?? []), ...(server.invite ?? [])];
  const otherError =
    error &&
    !(error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => KNOWN_FIELDS.includes(e.field)))
      ? error
      : null;

  const set = <K extends keyof UserFormValues>(key: K, value: UserFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    form.markSubmitted();
    onSubmit({ ...values, email: values.email.trim(), username: values.username.trim() });
  };

  const create = mode === "create";

  return (
    <>
      {/* Outside the form: the guard's buttons must not submit it. */}
      <UnsavedChangesGuard blocker={blocker} />
      <form onSubmit={submit} className="space-y-4" noValidate aria-label={create ? "Create user" : "Edit user"} data-testid="user-form">
        {otherError ? <ProblemAlert error={otherError} /> : null}
        <TextField
          label="Email"
          type="email"
          required
          autoComplete="off"
          value={values.email}
          onChange={(e) => set("email", e.target.value)}
          errors={server.email}
          hint={create ? undefined : "A changed address is saved as unverified."}
          data-testid="user-form-email"
        />
        <TextField
          label="Username"
          optional
          autoComplete="off"
          value={values.username}
          onChange={(e) => set("username", e.target.value)}
          errors={server.username}
          hint={create ? "Lets the user sign in with a name instead of the email address." : "Leave empty to remove the username."}
          data-testid="user-form-username"
        />
        {create && (
          <>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">Password</legend>
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id={`${methodName}-password`}
                  name={methodName}
                  className="size-4"
                  checked={values.method === "password"}
                  onChange={() => set("method", "password")}
                  data-testid="user-form-method-password"
                />
                <label htmlFor={`${methodName}-password`} className="text-sm">
                  Set a password now
                </label>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  id={`${methodName}-invite`}
                  name={methodName}
                  className="size-4"
                  checked={values.method === "invite"}
                  onChange={() => set("method", "invite")}
                  data-testid="user-form-method-invite"
                />
                <label htmlFor={`${methodName}-invite`} className="text-sm">
                  Send an invitation email (the user chooses a password; the link is valid for 7 days)
                </label>
              </div>
            </fieldset>
            {values.method === "password" ? (
              <TextField
                label="Initial password"
                type="password"
                autoComplete="new-password"
                value={values.password}
                onChange={(e) => set("password", e.target.value)}
                errors={passwordErrors}
                hint="The tenant's password policy applies."
                data-testid="user-form-password"
              />
            ) : (
              <>
                {passwordErrors.length > 0 && (
                  <ul className="text-destructive space-y-0.5 text-sm" data-field-error>
                    {passwordErrors.map((m) => (
                      <li key={m.message}>{m.message}</li>
                    ))}
                  </ul>
                )}
                {smtpAvailable === false && <NoSmtpWarning action="An invitation" />}
              </>
            )}
            <CheckboxField
              label="Email address is verified"
              hint="Only check this when you know the address belongs to the user."
              checked={values.emailVerified}
              onChange={(e) => set("emailVerified", e.target.checked)}
              errors={server.email_verified}
              data-testid="user-form-verified"
            />
          </>
        )}
        <Button type="submit" disabled={pending} data-testid="user-form-save">
          {pending ? "Saving…" : create ? (values.method === "invite" ? "Create and invite" : "Create user") : "Save"}
        </Button>
      </form>
    </>
  );
}
