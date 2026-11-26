// Tenant login settings (0.3): MFA policy, passwordless email sign-in, automatic account linking,
// registration through upstream connections and the default page language. Saved with a
// field-wise PATCH of the tenant: only changed fields are sent.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import {
  UNDELETABLE_TENANTS,
  forgetTenant,
  tenantQueryKey,
  useDiscovery,
  useTenant,
  useTenantView,
} from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { CheckboxField, type FieldErrors, SelectField, StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

type TenantView = components["schemas"]["TenantView"];
type TenantSettingsPatch = components["schemas"]["TenantSettingsPatch"];
type MfaPolicy = components["schemas"]["MfaPolicy"];

const MFA_OPTIONS: readonly { value: MfaPolicy; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "optional", label: "Optional (users who enrolled a second factor)" },
  { value: "required", label: "Required (users without one enrol first)" },
];

type UpstreamChoice = "follow" | "allow" | "deny";

const FIELDS = ["mfa_policy", "email_otp", "magic_link", "auto_link", "upstream_registration", "default_locale"] as const;

interface Values {
  mfa_policy: MfaPolicy;
  email_otp: boolean;
  magic_link: boolean;
  auto_link: boolean;
  upstream_registration: UpstreamChoice;
  default_locale: string;
}

function valuesFromTenant(t: TenantView): Values {
  const s = t.settings;
  return {
    mfa_policy: s.mfa_policy,
    email_otp: s.email_otp,
    magic_link: s.magic_link,
    auto_link: s.auto_link,
    upstream_registration:
      s.upstream_registration === true ? "allow" : s.upstream_registration === false ? "deny" : "follow",
    default_locale: s.default_locale,
  };
}

function upstreamValue(choice: UpstreamChoice): boolean | null {
  return choice === "allow" ? true : choice === "deny" ? false : null;
}

/** Only the fields that differ from the saved settings (absent fields keep their value). */
function patchBody(saved: Values, values: Values): TenantSettingsPatch {
  const patch: TenantSettingsPatch = {};
  if (values.mfa_policy !== saved.mfa_policy) patch.mfa_policy = values.mfa_policy;
  if (values.email_otp !== saved.email_otp) patch.email_otp = values.email_otp;
  if (values.magic_link !== saved.magic_link) patch.magic_link = values.magic_link;
  if (values.auto_link !== saved.auto_link) patch.auto_link = values.auto_link;
  if (values.upstream_registration !== saved.upstream_registration)
    patch.upstream_registration = upstreamValue(values.upstream_registration);
  if (values.default_locale !== saved.default_locale) patch.default_locale = values.default_locale;
  return patch;
}

/** Field errors of the PATCH, keyed by settings field (`settings.x` and `x` both map to `x`). */
function settingsErrors(error: unknown): FieldErrors {
  if (!(error instanceof ApiError)) return {};
  const out: FieldErrors = {};
  for (const e of error.problem.errors) {
    const field = e.field.startsWith("settings.") ? e.field.slice("settings.".length) : e.field;
    (out[field] ??= []).push({ message: e.message, line: e.line });
  }
  return out;
}

/** Languages the tenant's sign-in pages offer (`ui_locales_supported` of its discovery document). */
function useUiLocales(slug: string): { locales: string[]; failed: boolean } {
  const query = useDiscovery(slug);
  const list = query.data?.ui_locales_supported;
  const locales = Array.isArray(list) ? list.filter((l): l is string => typeof l === "string") : [];
  return { locales, failed: query.isError };
}

function SettingsForm({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const queryClient = useQueryClient();
  const saved = valuesFromTenant(tenant);
  const [values, setValues] = useState<Values>(saved);
  const [status, setStatus] = useState<string | null>(null);
  // Set when the API refused to turn on an email sign-in method because no SMTP server is configured.
  const [smtpMissing, setSmtpMissing] = useState(false);
  const { locales, failed: localesFailed } = useUiLocales(slug);
  const set = <K extends keyof Values>(key: K, value: Values[K]) => setValues((v) => ({ ...v, [key]: value }));

  const save = useMutation({
    mutationFn: async (body: TenantSettingsPatch) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}", {
          params: { path: { slug } },
          body: { settings: body },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (updated) => {
      queryClient.setQueryData(tenantQueryKey(slug), updated);
      setValues(valuesFromTenant(updated));
      setStatus("Login settings saved.");
      await queryClient.invalidateQueries({ queryKey: ["tenant"] });
    },
    onError: (error) => {
      const errs = settingsErrors(error);
      if (errs.email_otp || errs.magic_link) {
        setSmtpMissing(true);
        // Revert the refused switches so the form matches what is stored.
        setValues((v) => ({
          ...v,
          email_otp: errs.email_otp ? saved.email_otp : v.email_otp,
          magic_link: errs.magic_link ? saved.magic_link : v.magic_link,
        }));
      }
    },
  });

  const errors = settingsErrors(save.error);
  const otherError =
    save.error &&
    !(
      save.error instanceof ApiError &&
      save.error.problem.errors.length > 0 &&
      Object.keys(errors).every((f) => (FIELDS as readonly string[]).includes(f))
    )
      ? save.error
      : null;

  const localeOptions = (locales.includes(values.default_locale) ? locales : [values.default_locale, ...locales]).map(
    (l) => ({ value: l, label: l }),
  );
  const registrationLabel = tenant.settings.registration;
  const dirty = Object.keys(patchBody(saved, values)).length > 0;

  const smtpHint = (
    <>
      Needs an SMTP server (the tenant's{" "}
      <Link to="/t/$tenant/email/smtp" params={{ tenant: slug }} className="underline underline-offset-4">
        SMTP settings
      </Link>{" "}
      or the installation's).
    </>
  );

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = patchBody(saved, values);
    if (Object.keys(body).length === 0) {
      setStatus("Nothing changed.");
      return;
    }
    save.mutate(body);
  };

  return (
    <form onSubmit={submit} aria-label="Login settings" className="space-y-6" noValidate data-testid="login-settings-form">
      {save.error instanceof ApiError && save.error.status === 422 && (
        <p role="alert" className="text-destructive text-sm">
          The settings were not saved. Fix the errors below.
        </p>
      )}
      {otherError ? <ProblemAlert error={otherError} /> : null}

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Multi-factor authentication</h2>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SelectField
            label="MFA policy"
            name="mfa_policy"
            value={values.mfa_policy}
            onChange={(e) => set("mfa_policy", e.target.value as MfaPolicy)}
            options={MFA_OPTIONS}
            hint="A client may make this stricter; the strictest of tenant and client policy applies."
            errors={errors.mfa_policy}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Passwordless sign-in by email</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <CheckboxField
            label="One-time sign-in code by email"
            name="email_otp"
            checked={values.email_otp}
            // Turning it on is refused without SMTP; turning it off is always possible.
            disabled={smtpMissing && !values.email_otp && !saved.email_otp}
            hint={smtpHint}
            onChange={(e) => set("email_otp", e.target.checked)}
            errors={errors.email_otp}
          />
          <CheckboxField
            label="Magic link by email"
            name="magic_link"
            checked={values.magic_link}
            disabled={smtpMissing && !values.magic_link && !saved.magic_link}
            hint={smtpHint}
            onChange={(e) => set("magic_link", e.target.checked)}
            errors={errors.magic_link}
          />
          {smtpMissing && (
            <p className="text-muted-foreground text-sm" data-testid="smtp-missing-hint">
              No SMTP server is configured for this tenant, so email sign-in cannot be turned on.{" "}
              <Link to="/t/$tenant/email/smtp" params={{ tenant: slug }} className="underline underline-offset-4">
                Configure SMTP
              </Link>{" "}
              and reload this page.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Upstream connections</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <CheckboxField
            label="Link verified emails automatically"
            name="auto_link"
            hint="An upstream sign-in with a trusted, verified email equal to an existing account's verified email is linked to that account."
            checked={values.auto_link}
            onChange={(e) => set("auto_link", e.target.checked)}
            errors={errors.auto_link}
          />
          <SelectField
            label="Account creation through connections"
            name="upstream_registration"
            value={values.upstream_registration}
            onChange={(e) => set("upstream_registration", e.target.value as UpstreamChoice)}
            options={[
              { value: "follow", label: `Follow the registration setting (currently: ${registrationLabel})` },
              { value: "allow", label: "Allow: first upstream sign-in creates an account" },
              { value: "deny", label: "Deny: only existing or linked accounts" },
            ]}
            errors={errors.upstream_registration}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Language</h2>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SelectField
            label="Default language"
            name="default_locale"
            value={values.default_locale}
            onChange={(e) => set("default_locale", e.target.value)}
            options={localeOptions}
            hint={
              localesFailed
                ? "The list of available languages could not be loaded."
                : "Used when neither ui_locales nor the browser's Accept-Language matches."
            }
            errors={errors.default_locale}
          />
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" disabled={save.isPending} data-testid="save-login-settings">
          {save.isPending ? "Saving…" : "Save login settings"}
        </Button>
        {dirty && <span className="text-muted-foreground text-sm">Unsaved changes</span>}
      </div>
      <StatusMessage message={status} />
    </form>
  );
}

/** Deleting the tenant removes all its data. `system` and `default` cannot be deleted (the API answers 403). */
function DeleteTenant({ tenant }: { tenant: TenantView }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}", { params: { path: { slug: tenant.slug } } });
    },
    onSuccess: async () => {
      setConfirm(false);
      forgetTenant(tenant.slug);
      await navigate({ to: "/tenants" });
      queryClient.removeQueries({ queryKey: tenantQueryKey(tenant.slug) });
      await queryClient.invalidateQueries({ queryKey: ["tenants"] });
    },
  });

  if (UNDELETABLE_TENANTS.includes(tenant.slug)) {
    return (
      <p className="text-muted-foreground text-sm" data-testid="tenant-undeletable">
        The <code>{tenant.slug}</code> tenant is part of the installation and cannot be deleted.
      </p>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Delete tenant</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-sm">
          Deletes <code>{tenant.slug}</code> with all its users, clients, connections, sessions and keys. Relying
          parties of this tenant stop working.
        </p>
        <Button variant="destructive" onClick={() => setConfirm(true)} data-testid="delete-tenant">
          Delete tenant
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Delete this tenant?"
        description={<p>{`The tenant ${tenant.slug} and all its data are removed. This cannot be undone.`}</p>}
        confirmLabel="Delete tenant"
        onConfirm={() => remove.mutate()}
        onCancel={() => {
          setConfirm(false);
          remove.reset();
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </Card>
  );
}

function LoginSettingsPage() {
  const tenant = useTenant();
  const query = useTenantView(tenant);

  return (
    <section aria-labelledby="settings-heading" className="space-y-4">
      <h1 id="settings-heading" className="text-xl font-semibold">
        Login settings
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading login settings" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        // The form keeps local edits; it is keyed by tenant so another tenant starts fresh.
        <>
          <SettingsForm key={query.data.id} tenant={query.data} />
          <DeleteTenant tenant={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/settings/")({ component: LoginSettingsPage });
