// Tenant login settings (0.3): MFA policy, passwordless email sign-in, automatic account linking,
// registration through upstream connections and the default page language. Saved with a
// field-wise PATCH of the tenant: only changed fields are sent. Since 0.4 also the token claim
// mapping of roles and permissions, and links to the registration, configuration and webhook pages.
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
import { TOKEN_TARGETS } from "@/components/AttributeForm";
import { CheckboxField, CheckboxGroup, type FieldErrors, SelectField, StatusMessage, TextField } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

type TenantView = components["schemas"]["TenantView"];
type TenantSettingsPatch = components["schemas"]["TenantSettingsPatch"];
type MfaPolicy = components["schemas"]["MfaPolicy"];
type TokenClaimRule = components["schemas"]["TokenClaimRule"];
type TokenTarget = components["schemas"]["TokenTarget"];

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

interface RuleValues {
  enabled: boolean;
  claim: string;
  tokens: TokenTarget[];
  scope: string;
}

function ruleValues(rule: TokenClaimRule | null | undefined, fallbackClaim: string): RuleValues {
  return {
    enabled: Boolean(rule),
    claim: rule?.claim ?? fallbackClaim,
    tokens: rule?.tokens ?? ["access_token"],
    scope: rule?.scope ?? "",
  };
}

function ruleBody(v: RuleValues): TokenClaimRule | null {
  return v.enabled ? { claim: v.claim.trim(), tokens: v.tokens, scope: v.scope.trim() || null } : null;
}

const CLAIM_RULES = [
  { key: "roles", title: "Roles", hint: "The names of the user's roles." },
  { key: "permissions", title: "Permissions", hint: "The union of the permissions of the user's roles." },
] as const;

/** Mapping of roles and permissions into tokens (`settings.claims`, ORG-05). */
function ClaimMapping({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const queryClient = useQueryClient();
  const initial = {
    roles: ruleValues(tenant.settings.claims.roles, "roles"),
    permissions: ruleValues(tenant.settings.claims.permissions, "permissions"),
  };
  const [values, setValues] = useState(initial);
  const [status, setStatus] = useState<string | null>(null);
  const set = (key: "roles" | "permissions", patch: Partial<RuleValues>) =>
    setValues((v) => ({ ...v, [key]: { ...v[key], ...patch } }));

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}", {
          params: { path: { slug } },
          body: { settings: { claims: { roles: ruleBody(values.roles), permissions: ruleBody(values.permissions) } } },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (updated) => {
      queryClient.setQueryData(tenantQueryKey(slug), updated);
      setStatus("Token claims saved.");
      await queryClient.invalidateQueries({ queryKey: ["tenant"] });
    },
  });
  const errors = settingsErrors(save.error);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Token claims</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="space-y-4"
          aria-label="Token claims"
          noValidate
          data-testid="claim-mapping-form"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <p className="text-muted-foreground text-sm">
            Which tokens carry the user's roles and permissions. A claim with a required scope appears only when the
            client was granted that scope. Attribute claims are set on each{" "}
            <Link to="/t/$tenant/attributes" params={{ tenant: slug }} className="underline underline-offset-4">
              attribute
            </Link>
            .
          </p>
          {save.error ? <ProblemAlert error={save.error} /> : null}
          {CLAIM_RULES.map(({ key, title, hint }) => {
            const v = values[key];
            return (
              <fieldset key={key} className="space-y-3 rounded-md border p-4" data-testid={`claim-rule-${key}`}>
                <legend className="px-1 text-sm font-medium">{title}</legend>
                <CheckboxField
                  label={`Put ${key} into tokens`}
                  checked={v.enabled}
                  onChange={(e) => set(key, { enabled: e.target.checked })}
                  hint={hint}
                />
                {v.enabled && (
                  <>
                    <TextField
                      label="Claim name"
                      value={v.claim}
                      onChange={(e) => set(key, { claim: e.target.value })}
                      errors={errors[`claims.${key}.claim`] ?? errors[`claims.${key}`]}
                      autoComplete="off"
                    />
                    <CheckboxGroup
                      legend="Tokens"
                      options={TOKEN_TARGETS}
                      value={v.tokens}
                      onChange={(next) => set(key, { tokens: next })}
                      errors={errors[`claims.${key}.tokens`]}
                    />
                    <TextField
                      label="Required scope"
                      optional
                      value={v.scope}
                      onChange={(e) => set(key, { scope: e.target.value })}
                      hint="Empty = always included."
                      errors={errors[`claims.${key}.scope`]}
                      autoComplete="off"
                    />
                  </>
                )}
              </fieldset>
            );
          })}
          <Button type="submit" disabled={save.isPending} data-testid="save-claim-mapping">
            {save.isPending ? "Saving…" : "Save token claims"}
          </Button>
          <StatusMessage message={status} />
        </form>
      </CardContent>
    </Card>
  );
}

/** The other tenant settings pages. */
function MoreSettings() {
  const tenant = useTenant();
  const link = "font-medium underline underline-offset-4";
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>More settings</h2>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2 text-sm">
          <li>
            <Link to="/t/$tenant/settings/registration" params={{ tenant }} className={link} data-testid="registration-settings-link">
              Client registration
            </Link>{" "}
            <span className="text-muted-foreground">
              Dynamic client registration, Client ID Metadata Documents and initial access tokens.
            </span>
          </li>
          <li>
            <Link to="/t/$tenant/settings/config" params={{ tenant }} className={link} data-testid="config-settings-link">
              Configuration
            </Link>{" "}
            <span className="text-muted-foreground">Export the tenant as a document, plan and apply changes.</span>
          </li>
          <li>
            <Link to="/t/$tenant/webhooks" params={{ tenant }} className={link}>
              Webhooks
            </Link>{" "}
            <span className="text-muted-foreground">Signed event deliveries to your endpoints.</span>
          </li>
        </ul>
      </CardContent>
    </Card>
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
          <ClaimMapping key={`claims-${query.data.id}`} tenant={query.data} />
          <MoreSettings />
          <DeleteTenant tenant={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/settings/")({ component: LoginSettingsPage });
