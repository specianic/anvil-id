// Tenant login settings: who may sign up (registration mode, first), MFA policy, passwordless email
// sign-in, automatic account linking, registration through upstream connections, the default page
// language, the token claim mapping of roles and permissions, the tenant PAR policy and the
// headless flow API's allowed browser origins. One form with one Save (C-M12): a field-wise PATCH
// of the tenant that sends only what changed, and an unsaved-changes guard. Links to the other
// settings pages follow; deleting the tenant sits in the Danger zone at the bottom (C-M13).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, type ReactNode, useId, useState } from "react";
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
import { DangerZone } from "@/components/DangerZone";
import { ProblemAlert } from "@/components/ProblemAlert";
import { TOKEN_TARGETS } from "@/components/AttributeForm";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";
import {
  CheckboxField,
  CheckboxGroup,
  type FieldErrors,
  type FieldMessage,
  SelectField,
  StatusMessage,
  TextField,
} from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useFormState } from "@/lib/formState";
import { useUnsavedChanges } from "@/lib/unsaved";

type TenantView = components["schemas"]["TenantView"];
type TenantSettingsPatch = components["schemas"]["TenantSettingsPatch"];
type MfaPolicy = components["schemas"]["MfaPolicy"];
type RegistrationMode = components["schemas"]["RegistrationMode"];
type TokenClaimRule = components["schemas"]["TokenClaimRule"];
type TokenTarget = components["schemas"]["TokenTarget"];

const MFA_OPTIONS: readonly { value: MfaPolicy; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "optional", label: "Optional (users who enrolled a second factor)" },
  { value: "required", label: "Required (users without one enrol first)" },
];

const SIGN_UP_OPTIONS: readonly { value: RegistrationMode; label: string; hint: string }[] = [
  {
    value: "open",
    label: "Open",
    hint: "Anyone can create an account: the sign-in page shows “Create an account”.",
  },
  {
    value: "invite_only",
    label: "Invite only",
    hint: "People join through an invitation an administrator sends. There is no public sign-up page.",
  },
  {
    value: "disabled",
    label: "Disabled",
    hint: "Nobody signs up. Administrators create users here in the console or through the API.",
  },
];

const SIGN_UP_LABEL: Record<RegistrationMode, string> = { open: "open", invite_only: "invite only", disabled: "disabled" };

type UpstreamChoice = "follow" | "allow" | "deny";

interface RuleValues {
  enabled: boolean;
  claim: string;
  tokens: TokenTarget[];
  scope: string;
}

interface Values {
  registration: RegistrationMode;
  mfa_policy: MfaPolicy;
  email_otp: boolean;
  magic_link: boolean;
  auto_link: boolean;
  upstream_registration: UpstreamChoice;
  default_locale: string;
  claims: { roles: RuleValues; permissions: RuleValues };
  require_par: boolean;
  origins: string[];
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

function valuesFromTenant(t: TenantView): Values {
  const s = t.settings;
  return {
    registration: s.registration,
    mfa_policy: s.mfa_policy,
    email_otp: s.email_otp,
    magic_link: s.magic_link,
    auto_link: s.auto_link,
    upstream_registration:
      s.upstream_registration === true ? "allow" : s.upstream_registration === false ? "deny" : "follow",
    default_locale: s.default_locale,
    claims: { roles: ruleValues(s.claims.roles, "roles"), permissions: ruleValues(s.claims.permissions, "permissions") },
    require_par: s.par.require_pushed_authorization_requests,
    origins: [...s.headless.allowed_origins],
  };
}

function upstreamValue(choice: UpstreamChoice): boolean | null {
  return choice === "allow" ? true : choice === "deny" ? false : null;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Only the fields that differ from the saved settings (absent fields keep their value). */
function patchBody(saved: Values, values: Values): TenantSettingsPatch {
  const patch: TenantSettingsPatch = {};
  if (values.registration !== saved.registration) patch.registration = values.registration;
  if (values.mfa_policy !== saved.mfa_policy) patch.mfa_policy = values.mfa_policy;
  if (values.email_otp !== saved.email_otp) patch.email_otp = values.email_otp;
  if (values.magic_link !== saved.magic_link) patch.magic_link = values.magic_link;
  if (values.auto_link !== saved.auto_link) patch.auto_link = values.auto_link;
  if (values.upstream_registration !== saved.upstream_registration)
    patch.upstream_registration = upstreamValue(values.upstream_registration);
  if (values.default_locale !== saved.default_locale) patch.default_locale = values.default_locale;
  if (!same(values.claims, saved.claims))
    patch.claims = { roles: ruleBody(values.claims.roles), permissions: ruleBody(values.claims.permissions) };
  // PAR and headless objects are replaced whole; the API validates the origins.
  if (values.require_par !== saved.require_par)
    patch.par = { require_pushed_authorization_requests: values.require_par };
  if (!same(values.origins, saved.origins)) patch.headless = { allowed_origins: values.origins };
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

/** Field errors under `key` (`headless.allowed_origins[0]`, `claims.roles.claim`, ...). */
function errorsUnder(errors: FieldErrors, key: string): FieldMessage[] {
  return Object.entries(errors)
    .filter(([field]) => field === key || field.startsWith(`${key}.`) || field.startsWith(`${key}[`))
    .flatMap(([, messages]) => messages);
}

/** Fields the form places next to their control; anything else goes to the problem alert. */
const PLACED = [
  "registration",
  "mfa_policy",
  "email_otp",
  "magic_link",
  "auto_link",
  "upstream_registration",
  "default_locale",
  "claims",
  "par",
  "headless",
];
const placed = (field: string) => PLACED.some((p) => field === p || field.startsWith(`${p}.`) || field.startsWith(`${p}[`));

/** Languages the tenant's sign-in pages offer (`ui_locales_supported` of its discovery document). */
function useUiLocales(slug: string): { locales: string[]; failed: boolean } {
  const query = useDiscovery(slug);
  const list = query.data?.ui_locales_supported;
  const locales = Array.isArray(list) ? list.filter((l): l is string => typeof l === "string") : [];
  return { locales, failed: query.isError };
}

function Section({ title, id, testId, children }: { title: string; id?: string; testId?: string; children: ReactNode }) {
  return (
    <Card id={id} data-testid={testId} className="scroll-mt-4">
      <CardHeader>
        <CardTitle>
          <h2>{title}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">{children}</CardContent>
    </Card>
  );
}

const CLAIM_RULES = [
  { key: "roles", title: "Roles", hint: "The names of the user's roles." },
  { key: "permissions", title: "Permissions", hint: "The union of the permissions of the user's roles." },
] as const;

function SignUpField({
  value,
  onChange,
  errors,
}: {
  value: RegistrationMode;
  onChange: (mode: RegistrationMode) => void;
  errors?: FieldMessage[];
}) {
  const name = useId();
  const errorId = `${name}-error`;
  return (
    <fieldset
      className="space-y-3"
      data-testid="sign-up-mode"
      aria-describedby={errors?.length ? errorId : undefined}
    >
      <legend className="text-sm font-medium">Who can create an account</legend>
      {SIGN_UP_OPTIONS.map((o) => {
        const id = `${name}-${o.value}`;
        return (
          <div key={o.value} className="flex items-start gap-2">
            <input
              id={id}
              type="radio"
              name="registration"
              value={o.value}
              checked={value === o.value}
              onChange={() => onChange(o.value)}
              aria-describedby={`${id}-hint`}
              className="mt-0.5 size-4 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
              data-testid={`sign-up-${o.value}`}
            />
            <div>
              <label htmlFor={id} className="text-sm font-medium">
                {o.label}
              </label>
              <p id={`${id}-hint`} className="text-muted-foreground text-xs">
                {o.hint}
              </p>
            </div>
          </div>
        );
      })}
      {errors?.length ? (
        <ul id={errorId} className="text-destructive space-y-0.5 text-sm" data-field-error>
          {errors.map((e) => (
            <li key={e.message}>{e.message}</li>
          ))}
        </ul>
      ) : null}
    </fieldset>
  );
}

function SettingsForm({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const queryClient = useQueryClient();
  const saved = valuesFromTenant(tenant);
  const form = useFormState<Values>(saved);
  const { values, setValues } = form;
  const [status, setStatus] = useState<string | null>(null);
  // Set when the API refused to turn on an email sign-in method because no SMTP server is configured.
  const [smtpMissing, setSmtpMissing] = useState(false);
  const [draft, setDraft] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const { locales, failed: localesFailed } = useUiLocales(slug);
  const set = <K extends keyof Values>(key: K, value: Values[K]) => setValues((v) => ({ ...v, [key]: value }));
  const setRule = (key: "roles" | "permissions", patch: Partial<RuleValues>) =>
    setValues((v) => ({ ...v, claims: { ...v.claims, [key]: { ...v.claims[key], ...patch } } }));

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

  const blocker = useUnsavedChanges(form.isDirty && !save.isPending);

  const errors = settingsErrors(save.error);
  const parErrors = errorsUnder(errors, "par");
  const originErrors = errorsUnder(errors, "headless");
  const otherError =
    save.error &&
    !(
      save.error instanceof ApiError &&
      save.error.problem.errors.length > 0 &&
      Object.keys(errors).every((f) => placed(f))
    )
      ? save.error
      : null;

  const localeOptions = (locales.includes(values.default_locale) ? locales : [values.default_locale, ...locales]).map(
    (l) => ({ value: l, label: l }),
  );

  const smtpHint = (
    <>
      Needs an SMTP server (the tenant's{" "}
      <Link to="/t/$tenant/email/smtp" params={{ tenant: slug }} className="underline underline-offset-4">
        SMTP settings
      </Link>{" "}
      or the installation's).
    </>
  );

  const addOrigin = () => {
    const value = draft.trim();
    if (value === "") return;
    // Exact comparison only; the API checks the form of each origin.
    if (values.origins.includes(value)) {
      setLocalError(`${value} is already in the list.`);
      return;
    }
    setLocalError(null);
    setValues((v) => ({ ...v, origins: [...v.origins, value] }));
    setDraft("");
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body = patchBody(saved, values);
    if (Object.keys(body).length === 0) {
      setStatus("Nothing changed.");
      return;
    }
    form.markSubmitted();
    save.mutate(body);
  };

  return (
    <>
      <UnsavedChangesGuard blocker={blocker} />
      <form onSubmit={submit} aria-label="Login settings" className="space-y-6" noValidate data-testid="login-settings-form">
        {save.error instanceof ApiError && save.error.status === 422 && (
          <p role="alert" className="text-destructive text-sm" data-testid="login-settings-invalid">
            The settings were not saved. Fix the errors below.
          </p>
        )}
        {otherError ? <ProblemAlert error={otherError} /> : null}

        <Section title="Sign-up" id="sign-up" testId="sign-up-section">
          <SignUpField value={values.registration} onChange={(mode) => set("registration", mode)} errors={errors.registration} />
          <p className="text-muted-foreground text-xs">
            This is about people creating accounts. Apps registering themselves are configured under{" "}
            <Link to="/t/$tenant/settings/registration" params={{ tenant: slug }} className="underline underline-offset-4">
              Dynamic client registration
            </Link>
            .
          </p>
        </Section>

        <Section title="Multi-factor authentication">
          <SelectField
            label="MFA policy"
            name="mfa_policy"
            value={values.mfa_policy}
            onChange={(e) => set("mfa_policy", e.target.value as MfaPolicy)}
            options={MFA_OPTIONS}
            hint="A client may make this stricter; the strictest of tenant and client policy applies."
            errors={errors.mfa_policy}
          />
        </Section>

        <Section title="Passwordless sign-in by email">
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
        </Section>

        <Section title="Upstream connections">
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
              { value: "follow", label: `Follow the sign-up setting (currently: ${SIGN_UP_LABEL[values.registration]})` },
              { value: "allow", label: "Allow: first upstream sign-in creates an account" },
              { value: "deny", label: "Deny: only existing or linked accounts" },
            ]}
            errors={errors.upstream_registration}
          />
        </Section>

        <Section title="Language">
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
        </Section>

        <Section title="Token claims" testId="claim-mapping-form">
          <p className="text-muted-foreground text-sm">
            Which tokens carry the user's roles and permissions. A claim with a required scope appears only when the
            client was granted that scope. Attribute claims are set on each{" "}
            <Link to="/t/$tenant/attributes" params={{ tenant: slug }} className="underline underline-offset-4">
              attribute
            </Link>
            .
          </p>
          {CLAIM_RULES.map(({ key, title, hint }) => {
            const v = values.claims[key];
            return (
              <fieldset key={key} className="space-y-3 rounded-md border p-4" data-testid={`claim-rule-${key}`}>
                <legend className="px-1 text-sm font-medium">{title}</legend>
                <CheckboxField
                  label={`Put ${key} into tokens`}
                  checked={v.enabled}
                  onChange={(e) => setRule(key, { enabled: e.target.checked })}
                  hint={hint}
                />
                {v.enabled && (
                  <>
                    <TextField
                      label="Claim name"
                      value={v.claim}
                      onChange={(e) => setRule(key, { claim: e.target.value })}
                      errors={errors[`claims.${key}.claim`] ?? errors[`claims.${key}`]}
                      autoComplete="off"
                    />
                    <CheckboxGroup
                      legend="Tokens"
                      options={TOKEN_TARGETS}
                      value={v.tokens}
                      onChange={(next) => setRule(key, { tokens: next })}
                      errors={errors[`claims.${key}.tokens`]}
                    />
                    <TextField
                      label="Required scope"
                      optional
                      value={v.scope}
                      onChange={(e) => setRule(key, { scope: e.target.value })}
                      hint="Empty = always included."
                      errors={errors[`claims.${key}.scope`]}
                      autoComplete="off"
                    />
                  </>
                )}
              </fieldset>
            );
          })}
        </Section>

        <Section title="Authorization requests and headless sign-in" testId="par-headless-form">
          <CheckboxField
            label="Require PAR for all clients"
            name="require_pushed_authorization_requests"
            hint="Every client of this tenant must send its authorization requests to the pushed authorization request endpoint first (RFC 9126). Clients can also require it individually."
            checked={values.require_par}
            onChange={(e) => set("require_par", e.target.checked)}
            errors={parErrors}
            data-testid="tenant-require-par"
          />
          <fieldset className="space-y-3 rounded-md border p-4" data-testid="headless-origins">
            <legend className="px-1 text-sm font-medium">Headless API allowed origins</legend>
            <p className="text-muted-foreground text-sm">
              Single-page apps on these exact origins may call the headless flow API from the browser. Use{" "}
              <code>https://host[:port]</code> without a path or wildcard; the app must be on the same site as the
              issuer. Empty: only the tenant's own origin. At most 50.
            </p>
            {values.origins.length === 0 ? (
              <p className="text-muted-foreground text-sm" data-testid="headless-origins-empty">
                No extra origins.
              </p>
            ) : (
              <ul className="space-y-1">
                {values.origins.map((origin) => (
                  <li key={origin} className="flex items-center gap-2" data-testid="headless-origin" data-origin={origin}>
                    <code className="text-sm break-all">{origin}</code>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      aria-label={`Remove ${origin}`}
                      onClick={() => setValues((v) => ({ ...v, origins: v.origins.filter((x) => x !== origin) }))}
                    >
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            )}
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-64 flex-1">
                <TextField
                  label="Origin to add"
                  value={draft}
                  placeholder="https://app.example.com"
                  autoComplete="off"
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    // Enter adds the origin instead of submitting the whole form.
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addOrigin();
                    }
                  }}
                  errors={[...(localError ? [{ message: localError }] : []), ...originErrors]}
                  data-testid="headless-origin-input"
                />
              </div>
              <Button type="button" variant="outline" onClick={addOrigin} data-testid="headless-origin-add">
                Add origin
              </Button>
            </div>
          </fieldset>
        </Section>

        <div
          className="bg-background sticky bottom-0 z-10 flex flex-wrap items-center gap-3 border-t py-3"
          data-testid="login-settings-save-bar"
        >
          <Button type="submit" disabled={save.isPending} data-testid="save-login-settings">
            {save.isPending ? "Saving…" : "Save login settings"}
          </Button>
          {form.isDirty && (
            <span className="text-muted-foreground text-sm" data-testid="login-settings-dirty">
              Unsaved changes
            </span>
          )}
          <StatusMessage message={status} />
        </div>
      </form>
    </>
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
              Dynamic client registration
            </Link>{" "}
            <span className="text-muted-foreground">
              Lets apps register themselves (RFC 7591, Client ID Metadata Documents, initial access tokens). Not about
              user sign-up.
            </span>
          </li>
          <li>
            <Link to="/t/$tenant/settings/config" params={{ tenant }} className={link} data-testid="config-settings-link">
              Configuration
            </Link>{" "}
            <span className="text-muted-foreground">Export the tenant as a document, plan and apply changes.</span>
          </li>
          <li>
            <Link to="/t/$tenant/password-profiles" params={{ tenant }} className={link} data-testid="password-profiles-link">
              Password hash profiles
            </Link>{" "}
            <span className="text-muted-foreground">Firebase scrypt parameters for imported password hashes.</span>
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
  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}", { params: { path: { slug: tenant.slug } } });
    },
    onSuccess: async () => {
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
    <DangerZone
      title="Delete this tenant"
      description={
        <p>
          Deletes <code>{tenant.slug}</code> with all its users, clients, connections, sessions and keys. Relying
          parties of this tenant stop working. This cannot be undone.
        </p>
      }
      confirmText={tenant.slug}
      actionLabel="Delete tenant"
      onConfirm={() => remove.mutate()}
      pending={remove.isPending}
      error={remove.error}
    />
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
          <MoreSettings />
          <DeleteTenant tenant={query.data} />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/settings/")({ component: LoginSettingsPage });
