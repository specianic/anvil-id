// Create a tenant (ORG-01). The slug is immutable and becomes the path of the tenant's issuer
// (`{public_url}/t/{slug}`); a custom host is optional. The slug rule is checked here for quick
// feedback, the API validates everything again (409 for a taken slug or host). The slug follows the
// display name until the admin edits it (C-M11). After creation the page shows the tenant's issuer
// and discovery URL and leads to its first app (C-M15) instead of an empty Users page.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { CircleCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import type { components } from "@/api/schema";
import { api, unwrap } from "@/api/client";
import { CopyField } from "@/components/CopyField";
import { ProblemAlert } from "@/components/ProblemAlert";
import { type FieldErrors, SelectField, TextField, fieldErrors } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useSlugFromName } from "@/lib/slug";
import { SLUG_PATTERN, UNDELETABLE_TENANTS, rememberTenant } from "@/lib/tenant";

type CreateTenant = components["schemas"]["CreateTenant"];
type NewTenantSettings = components["schemas"]["NewTenantSettings"];
type RegistrationMode = components["schemas"]["RegistrationMode"];
type TenantView = components["schemas"]["TenantView"];

const REGISTRATION_OPTIONS: readonly { value: RegistrationMode; label: string }[] = [
  { value: "open", label: "Open: anyone can create an account" },
  { value: "invite_only", label: "Invite only: people join through an invitation" },
  { value: "disabled", label: "Disabled: administrators create users" },
];

const linkClass =
  "text-sm underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

interface Values {
  slug: string;
  displayName: string;
  host: string;
  registration: RegistrationMode;
}

function localErrors(v: Values): FieldErrors {
  const out: FieldErrors = {};
  if (!SLUG_PATTERN.test(v.slug)) {
    out.slug = [{ message: "Use 2 to 63 characters: lowercase letters, digits and '-'." }];
  } else if (UNDELETABLE_TENANTS.includes(v.slug)) {
    out.slug = [{ message: `'${v.slug}' is reserved.` }];
  }
  if (!v.displayName.trim()) out.display_name = [{ message: "Enter a display name." }];
  return out;
}

function body(v: Values): CreateTenant {
  // Settings not sent keep the API's documented defaults (NewTenantSettings); only the
  // registration mode is chosen here, the rest is edited on the tenant's Login settings page.
  const settings = { registration: v.registration } as Partial<NewTenantSettings> as NewTenantSettings;
  const host = v.host.trim();
  return { slug: v.slug, display_name: v.displayName.trim(), host: host || null, settings };
}

/** Shown once the tenant exists: its URLs and the next step. */
function TenantCreated({ tenant }: { tenant: TenantView }) {
  const params = { tenant: tenant.slug };
  return (
    <section aria-labelledby="tenant-created-heading" className="space-y-4" data-testid="tenant-created">
      <Link to="/tenants" className={`text-muted-foreground ${linkClass}`}>
        ← Tenants
      </Link>
      <h1 id="tenant-created-heading" className="flex items-center gap-2 text-xl font-semibold">
        <CircleCheck aria-hidden="true" className="text-success size-6" />
        Tenant created
      </h1>
      <p className="text-sm" role="status">
        <strong>{tenant.display_name}</strong> (<code>{tenant.slug}</code>) is ready. Apps of this tenant use the
        issuer below.
      </p>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Connect an app</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <CopyField label="Issuer" value={tenant.issuer} mono />
          <CopyField label="Discovery URL" value={tenant.discovery_url} mono />
        </CardContent>
      </Card>
      <div className="flex flex-wrap gap-2">
        <Button asChild>
          <Link to="/t/$tenant/clients/new" params={params} data-testid="tenant-created-first-app">
            Create your first app
          </Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/t/$tenant" params={params} data-testid="tenant-created-overview">
            Open the tenant overview
          </Link>
        </Button>
      </div>
    </section>
  );
}

function NewTenantPage() {
  const queryClient = useQueryClient();
  const { slug, setSlug, onNameChange } = useSlugFromName();
  const [values, setValues] = useState<Omit<Values, "slug">>({ displayName: "", host: "", registration: "open" });
  const [local, setLocal] = useState<FieldErrors>({});
  const [created, setCreated] = useState<TenantView | null>(null);
  const set = <K extends keyof Omit<Values, "slug">>(key: K, value: Values[K]) =>
    setValues((v) => ({ ...v, [key]: value }));
  const all: Values = { ...values, slug };

  const create = useMutation({
    mutationFn: async (input: CreateTenant) => unwrap(await api.POST("/api/admin/v1/tenants", { body: input })),
    onSuccess: async (tenant) => {
      queryClient.setQueryData(["tenant", tenant.slug], tenant);
      // The next /console/ visit opens the new tenant, as the switcher would.
      rememberTenant(tenant.slug);
      setCreated(tenant);
      await queryClient.invalidateQueries({ queryKey: ["tenants"] });
    },
  });

  if (created) return <TenantCreated tenant={created} />;

  const api422 = fieldErrors(create.error);
  const errors: FieldErrors = { ...api422, ...local };
  const known = new Set(["slug", "display_name", "host", "settings.registration"]);
  const otherError = create.error && !Object.keys(api422).some((k) => known.has(k)) ? create.error : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const errs = localErrors(all);
    setLocal(errs);
    if (Object.keys(errs).length > 0) return;
    create.mutate(body(all));
  };

  return (
    <section aria-labelledby="new-tenant-heading" className="space-y-4">
      <Link to="/tenants" className={`text-muted-foreground ${linkClass}`}>
        ← Tenants
      </Link>
      <h1 id="new-tenant-heading" className="text-xl font-semibold">
        New tenant
      </h1>
      <Card>
        <CardContent>
          <form className="max-w-xl space-y-4" onSubmit={submit} noValidate data-testid="tenant-form">
            {Object.keys(errors).length > 0 && (
              <p role="alert" className="text-destructive text-sm">
                The tenant was not created. Fix the errors below.
              </p>
            )}
            <TextField
              label="Display name"
              name="display_name"
              value={values.displayName}
              onChange={(e) => {
                set("displayName", e.target.value);
                onNameChange(e.target.value);
              }}
              errors={errors.display_name}
              required
              data-testid="tenant-display-name"
            />
            <TextField
              label="Slug"
              name="slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase())}
              hint="Filled in from the display name until you edit it. 2-63 characters of a-z, 0-9 and '-'. It cannot be changed later: it is part of the issuer URL."
              errors={errors.slug}
              autoComplete="off"
              spellCheck={false}
              required
              pattern="[a-z0-9-]{2,63}"
              data-testid="tenant-slug"
            />
            <TextField
              label="Custom host"
              name="host"
              optional
              value={values.host}
              onChange={(e) => set("host", e.target.value)}
              hint="A domain that serves this tenant directly (issuer https://host). Leave empty to use the path issuer only."
              errors={errors.host}
              autoComplete="off"
              spellCheck={false}
              data-testid="tenant-host"
            />
            <SelectField
              label="Sign-up"
              name="registration"
              value={values.registration}
              onChange={(e) => set("registration", e.target.value as RegistrationMode)}
              options={REGISTRATION_OPTIONS}
              hint="Who can create an account. You can change it later in Login settings."
              errors={errors["settings.registration"]}
              data-testid="tenant-registration"
            />
            {otherError ? <ProblemAlert error={otherError} /> : null}
            <Button type="submit" disabled={create.isPending} data-testid="create-tenant">
              {create.isPending ? "Creating…" : "Create tenant"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </section>
  );
}

export const Route = createFileRoute("/tenants/new")({ component: NewTenantPage });
