// Dynamic client registration settings (OIDC-17, AGT-02): the dynamic client registration policy (RFC 7591)
// with its allow-lists, the Client ID Metadata Document policy, and initial access tokens for
// `allow_listed` registration. The system tenant always has both policies disabled (read-only here).
// An initial access token's value is shown once and kept only in this page's state.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { OneTimeSecret } from "@/components/WebhookForm";
import {
  CheckboxField,
  type FieldErrors,
  SelectField,
  StatusMessage,
  TextField,
  TextareaField,
  lines,
  tokens,
} from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";
import { SYSTEM_TENANT, tenantQueryKey, useTenant, useTenantView } from "@/lib/tenant";

type TenantView = components["schemas"]["TenantView"];
type DcrPolicy = components["schemas"]["DcrPolicy"];
type CimdPolicy = components["schemas"]["CimdPolicy"];
type InitialAccessToken = components["schemas"]["InitialAccessTokenDto"];

const DCR_OPTIONS: readonly { value: DcrPolicy; label: string }[] = [
  { value: "disabled", label: "Disabled: /register answers 404" },
  { value: "allow_listed", label: "Allow-listed: an initial access token is required" },
  { value: "open", label: "Open: anyone may register a client" },
];

const CIMD_OPTIONS: readonly { value: CimdPolicy; label: string }[] = [
  { value: "disabled", label: "Disabled" },
  { value: "allow_listed", label: "Allow-listed: only documents on the listed hosts" },
  { value: "open", label: "Open: any https client_id URL" },
];

interface Values {
  dcrPolicy: DcrPolicy;
  redirectHosts: string;
  scopes: string;
  resources: string;
  clientCredentials: boolean;
  maxClients: string;
  cimdPolicy: CimdPolicy;
  cimdHosts: string;
  minCache: string;
  maxCache: string;
}

function valuesFromTenant(t: TenantView): Values {
  const { dcr, cimd } = t.settings;
  return {
    dcrPolicy: dcr.policy,
    redirectHosts: dcr.allowed_redirect_hosts.join("\n"),
    scopes: dcr.allowed_scopes.join(" "),
    resources: dcr.allowed_resources.join("\n"),
    clientCredentials: dcr.allow_client_credentials,
    maxClients: String(dcr.max_clients),
    cimdPolicy: cimd.policy,
    cimdHosts: cimd.allowed_hosts.join("\n"),
    minCache: String(cimd.min_cache_secs),
    maxCache: String(cimd.max_cache_secs),
  };
}

/** Field errors keyed without the `settings.` prefix (`dcr.allowed_redirect_hosts`, `cimd.policy`, ...). */
function settingsErrors(error: unknown): FieldErrors {
  if (!(error instanceof ApiError)) return {};
  const out: FieldErrors = {};
  for (const e of error.problem.errors) {
    const field = e.field.replace(/^settings\./, "").replace(/\[\d+\]$/, "");
    (out[field] ??= []).push({ message: e.message, line: e.line });
  }
  return out;
}

function intOrNull(text: string): number | null {
  const n = Number(text);
  return text.trim() !== "" && Number.isInteger(n) ? n : null;
}

function PoliciesForm({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const readOnly = slug === SYSTEM_TENANT;
  const queryClient = useQueryClient();
  const [values, setValues] = useState<Values>(() => valuesFromTenant(tenant));
  const [local, setLocal] = useState<FieldErrors>({});
  const [status, setStatus] = useState<string | null>(null);
  const set = <K extends keyof Values>(key: K, value: Values[K]) => setValues((v) => ({ ...v, [key]: value }));

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}", {
          params: { path: { slug } },
          body: {
            settings: {
              dcr: {
                policy: values.dcrPolicy,
                allowed_redirect_hosts: lines(values.redirectHosts),
                allowed_scopes: tokens(values.scopes),
                allowed_resources: lines(values.resources),
                allow_client_credentials: values.clientCredentials,
                max_clients: intOrNull(values.maxClients),
              },
              cimd: {
                policy: values.cimdPolicy,
                allowed_hosts: lines(values.cimdHosts),
                min_cache_secs: intOrNull(values.minCache),
                max_cache_secs: intOrNull(values.maxCache),
              },
            },
          },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (updated) => {
      queryClient.setQueryData(tenantQueryKey(slug), updated);
      setValues(valuesFromTenant(updated));
      setStatus("Registration settings saved.");
      await queryClient.invalidateQueries({ queryKey: ["tenant"] });
    },
  });
  const server = settingsErrors(save.error);
  const errorsFor = (field: string) => local[field] ?? server[field];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const issues: FieldErrors = {};
    for (const [field, text] of [
      ["dcr.max_clients", values.maxClients],
      ["cimd.min_cache_secs", values.minCache],
      ["cimd.max_cache_secs", values.maxCache],
    ] as const) {
      if (intOrNull(text) === null) issues[field] = [{ message: "Enter a whole number." }];
    }
    setLocal(issues);
    if (Object.keys(issues).length === 0) save.mutate();
  };

  return (
    <form onSubmit={submit} aria-label="Registration policies" className="space-y-6" noValidate data-testid="registration-form">
      {readOnly && (
        <p className="text-muted-foreground rounded-md border p-3 text-sm" data-testid="registration-read-only">
          The system tenant never accepts dynamic or metadata-document clients: both policies are always disabled.
        </p>
      )}
      {save.error ? <ProblemAlert error={save.error} /> : null}
      <fieldset disabled={readOnly} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Registration endpoint (RFC 7591)</h2>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <SelectField
              label="Policy"
              value={values.dcrPolicy}
              onChange={(e) => set("dcrPolicy", e.target.value as DcrPolicy)}
              options={DCR_OPTIONS}
              hint="Registered clients always need consent and PKCE."
              errors={errorsFor("dcr.policy")}
              data-testid="dcr-policy"
            />
            <TextareaField
              label="Allowed redirect hosts"
              optional
              rows={3}
              value={values.redirectHosts}
              onChange={(e) => set("redirectHosts", e.target.value)}
              hint="One host name or IP literal per line (no scheme or port). Empty = any host the redirect URI rules allow."
              errors={errorsFor("dcr.allowed_redirect_hosts")}
            />
            <TextField
              label="Allowed scopes"
              optional
              value={values.scopes}
              onChange={(e) => set("scopes", e.target.value)}
              hint="Space separated. Empty = openid profile email address phone. Admin scopes are refused."
              errors={errorsFor("dcr.allowed_scopes")}
              autoComplete="off"
            />
            <TextareaField
              label="Allowed resources"
              optional
              rows={2}
              value={values.resources}
              onChange={(e) => set("resources", e.target.value)}
              hint="RFC 8707 resource indicators, one per line. Also granted to metadata-document clients."
              errors={errorsFor("dcr.allowed_resources")}
            />
            <CheckboxField
              label="Allow client_credentials"
              checked={values.clientCredentials}
              onChange={(e) => set("clientCredentials", e.target.checked)}
              hint="Registered confidential clients may use the client credentials grant."
              errors={errorsFor("dcr.allow_client_credentials")}
            />
            <TextField
              label="Maximum dynamic clients"
              type="number"
              min={0}
              step={1}
              value={values.maxClients}
              onChange={(e) => set("maxClients", e.target.value)}
              errors={errorsFor("dcr.max_clients")}
              className="max-w-40"
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Client ID Metadata Documents</h2>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <SelectField
              label="Policy"
              value={values.cimdPolicy}
              onChange={(e) => set("cimdPolicy", e.target.value as CimdPolicy)}
              options={CIMD_OPTIONS}
              hint="A client whose client_id is an https URL is created from the document at that URL."
              errors={errorsFor("cimd.policy")}
              data-testid="cimd-policy"
            />
            <TextareaField
              label="Allowed hosts"
              optional
              rows={3}
              value={values.cimdHosts}
              onChange={(e) => set("cimdHosts", e.target.value)}
              hint="One host per line; required for allow-listed."
              errors={errorsFor("cimd.allowed_hosts")}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField
                label="Minimum cache time (seconds)"
                type="number"
                min={60}
                max={604800}
                value={values.minCache}
                onChange={(e) => set("minCache", e.target.value)}
                errors={errorsFor("cimd.min_cache_secs")}
              />
              <TextField
                label="Maximum cache time (seconds)"
                type="number"
                min={60}
                max={604800}
                value={values.maxCache}
                onChange={(e) => set("maxCache", e.target.value)}
                hint="A document's max-age is clamped to these bounds (60 to 604800)."
                errors={errorsFor("cimd.max_cache_secs")}
              />
            </div>
          </CardContent>
        </Card>
        {!readOnly && (
          <div className="space-y-2">
            <Button type="submit" disabled={save.isPending} data-testid="save-registration">
              {save.isPending ? "Saving…" : "Save registration settings"}
            </Button>
            <StatusMessage message={status} />
          </div>
        )}
      </fieldset>
    </form>
  );
}

function tokenState(t: InitialAccessToken): { label: string; variant: "secondary" | "outline" | "destructive" } {
  if (t.revoked_at) return { label: "Revoked", variant: "destructive" };
  if (t.usable) return { label: "Usable", variant: "secondary" };
  return { label: "Expired or used up", variant: "outline" };
}

const EXPIRY_OPTIONS = [
  { value: "3600", label: "1 hour" },
  { value: "86400", label: "24 hours" },
  { value: "604800", label: "7 days" },
  { value: "2592000", label: "30 days" },
  { value: "31536000", label: "365 days" },
] as const;

function InitialAccessTokens({ tenant }: { tenant: TenantView }) {
  const slug = tenant.slug;
  const queryClient = useQueryClient();
  const [description, setDescription] = useState("");
  const [expiresIn, setExpiresIn] = useState("86400");
  const [uses, setUses] = useState("1");
  const [usesIssue, setUsesIssue] = useState<string | null>(null);
  const [issued, setIssued] = useState<string | null>(null);
  const [target, setTarget] = useState<InitialAccessToken | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const key = ["initial-access-tokens", slug] as const;

  const query = useQuery({
    queryKey: key,
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/initial-access-tokens", { params: { path: { slug } }, signal }),
      ),
  });

  const create = useMutation({
    mutationFn: async (body: { description: string; expires_in: number; uses: number | null }) => {
      const result = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/initial-access-tokens", { params: { path: { slug } }, body }),
      );
      // The value stays in component state only; the cached mutation result is the token record.
      setIssued(result.value);
      return result.token;
    },
    onMutate: () => setStatus(null),
    onSuccess: async () => {
      setDescription("");
      await queryClient.invalidateQueries({ queryKey: key });
    },
  });
  const revoke = useMutation({
    mutationFn: async (t: InitialAccessToken) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/initial-access-tokens/{id}", {
        params: { path: { slug, id: t.id } },
      });
    },
    onSuccess: async () => {
      setTarget(null);
      setStatus("Token revoked.");
      await queryClient.invalidateQueries({ queryKey: key });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    let count: number | null = null;
    if (uses.trim() !== "") {
      count = Number(uses);
      if (!Number.isInteger(count) || count < 1 || count > 100000) {
        setUsesIssue("Enter 1 to 100000, or leave empty for unlimited.");
        return;
      }
    }
    setUsesIssue(null);
    create.mutate({ description: description.trim(), expires_in: Number(expiresIn), uses: count });
  };

  const items = query.data?.items ?? [];
  const createErrors = create.error instanceof ApiError ? settingsErrors(create.error) : {};

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Initial access tokens</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-muted-foreground text-sm">
          Under the allow-listed policy, <code>POST /register</code> needs <code>Authorization: Bearer</code> with one
          of these tokens. A refused registration does not use one up.
        </p>
        {issued && (
          <OneTimeSecret
            title="Copy the initial access token now. It is not shown again."
            label="Initial access token"
            value={issued}
            testId="iat-value"
            onDone={() => setIssued(null)}
          />
        )}
        <form onSubmit={submit} className="space-y-4" aria-label="Create initial access token" noValidate data-testid="iat-form">
          {create.error && Object.keys(createErrors).length === 0 ? <ProblemAlert error={create.error} /> : null}
          <TextField
            label="Description"
            optional
            maxLength={200}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            errors={createErrors.description}
            autoComplete="off"
            data-testid="iat-description"
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <SelectField
              label="Expires after"
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              options={EXPIRY_OPTIONS}
              errors={createErrors.expires_in}
            />
            <TextField
              label="Uses"
              type="number"
              min={1}
              max={100000}
              value={uses}
              onChange={(e) => setUses(e.target.value)}
              hint="Registrations it authorizes; empty = unlimited until it expires."
              errors={usesIssue ? [{ message: usesIssue }] : createErrors.uses}
              data-testid="iat-uses"
            />
          </div>
          <Button type="submit" disabled={create.isPending} data-testid="create-iat">
            {create.isPending ? "Creating…" : "Create token"}
          </Button>
        </form>
        <StatusMessage message={status} />
        {query.isError ? (
          <ProblemAlert error={query.error} />
        ) : (
          <div className="rounded-md border">
            <Table aria-busy={query.isFetching}>
              <TableCaption className="sr-only">Initial access tokens</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Description</TableHead>
                  <TableHead scope="col">Created</TableHead>
                  <TableHead scope="col">Expires</TableHead>
                  <TableHead scope="col">Uses left</TableHead>
                  <TableHead scope="col">State</TableHead>
                  <TableHead scope="col">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {query.isPending ? (
                  <TableRow>
                    <TableCell colSpan={6}>
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  </TableRow>
                ) : items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground h-20 text-center">
                      No initial access tokens.
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((t) => {
                    const state = tokenState(t);
                    return (
                      <TableRow key={t.id} data-testid={`iat-${t.id}`}>
                        <TableCell className="break-words">{t.description || "—"}</TableCell>
                        <TableCell>{formatDateTime(t.created_at)}</TableCell>
                        <TableCell>{formatDateTime(t.expires_at)}</TableCell>
                        <TableCell>{t.uses_remaining ?? "Unlimited"}</TableCell>
                        <TableCell>
                          <Badge variant={state.variant}>{state.label}</Badge>
                        </TableCell>
                        <TableCell>
                          {!t.revoked_at && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setTarget(t)}
                              aria-label={`Revoke token ${t.description || formatDateTime(t.created_at)}`}
                            >
                              Revoke
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        )}
        <ConfirmDialog
          open={target !== null}
          title="Revoke this token?"
          description={<p>Registrations presenting it are refused from now on. Clients it registered are kept.</p>}
          confirmLabel="Revoke token"
          onConfirm={() => target && revoke.mutate(target)}
          onCancel={() => {
            revoke.reset();
            setTarget(null);
          }}
          pending={revoke.isPending}
          error={revoke.error}
        />
      </CardContent>
    </Card>
  );
}

function RegistrationPage() {
  const tenant = useTenant();
  const query = useTenantView(tenant);
  return (
    <section aria-labelledby="registration-heading" className="space-y-4">
      <Link
        to="/t/$tenant/settings"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Login settings
      </Link>
      <h1 id="registration-heading" className="text-xl font-semibold">
        Dynamic client registration
      </h1>
      <p className="text-muted-foreground text-sm" data-testid="registration-explainer">
        Lets apps register themselves with this tenant (RFC 7591 dynamic registration and Client ID Metadata
        Documents) instead of an administrator creating them. It has nothing to do with users signing up: that is
        the{" "}
        <Link to="/t/$tenant/settings" hash="sign-up" params={{ tenant }} className="underline underline-offset-4">
          Sign-up
        </Link>{" "}
        setting in Login settings.
      </p>
      {query.isPending ? (
        <div role="status" aria-label="Loading registration settings" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <>
          <PoliciesForm key={query.data.id} tenant={query.data} />
          {query.data.slug !== SYSTEM_TENANT && <InitialAccessTokens tenant={query.data} />}
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/settings/registration")({ component: RegistrationPage });
