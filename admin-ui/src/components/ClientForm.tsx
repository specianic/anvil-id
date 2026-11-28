// Create/edit form for OAuth clients, shared by /clients/new and /clients/$clientId.
//
// Creating starts with "What are you building?" (AppTypePicker): the chosen type fills in the
// settings that make a working, safe setup for it (APP_TYPES). The form then shows only what that
// kind of app needs: a client without the authorization code grant (machine-to-machine) has no
// redirect URIs, consent, PKCE or ID token fields, and the protocol details sit under "Advanced".
// The server's client policy still decides every value.
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, TriangleAlert } from "lucide-react";
import { type FormEvent, useId, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { type AppTypeDefaults, type AppTypeId, AppTypePicker, appType } from "@/components/AppTypePicker";
import { ProblemAlert } from "@/components/ProblemAlert";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";
import {
  CheckboxField,
  CheckboxGroup,
  type FieldErrors,
  SelectField,
  TextField,
  TextareaField,
  fieldErrors,
  lines,
  tokens,
} from "@/components/form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useFormState } from "@/lib/formState";
import { useUnsavedChanges } from "@/lib/unsaved";

type ClientView = components["schemas"]["ClientView"];
type ClientType = components["schemas"]["ClientType"];
type ApplicationType = components["schemas"]["ApplicationType"];
type ClientAuthMethod = components["schemas"]["ClientAuthMethod"];
type GrantType = components["schemas"]["GrantType"];
type TokenFormat = components["schemas"]["TokenFormat"];
type ConsentMode = components["schemas"]["ConsentMode"];
type MfaPolicy = components["schemas"]["MfaPolicy"];
type OrgClientPolicy = components["schemas"]["OrgClientPolicy"];
type ClientKind = components["schemas"]["ClientKind"];
export type CreateClient = components["schemas"]["CreateClient"];
export type UpdateClient = components["schemas"]["UpdateClient"];

export interface ClientFormValues {
  name: string;
  client_type: ClientType;
  application_type: ApplicationType;
  auth_method: ClientAuthMethod;
  jwks: string;
  redirect_uris: string;
  grant_types: GrantType[];
  scopes: string;
  require_pkce: boolean;
  token_format: TokenFormat;
  consent_mode: ConsentMode;
  id_token_signed_response_alg: string;
  can_introspect: boolean;
  post_logout_redirect_uris: string;
  backchannel_logout_uri: string;
  backchannel_logout_session_required: boolean;
  allowed_resources: string;
  /** `inherit` = no client override (the tenant policy applies). */
  mfa_policy: MfaPolicy | "inherit";
  organization: OrgClientPolicy;
  require_pushed_authorization_requests: boolean;
  client_kind: ClientKind;
  headless_native: boolean;
  /** OIDC `client_uri` ("App home page"); empty = none. */
  client_uri: string;
  /** OIDC `initiate_login_uri` ("Sign-in start URL"); empty = none. */
  initiate_login_uri: string;
}

/** Values every app type shares; the type's defaults (APP_TYPES) are applied on top. */
const BASE_VALUES: Omit<ClientFormValues, keyof AppTypeDefaults> = {
  name: "",
  jwks: "",
  redirect_uris: "",
  token_format: "jwt",
  id_token_signed_response_alg: "RS256",
  can_introspect: false,
  post_logout_redirect_uris: "",
  backchannel_logout_uri: "",
  backchannel_logout_session_required: false,
  allowed_resources: "",
  mfa_policy: "inherit",
  organization: "off",
  require_pushed_authorization_requests: false,
  headless_native: false,
  client_uri: "",
  initiate_login_uri: "",
};

/** The create form's starting values for an app type. */
export function newClientValues(type: AppTypeId): ClientFormValues {
  return { ...BASE_VALUES, ...appType(type).defaults, grant_types: [...appType(type).defaults.grant_types] };
}

export function valuesFromClient(client: ClientView): ClientFormValues {
  return {
    name: client.name,
    client_type: client.client_type,
    application_type: client.application_type,
    auth_method: client.auth_method,
    jwks: client.jwks ? JSON.stringify(client.jwks, null, 2) : "",
    redirect_uris: client.redirect_uris.join("\n"),
    grant_types: [...client.grant_types],
    scopes: client.scopes.join(" "),
    require_pkce: client.require_pkce,
    token_format: client.token_format,
    consent_mode: client.consent_mode,
    id_token_signed_response_alg: client.id_token_signed_response_alg,
    can_introspect: client.can_introspect,
    post_logout_redirect_uris: client.post_logout_redirect_uris.join("\n"),
    backchannel_logout_uri: client.backchannel_logout_uri ?? "",
    backchannel_logout_session_required: client.backchannel_logout_session_required,
    allowed_resources: client.allowed_resources.join("\n"),
    mfa_policy: client.mfa_policy ?? "inherit",
    organization: client.organization,
    require_pushed_authorization_requests: client.require_pushed_authorization_requests,
    client_kind: client.client_kind,
    headless_native: client.headless_native,
    client_uri: client.client_uri ?? "",
    initiate_login_uri: client.initiate_login_uri ?? "",
  };
}

/** Whether users sign in through this client (the authorization code grant). */
function signsInUsers(values: Pick<ClientFormValues, "grant_types">): boolean {
  return values.grant_types.includes("authorization_code");
}

const optionalUri = (value: string) => {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
};

/** The 1.0 PAR, client kind and native headless fields and the home URLs, shared by both bodies. */
function v10Fields(values: ClientFormValues) {
  return {
    require_pushed_authorization_requests: values.require_pushed_authorization_requests,
    client_kind: values.client_kind,
    headless_native: values.headless_native,
    client_uri: optionalUri(values.client_uri),
    initiate_login_uri: optionalUri(values.initiate_login_uri),
  };
}

/** The 0.3 logout, resource and MFA fields, shared by the create and update bodies. */
function logoutAndPolicy(values: ClientFormValues) {
  return {
    post_logout_redirect_uris: lines(values.post_logout_redirect_uris),
    backchannel_logout_uri: optionalUri(values.backchannel_logout_uri),
    backchannel_logout_session_required: values.backchannel_logout_session_required,
    allowed_resources: lines(values.allowed_resources),
    mfa_policy: values.mfa_policy === "inherit" ? null : values.mfa_policy,
    organization: values.organization,
  };
}

/** Thrown by the body builders for input that never reaches the server (e.g. malformed JSON). */
export class LocalFieldError extends Error {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super(message);
  }
}

function parseJwks(values: ClientFormValues): Record<string, never> | null {
  if (values.auth_method !== "private_key_jwt") return null;
  if (values.jwks.trim() === "") return null;
  try {
    const parsed: unknown = JSON.parse(values.jwks);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, never>;
  } catch {
    throw new LocalFieldError("jwks", "The JWK Set must be a JSON object.");
  }
}

export function createBody(values: ClientFormValues): CreateClient {
  const confidential = values.client_type === "confidential";
  // The sign-in fields are hidden for clients without the authorization code grant: whatever was
  // typed there before switching to machine-to-machine is not sent.
  const users = signsInUsers(values);
  return {
    name: values.name.trim(),
    client_type: values.client_type,
    application_type: values.application_type,
    auth_method: confidential ? values.auth_method : "none",
    jwks: parseJwks(values),
    redirect_uris: users ? lines(values.redirect_uris) : [],
    grant_types: values.grant_types,
    scopes: tokens(values.scopes),
    require_pkce: confidential ? values.require_pkce : true,
    token_format: values.token_format,
    consent_mode: values.consent_mode,
    id_token_signed_response_alg: values.id_token_signed_response_alg,
    can_introspect: confidential ? values.can_introspect : false,
    ...logoutAndPolicy(values),
    ...(users ? {} : { post_logout_redirect_uris: [], backchannel_logout_uri: null }),
    ...v10Fields(values),
  };
}

export function updateBody(values: ClientFormValues): UpdateClient {
  const confidential = values.client_type === "confidential";
  const body: UpdateClient = {
    name: values.name.trim(),
    redirect_uris: lines(values.redirect_uris),
    grant_types: values.grant_types,
    scopes: tokens(values.scopes),
    require_pkce: confidential ? values.require_pkce : true,
    token_format: values.token_format,
    consent_mode: values.consent_mode,
    id_token_signed_response_alg: values.id_token_signed_response_alg,
    can_introspect: confidential ? values.can_introspect : false,
    ...logoutAndPolicy(values),
    ...v10Fields(values),
  };
  if (values.auth_method === "private_key_jwt") body.jwks = parseJwks(values);
  return body;
}

const GRANT_OPTIONS: readonly { value: GrantType; label: string }[] = [
  { value: "authorization_code", label: "User sign-in (authorization code)" },
  { value: "refresh_token", label: "Stay signed in (refresh token)" },
  { value: "client_credentials", label: "Service credentials (client credentials)" },
];

/** Human labels of the token endpoint authentication methods; the raw value is shown as a hint. */
export const AUTH_METHOD_LABELS: Record<ClientAuthMethod, string> = {
  client_secret_basic: "Client secret (HTTP Basic)",
  client_secret_post: "Client secret (in the request body)",
  private_key_jwt: "Private key (signed JWT assertion)",
  none: "None (public client, PKCE)",
};

export const CLIENT_TYPE_LABELS: Record<ClientType, string> = {
  confidential: "Confidential",
  public: "Public",
};

const FORM_FIELDS = new Set([
  "name",
  "client_type",
  "application_type",
  "auth_method",
  "jwks",
  "redirect_uris",
  "grant_types",
  "scopes",
  "require_pkce",
  "token_format",
  "consent_mode",
  "id_token_signed_response_alg",
  "can_introspect",
  "post_logout_redirect_uris",
  "backchannel_logout_uri",
  "backchannel_logout_session_required",
  "allowed_resources",
  "mfa_policy",
  "organization",
  "require_pushed_authorization_requests",
  "client_kind",
  "headless_native",
  "client_uri",
  "initiate_login_uri",
]);

/** Fields inside the collapsed "Advanced" section: a server error on one of them opens it. */
const ADVANCED_FIELDS = [
  "application_type",
  "token_format",
  "id_token_signed_response_alg",
  "can_introspect",
  "allowed_resources",
  "backchannel_logout_uri",
  "backchannel_logout_session_required",
  "require_pushed_authorization_requests",
  "client_kind",
  "headless_native",
] as const;

const CLIENT_KIND_HINTS: Record<ClientKind, string> = {
  application: "A regular application acting for a signed-in user.",
  agent:
    "An AI agent or other automated client acting for a user. Agents always see the consent screen: consent cannot be skipped for them.",
};

const MFA_OPTIONS: readonly { value: MfaPolicy | "inherit"; label: string }[] = [
  { value: "inherit", label: "Inherit (tenant policy)" },
  { value: "off", label: "Off" },
  { value: "optional", label: "Optional (users who enrolled a second factor)" },
  { value: "required", label: "Required" },
];

const ORG_POLICY_OPTIONS: readonly { value: OrgClientPolicy; label: string }[] = [
  { value: "off", label: "Off (no organizations)" },
  { value: "optional", label: "Optional" },
  { value: "required", label: "Required" },
];

const ORG_POLICY_HINTS: Record<OrgClientPolicy, string> = {
  off: "Tokens carry no organization claims and the organization authorization parameter is refused.",
  optional:
    "Users who belong to an organization sign in to one (the organization parameter or their own choice) and tokens carry its claims; users without organizations still sign in.",
  required:
    "Every sign-in needs an organization (the organization parameter or a choice among the user's own memberships); users in no organization are denied.",
};

/** The tenant's enabled ID-token signing algorithms (RS256 first). */
function useSigningAlgs(): string[] {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: ["tenant", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}", { params: { path: { slug: tenant } }, signal })),
  });
  return query.data?.settings.signing_algs ?? ["RS256"];
}

interface ClientFormProps {
  mode: "create" | "edit";
  initial: ClientFormValues;
  /** The app type `initial` was built for (create mode). */
  initialAppType?: AppTypeId;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: ClientFormValues) => void;
}

export function ClientForm({ mode, initial, initialAppType = "web", submitLabel, pending, error, onSubmit }: ClientFormProps) {
  const form = useFormState<ClientFormValues>(initial);
  const values = form.values;
  const setValues = form.setValues;
  const blocker = useUnsavedChanges(form.isDirty && !pending);
  const [appTypeId, setAppTypeId] = useState<AppTypeId>(initialAppType);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const advancedId = useId();
  const tenant = useTenant();
  const algs = useSigningAlgs();
  const set = <K extends keyof ClientFormValues>(key: K, value: ClientFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));

  const create = mode === "create";
  const confidential = values.client_type === "confidential";
  const users = signsInUsers(values);
  const errors: FieldErrors = fieldErrors(error);
  if (error instanceof LocalFieldError) errors[error.field] = [{ message: error.message }];
  const otherError =
    error && !(error instanceof LocalFieldError) && !(error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => FORM_FIELDS.has(e.field)))
      ? error
      : null;
  const showAdvanced = advancedOpen || ADVANCED_FIELDS.some((f) => errors[f]);
  // An algorithm the tenant disabled since the client was saved stays selectable so the form shows it.
  const algOptions = (algs.includes(values.id_token_signed_response_alg) ? algs : [...algs, values.id_token_signed_response_alg]).map(
    (a) => ({ value: a, label: a }),
  );
  // A secret inside a browser bundle or an app package can be extracted by anyone (C-H5).
  const shippedApp = (create && (appTypeId === "spa" || appTypeId === "native")) || values.application_type === "native";
  const redirectExample = create
    ? appType(appTypeId).redirectExample || appType("web").redirectExample
    : values.application_type === "native"
      ? appType("native").redirectExample
      : appType("web").redirectExample;

  const chooseType = (id: AppTypeId) => {
    setAppTypeId(id);
    const defaults = appType(id).defaults;
    // What the admin typed (name, URLs) stays; the type's settings replace the rest.
    setValues((v) => ({
      ...v,
      ...defaults,
      grant_types: [...defaults.grant_types],
      jwks: "",
      can_introspect: false,
      headless_native: false,
    }));
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    form.markSubmitted();
    onSubmit(values);
  };

  return (
    <>
      <form onSubmit={submit} aria-label={create ? "New client" : "Edit client"} className="space-y-6" noValidate>
        {error instanceof ApiError && error.status === 422 && (
          <p role="alert" className="text-destructive text-sm">
            The client was not saved. Fix the errors below.
          </p>
        )}
        {otherError ? <ProblemAlert error={otherError} /> : null}

        {create ? <AppTypePicker value={appTypeId} onChange={chooseType} /> : null}

        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-2 text-base font-semibold">Application</legend>
          <TextField
            label="Name"
            name="name"
            required
            value={values.name}
            onChange={(e) => set("name", e.target.value)}
            errors={errors.name}
          />
          {create ? (
            <SelectField
              label="Client type"
              name="client_type"
              value={values.client_type}
              onChange={(e) => {
                const type = e.target.value as ClientType;
                setValues((v) => ({
                  ...v,
                  client_type: type,
                  auth_method: type === "public" ? "none" : v.auth_method === "none" ? "client_secret_basic" : v.auth_method,
                  require_pkce: type === "public" ? true : v.require_pkce,
                  can_introspect: type === "public" ? false : v.can_introspect,
                }));
              }}
              options={[
                { value: "public", label: "Public (no secret: browser or mobile app)" },
                { value: "confidential", label: "Confidential (has a secret: runs on a server)" },
              ]}
              errors={errors.client_type}
            />
          ) : null}
          {create && confidential && shippedApp ? (
            <div className="sm:col-span-2">
              <Alert icon={<TriangleAlert aria-hidden="true" />} data-testid="confidential-warning">
                <AlertTitle>A secret in a shipped app is not secret</AlertTitle>
                <AlertDescription>
                  <p>
                    Anyone can extract a client secret from a browser bundle or an app package. Keep single-page and
                    native apps public: they sign in safely with PKCE and no secret.
                  </p>
                </AlertDescription>
              </Alert>
            </div>
          ) : null}
          {create && confidential ? (
            <SelectField
              label="Token endpoint authentication"
              name="auth_method"
              value={values.auth_method}
              onChange={(e) => set("auth_method", e.target.value as ClientAuthMethod)}
              options={(["client_secret_basic", "client_secret_post", "private_key_jwt"] as const).map((m) => ({
                value: m,
                label: AUTH_METHOD_LABELS[m],
              }))}
              hint={
                <>
                  Protocol value: <code className="font-mono">{values.auth_method}</code>
                </>
              }
              errors={errors.auth_method}
            />
          ) : null}
          {values.auth_method === "private_key_jwt" && (
            <div className="sm:col-span-2">
              <TextareaField
                label="JWK Set"
                name="jwks"
                rows={6}
                hint="The client's public keys as a JSON Web Key Set."
                value={values.jwks}
                onChange={(e) => set("jwks", e.target.value)}
                errors={errors.jwks}
              />
            </div>
          )}
          {users ? (
            <>
              <TextField
                label="App home page"
                name="client_uri"
                type="url"
                optional
                placeholder="https://app.example.com"
                hint="Where users find the app (OIDC client_uri). https, or http on localhost."
                value={values.client_uri}
                onChange={(e) => set("client_uri", e.target.value)}
                errors={errors.client_uri}
              />
              <TextField
                label="Sign-in start URL"
                name="initiate_login_uri"
                type="url"
                optional
                placeholder="https://app.example.com/login"
                hint="Where the app starts a sign-in (OIDC initiate_login_uri). Used for “Back to the app” links."
                value={values.initiate_login_uri}
                onChange={(e) => set("initiate_login_uri", e.target.value)}
                errors={errors.initiate_login_uri}
              />
            </>
          ) : null}
        </fieldset>

        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-2 text-base font-semibold">{users ? "Sign-in" : "Access"}</legend>
          {users ? (
            <>
              <div className="sm:col-span-2">
                <TextareaField
                  label="Redirect URIs"
                  name="redirect_uris"
                  rows={3}
                  placeholder={redirectExample}
                  hint={
                    <>
                      Where users return after signing in. One per line, matched exactly, with the scheme: for example{" "}
                      <code className="font-mono">{redirectExample}</code>. http is only allowed for localhost.
                    </>
                  }
                  value={values.redirect_uris}
                  onChange={(e) => set("redirect_uris", e.target.value)}
                  errors={errors.redirect_uris}
                />
              </div>
              <div className="sm:col-span-2">
                <TextareaField
                  label="Post-logout redirect URIs"
                  name="post_logout_redirect_uris"
                  rows={2}
                  optional
                  hint="Where RP-initiated logout may send the user afterwards. One per line; matched exactly."
                  value={values.post_logout_redirect_uris}
                  onChange={(e) => set("post_logout_redirect_uris", e.target.value)}
                  errors={errors.post_logout_redirect_uris}
                />
              </div>
            </>
          ) : null}
          <div className="sm:col-span-2 space-y-1">
            <CheckboxGroup
              legend="Grant types"
              options={GRANT_OPTIONS}
              value={values.grant_types}
              onChange={(next) => set("grant_types", next)}
              errors={errors.grant_types}
            />
            <p className="text-muted-foreground text-xs">
              Protocol values: <code className="font-mono">{values.grant_types.join(" ") || "none"}</code>
            </p>
          </div>
          <TextField
            label="Scopes"
            name="scopes"
            placeholder={users ? "openid profile email" : "orders:read orders:write"}
            hint={users ? "Separated by spaces." : "The API scopes this service may request, separated by spaces."}
            value={values.scopes}
            onChange={(e) => set("scopes", e.target.value)}
            errors={errors.scopes}
          />
          {users ? (
            <>
              <SelectField
                label="Consent"
                name="consent_mode"
                value={values.consent_mode}
                onChange={(e) => set("consent_mode", e.target.value as ConsentMode)}
                options={[
                  { value: "skip_first_party", label: "Skip (first-party application)" },
                  { value: "required", label: "Ask the user for new scopes" },
                ]}
                hint={values.client_kind === "agent" ? "Agents always ask: the server refuses to skip consent for them." : undefined}
                errors={errors.consent_mode}
              />
              <CheckboxField
                label="Require PKCE"
                name="require_pkce"
                checked={values.require_pkce}
                disabled={!confidential}
                hint={confidential ? undefined : "Always required for public clients."}
                onChange={(e) => set("require_pkce", e.target.checked)}
                errors={errors.require_pkce}
              />
            </>
          ) : null}
        </fieldset>

        {users ? (
          <fieldset className="grid gap-4 sm:grid-cols-2">
            <legend className="mb-2 text-base font-semibold">Sign-in policy</legend>
            <SelectField
              label="Multi-factor authentication"
              name="mfa_policy"
              value={values.mfa_policy}
              onChange={(e) => set("mfa_policy", e.target.value as MfaPolicy | "inherit")}
              options={MFA_OPTIONS}
              hint="The strictest of tenant and client policy applies."
              errors={errors.mfa_policy}
            />
            {tenant === SYSTEM_TENANT ? null : (
              <SelectField
                label="Organizations"
                name="organization"
                value={values.organization}
                onChange={(e) => set("organization", e.target.value as OrgClientPolicy)}
                options={ORG_POLICY_OPTIONS}
                hint={ORG_POLICY_HINTS[values.organization]}
                errors={errors.organization}
                data-testid="client-organization-policy"
              />
            )}
          </fieldset>
        ) : null}

        <div className="space-y-4 border-t pt-4">
          <Button
            type="button"
            variant="ghost"
            aria-expanded={showAdvanced}
            aria-controls={advancedId}
            onClick={() => setAdvancedOpen(!showAdvanced)}
            data-testid="client-advanced-toggle"
          >
            {showAdvanced ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
            Advanced
          </Button>
          {!showAdvanced ? (
            <p className="text-muted-foreground text-xs">
              Token format, signing algorithm, introspection, resource indicators, back-channel logout, pushed
              authorization requests, client kind and the native headless API.
            </p>
          ) : null}
          <div id={advancedId} hidden={!showAdvanced} className="space-y-6">
            {showAdvanced ? (
              <>
                <fieldset className="grid gap-4 sm:grid-cols-2">
                  <legend className="mb-2 text-base font-semibold">Tokens</legend>
                  {create ? (
                    <SelectField
                      label="Application type"
                      name="application_type"
                      value={values.application_type}
                      onChange={(e) => set("application_type", e.target.value as ApplicationType)}
                      options={[
                        { value: "web", label: "Web (https redirect URIs)" },
                        { value: "native", label: "Native (custom scheme or loopback redirect URIs)" },
                      ]}
                      errors={errors.application_type}
                    />
                  ) : null}
                  <SelectField
                    label="Access token format"
                    name="token_format"
                    value={values.token_format}
                    onChange={(e) => set("token_format", e.target.value as TokenFormat)}
                    options={[
                      { value: "jwt", label: "JWT (self-contained)" },
                      { value: "opaque", label: "Opaque (introspection only)" },
                    ]}
                    errors={errors.token_format}
                  />
                  {users ? (
                    <SelectField
                      label="ID token signing algorithm"
                      name="id_token_signed_response_alg"
                      value={values.id_token_signed_response_alg}
                      onChange={(e) => set("id_token_signed_response_alg", e.target.value)}
                      options={algOptions}
                      hint="The algorithms enabled for this tenant."
                      errors={errors.id_token_signed_response_alg}
                    />
                  ) : null}
                  <div className="sm:col-span-2">
                    <CheckboxField
                      label="May introspect any token of the tenant"
                      name="can_introspect"
                      checked={values.can_introspect}
                      disabled={!confidential}
                      hint={confidential ? undefined : "Only confidential clients can introspect."}
                      onChange={(e) => set("can_introspect", e.target.checked)}
                      errors={errors.can_introspect}
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <TextareaField
                      label="Allowed resources"
                      name="allowed_resources"
                      rows={2}
                      optional
                      hint="Resource indicators (RFC 8707) the client may request, one absolute URI per line."
                      value={values.allowed_resources}
                      onChange={(e) => set("allowed_resources", e.target.value)}
                      errors={errors.allowed_resources}
                    />
                  </div>
                </fieldset>

                {users ? (
                  <fieldset className="grid gap-4 sm:grid-cols-2">
                    <legend className="mb-2 text-base font-semibold">Back-channel logout</legend>
                    <div className="sm:col-span-2">
                      <TextField
                        label="Back-channel logout URI"
                        name="backchannel_logout_uri"
                        type="url"
                        optional
                        hint="Receives a logout token when the user's session ends. Empty disables back-channel logout."
                        value={values.backchannel_logout_uri}
                        onChange={(e) => set("backchannel_logout_uri", e.target.value)}
                        errors={errors.backchannel_logout_uri}
                      />
                    </div>
                    <div className="sm:col-span-2">
                      <CheckboxField
                        label="Back-channel logout requires the session id"
                        name="backchannel_logout_session_required"
                        hint="Logout tokens carry the sid claim."
                        checked={values.backchannel_logout_session_required}
                        onChange={(e) => set("backchannel_logout_session_required", e.target.checked)}
                        errors={errors.backchannel_logout_session_required}
                      />
                    </div>
                  </fieldset>
                ) : null}

                <fieldset className="grid gap-4 sm:grid-cols-2" data-testid="client-v10-fields">
                  <legend className="mb-2 text-base font-semibold">Authorization requests and client kind</legend>
                  {users ? (
                    <div className="sm:col-span-2">
                      <CheckboxField
                        label="Require pushed authorization requests"
                        name="require_pushed_authorization_requests"
                        hint="The client must send its authorization requests to the pushed authorization request endpoint first (RFC 9126). The tenant can also require this for every client."
                        checked={values.require_pushed_authorization_requests}
                        onChange={(e) => set("require_pushed_authorization_requests", e.target.checked)}
                        errors={errors.require_pushed_authorization_requests}
                        data-testid="client-require-par"
                      />
                    </div>
                  ) : null}
                  <SelectField
                    label="Client kind"
                    name="client_kind"
                    value={values.client_kind}
                    onChange={(e) => set("client_kind", e.target.value as ClientKind)}
                    options={[
                      { value: "application", label: "Application" },
                      { value: "agent", label: "Agent" },
                    ]}
                    hint={CLIENT_KIND_HINTS[values.client_kind]}
                    errors={errors.client_kind}
                    data-testid="client-kind"
                  />
                  {users ? (
                    <div className="sm:col-span-2">
                      <CheckboxField
                        label="Native headless client"
                        name="headless_native"
                        hint="Lets this client drive the sign-in through the headless flow API without a browser. Only for clients created by an administrator (never dynamically registered or metadata-document clients) that are applications, skip consent (first-party) and require PKCE."
                        checked={values.headless_native}
                        onChange={(e) => set("headless_native", e.target.checked)}
                        errors={errors.headless_native}
                        data-testid="client-headless-native"
                      />
                    </div>
                  ) : null}
                </fieldset>
              </>
            ) : null}
          </div>
        </div>

        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : submitLabel}
        </Button>
      </form>
      <UnsavedChangesGuard blocker={blocker} />
    </>
  );
}
