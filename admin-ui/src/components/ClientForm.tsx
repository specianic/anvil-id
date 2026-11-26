// Create/edit form for OAuth clients, shared by /clients/new and /clients/$clientId.
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
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
import { Button } from "@/components/ui/button";

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
}

export const NEW_CLIENT: ClientFormValues = {
  name: "",
  client_type: "confidential",
  application_type: "web",
  auth_method: "client_secret_basic",
  jwks: "",
  redirect_uris: "",
  grant_types: ["authorization_code", "refresh_token"],
  scopes: "openid profile email",
  require_pkce: true,
  token_format: "jwt",
  consent_mode: "required",
  id_token_signed_response_alg: "RS256",
  can_introspect: false,
  post_logout_redirect_uris: "",
  backchannel_logout_uri: "",
  backchannel_logout_session_required: false,
  allowed_resources: "",
  mfa_policy: "inherit",
  organization: "off",
  require_pushed_authorization_requests: false,
  client_kind: "application",
  headless_native: false,
};

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
  };
}

/** The 1.0 PAR, client kind and native headless fields, shared by the create and update bodies. */
function v10Fields(values: ClientFormValues) {
  return {
    require_pushed_authorization_requests: values.require_pushed_authorization_requests,
    client_kind: values.client_kind,
    headless_native: values.headless_native,
  };
}

/** The 0.3 logout, resource and MFA fields, shared by the create and update bodies. */
function logoutAndPolicy(values: ClientFormValues) {
  const backchannel = values.backchannel_logout_uri.trim();
  return {
    post_logout_redirect_uris: lines(values.post_logout_redirect_uris),
    backchannel_logout_uri: backchannel === "" ? null : backchannel,
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
  return {
    name: values.name.trim(),
    client_type: values.client_type,
    application_type: values.application_type,
    auth_method: confidential ? values.auth_method : "none",
    jwks: parseJwks(values),
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
  { value: "authorization_code", label: "Authorization code" },
  { value: "refresh_token", label: "Refresh token" },
  { value: "client_credentials", label: "Client credentials" },
];

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
]);

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
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: ClientFormValues) => void;
}

export function ClientForm({ mode, initial, submitLabel, pending, error, onSubmit }: ClientFormProps) {
  const [values, setValues] = useState<ClientFormValues>(initial);
  const tenant = useTenant();
  const algs = useSigningAlgs();
  const set = <K extends keyof ClientFormValues>(key: K, value: ClientFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));

  const confidential = values.client_type === "confidential";
  const errors: FieldErrors = fieldErrors(error);
  if (error instanceof LocalFieldError) errors[error.field] = [{ message: error.message }];
  const otherError =
    error && !(error instanceof LocalFieldError) && !(error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => FORM_FIELDS.has(e.field)))
      ? error
      : null;
  // An algorithm the tenant disabled since the client was saved stays selectable so the form shows it.
  const algOptions = (algs.includes(values.id_token_signed_response_alg) ? algs : [...algs, values.id_token_signed_response_alg]).map(
    (a) => ({ value: a, label: a }),
  );

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit(values);
  };

  return (
    <form onSubmit={submit} aria-label={mode === "create" ? "New client" : "Edit client"} className="space-y-6" noValidate>
      {error instanceof ApiError && error.status === 422 && (
        <p role="alert" className="text-destructive text-sm">
          The client was not saved. Fix the errors below.
        </p>
      )}
      {otherError ? <ProblemAlert error={otherError} /> : null}

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
        {mode === "create" ? (
          <>
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
                { value: "confidential", label: "Confidential (server-side, has a secret)" },
                { value: "public", label: "Public (browser or native app, no secret)" },
              ]}
              errors={errors.client_type}
            />
            <SelectField
              label="Application type"
              name="application_type"
              value={values.application_type}
              onChange={(e) => set("application_type", e.target.value as ApplicationType)}
              options={[
                { value: "web", label: "Web" },
                { value: "native", label: "Native" },
              ]}
              errors={errors.application_type}
            />
            <SelectField
              label="Token endpoint authentication"
              name="auth_method"
              value={values.auth_method}
              disabled={!confidential}
              onChange={(e) => set("auth_method", e.target.value as ClientAuthMethod)}
              options={
                confidential
                  ? [
                      { value: "client_secret_basic", label: "client_secret_basic" },
                      { value: "client_secret_post", label: "client_secret_post" },
                      { value: "private_key_jwt", label: "private_key_jwt" },
                    ]
                  : [{ value: "none", label: "none (public client)" }]
              }
              errors={errors.auth_method}
            />
          </>
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
      </fieldset>

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Authorization</legend>
        <div className="sm:col-span-2">
          <TextareaField
            label="Redirect URIs"
            name="redirect_uris"
            rows={3}
            hint="One per line; matched exactly."
            value={values.redirect_uris}
            onChange={(e) => set("redirect_uris", e.target.value)}
            errors={errors.redirect_uris}
          />
        </div>
        <div className="sm:col-span-2">
          <CheckboxGroup
            legend="Grant types"
            options={GRANT_OPTIONS}
            value={values.grant_types}
            onChange={(next) => set("grant_types", next)}
            errors={errors.grant_types}
          />
        </div>
        <TextField
          label="Scopes"
          name="scopes"
          hint="Separated by spaces."
          value={values.scopes}
          onChange={(e) => set("scopes", e.target.value)}
          errors={errors.scopes}
        />
        <SelectField
          label="Consent"
          name="consent_mode"
          value={values.consent_mode}
          onChange={(e) => set("consent_mode", e.target.value as ConsentMode)}
          options={[
            { value: "required", label: "Ask the user for new scopes" },
            { value: "skip_first_party", label: "Skip (first-party application)" },
          ]}
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
      </fieldset>

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Tokens</legend>
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
        <SelectField
          label="ID token signing algorithm"
          name="id_token_signed_response_alg"
          value={values.id_token_signed_response_alg}
          onChange={(e) => set("id_token_signed_response_alg", e.target.value)}
          options={algOptions}
          hint="The algorithms enabled for this tenant."
          errors={errors.id_token_signed_response_alg}
        />
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
      </fieldset>

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Logout</legend>
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

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Resources and sign-in policy</legend>
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

      <fieldset className="grid gap-4 sm:grid-cols-2" data-testid="client-v10-fields">
        <legend className="mb-2 text-base font-semibold">Authorization requests and client kind</legend>
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
      </fieldset>

      <Button type="submit" disabled={pending}>
        {pending ? "Saving…" : submitLabel}
      </Button>
    </form>
  );
}
