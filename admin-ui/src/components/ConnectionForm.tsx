// Create/edit form for upstream connections (social presets, generic OIDC, generic OAuth2), shared
// by /connections/new and /connections/$connectionId. Secrets are write-only: they are read from
// the password field (or the Apple .p8 file) at submit time and never shown again.
import { type FormEvent, type RefObject, useId, useRef, useState } from "react";
import { ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  CheckboxField,
  type FieldErrors,
  type FieldMessage,
  StatusMessage,
  TextField,
  TextareaField,
  controlClass,
  fieldErrors,
  lines,
  tokens,
} from "@/components/form";
import { Button } from "@/components/ui/button";

export type ConnectionView = components["schemas"]["ConnectionView"];
export type ConnectionKind = components["schemas"]["ConnectionKind"];
type ConnectionConfig = components["schemas"]["ConnectionConfig"];
type EndpointOverrides = components["schemas"]["EndpointOverrides"];
type SocialProvider = components["schemas"]["SocialProvider"];
export type CreateConnection = components["schemas"]["CreateConnection"];
export type UpdateConnection = components["schemas"]["UpdateConnection"];

/** Human names of the connection kinds (Record: the compiler flags new API kinds). */
export const KIND_LABELS: Record<ConnectionKind, string> = {
  google: "Google",
  apple: "Apple",
  microsoft: "Microsoft",
  github: "GitHub",
  oidc: "Generic OpenID Connect",
  oauth2: "Generic OAuth2",
};

export const KIND_DESCRIPTIONS: Record<ConnectionKind, string> = {
  google: "Sign in with Google accounts, optionally limited to Workspace domains.",
  apple: "Sign in with Apple; needs a Services ID, team id, key id and a .p8 key.",
  microsoft: "Microsoft personal and work or school accounts (Entra ID).",
  github: "GitHub.com or GitHub Enterprise Server.",
  oidc: "Any OpenID Connect provider with a discovery document.",
  oauth2: "An OAuth2 provider without ID tokens; the identity comes from a profile endpoint.",
};

export const KINDS = Object.keys(KIND_LABELS) as ConnectionKind[];

/** Scopes the server requests when a social connection has none (shown as the starting value). */
const PRESET_SCOPES: Record<ConnectionKind, string> = {
  google: "openid email profile",
  apple: "name email",
  microsoft: "openid email profile",
  github: "read:user user:email",
  oidc: "openid email profile",
  oauth2: "",
};

/** Whether the provider's verified-email claim is trusted by default (matches the API default). */
const TRUST_DEFAULT: Record<ConnectionKind, boolean> = {
  google: true,
  apple: true,
  github: true,
  microsoft: false,
  oidc: false,
  oauth2: false,
};

const NO_OVERRIDES: EndpointOverrides = {
  issuer: null,
  authorization_endpoint: null,
  token_endpoint: null,
  userinfo_endpoint: null,
  jwks_uri: null,
  api_base_url: null,
};

export interface ConnectionFormValues {
  kind: ConnectionKind;
  slug: string;
  display_name: string;
  enabled: boolean;
  client_id: string;
  scopes: string;
  trust_email_verified: boolean;
  accept_email_trust_risk: boolean;
  // Google
  hosted_domains: string;
  // Microsoft
  microsoft_tenant: string;
  allowed_tenants: string;
  // Apple
  apple_team_id: string;
  apple_key_id: string;
  // Social endpoint overrides (only the GitHub Enterprise ones are editable; the rest is kept).
  endpoints: EndpointOverrides;
  // Generic OIDC
  issuer: string;
  fetch_userinfo: boolean;
  // Generic OAuth2
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  mapping_subject: string;
  mapping_email: string;
  mapping_email_verified: string;
  mapping_name: string;
  // OIDC and OAuth2
  use_pkce: boolean;
}

export function newConnectionValues(kind: ConnectionKind): ConnectionFormValues {
  return {
    kind,
    slug: kind === "oidc" || kind === "oauth2" ? "" : kind,
    display_name: kind === "oidc" || kind === "oauth2" ? "" : KIND_LABELS[kind],
    enabled: true,
    client_id: "",
    scopes: PRESET_SCOPES[kind],
    trust_email_verified: TRUST_DEFAULT[kind],
    accept_email_trust_risk: false,
    hosted_domains: "",
    microsoft_tenant: "",
    allowed_tenants: "",
    apple_team_id: "",
    apple_key_id: "",
    endpoints: NO_OVERRIDES,
    issuer: "",
    fetch_userinfo: false,
    authorization_endpoint: "",
    token_endpoint: "",
    userinfo_endpoint: "",
    mapping_subject: "/id",
    mapping_email: "/email",
    mapping_email_verified: "",
    mapping_name: "/name",
    use_pkce: true,
  };
}

export function valuesFromConnection(c: ConnectionView): ConnectionFormValues {
  const v: ConnectionFormValues = {
    ...newConnectionValues(c.kind),
    slug: c.slug,
    display_name: c.display_name,
    enabled: c.enabled,
    trust_email_verified: c.trust_email_verified,
  };
  const config = c.config;
  v.client_id = config.client_id;
  v.scopes = (config.scopes ?? []).join(" ");
  if (config.type === "social") {
    v.hosted_domains = (config.hosted_domains ?? []).join("\n");
    v.microsoft_tenant = config.microsoft_tenant ?? "";
    v.allowed_tenants = (config.allowed_tenants ?? []).join("\n");
    v.apple_team_id = config.apple?.team_id ?? "";
    v.apple_key_id = config.apple?.key_id ?? "";
    v.endpoints = { ...NO_OVERRIDES, ...config.endpoints };
  } else if (config.type === "oidc") {
    v.issuer = config.issuer;
    v.fetch_userinfo = config.fetch_userinfo ?? false;
    v.use_pkce = config.use_pkce ?? true;
  } else {
    v.authorization_endpoint = config.authorization_endpoint;
    v.token_endpoint = config.token_endpoint;
    v.userinfo_endpoint = config.userinfo_endpoint;
    v.mapping_subject = config.mapping.subject;
    v.mapping_email = config.mapping.email ?? "";
    v.mapping_email_verified = config.mapping.email_verified ?? "";
    v.mapping_name = config.mapping.name ?? "";
    v.use_pkce = config.use_pkce ?? true;
  }
  return v;
}

const orNull = (s: string): string | null => (s.trim() === "" ? null : s.trim());

/** The `config` object of the API for the form values (only the fields of the chosen kind). */
export function configFromValues(v: ConnectionFormValues): ConnectionConfig {
  const client_id = v.client_id.trim();
  const scopes = tokens(v.scopes);
  if (v.kind === "oidc") {
    return { type: "oidc", issuer: v.issuer.trim(), client_id, scopes, use_pkce: v.use_pkce, fetch_userinfo: v.fetch_userinfo };
  }
  if (v.kind === "oauth2") {
    return {
      type: "oauth2",
      authorization_endpoint: v.authorization_endpoint.trim(),
      token_endpoint: v.token_endpoint.trim(),
      userinfo_endpoint: v.userinfo_endpoint.trim(),
      client_id,
      scopes,
      use_pkce: v.use_pkce,
      mapping: {
        subject: v.mapping_subject.trim(),
        email: orNull(v.mapping_email),
        email_verified: orNull(v.mapping_email_verified),
        name: orNull(v.mapping_name),
      },
    };
  }
  const provider: SocialProvider = v.kind;
  return {
    type: "social",
    provider,
    client_id,
    scopes,
    hosted_domains: provider === "google" ? lines(v.hosted_domains) : [],
    microsoft_tenant: provider === "microsoft" ? orNull(v.microsoft_tenant) : null,
    allowed_tenants: provider === "microsoft" ? lines(v.allowed_tenants) : [],
    apple: provider === "apple" ? { team_id: v.apple_team_id.trim(), key_id: v.apple_key_id.trim() } : null,
    endpoints: {
      ...v.endpoints,
      api_base_url: provider === "github" ? orNull(v.endpoints.api_base_url ?? "") : null,
    },
  };
}

export function createBody(v: ConnectionFormValues, secret: string | null): CreateConnection {
  return {
    slug: v.slug.trim(),
    display_name: v.display_name.trim(),
    enabled: v.enabled,
    config: configFromValues(v),
    secret,
    trust_email_verified: v.trust_email_verified,
    accept_email_trust_risk: v.kind === "microsoft" && v.trust_email_verified && v.accept_email_trust_risk,
  };
}

export function updateBody(v: ConnectionFormValues): UpdateConnection {
  return {
    display_name: v.display_name.trim(),
    enabled: v.enabled,
    config: configFromValues(v),
    trust_email_verified: v.trust_email_verified,
    accept_email_trust_risk: v.kind === "microsoft" && v.trust_email_verified && v.accept_email_trust_risk,
  };
}

/** Thrown for input that never reaches the server (an unreadable key file). */
export class LocalFieldError extends Error {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super(message);
  }
}

/** Read a small text file (the Apple .p8 PEM) in the browser. */
function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

/**
 * The secret entered for a connection: the Apple key file's PEM text, or the password field.
 * `null` when nothing was entered.
 */
export async function readSecret(
  kind: ConnectionKind,
  password: string,
  fileInput: RefObject<HTMLInputElement | null>,
): Promise<string | null> {
  if (kind !== "apple") return password === "" ? null : password;
  const file = fileInput.current?.files?.[0];
  if (!file) return null;
  if (file.size > 16 * 1024) throw new LocalFieldError("secret", "The key file is too large for a .p8 key.");
  try {
    return await readFileAsText(file);
  } catch {
    throw new LocalFieldError("secret", "The key file could not be read.");
  }
}

/** Write-only secret input: a password field, or a .p8 file picker for Apple. */
export function SecretInput({
  kind,
  label,
  hint,
  password,
  onPasswordChange,
  fileInput,
  errors,
}: {
  kind: ConnectionKind;
  label: string;
  hint: string;
  password: string;
  onPasswordChange: (value: string) => void;
  fileInput: RefObject<HTMLInputElement | null>;
  errors?: FieldMessage[];
}) {
  if (kind !== "apple") {
    return (
      <TextField
        label={label}
        name="secret"
        type="password"
        autoComplete="new-password"
        optional
        hint={hint}
        value={password}
        onChange={(e) => onPasswordChange(e.target.value)}
        errors={errors}
        data-testid="connection-secret-input"
      />
    );
  }
  return <AppleKeyInput label={label} hint={hint} fileInput={fileInput} errors={errors} />;
}

function AppleKeyInput({
  label,
  hint,
  fileInput,
  errors,
}: {
  label: string;
  hint: string;
  fileInput: RefObject<HTMLInputElement | null>;
  errors?: FieldMessage[];
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = errors?.length ? `${id}-error` : undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label} <span className="text-muted-foreground font-normal">(optional)</span>
      </label>
      <input
        id={id}
        ref={fileInput}
        type="file"
        name="secret"
        accept=".p8,.pem,application/x-pem-file,text/plain"
        className={controlClass}
        aria-describedby={[hintId, errorId].filter(Boolean).join(" ")}
        aria-invalid={errorId ? true : undefined}
        data-testid="connection-secret-file"
      />
      <p id={hintId} className="text-muted-foreground text-sm">
        {hint}
      </p>
      {errorId && (
        <ul id={errorId} className="text-destructive space-y-0.5 text-sm" data-field-error>
          {errors?.map((e) => (
            <li key={e.message}>{e.message}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

const FORM_FIELDS = new Set([
  "slug",
  "display_name",
  "enabled",
  "secret",
  "trust_email_verified",
  "accept_email_trust_risk",
  "config.client_id",
  "config.scopes",
  "config.hosted_domains",
  "config.microsoft_tenant",
  "config.allowed_tenants",
  "config.apple",
  "config.apple.team_id",
  "config.apple.key_id",
  "config.endpoints.api_base_url",
  "config.endpoints.authorization_endpoint",
  "config.endpoints.token_endpoint",
  "config.issuer",
  "config.authorization_endpoint",
  "config.token_endpoint",
  "config.userinfo_endpoint",
  "config.mapping.subject",
  "config.mapping.email",
  "config.mapping.email_verified",
  "config.mapping.name",
]);

interface ConnectionFormProps {
  mode: "create" | "edit";
  initial: ConnectionFormValues;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  /** `secret` is only read in create mode (edit mode rotates it separately). */
  onSubmit: (values: ConnectionFormValues, secret: string | null) => void;
  status?: string | null;
}

export function ConnectionForm({ mode, initial, submitLabel, pending, error, onSubmit, status }: ConnectionFormProps) {
  const [values, setValues] = useState<ConnectionFormValues>(initial);
  const [password, setPassword] = useState("");
  const [localError, setLocalError] = useState<LocalFieldError | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const set = <K extends keyof ConnectionFormValues>(key: K, value: ConnectionFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));
  const setEndpoint = (key: keyof EndpointOverrides, value: string) =>
    setValues((v) => ({ ...v, endpoints: { ...v.endpoints, [key]: value === "" ? null : value } }));

  const { kind } = values;
  const shownError = localError ?? error;
  const errors: FieldErrors = fieldErrors(shownError);
  if (shownError instanceof LocalFieldError) errors[shownError.field] = [{ message: shownError.message }];
  const otherError =
    shownError &&
    !(shownError instanceof LocalFieldError) &&
    !(
      shownError instanceof ApiError &&
      shownError.problem.errors.length > 0 &&
      shownError.problem.errors.every((e) => FORM_FIELDS.has(e.field))
    )
      ? shownError
      : null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    let secret: string | null = null;
    if (mode === "create") {
      try {
        secret = await readSecret(kind, password, fileInput);
      } catch (err) {
        if (err instanceof LocalFieldError) {
          setLocalError(err);
          return;
        }
        throw err;
      }
    }
    onSubmit(values, secret);
  };

  const social = kind !== "oidc" && kind !== "oauth2";

  return (
    <form
      onSubmit={(e) => void submit(e)}
      aria-label={mode === "create" ? `New ${KIND_LABELS[kind]} connection` : "Edit connection"}
      className="space-y-6"
      noValidate
      data-testid="connection-form"
    >
      {shownError instanceof ApiError && shownError.status === 422 && (
        <p role="alert" className="text-destructive text-sm">
          The connection was not saved. Fix the errors below.
        </p>
      )}
      {otherError ? <ProblemAlert error={otherError} /> : null}

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Connection</legend>
        <TextField
          label="Display name"
          name="display_name"
          required
          hint="Shown on the sign-in button."
          value={values.display_name}
          onChange={(e) => set("display_name", e.target.value)}
          errors={errors.display_name}
        />
        <TextField
          label="Slug"
          name="slug"
          required
          disabled={mode === "edit"}
          hint={
            mode === "edit"
              ? "The slug cannot change; it is part of the redirect URI."
              : "Lowercase letters, digits and '-'. Part of the redirect URI; cannot change later."
          }
          value={values.slug}
          onChange={(e) => set("slug", e.target.value)}
          errors={errors.slug}
        />
        <div className="sm:col-span-2">
          <CheckboxField
            label="Enabled"
            name="enabled"
            hint="Disabled connections are hidden from the sign-in page."
            checked={values.enabled}
            onChange={(e) => set("enabled", e.target.checked)}
            errors={errors.enabled}
          />
        </div>
      </fieldset>

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Provider</legend>
        {kind === "oidc" && (
          <div className="sm:col-span-2">
            <TextField
              label="Issuer"
              name="issuer"
              type="url"
              required
              hint="The provider's issuer URL; its discovery document is read at sign-in."
              value={values.issuer}
              onChange={(e) => set("issuer", e.target.value)}
              errors={errors["config.issuer"]}
            />
          </div>
        )}
        {kind === "oauth2" && (
          <>
            <div className="sm:col-span-2">
              <TextField
                label="Authorization endpoint"
                name="authorization_endpoint"
                type="url"
                required
                value={values.authorization_endpoint}
                onChange={(e) => set("authorization_endpoint", e.target.value)}
                errors={errors["config.authorization_endpoint"]}
              />
            </div>
            <TextField
              label="Token endpoint"
              name="token_endpoint"
              type="url"
              required
              value={values.token_endpoint}
              onChange={(e) => set("token_endpoint", e.target.value)}
              errors={errors["config.token_endpoint"]}
            />
            <TextField
              label="Profile (userinfo) endpoint"
              name="userinfo_endpoint"
              type="url"
              required
              value={values.userinfo_endpoint}
              onChange={(e) => set("userinfo_endpoint", e.target.value)}
              errors={errors["config.userinfo_endpoint"]}
            />
          </>
        )}
        <TextField
          label={kind === "apple" ? "Services ID (client ID)" : "Client ID"}
          name="client_id"
          required
          autoComplete="off"
          value={values.client_id}
          onChange={(e) => set("client_id", e.target.value)}
          errors={errors["config.client_id"]}
        />
        <TextField
          label="Scopes"
          name="scopes"
          optional
          hint={
            social
              ? `Separated by spaces. Empty uses the defaults (${PRESET_SCOPES[kind]}).`
              : kind === "oidc"
                ? "Separated by spaces; openid is always requested."
                : "Separated by spaces."
          }
          value={values.scopes}
          onChange={(e) => set("scopes", e.target.value)}
          errors={errors["config.scopes"]}
        />

        {kind === "google" && (
          <div className="sm:col-span-2">
            <TextareaField
              label="Hosted domains"
              name="hosted_domains"
              rows={2}
              optional
              hint="Google Workspace domains allowed to sign in, one per line. Empty allows any Google account."
              value={values.hosted_domains}
              onChange={(e) => set("hosted_domains", e.target.value)}
              errors={errors["config.hosted_domains"]}
            />
          </div>
        )}

        {kind === "microsoft" && (
          <>
            <TextField
              label="Microsoft tenant"
              name="microsoft_tenant"
              optional
              hint="common (default), organizations, consumers or a directory (tenant) id."
              value={values.microsoft_tenant}
              onChange={(e) => set("microsoft_tenant", e.target.value)}
              errors={errors["config.microsoft_tenant"]}
            />
            <TextareaField
              label="Allowed tenant ids"
              name="allowed_tenants"
              rows={2}
              optional
              hint="Directory ids (tid) accepted at sign-in, one per line. Empty accepts any."
              value={values.allowed_tenants}
              onChange={(e) => set("allowed_tenants", e.target.value)}
              errors={errors["config.allowed_tenants"]}
            />
          </>
        )}

        {kind === "apple" && (
          <>
            <TextField
              label="Team ID"
              name="apple_team_id"
              required
              autoComplete="off"
              value={values.apple_team_id}
              onChange={(e) => set("apple_team_id", e.target.value)}
              errors={errors["config.apple.team_id"] ?? errors["config.apple"]}
            />
            <TextField
              label="Key ID"
              name="apple_key_id"
              required
              autoComplete="off"
              value={values.apple_key_id}
              onChange={(e) => set("apple_key_id", e.target.value)}
              errors={errors["config.apple.key_id"]}
            />
          </>
        )}

        {kind === "github" && (
          <>
            <div className="sm:col-span-2">
              <TextField
                label="GitHub Enterprise API base URL"
                name="api_base_url"
                type="url"
                optional
                hint="Only for GitHub Enterprise Server, e.g. https://github.example.com/api/v3. Empty uses github.com."
                value={values.endpoints.api_base_url ?? ""}
                onChange={(e) => setEndpoint("api_base_url", e.target.value)}
                errors={errors["config.endpoints.api_base_url"]}
              />
            </div>
            <TextField
              label="Enterprise authorization endpoint"
              name="enterprise_authorization_endpoint"
              type="url"
              optional
              value={values.endpoints.authorization_endpoint ?? ""}
              onChange={(e) => setEndpoint("authorization_endpoint", e.target.value)}
              errors={errors["config.endpoints.authorization_endpoint"]}
            />
            <TextField
              label="Enterprise token endpoint"
              name="enterprise_token_endpoint"
              type="url"
              optional
              value={values.endpoints.token_endpoint ?? ""}
              onChange={(e) => setEndpoint("token_endpoint", e.target.value)}
              errors={errors["config.endpoints.token_endpoint"]}
            />
          </>
        )}

        {(kind === "oidc" || kind === "oauth2") && (
          <CheckboxField
            label="Use PKCE"
            name="use_pkce"
            hint="Turn off only for providers that reject code_challenge."
            checked={values.use_pkce}
            onChange={(e) => set("use_pkce", e.target.checked)}
          />
        )}
        {kind === "oidc" && (
          <CheckboxField
            label="Fetch UserInfo"
            name="fetch_userinfo"
            hint="Also call the UserInfo endpoint after the ID token was validated."
            checked={values.fetch_userinfo}
            onChange={(e) => set("fetch_userinfo", e.target.checked)}
          />
        )}
      </fieldset>

      {kind === "oauth2" && (
        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-2 text-base font-semibold">Claim mapping</legend>
          <p className="text-muted-foreground text-sm sm:col-span-2">
            JSON pointers into the profile response, for example <code>/id</code> or <code>/data/email</code>.
          </p>
          <TextField
            label="Subject"
            name="mapping_subject"
            required
            value={values.mapping_subject}
            onChange={(e) => set("mapping_subject", e.target.value)}
            errors={errors["config.mapping.subject"]}
          />
          <TextField
            label="Email"
            name="mapping_email"
            optional
            value={values.mapping_email}
            onChange={(e) => set("mapping_email", e.target.value)}
            errors={errors["config.mapping.email"]}
          />
          <TextField
            label="Email verified"
            name="mapping_email_verified"
            optional
            value={values.mapping_email_verified}
            onChange={(e) => set("mapping_email_verified", e.target.value)}
            errors={errors["config.mapping.email_verified"]}
          />
          <TextField
            label="Name"
            name="mapping_name"
            optional
            value={values.mapping_name}
            onChange={(e) => set("mapping_name", e.target.value)}
            errors={errors["config.mapping.name"]}
          />
        </fieldset>
      )}

      <fieldset className="grid gap-4 sm:grid-cols-2">
        <legend className="mb-2 text-base font-semibold">Email trust</legend>
        <div className="sm:col-span-2 space-y-3">
          <CheckboxField
            label="Trust the provider's verified email"
            name="trust_email_verified"
            hint="A trusted, verified email can link to an existing account with the same verified email (if automatic linking is on)."
            checked={values.trust_email_verified}
            onChange={(e) => set("trust_email_verified", e.target.checked)}
            errors={errors.trust_email_verified}
          />
          {kind === "microsoft" && (
            <p className="text-muted-foreground text-sm" data-testid="microsoft-email-note">
              Microsoft can return email addresses that nobody verified, so they are untrusted by default. Trusting them
              lets anyone who controls a Microsoft directory claim an address and take over the matching account.
            </p>
          )}
          {kind === "microsoft" && values.trust_email_verified && (
            <CheckboxField
              label="I accept the risk of trusting Microsoft email addresses"
              name="accept_email_trust_risk"
              checked={values.accept_email_trust_risk}
              onChange={(e) => set("accept_email_trust_risk", e.target.checked)}
              errors={errors.accept_email_trust_risk}
            />
          )}
        </div>
      </fieldset>

      {mode === "create" && (
        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-2 text-base font-semibold">{kind === "apple" ? "Private key" : "Client secret"}</legend>
          <SecretInput
            kind={kind}
            label={kind === "apple" ? "Key file (.p8)" : "Client secret"}
            hint={
              kind === "apple"
                ? "The .p8 key downloaded from Apple. It is stored encrypted and never shown again."
                : "Stored encrypted; it is never shown again."
            }
            password={password}
            onPasswordChange={setPassword}
            fileInput={fileInput}
            errors={errors.secret}
          />
        </fieldset>
      )}

      <Button type="submit" disabled={pending} data-testid="connection-submit">
        {pending ? "Saving…" : submitLabel}
      </Button>
      {status !== undefined && <StatusMessage message={status} />}
    </form>
  );
}
