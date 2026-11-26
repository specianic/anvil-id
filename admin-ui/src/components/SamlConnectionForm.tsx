// SAML 2.0 connection of an organization (experimental through 1.0, behind the operator flag
// `saml_experimental`): import of the IdP metadata (pasted XML or an https URL the server fetches),
// the IdP fields, 1-3 signing certificates (public material, shown with subject and expiry when they
// parse), the NameID format and the attribute mapping. The SP values the IdP needs are shown with
// copy buttons once the connection exists. A SAML connection has no secret.
import { useMutation } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import type { ConnectionView, CreateConnection, UpdateConnection } from "@/components/ConnectionForm";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  CheckboxField,
  type FieldErrors,
  SelectField,
  StatusMessage,
  TextField,
  TextareaField,
  fieldErrors,
} from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";

type NameIdFormat = components["schemas"]["NameIdFormat"];
type SamlSpValuesView = components["schemas"]["SamlSpValues"];
type SamlAttributeMapping = components["schemas"]["SamlAttributeMapping"];

export const MAX_SIGNING_CERTS = 3;

/** NameID formats offered (transient is refused by the API: it cannot identify a returning user). */
const NAME_ID_OPTIONS: readonly { value: NameIdFormat; label: string }[] = [
  { value: "unspecified", label: "Unspecified (IdP default)" },
  { value: "persistent", label: "Persistent" },
  { value: "email_address", label: "Email address" },
];

const ATTRIBUTE_FIELDS: readonly { key: keyof SamlAttributeMapping; label: string }[] = [
  { key: "email", label: "Email attribute" },
  { key: "given_name", label: "Given name attribute" },
  { key: "family_name", label: "Family name attribute" },
  { key: "name", label: "Full name attribute" },
];

/** Explains why SAML cannot be chosen when the operator flag is off. */
export const SAML_DISABLED_NOTE =
  "SAML connections are experimental and turned off on this server. The operator enables them with " +
  "saml_experimental = true (environment ANVILID_SAML_EXPERIMENTAL=true).";

export function ExperimentalBadge() {
  return (
    <Badge variant="outline" data-testid="saml-experimental">
      Experimental
    </Badge>
  );
}

export interface SamlFormValues {
  slug: string;
  display_name: string;
  enabled: boolean;
  idp_entity_id: string;
  sso_url: string;
  certs: string[];
  name_id_format: NameIdFormat;
  attributes: Record<keyof SamlAttributeMapping, string>;
  metadata_url: string | null;
  trust_email_verified: boolean;
}

export function newSamlValues(): SamlFormValues {
  return {
    slug: "",
    display_name: "",
    enabled: true,
    idp_entity_id: "",
    sso_url: "",
    certs: [""],
    name_id_format: "unspecified",
    attributes: { email: "", given_name: "", family_name: "", name: "" },
    metadata_url: null,
    trust_email_verified: false,
  };
}

export function samlValuesFromConnection(c: ConnectionView): SamlFormValues {
  const v = { ...newSamlValues(), slug: c.slug, display_name: c.display_name, enabled: c.enabled };
  v.trust_email_verified = c.trust_email_verified;
  if (c.config.type !== "saml") return v;
  const cfg = c.config;
  v.idp_entity_id = cfg.idp_entity_id;
  v.sso_url = cfg.sso_url;
  v.certs = cfg.signing_certs.length > 0 ? [...cfg.signing_certs] : [""];
  v.name_id_format = cfg.name_id_format ?? "unspecified";
  v.attributes = {
    email: cfg.attributes?.email ?? "",
    given_name: cfg.attributes?.given_name ?? "",
    family_name: cfg.attributes?.family_name ?? "",
    name: cfg.attributes?.name ?? "",
  };
  v.metadata_url = cfg.metadata_url ?? null;
  return v;
}

const orNull = (s: string): string | null => (s.trim() === "" ? null : s.trim());

function samlConfig(v: SamlFormValues): CreateConnection["config"] {
  return {
    type: "saml",
    idp_entity_id: v.idp_entity_id.trim(),
    sso_url: v.sso_url.trim(),
    signing_certs: v.certs.map((c) => c.trim()).filter((c) => c !== ""),
    name_id_format: v.name_id_format,
    attributes: {
      email: orNull(v.attributes.email),
      given_name: orNull(v.attributes.given_name),
      family_name: orNull(v.attributes.family_name),
      name: orNull(v.attributes.name),
    },
    metadata_url: v.metadata_url,
  };
}

export function samlCreateBody(v: SamlFormValues): CreateConnection {
  return {
    slug: v.slug.trim(),
    display_name: v.display_name.trim(),
    enabled: v.enabled,
    config: samlConfig(v),
    secret: null,
    trust_email_verified: v.trust_email_verified,
  };
}

export function samlUpdateBody(v: SamlFormValues): UpdateConnection {
  return {
    display_name: v.display_name.trim(),
    enabled: v.enabled,
    config: samlConfig(v),
    trust_email_verified: v.trust_email_verified,
  };
}

// ---------------------------------------------------------------------------------------------
// Certificate details (best effort, client-side): subject CN and validity of a PEM certificate.
// The server validates the certificate; a parse failure here only hides the details.

interface Tlv {
  tag: number;
  start: number; // first content byte
  end: number; // one past the last content byte
}

function byteAt(der: Uint8Array, i: number): number {
  const b = der[i];
  if (b === undefined) throw new Error("truncated");
  return b;
}

function readTlv(der: Uint8Array, offset: number): Tlv {
  const tag = byteAt(der, offset);
  let len = byteAt(der, offset + 1);
  let pos = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + byteAt(der, pos + i);
    pos += n;
  }
  if (pos + len > der.length) throw new Error("truncated");
  return { tag, start: pos, end: pos + len };
}

function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let pos = parent.start;
  while (pos < parent.end) {
    const t = readTlv(der, pos);
    out.push(t);
    pos = t.end;
  }
  return out;
}

const ascii = (der: Uint8Array, t: Tlv) => new TextDecoder().decode(der.subarray(t.start, t.end));

function parseTime(der: Uint8Array, t: Tlv): Date | null {
  const s = ascii(der, t);
  // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ.
  const m = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) return null;
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
}

const OID_CN = "550403";

function commonName(der: Uint8Array, name: Tlv): string | null {
  for (const rdn of children(der, name)) {
    for (const atv of children(der, rdn)) {
      const [oid, value] = children(der, atv);
      if (!oid || !value) continue;
      const hex = Array.from(der.subarray(oid.start, oid.end), (b) => b.toString(16).padStart(2, "0")).join("");
      if (hex === OID_CN) return ascii(der, value);
    }
  }
  return null;
}

export interface CertificateInfo {
  subject: string | null;
  notAfter: Date | null;
}

/** Subject CN and expiry of one PEM certificate; `null` when it does not parse. */
export function parseCertificate(pem: string): CertificateInfo | null {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem);
  if (!m) return null;
  try {
    const bin = atob((m[1] ?? "").replace(/\s+/g, ""));
    const der = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const cert = readTlv(der, 0);
    const tbs = children(der, cert)[0];
    if (!tbs) return null;
    const fields = children(der, tbs);
    // version [0] is optional; then serial, signature, issuer, validity, subject.
    const i = fields[0]?.tag === 0xa0 ? 1 : 0;
    const validity = fields[i + 3];
    const subject = fields[i + 4];
    if (!validity || !subject) return null;
    const [, notAfter] = children(der, validity);
    return { subject: commonName(der, subject), notAfter: notAfter ? parseTime(der, notAfter) : null };
  } catch {
    return null;
  }
}

function CertificateDetails({ pem }: { pem: string }) {
  if (pem.trim() === "") return null;
  const info = parseCertificate(pem);
  if (!info) {
    return (
      <p className="text-muted-foreground text-xs" data-testid="saml-cert-info">
        The details of this certificate could not be read here; the server checks it when you save.
      </p>
    );
  }
  const expired = info.notAfter !== null && info.notAfter.getTime() < Date.now();
  return (
    <div className="space-y-1 text-xs" data-testid="saml-cert-info">
      <p className="text-muted-foreground">
        {info.subject ? <>Subject CN {info.subject}. </> : null}
        {info.notAfter ? <>Expires {formatDateTime(info.notAfter.toISOString())}.</> : null}
      </p>
      {expired && (
        <p className="text-destructive" data-testid="saml-cert-expired">
          This certificate has expired. It can still be saved (only its public key is used), but check with the IdP
          that it still signs with it.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// SP values

function CopyValue({ label, value, testId }: { label: string; value: string; testId: string }) {
  const [status, setStatus] = useState<string | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setStatus(`${label} copied.`);
    } catch {
      setStatus("Copying failed; select the value and copy it manually.");
    }
  };
  return (
    <div className="space-y-1">
      <dt className="text-sm font-medium">{label}</dt>
      <dd className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <code className="bg-muted rounded px-2 py-1 text-sm break-all" data-testid={testId}>
            {value}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void copy()}
            aria-label={`Copy ${label.toLowerCase()}`}
            data-testid={`copy-${testId}`}
          >
            Copy
          </Button>
        </div>
        <StatusMessage message={status} />
      </dd>
    </div>
  );
}

/** The values to register at the IdP for this connection (read-only). */
export function SamlSpValues({ sp }: { sp: SamlSpValuesView }) {
  return (
    <section aria-labelledby="saml-sp-heading" className="space-y-3" data-testid="saml-sp-values">
      <h3 id="saml-sp-heading" className="text-base font-semibold">
        Values for the identity provider
      </h3>
      <p className="text-muted-foreground text-sm">
        Register AnvilID at the IdP with these values (or give it the metadata URL).
      </p>
      <dl className="space-y-3">
        <CopyValue label="SP entity ID" value={sp.entity_id} testId="saml-sp-entity-id" />
        <CopyValue label="ACS URL" value={sp.acs_url} testId="saml-sp-acs-url" />
        <CopyValue label="SP metadata URL" value={sp.metadata_url} testId="saml-sp-metadata-url" />
      </dl>
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
// Metadata import

function MetadataImport({
  tenant,
  org,
  disabled,
  onImported,
}: {
  tenant: string;
  org: string;
  disabled: boolean;
  onImported: (m: components["schemas"]["SamlMetadataView"]) => void;
}) {
  const [xml, setXml] = useState("");
  const [url, setUrl] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const importMetadata = useMutation({
    mutationFn: async (body: components["schemas"]["SamlMetadataImport"]) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/connections/saml-metadata", {
          params: { path: { slug: tenant, org } },
          body,
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: (m) => {
      onImported(m);
      setStatus("Metadata imported. Check the values below, then save the connection.");
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    const hasXml = xml.trim() !== "";
    const hasUrl = url.trim() !== "";
    if (hasXml === hasUrl) {
      setLocalError("Paste the metadata XML or enter its URL (one of the two).");
      return;
    }
    importMetadata.mutate(hasXml ? { xml } : { url: url.trim() });
  };

  const errors = fieldErrors(importMetadata.error);
  const otherError =
    importMetadata.error &&
    !(
      importMetadata.error instanceof ApiError &&
      importMetadata.error.problem.errors.length > 0 &&
      importMetadata.error.problem.errors.every((e) => e.field === "xml" || e.field === "url")
    )
      ? importMetadata.error
      : null;

  return (
    <form
      onSubmit={submit}
      aria-label="Import IdP metadata"
      className="space-y-4 rounded-md border p-4"
      noValidate
      data-testid="saml-metadata-form"
    >
      <div>
        <h3 className="text-base font-semibold">Import metadata</h3>
        <p className="text-muted-foreground text-sm">
          Fills in the IdP entity ID, sign-in URL and signing certificates. Nothing is saved until you save the
          connection.
        </p>
      </div>
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <TextareaField
        label="Metadata XML"
        name="metadata_xml"
        rows={5}
        optional
        spellCheck={false}
        className="font-mono text-xs"
        value={xml}
        onChange={(e) => setXml(e.target.value)}
        errors={errors.xml}
        disabled={disabled}
        data-testid="saml-metadata-xml"
      />
      <TextField
        label="Metadata URL"
        name="metadata_url"
        type="url"
        optional
        hint="https only; the server fetches it once (private and internal addresses are refused)."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        errors={errors.url}
        disabled={disabled}
        data-testid="saml-metadata-url"
      />
      {localError && (
        <p role="alert" className="text-destructive text-sm">
          {localError}
        </p>
      )}
      <Button
        type="submit"
        variant="outline"
        disabled={disabled || importMetadata.isPending}
        data-testid="saml-import-metadata"
      >
        {importMetadata.isPending ? "Importing…" : "Import"}
      </Button>
      <StatusMessage message={status} />
    </form>
  );
}

// ---------------------------------------------------------------------------------------------
// Form

const FORM_FIELDS = new Set([
  "slug",
  "display_name",
  "enabled",
  "trust_email_verified",
  "config.idp_entity_id",
  "config.sso_url",
  "config.signing_certs",
  "config.name_id_format",
  "config.metadata_url",
  "config.attributes.email",
  "config.attributes.given_name",
  "config.attributes.family_name",
  "config.attributes.name",
]);

interface SamlConnectionFormProps {
  mode: "create" | "edit";
  tenant: string;
  org: string;
  initial: SamlFormValues;
  /** The operator flag (`TenantView.features.saml`); off: only disabling and deletion work. */
  samlEnabled: boolean;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (values: SamlFormValues) => void;
  status?: string | null;
}

export function SamlConnectionForm({
  mode,
  tenant,
  org,
  initial,
  samlEnabled,
  submitLabel,
  pending,
  error,
  onSubmit,
  status,
}: SamlConnectionFormProps) {
  const [values, setValues] = useState<SamlFormValues>(initial);
  const set = <K extends keyof SamlFormValues>(key: K, value: SamlFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));
  const setCert = (i: number, pem: string) =>
    setValues((v) => ({ ...v, certs: v.certs.map((c, j) => (j === i ? pem : c)) }));
  const setAttribute = (key: keyof SamlAttributeMapping, value: string) =>
    setValues((v) => ({ ...v, attributes: { ...v.attributes, [key]: value } }));

  const errors: FieldErrors = fieldErrors(error);
  const otherError =
    error &&
    !(
      error instanceof ApiError &&
      error.problem.errors.length > 0 &&
      error.problem.errors.every((e) => FORM_FIELDS.has(e.field))
    )
      ? error
      : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit(values);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <ExperimentalBadge />
        <p className="text-muted-foreground text-sm">
          SAML support is experimental in this release: test the connection before you rely on it.
        </p>
      </div>
      {!samlEnabled && (
        <p className="text-muted-foreground rounded-md border p-3 text-sm" data-testid="saml-flag-off">
          {SAML_DISABLED_NOTE}
          {mode === "edit" ? " This connection can still be disabled or deleted." : ""}
        </p>
      )}

      <MetadataImport
        tenant={tenant}
        org={org}
        disabled={!samlEnabled}
        onImported={(m) =>
          setValues((v) => ({
            ...v,
            idp_entity_id: m.idp_entity_id,
            sso_url: m.sso_url,
            certs: m.signing_certs.length > 0 ? m.signing_certs.slice(0, MAX_SIGNING_CERTS) : v.certs,
            metadata_url: m.metadata_url ?? null,
          }))
        }
      />

      <form
        onSubmit={submit}
        aria-label={mode === "create" ? "New SAML connection" : "Edit SAML connection"}
        className="space-y-6"
        noValidate
        data-testid="saml-connection-form"
      >
        {error instanceof ApiError && error.status === 422 && (
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
            hint="Shown on the single sign-on button."
            value={values.display_name}
            onChange={(e) => set("display_name", e.target.value)}
            errors={errors.display_name}
            data-testid="saml-display-name"
          />
          <TextField
            label="Slug"
            name="slug"
            required
            disabled={mode === "edit"}
            hint={
              mode === "edit"
                ? "The slug cannot change; it is part of the SP entity ID and ACS URL."
                : "Lowercase letters, digits and '-'. Part of the SP entity ID and ACS URL; cannot change later."
            }
            value={values.slug}
            onChange={(e) => set("slug", e.target.value)}
            errors={errors.slug}
            data-testid="saml-slug"
          />
          <div className="sm:col-span-2">
            <CheckboxField
              label="Enabled"
              name="enabled"
              hint="Domains route only to enabled connections."
              checked={values.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
              errors={errors.enabled}
            />
          </div>
        </fieldset>

        <fieldset className="grid gap-4">
          <legend className="mb-2 text-base font-semibold">Identity provider</legend>
          <TextField
            label="IdP entity ID"
            name="idp_entity_id"
            required
            spellCheck={false}
            value={values.idp_entity_id}
            onChange={(e) => set("idp_entity_id", e.target.value)}
            errors={errors["config.idp_entity_id"]}
            data-testid="saml-idp-entity-id"
          />
          <TextField
            label="Single sign-on URL"
            name="sso_url"
            type="url"
            required
            hint="The IdP endpoint for the HTTP-Redirect binding (https)."
            value={values.sso_url}
            onChange={(e) => set("sso_url", e.target.value)}
            errors={errors["config.sso_url"]}
            data-testid="saml-sso-url"
          />
          {values.metadata_url && (
            <p className="text-muted-foreground text-sm" data-testid="saml-metadata-source">
              Imported from <code className="break-all">{values.metadata_url}</code>.
            </p>
          )}
        </fieldset>

        <fieldset className="space-y-4" data-testid="saml-certs">
          <legend className="mb-2 text-base font-semibold">Signing certificates</legend>
          <p className="text-muted-foreground text-sm">
            1 to {MAX_SIGNING_CERTS} PEM certificates of the IdP. Add the next one before the IdP rolls its key over.
            Certificates are public; only their public keys are used.
          </p>
          {values.certs.map((pem, i) => (
            // Positional list (certificate 1, 2, 3): the index is the identity.
            <div key={i} className="space-y-2">
              <TextareaField
                label={`Signing certificate ${i + 1}`}
                name={`signing_cert_${i + 1}`}
                rows={4}
                spellCheck={false}
                className="font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
                value={pem}
                onChange={(e) => setCert(i, e.target.value)}
                data-testid={`saml-cert-${i + 1}`}
              />
              <CertificateDetails pem={pem} />
              {values.certs.length > 1 && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => set("certs", values.certs.filter((_, j) => j !== i))}
                  aria-label={`Remove signing certificate ${i + 1}`}
                >
                  Remove
                </Button>
              )}
            </div>
          ))}
          {errors["config.signing_certs"] && (
            <ul className="text-destructive space-y-0.5 text-sm" data-field-error>
              {errors["config.signing_certs"].map((e) => (
                <li key={e.message}>{e.message}</li>
              ))}
            </ul>
          )}
          {values.certs.length < MAX_SIGNING_CERTS && (
            <Button type="button" variant="outline" size="sm" onClick={() => set("certs", [...values.certs, ""])}>
              Add certificate
            </Button>
          )}
        </fieldset>

        <fieldset className="grid gap-4 sm:grid-cols-2">
          <legend className="mb-2 text-base font-semibold">Subject and attributes</legend>
          <div className="sm:col-span-2">
            <SelectField
              label="NameID format"
              name="name_id_format"
              hint="Requested from the IdP; the NameID identifies the user. Transient NameIDs are not supported."
              options={NAME_ID_OPTIONS}
              value={values.name_id_format}
              onChange={(e) => set("name_id_format", e.target.value as NameIdFormat)}
              errors={errors["config.name_id_format"]}
              data-testid="saml-name-id-format"
            />
          </div>
          <p className="text-muted-foreground text-sm sm:col-span-2">
            Assertion attributes (matched by Name or FriendlyName) that carry the profile. Empty: not mapped.
          </p>
          {ATTRIBUTE_FIELDS.map((f) => (
            <TextField
              key={f.key}
              label={f.label}
              name={`attribute_${f.key}`}
              optional
              spellCheck={false}
              value={values.attributes[f.key]}
              onChange={(e) => setAttribute(f.key, e.target.value)}
              errors={errors[`config.attributes.${f.key}`]}
              data-testid={`saml-attr-${f.key}`}
            />
          ))}
          <div className="sm:col-span-2">
            <CheckboxField
              label="Trust the IdP's email"
              name="trust_email_verified"
              hint="A trusted email can link to an existing account with the same verified email (if automatic linking is on)."
              checked={values.trust_email_verified}
              onChange={(e) => set("trust_email_verified", e.target.checked)}
              errors={errors.trust_email_verified}
            />
          </div>
        </fieldset>

        <Button type="submit" disabled={pending} data-testid="saml-submit">
          {pending ? "Saving…" : submitLabel}
        </Button>
        {status !== undefined && <StatusMessage message={status} />}
      </form>
    </div>
  );
}
