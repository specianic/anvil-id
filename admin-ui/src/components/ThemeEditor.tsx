// Theme editor for one branding scope (the tenant, one organization or one client): colour tokens with an optional
// dark set, font family, corner radius, custom CSS and the logo. Every change is previewed live
// (ThemePreview); "Publish" makes the previewed draft live and "Reset" deletes the scope's branding.
//
// Console CSP (style-src 'self'): no inline styles. Colour swatches are native <input type="color">
// elements (value attribute only) next to a hex text field; both edit the same token.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type ReactNode, useId, useMemo, useRef, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  type BrandingScope,
  type BrandingView,
  ContrastWarnings,
  type PutBranding,
  ThemePreview,
  type ThemeWarning,
  brandingQueryKey,
  postPublish,
  useBrandingPreview,
} from "@/components/ThemePreview";
import { CheckboxField, type FieldErrors, type FieldMessage, StatusMessage, controlClass, fieldErrors } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

type ThemeColors = components["schemas"]["ThemeColorsDto"];
type ColorKey = keyof ThemeColors;

const COLOR_FIELDS: readonly { key: ColorKey; label: string; hint?: string }[] = [
  { key: "primary", label: "Primary", hint: "Buttons and links." },
  { key: "primary_text", label: "Text on primary", hint: "Button labels." },
  { key: "bg", label: "Background", hint: "Page background." },
  { key: "surface", label: "Surface", hint: "Cards and forms." },
  { key: "text", label: "Text" },
  { key: "muted", label: "Muted text" },
  { key: "border", label: "Border" },
  { key: "focus", label: "Focus ring" },
  { key: "danger", label: "Danger", hint: "Errors." },
];

// The built-in palette of the default theme (themes/default/static/anvil.css), shown for empty fields.
const LIGHT_DEFAULTS: Record<ColorKey, string> = {
  primary: "#2f5bd3",
  primary_text: "#ffffff",
  bg: "#f6f7f9",
  surface: "#ffffff",
  text: "#1c1f24",
  muted: "#5b6270",
  border: "#d6dae1",
  focus: "#1d4ed8",
  danger: "#b42318",
};

const DARK_DEFAULTS: Record<ColorKey, string> = {
  primary: "#6d8ef0",
  primary_text: "#0d1020",
  bg: "#14161a",
  surface: "#1d2026",
  text: "#e7e9ee",
  muted: "#a0a7b4",
  border: "#343944",
  focus: "#a9c0ff",
  danger: "#f97066",
};

const DEFAULT_RADIUS = 6;
const MAX_RADIUS = 32;
const MAX_LOGO_BYTES = 256 * 1024;
const LOGO_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;

const FONT_SUGGESTIONS = [
  'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  '"Helvetica Neue", Arial, sans-serif',
  "Georgia, Cambria, serif",
  '"Iowan Old Style", "Palatino Linotype", Palatino, serif',
  'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace',
];

type ColorValues = Record<ColorKey, string>;

/** The editor's form state: empty strings mean "inherit / default". */
export interface ThemeValues {
  colors: ColorValues;
  darkEnabled: boolean;
  colorsDark: ColorValues;
  fontFamily: string;
  radius: number | null;
  customCss: string;
}

function colorValues(c: ThemeColors | null | undefined): ColorValues {
  const out = {} as ColorValues;
  for (const { key } of COLOR_FIELDS) out[key] = c?.[key] ?? "";
  return out;
}

export function valuesFromView(view: BrandingView): ThemeValues {
  const t = view.tokens;
  return {
    colors: colorValues(t.colors),
    darkEnabled: t.colors_dark != null,
    colorsDark: colorValues(t.colors_dark),
    fontFamily: t.font_family ?? "",
    radius: t.radius_px ?? null,
    customCss: view.custom_css ?? "",
  };
}

function colorsBody(c: ColorValues): ThemeColors {
  const out = {} as ThemeColors;
  for (const { key } of COLOR_FIELDS) {
    const v = c[key].trim();
    out[key] = v === "" ? null : v;
  }
  return out;
}

/** The draft as sent to preview (and, through publish, stored). */
export function draftBody(v: ThemeValues): PutBranding {
  const font = v.fontFamily.trim();
  return {
    tokens: {
      colors: colorsBody(v.colors),
      colors_dark: v.darkEnabled ? colorsBody(v.colorsDark) : null,
      font_family: font === "" ? null : font,
      radius_px: v.radius,
    },
    custom_css: v.customCss.trim() === "" ? null : v.customCss,
  };
}

/** `#rgb`, `#rrggbb` or `#rrggbbaa` as the `#rrggbb` a native colour input accepts; null otherwise. */
function toPickerHex(value: string): string | null {
  const v = value.trim().toLowerCase();
  if (/^#[0-9a-f]{3}$/.test(v)) return `#${v[1]}${v[1]}${v[2]}${v[2]}${v[3]}${v[3]}`;
  if (/^#[0-9a-f]{6}$/.test(v)) return v;
  if (/^#[0-9a-f]{8}$/.test(v)) return v.slice(0, 7);
  return null;
}

function messageText(e: FieldMessage): string {
  return e.line ? `Line ${e.line}: ${e.message}` : e.message;
}

function FieldErrorList({ id, errors }: { id: string; errors?: FieldMessage[] }) {
  if (!errors?.length) return null;
  return (
    <ul id={id} className="text-destructive space-y-0.5 text-sm" data-field-error>
      {errors.map((e) => (
        <li key={messageText(e)}>{messageText(e)}</li>
      ))}
    </ul>
  );
}

function ColorField({
  name,
  label,
  hint,
  value,
  fallback,
  onChange,
  errors,
}: {
  name: string;
  label: string;
  hint?: string;
  value: string;
  fallback: string;
  onChange: (value: string) => void;
  errors?: FieldMessage[];
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hintId, errors?.length ? errorId : null].filter(Boolean).join(" ");
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <input
          type="color"
          aria-label={`${label} colour picker`}
          value={toPickerHex(value) ?? fallback}
          onChange={(e) => onChange(e.target.value)}
          className="border-input h-8 w-10 shrink-0 cursor-pointer rounded-md border bg-transparent p-0.5 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
          data-testid={`color-picker-${name}`}
        />
        <input
          id={id}
          type="text"
          inputMode="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={fallback}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={describedBy}
          aria-invalid={errors?.length ? true : undefined}
          className={cn(controlClass, "font-mono")}
          data-testid={`color-${name}`}
        />
        {value !== "" && (
          <Button type="button" variant="ghost" size="sm" onClick={() => onChange("")} aria-label={`Use the default ${label.toLowerCase()} colour`}>
            Default
          </Button>
        )}
      </div>
      <p id={hintId} className="text-muted-foreground text-xs">
        {hint ? `${hint} ` : ""}
        {value === "" ? `Default ${fallback}.` : "Hex: #rgb, #rrggbb or #rrggbbaa."}
      </p>
      <FieldErrorList id={errorId} errors={errors} />
    </div>
  );
}

function ColorGrid({
  prefix,
  values,
  defaults,
  onChange,
  errors,
}: {
  prefix: "colors" | "colors_dark";
  values: ColorValues;
  defaults: ColorValues;
  onChange: (key: ColorKey, value: string) => void;
  errors: FieldErrors;
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {COLOR_FIELDS.map((f) => (
        <ColorField
          key={f.key}
          name={`${prefix}.${f.key}`}
          label={f.label}
          hint={f.hint}
          value={values[f.key]}
          fallback={defaults[f.key]}
          onChange={(v) => onChange(f.key, v)}
          errors={errors[`${prefix}.${f.key}`]}
        />
      ))}
    </div>
  );
}

function Section({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <Card data-testid={testId}>
      <CardHeader>
        <CardTitle>
          <h2>{title}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">{children}</CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------------------------
// Scope operations other than preview/publish (those live with the preview).

/** The scope's stored branding (GET); also used by the scope pages to load the editor's start. */
export async function getBranding(scope: BrandingScope, signal?: AbortSignal): Promise<BrandingView> {
  if (scope.kind === "tenant") {
    return unwrap(
      await api.GET("/api/admin/v1/tenants/{slug}/branding", { params: { path: { slug: scope.tenant } }, signal }),
    );
  }
  if (scope.kind === "org") {
    return unwrap(
      await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/branding", {
        params: { path: { slug: scope.tenant, org: scope.orgId } },
        signal,
      }),
    );
  }
  return unwrap(
    await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding", {
      params: { path: { slug: scope.tenant, client_id: scope.clientId } },
      signal,
    }),
  );
}

async function deleteBranding(scope: BrandingScope) {
  if (scope.kind === "tenant") {
    await api.DELETE("/api/admin/v1/tenants/{slug}/branding", { params: { path: { slug: scope.tenant } } });
  } else if (scope.kind === "org") {
    await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/branding", {
      params: { path: { slug: scope.tenant, org: scope.orgId } },
    });
  } else {
    await api.DELETE("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding", {
      params: { path: { slug: scope.tenant, client_id: scope.clientId } },
    });
  }
}

async function putLogo(scope: BrandingScope, data: string) {
  if (scope.kind === "tenant") {
    return unwrap(
      await api.PUT("/api/admin/v1/tenants/{slug}/branding/logo", {
        params: { path: { slug: scope.tenant } },
        body: { data },
      }),
    );
  }
  if (scope.kind === "org") {
    return unwrap(
      await api.PUT("/api/admin/v1/tenants/{slug}/organizations/{org}/branding/logo", {
        params: { path: { slug: scope.tenant, org: scope.orgId } },
        body: { data },
      }),
    );
  }
  return unwrap(
    await api.PUT("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/logo", {
      params: { path: { slug: scope.tenant, client_id: scope.clientId } },
      body: { data },
    }),
  );
}

async function deleteLogo(scope: BrandingScope) {
  if (scope.kind === "tenant") {
    return unwrap(
      await api.DELETE("/api/admin/v1/tenants/{slug}/branding/logo", { params: { path: { slug: scope.tenant } } }),
    );
  }
  if (scope.kind === "org") {
    return unwrap(
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/branding/logo", {
        params: { path: { slug: scope.tenant, org: scope.orgId } },
      }),
    );
  }
  return unwrap(
    await api.DELETE("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/logo", {
      params: { path: { slug: scope.tenant, client_id: scope.clientId } },
    }),
  );
}

/** Human wording per scope: what the scope is called and what it falls back to. */
const SCOPE_TEXT: Record<BrandingScope["kind"], { name: string; fallback: string; noLogo: string; inherit: string }> = {
  tenant: {
    name: "tenant",
    fallback: "default theme",
    noLogo: "No logo.",
    inherit: "Empty fields use the default theme.",
  },
  org: {
    name: "organization",
    fallback: "tenant theme",
    noLogo: "No organization logo (the tenant logo is used).",
    inherit: "Empty fields inherit the tenant theme; the organization's custom CSS follows the tenant's.",
  },
  client: {
    name: "client",
    fallback: "tenant theme",
    noLogo: "No client logo (the tenant logo is used).",
    inherit: "Empty fields inherit the tenant theme; the client's custom CSS follows the tenant's.",
  },
};

/** A file read as a data URL: `data` is its standard base64 payload. */
interface PickedLogo {
  name: string;
  dataUrl: string;
  data: string;
}

class LogoFileError extends Error {}

function readLogo(file: File): Promise<PickedLogo> {
  if (!(LOGO_TYPES as readonly string[]).includes(file.type)) {
    return Promise.reject(new LogoFileError("Choose a PNG, JPEG or WebP image (SVG is not accepted)."));
  }
  if (file.size > MAX_LOGO_BYTES) {
    return Promise.reject(new LogoFileError("The logo is larger than 256 KiB."));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new LogoFileError("The file could not be read."));
    reader.onload = () => {
      const dataUrl = typeof reader.result === "string" ? reader.result : "";
      const comma = dataUrl.indexOf(",");
      if (comma < 0) {
        reject(new LogoFileError("The file could not be read."));
        return;
      }
      resolve({ name: file.name, dataUrl, data: dataUrl.slice(comma + 1) });
    };
    reader.readAsDataURL(file);
  });
}

function LogoSection({
  scope,
  view,
  onSaved,
}: {
  scope: BrandingScope;
  view: BrandingView;
  onSaved: (view: BrandingView) => void;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState<PickedLogo | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const inputId = useId();

  const upload = useMutation({
    mutationFn: async (logo: PickedLogo) => putLogo(scope, logo.data),
    onMutate: () => setStatus(null),
    onSuccess: (saved) => {
      setPicked(null);
      if (fileInput.current) fileInput.current.value = "";
      setStatus("Logo saved. It is live on the sign-in pages.");
      onSaved(saved);
    },
  });
  const remove = useMutation({
    mutationFn: async () => deleteLogo(scope),
    onMutate: () => setStatus(null),
    onSuccess: (saved) => {
      setConfirmRemove(false);
      setStatus("Logo removed.");
      onSaved(saved);
    },
  });

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    setLocalError(null);
    setStatus(null);
    upload.reset();
    const file = e.target.files?.[0];
    if (!file) {
      setPicked(null);
      return;
    }
    try {
      setPicked(await readLogo(file));
    } catch (err) {
      setPicked(null);
      setLocalError(err instanceof Error ? err.message : "The file could not be read.");
    }
  };

  const apiErrors = fieldErrors(upload.error);
  const errors: FieldMessage[] = [
    ...(localError ? [{ message: localError }] : []),
    ...(apiErrors.logo ?? []),
    ...(apiErrors.data ?? []),
  ];
  const otherError =
    upload.error && !(upload.error instanceof ApiError && (apiErrors.logo || apiErrors.data)) ? upload.error : null;
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  return (
    <Section title="Logo" testId="theme-logo">
      <div className="flex flex-wrap items-center gap-4">
        {view.logo_url ? (
          <img
            src={view.logo_url}
            alt="Current logo"
            className="bg-muted h-16 max-w-48 rounded-md border object-contain p-1"
            data-testid="logo-current"
          />
        ) : (
          <p className="text-muted-foreground text-sm" data-testid="logo-none">
            {SCOPE_TEXT[scope.kind].noLogo}
          </p>
        )}
        {picked && (
          <img
            src={picked.dataUrl}
            alt={`Selected logo ${picked.name}`}
            className="h-16 max-w-48 rounded-md border border-dashed object-contain p-1"
            data-testid="logo-selected"
          />
        )}
      </div>
      <div className="space-y-1.5">
        <label htmlFor={inputId} className="block text-sm font-medium">
          Logo image
        </label>
        <input
          id={inputId}
          ref={fileInput}
          type="file"
          accept={LOGO_TYPES.join(",")}
          onChange={(e) => void onFile(e)}
          aria-describedby={[hintId, errors.length ? errorId : null].filter(Boolean).join(" ")}
          aria-invalid={errors.length ? true : undefined}
          className="text-sm file:mr-3 file:rounded-md file:border file:bg-transparent file:px-3 file:py-1 file:text-sm"
          data-testid="logo-file"
        />
        <p id={hintId} className="text-muted-foreground text-xs">
          PNG, JPEG or WebP, at most 256 KiB. Logo changes apply immediately (they are not part of the draft).
        </p>
        <FieldErrorList id={errorId} errors={errors.length ? errors : undefined} />
      </div>
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={!picked || upload.isPending}
          onClick={() => picked && upload.mutate(picked)}
          data-testid="logo-upload"
        >
          {upload.isPending ? "Uploading…" : "Upload logo"}
        </Button>
        {view.logo_url && (
          <Button type="button" variant="outline" onClick={() => setConfirmRemove(true)} data-testid="logo-remove">
            Remove logo
          </Button>
        )}
      </div>
      <StatusMessage message={status} />
      <ConfirmDialog
        open={confirmRemove}
        title="Remove the logo?"
        description={<p>The sign-in pages stop showing this logo immediately.</p>}
        confirmLabel="Remove logo"
        onConfirm={() => remove.mutate()}
        onCancel={() => {
          remove.reset();
          setConfirmRemove(false);
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </Section>
  );
}

/** Line and column of a caret offset (1-based), for locating `line N` errors of the custom CSS. */
function caretPosition(text: string, offset: number): { line: number; column: number } {
  const before = text.slice(0, offset);
  const line = before.split("\n").length;
  const column = offset - before.lastIndexOf("\n");
  return { line, column };
}

function CustomCssField({
  value,
  onChange,
  errors,
}: {
  value: string;
  onChange: (value: string) => void;
  errors?: FieldMessage[];
}) {
  const id = useId();
  const [caret, setCaret] = useState({ line: 1, column: 1 });
  const lineCount = value === "" ? 1 : value.split("\n").length;
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        Custom CSS <span className="text-muted-foreground font-normal">(optional)</span>
      </label>
      <textarea
        id={id}
        value={value}
        rows={12}
        spellCheck={false}
        onChange={(e) => {
          onChange(e.target.value);
          setCaret(caretPosition(e.target.value, e.target.selectionStart));
        }}
        onSelect={(e) => setCaret(caretPosition(e.currentTarget.value, e.currentTarget.selectionStart))}
        aria-describedby={[hintId, errors?.length ? errorId : null].filter(Boolean).join(" ")}
        aria-invalid={errors?.length ? true : undefined}
        className={cn(controlClass, "font-mono text-xs")}
        data-testid="custom-css"
      />
      <p id={hintId} className="text-muted-foreground flex flex-wrap justify-between gap-2 text-xs">
        <span>
          Appended after the theme variables. At most 32 KiB; no <code>@import</code>, <code>url(</code> or
          backslashes. Errors name the line.
        </span>
        <span data-testid="custom-css-caret">
          Line {caret.line} of {lineCount}, column {caret.column}
        </span>
      </p>
      <FieldErrorList id={errorId} errors={errors} />
    </div>
  );
}

function warningsFor(warnings: readonly ThemeWarning[], scheme: "light" | "dark"): ThemeWarning[] {
  return warnings.filter((w) => (scheme === "dark" ? w.scheme === "dark" : w.scheme !== "dark"));
}

/** API error fields that have a control in the editor (others are listed above the sections). */
const KNOWN_FIELD = /^(colors(_dark)?(\.[a-z_]+)?|font_family|radius_px|custom_css)$/;

export interface ThemeEditorProps {
  scope: BrandingScope;
  view: BrandingView;
}

/** Editor + live preview for one scope. `view` is the stored branding when the page loaded. */
export function ThemeEditor({ scope, view: initialView }: ThemeEditorProps) {
  const queryClient = useQueryClient();
  const [view, setView] = useState<BrandingView>(initialView);
  const [values, setValues] = useState<ThemeValues>(() => valuesFromView(initialView));
  const [refreshKey, setRefreshKey] = useState(0);
  const [status, setStatus] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const fontListId = useId();
  const radiusId = useId();

  const body = useMemo(() => draftBody(values), [values]);
  const preview = useBrandingPreview(scope, body, refreshKey);
  const errors = fieldErrors(preview.error);
  const unplacedErrors =
    preview.error instanceof ApiError
      ? preview.error.problem.errors.filter((e) => !KNOWN_FIELD.test(e.field))
      : [];

  const stored = (saved: BrandingView) => {
    setView(saved);
    queryClient.setQueryData(brandingQueryKey(scope), saved);
  };

  const setColor = (set: "colors" | "colorsDark", key: ColorKey, value: string) =>
    setValues((v) => ({ ...v, [set]: { ...v[set], [key]: value } }));

  const publish = useMutation({
    mutationFn: async () => postPublish(scope, await preview.freshToken()),
    onMutate: () => setStatus(null),
    onSuccess: (saved) => {
      stored(saved);
      setStatus("Theme published. The sign-in pages use it now.");
      // The published draft is consumed; the next preview starts a new one.
      setRefreshKey((k) => k + 1);
    },
  });

  const reset = useMutation({
    mutationFn: async () => {
      await deleteBranding(scope);
      return queryClient.fetchQuery({
        queryKey: brandingQueryKey(scope),
        queryFn: ({ signal }) => getBranding(scope, signal),
        staleTime: 0,
      });
    },
    onMutate: () => setStatus(null),
    onSuccess: (fresh) => {
      setConfirmReset(false);
      setView(fresh);
      setValues(valuesFromView(fresh));
      setRefreshKey((k) => k + 1);
      setStatus(
        scope.kind === "tenant"
          ? "Branding removed. The sign-in pages use the default theme again."
          : `Branding removed. This ${SCOPE_TEXT[scope.kind].name} uses the tenant theme again.`,
      );
    },
  });

  const lightWarnings = preview.preview ? warningsFor(preview.preview.warnings, "light") : warningsFor(view.warnings, "light");
  const darkWarnings = preview.preview ? warningsFor(preview.preview.warnings, "dark") : warningsFor(view.warnings, "dark");
  const radiusShown = values.radius ?? DEFAULT_RADIUS;
  const inheritNote = SCOPE_TEXT[scope.kind].inherit;

  return (
    <div className="grid gap-6 lg:grid-cols-2" data-testid="theme-editor">
      <div className="space-y-6">
        <div className="space-y-1 text-sm">
          <p data-testid="branding-state">
            {view.customized ? (
              <>Customised; last published {formatDateTime(view.updated_at)}.</>
            ) : scope.kind !== "tenant" ? (
              <>Not customised: this {SCOPE_TEXT[scope.kind].name} uses the tenant theme.</>
            ) : (
              <>Not customised: the default theme is used.</>
            )}
          </p>
          <p className="text-muted-foreground">{inheritNote} Changes are previewed only until you publish them.</p>
        </div>

        {preview.error instanceof ApiError && preview.error.status === 422 && (
          <p role="alert" className="text-destructive text-sm" data-testid="draft-invalid">
            This draft cannot be published yet. Fix the errors below.
          </p>
        )}
        {unplacedErrors.length > 0 && (
          <ul className="text-destructive space-y-0.5 text-sm" data-field-error>
            {unplacedErrors.map((e) => (
              <li key={`${e.field}:${e.message}`}>
                <code>{e.field}</code>: {e.message}
              </li>
            ))}
          </ul>
        )}

        <Section title="Colours" testId="theme-colors">
          <ColorGrid
            prefix="colors"
            values={values.colors}
            defaults={LIGHT_DEFAULTS}
            onChange={(k, v) => setColor("colors", k, v)}
            errors={errors}
          />
          <FieldErrorList id="colors-contrast-error" errors={errors.colors} />
          <ContrastWarnings warnings={lightWarnings} testId="contrast-warnings-light" />
        </Section>

        <Section title="Dark colours" testId="theme-colors-dark">
          <CheckboxField
            label="Use custom dark colours"
            hint="Applied when the visitor's system prefers a dark colour scheme. Off: the built-in dark palette."
            checked={values.darkEnabled}
            onChange={(e) => setValues((v) => ({ ...v, darkEnabled: e.target.checked }))}
            data-testid="dark-enabled"
          />
          {values.darkEnabled && (
            <>
              <ColorGrid
                prefix="colors_dark"
                values={values.colorsDark}
                defaults={DARK_DEFAULTS}
                onChange={(k, v) => setColor("colorsDark", k, v)}
                errors={errors}
              />
              <FieldErrorList id="colors-dark-contrast-error" errors={errors.colors_dark} />
              <ContrastWarnings warnings={darkWarnings} testId="contrast-warnings-dark" />
            </>
          )}
        </Section>

        <Section title="Typography and shape" testId="theme-typography">
          <div className="space-y-1.5">
            <label htmlFor={`${fontListId}-input`} className="block text-sm font-medium">
              Font family <span className="text-muted-foreground font-normal">(optional)</span>
            </label>
            <input
              id={`${fontListId}-input`}
              type="text"
              list={fontListId}
              autoComplete="off"
              spellCheck={false}
              value={values.fontFamily}
              placeholder="Default system font stack"
              onChange={(e) => setValues((v) => ({ ...v, fontFamily: e.target.value }))}
              aria-describedby={`${fontListId}-hint${errors.font_family?.length ? ` ${fontListId}-error` : ""}`}
              aria-invalid={errors.font_family?.length ? true : undefined}
              className={cn(controlClass, "font-mono")}
              data-testid="font-family"
            />
            <datalist id={fontListId}>
              {FONT_SUGGESTIONS.map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
            <p id={`${fontListId}-hint`} className="text-muted-foreground text-xs">
              Installed (system) fonts only; web fonts cannot be loaded. Letters, digits, spaces, commas, hyphens and
              quotes.
            </p>
            <FieldErrorList id={`${fontListId}-error`} errors={errors.font_family} />
          </div>

          <div className="space-y-1.5">
            <label htmlFor={radiusId} className="block text-sm font-medium">
              Corner radius
            </label>
            <div className="flex items-center gap-3">
              <input
                id={radiusId}
                type="range"
                min={0}
                max={MAX_RADIUS}
                step={1}
                value={radiusShown}
                onChange={(e) => setValues((v) => ({ ...v, radius: Number(e.target.value) }))}
                aria-valuetext={`${radiusShown} px${values.radius === null ? " (default)" : ""}`}
                aria-describedby={`${radiusId}-hint${errors.radius_px?.length ? ` ${radiusId}-error` : ""}`}
                aria-invalid={errors.radius_px?.length ? true : undefined}
                className="accent-primary w-full max-w-xs"
                data-testid="radius"
              />
              <output htmlFor={radiusId} className="w-24 text-sm tabular-nums" data-testid="radius-value">
                {radiusShown} px{values.radius === null ? " (default)" : ""}
              </output>
              {values.radius !== null && (
                <Button type="button" variant="ghost" size="sm" onClick={() => setValues((v) => ({ ...v, radius: null }))}>
                  Default
                </Button>
              )}
            </div>
            <p id={`${radiusId}-hint`} className="text-muted-foreground text-xs">
              0 to {MAX_RADIUS} px for buttons, inputs and cards.
            </p>
            <FieldErrorList id={`${radiusId}-error`} errors={errors.radius_px} />
          </div>
        </Section>

        <LogoSection
          scope={scope}
          view={view}
          onSaved={(saved) => {
            stored(saved);
            // The preview shows the scope's live logo: reload it.
            setRefreshKey((k) => k + 1);
          }}
        />

        <Section title="Custom CSS" testId="theme-custom-css">
          <CustomCssField
            value={values.customCss}
            onChange={(customCss) => setValues((v) => ({ ...v, customCss }))}
            errors={errors.custom_css}
          />
        </Section>
      </div>

      <div className="space-y-4 lg:sticky lg:top-4 lg:self-start">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            onClick={() => publish.mutate()}
            disabled={publish.isPending || preview.pending || !preview.current}
            data-testid="publish-theme"
          >
            {publish.isPending ? "Publishing…" : "Publish"}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => setConfirmReset(true)}
            disabled={!view.customized}
            data-testid="reset-theme"
          >
            Reset
          </Button>
        </div>
        {publish.error ? <ProblemAlert error={publish.error} /> : null}
        <StatusMessage message={status} />
        <ThemePreview state={preview} />
      </div>

      <ConfirmDialog
        open={confirmReset}
        title={
          scope.kind === "tenant" ? "Remove the tenant's branding?" : `Remove this ${SCOPE_TEXT[scope.kind].name}'s branding?`
        }
        description={
          <p>
            Colours, fonts, custom CSS and the logo of this {SCOPE_TEXT[scope.kind].name} are deleted and the sign-in
            pages fall back to the {SCOPE_TEXT[scope.kind].fallback} immediately. Unpublished changes are lost.
          </p>
        }
        confirmLabel="Remove branding"
        onConfirm={() => reset.mutate()}
        onCancel={() => {
          reset.reset();
          setConfirmReset(false);
        }}
        pending={reset.isPending}
        error={reset.error}
      />
    </div>
  );
}
