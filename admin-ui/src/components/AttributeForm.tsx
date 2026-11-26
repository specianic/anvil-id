// Custom attribute definitions (AUTH-14): a JSON Schema editor with live parse feedback and the
// input shape the schema maps to, plus the per-user value editor of the user page. The simple
// shapes mirror the account page's (05-19): string enum -> select, string (email/uri/date formats)
// -> text input, boolean, integer/number. Anything else is edited as JSON. The API validates.
import { type FormEvent, useMemo, useState } from "react";
import { ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  CheckboxField,
  CheckboxGroup,
  type FieldErrors,
  type FieldMessage,
  SelectField,
  TextField,
  TextareaField,
  fieldErrors,
} from "@/components/form";
import { Button } from "@/components/ui/button";

export type AttributeDefinition = components["schemas"]["AttributeDefinitionDto"];
type TokenTarget = components["schemas"]["TokenTarget"];

/** `^[a-z][a-z0-9_]{0,63}$`; protocol and standard claim names are refused by the API. */
export const ATTRIBUTE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

export const TOKEN_TARGETS: readonly { value: TokenTarget; label: string }[] = [
  { value: "access_token", label: "Access token" },
  { value: "id_token", label: "ID token" },
  { value: "userinfo", label: "UserInfo" },
];

/** The generated API types model free-form JSON as `Record<string, never>`; values cross that boundary here. */
export function toApiJson(value: unknown): Record<string, never> {
  return value as Record<string, never>;
}

// ---------------------------------------------------------------------------------------------
// Shapes

export type AttributeShape =
  | { kind: "enum"; options: string[] }
  | { kind: "string"; input: "text" | "email" | "url" | "date"; minLength?: number; maxLength?: number }
  | { kind: "boolean" }
  | { kind: "number"; integer: boolean; min?: number; max?: number };

const ANNOTATIONS = ["title", "description", "$comment", "$schema", "examples", "default"];
const STRING_KEYS = ["type", "minLength", "maxLength", "pattern", "format", ...ANNOTATIONS];
const NUMBER_KEYS = ["type", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", ...ANNOTATIONS];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function onlyKeys(schema: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(schema).every((k) => allowed.includes(k));
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** The simple input a schema maps to, or null when it needs the JSON editor. */
export function attributeShape(schema: unknown): AttributeShape | null {
  if (!isObject(schema)) return null;
  const type = schema.type;
  if (type === "string" && Array.isArray(schema.enum)) {
    const options = schema.enum;
    if (options.length > 0 && options.every((o) => typeof o === "string") && onlyKeys(schema, ["type", "enum", ...ANNOTATIONS]))
      return { kind: "enum", options: options as string[] };
    return null;
  }
  if (type === "string") {
    if (!onlyKeys(schema, STRING_KEYS)) return null;
    const format = schema.format;
    const input =
      format === undefined ? "text" : format === "email" ? "email" : format === "uri" ? "url" : format === "date" ? "date" : null;
    if (!input) return null;
    return { kind: "string", input, minLength: num(schema.minLength), maxLength: num(schema.maxLength) };
  }
  if (type === "boolean") return onlyKeys(schema, ["type", ...ANNOTATIONS]) ? { kind: "boolean" } : null;
  if (type === "integer" || type === "number") {
    if (!onlyKeys(schema, NUMBER_KEYS)) return null;
    return { kind: "number", integer: type === "integer", min: num(schema.minimum), max: num(schema.maximum) };
  }
  return null;
}

export function shapeLabel(shape: AttributeShape | null): string {
  if (!shape) return "JSON value (edited as JSON)";
  switch (shape.kind) {
    case "enum":
      return `Choice of ${shape.options.length}`;
    case "string":
      return shape.input === "text" ? "Text" : `Text (${shape.input})`;
    case "boolean":
      return "Yes / no";
    case "number":
      return shape.integer ? "Integer" : "Number";
  }
}

// ---------------------------------------------------------------------------------------------
// Definition form

export interface AttributeFormValues {
  name: string;
  schema: string;
  required: boolean;
  user_editable: boolean;
  position: string;
  claimEnabled: boolean;
  claim: string;
  claimTokens: TokenTarget[];
  claimScope: string;
}

export const NEW_ATTRIBUTE: AttributeFormValues = {
  name: "",
  schema: '{\n  "type": "string",\n  "maxLength": 100\n}',
  required: false,
  user_editable: false,
  position: "0",
  claimEnabled: false,
  claim: "",
  claimTokens: ["id_token", "userinfo"],
  claimScope: "profile",
};

export function valuesFromDefinition(d: AttributeDefinition): AttributeFormValues {
  return {
    name: d.name,
    schema: JSON.stringify(d.schema, null, 2),
    required: d.required,
    user_editable: d.user_editable,
    position: String(d.position),
    claimEnabled: Boolean(d.claim),
    claim: d.claim?.claim ?? d.name,
    claimTokens: d.claim?.tokens ?? ["id_token", "userinfo"],
    claimScope: d.claim?.scope ?? "",
  };
}

export type AttributeBody = components["schemas"]["PutAttributeDefinition"];

/** Parse the schema text: the value, or the parse error to show. */
function parseSchema(text: string): { value?: unknown; error?: string } {
  try {
    const value: unknown = JSON.parse(text);
    if (!isObject(value) && typeof value !== "boolean") return { error: "A JSON Schema is an object." };
    return { value };
  } catch (e) {
    return { error: `Not valid JSON: ${e instanceof Error ? e.message : "parse error"}` };
  }
}

interface AttributeFormProps {
  mode: "create" | "edit";
  initial: AttributeFormValues;
  submitLabel: string;
  pending: boolean;
  error: unknown;
  onSubmit: (name: string, body: AttributeBody) => void;
}

export function AttributeForm({ mode, initial, submitLabel, pending, error, onSubmit }: AttributeFormProps) {
  const [values, setValues] = useState<AttributeFormValues>(initial);
  const [local, setLocal] = useState<FieldErrors>({});
  const set = <K extends keyof AttributeFormValues>(key: K, value: AttributeFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));
  const parsed = useMemo(() => parseSchema(values.schema), [values.schema]);
  const shape = parsed.value === undefined ? undefined : attributeShape(parsed.value);

  const server = fieldErrors(error);
  const errorsFor = (field: string): FieldMessage[] | undefined => {
    const own = [...(local[field] ?? []), ...(server[field] ?? [])];
    for (const [k, v] of Object.entries(server)) if (k.startsWith(`${field}.`)) own.push(...v);
    return own.length ? own : undefined;
  };
  const known = (f: string) => ["name", "schema", "claim", "position", "required", "user_editable"].some((k) => f === k || f.startsWith(`${k}.`));
  const otherError =
    error && !(error instanceof ApiError && error.problem.errors.length > 0 && error.problem.errors.every((e) => known(e.field)))
      ? error
      : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const issues: FieldErrors = {};
    if (mode === "create" && !ATTRIBUTE_NAME_PATTERN.test(values.name))
      issues.name = [{ message: "Start with a-z; then up to 63 of a-z, 0-9 and '_'." }];
    if (parsed.error) issues.schema = [{ message: parsed.error }];
    const position = Number(values.position || "0");
    if (!Number.isInteger(position)) issues.position = [{ message: "Enter a whole number." }];
    if (values.claimEnabled) {
      if (!values.claim.trim()) issues.claim = [{ message: "Enter the claim name." }];
      if (values.claimTokens.length === 0) issues.claim = [{ message: "Choose at least one token." }];
    }
    setLocal(issues);
    if (Object.keys(issues).length > 0) return;
    onSubmit(values.name, {
      schema: toApiJson(parsed.value),
      required: values.required,
      user_editable: values.user_editable,
      position,
      claim: values.claimEnabled
        ? { claim: values.claim.trim(), tokens: values.claimTokens, scope: values.claimScope.trim() || null }
        : null,
    });
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate aria-label="Attribute definition" data-testid="attribute-form">
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <TextField
        label="Name"
        name="name"
        value={values.name}
        disabled={mode === "edit"}
        onChange={(e) => set("name", e.target.value)}
        hint="The key of the value (and the default claim name). Standard claims such as email or name are refused."
        errors={errorsFor("name")}
        autoComplete="off"
        data-testid="attribute-name"
      />
      <TextareaField
        label="JSON Schema"
        name="schema"
        rows={8}
        value={values.schema}
        onChange={(e) => set("schema", e.target.value)}
        hint="Draft 2020-12, at most 16 KiB; only local #/$defs references. The server checks it when you save."
        errors={errorsFor("schema")}
        spellCheck={false}
        data-testid="attribute-schema"
      />
      <p className="text-sm" role="status" data-testid="attribute-schema-feedback">
        {parsed.error ? (
          <span className="text-destructive">{parsed.error}</span>
        ) : (
          <span className="text-muted-foreground">
            Parsed. Input on the user page: <strong>{shapeLabel(shape ?? null)}</strong>
          </span>
        )}
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <CheckboxField
          label="Required"
          name="required"
          checked={values.required}
          onChange={(e) => set("required", e.target.checked)}
          hint="Every write of a user's values must include it."
          errors={errorsFor("required")}
        />
        <CheckboxField
          label="Editable by the user"
          name="user_editable"
          checked={values.user_editable}
          onChange={(e) => set("user_editable", e.target.checked)}
          hint="Shown on the account page (simple shapes only)."
          errors={errorsFor("user_editable")}
        />
      </div>
      <TextField
        label="Position"
        name="position"
        type="number"
        step={1}
        value={values.position}
        onChange={(e) => set("position", e.target.value)}
        hint="Display order (ascending)."
        errors={errorsFor("position")}
        className="max-w-32"
      />
      <fieldset className="space-y-3 rounded-md border p-4">
        <legend className="px-1 text-sm font-medium">Token claim</legend>
        <CheckboxField
          label="Include the value in tokens"
          checked={values.claimEnabled}
          onChange={(e) => set("claimEnabled", e.target.checked)}
          hint="Only values that pass the current schema are included."
        />
        {values.claimEnabled && (
          <>
            <TextField
              label="Claim name"
              value={values.claim}
              onChange={(e) => set("claim", e.target.value)}
              errors={errorsFor("claim")}
              autoComplete="off"
            />
            <CheckboxGroup
              legend="Tokens"
              options={TOKEN_TARGETS}
              value={values.claimTokens}
              onChange={(next) => set("claimTokens", next)}
            />
            <TextField
              label="Required scope"
              optional
              value={values.claimScope}
              onChange={(e) => set("claimScope", e.target.value)}
              hint="A single scope the client must be granted; empty = always."
              autoComplete="off"
            />
          </>
        )}
      </fieldset>
      <Button type="submit" disabled={pending} data-testid="attribute-submit">
        {pending ? "Saving…" : submitLabel}
      </Button>
    </form>
  );
}

// ---------------------------------------------------------------------------------------------
// User values

/** The text an input shows for a stored value. */
export function valueToText(shape: AttributeShape | null, value: unknown): string {
  if (value === undefined || value === null) return "";
  if (!shape) return JSON.stringify(value, null, 2);
  if (shape.kind === "boolean") return value === true ? "true" : value === false ? "false" : "";
  if (shape.kind === "number") return typeof value === "number" ? String(value) : JSON.stringify(value);
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** The JSON value of an input (undefined = not set), or an error message. */
export function textToValue(shape: AttributeShape | null, text: string): { value?: unknown; error?: string } {
  if (text.trim() === "") return {};
  if (!shape) {
    try {
      return { value: JSON.parse(text) as unknown };
    } catch {
      return { error: "Not valid JSON." };
    }
  }
  switch (shape.kind) {
    case "boolean":
      return { value: text === "true" };
    case "number": {
      const n = Number(text);
      if (!Number.isFinite(n)) return { error: "Enter a number." };
      if (shape.integer && !Number.isInteger(n)) return { error: "Enter a whole number." };
      return { value: n };
    }
    default:
      return { value: text };
  }
}

/** First segment of a JSON pointer (`/tags/0` -> `tags`), unescaped (RFC 6901). */
export function pointerAttribute(pointer: string): string {
  const first = pointer.replace(/^\//, "").split("/")[0] ?? "";
  return first.replace(/~1/g, "/").replace(/~0/g, "~");
}

export function AttributeValueInput({
  definition,
  text,
  onChange,
  errors,
}: {
  definition: AttributeDefinition;
  text: string;
  onChange: (text: string) => void;
  errors?: FieldMessage[];
}) {
  const shape = attributeShape(definition.schema);
  const schema = definition.schema as unknown as Record<string, unknown>;
  const label = typeof schema.title === "string" && schema.title ? `${schema.title} (${definition.name})` : definition.name;
  const hint = [
    typeof schema.description === "string" ? schema.description : null,
    definition.required ? "Required." : null,
    definition.user_editable ? "The user can edit it." : null,
  ]
    .filter(Boolean)
    .join(" ");
  const id = `user-attr-${definition.name}`;
  const common = { id, label, hint: hint || undefined, errors, "data-testid": id };

  if (!shape) {
    return (
      <TextareaField
        {...common}
        rows={4}
        value={text}
        onChange={(e) => onChange(e.target.value)}
        optional={!definition.required}
        spellCheck={false}
      />
    );
  }
  switch (shape.kind) {
    case "enum":
      return (
        <SelectField
          {...common}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          options={[{ value: "", label: "Not set" }, ...shape.options.map((o) => ({ value: o, label: o }))]}
        />
      );
    case "boolean":
      return (
        <SelectField
          {...common}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          options={[
            { value: "", label: "Not set" },
            { value: "true", label: "Yes" },
            { value: "false", label: "No" },
          ]}
        />
      );
    case "number":
      return (
        <TextField
          {...common}
          type="number"
          step={shape.integer ? 1 : "any"}
          min={shape.min}
          max={shape.max}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          optional={!definition.required}
        />
      );
    case "string":
      return (
        <TextField
          {...common}
          type={shape.input}
          minLength={shape.minLength}
          maxLength={shape.maxLength}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          optional={!definition.required}
          autoComplete="off"
        />
      );
  }
}
