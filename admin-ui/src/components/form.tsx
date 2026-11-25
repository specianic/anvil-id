// Accessible form controls for the console: every control has a visible label, field errors are
// linked with aria-describedby/aria-invalid, and nothing uses inline styles (the console CSP has
// style-src 'self').
import { type ComponentProps, type ReactNode, useId } from "react";
import { ApiError } from "@/api/client";
import { cn } from "@/lib/utils";

export const controlClass =
  "border-input bg-background w-full rounded-md border px-3 py-1.5 text-sm shadow-xs focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none aria-invalid:border-destructive disabled:opacity-50";

/** One field error as shown below a control (template errors carry a line number). */
export interface FieldMessage {
  message: string;
  line?: number | null;
}

/** Field errors of a 422 problem, keyed by field name (several messages per field possible). */
export type FieldErrors = Record<string, FieldMessage[]>;

/** Group the `errors` of an API problem by field. Non-API errors yield no field errors. */
export function fieldErrors(error: unknown): FieldErrors {
  if (!(error instanceof ApiError)) return {};
  const out: FieldErrors = {};
  for (const e of error.problem.errors) {
    (out[e.field] ??= []).push({ message: e.message, line: e.line });
  }
  return out;
}

function errorText(e: FieldMessage): string {
  return e.line ? `Line ${e.line}: ${e.message}` : e.message;
}

interface FieldShellProps {
  id: string;
  label: string;
  hint?: ReactNode;
  errors?: FieldMessage[];
  optional?: boolean;
  children: (describedBy: string | undefined, invalid: boolean) => ReactNode;
}

function FieldShell({ id, label, hint, errors, optional, children }: FieldShellProps) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = errors?.length ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
        {optional && <span className="text-muted-foreground font-normal"> (optional)</span>}
      </label>
      {children(describedBy, Boolean(errorId))}
      {hint && (
        <p id={hintId} className="text-muted-foreground text-xs">
          {hint}
        </p>
      )}
      {errorId && (
        <ul id={errorId} className="text-destructive space-y-0.5 text-sm" data-field-error>
          {errors?.map((e) => (
            <li key={errorText(e)}>{errorText(e)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

type InputProps = Omit<ComponentProps<"input">, "id"> & {
  label: string;
  hint?: ReactNode;
  errors?: FieldMessage[];
  optional?: boolean;
  id?: string;
};

export function TextField({ label, hint, errors, optional, id, className, ...props }: InputProps) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} errors={errors} optional={optional}>
      {(describedBy, invalid) => (
        <input
          id={fieldId}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          className={cn(controlClass, className)}
          {...props}
        />
      )}
    </FieldShell>
  );
}

type TextareaProps = Omit<ComponentProps<"textarea">, "id"> & {
  label: string;
  hint?: ReactNode;
  errors?: FieldMessage[];
  optional?: boolean;
  id?: string;
};

export function TextareaField({ label, hint, errors, optional, id, className, ...props }: TextareaProps) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} errors={errors} optional={optional}>
      {(describedBy, invalid) => (
        <textarea
          id={fieldId}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          className={cn(controlClass, "font-mono", className)}
          {...props}
        />
      )}
    </FieldShell>
  );
}

type SelectProps = Omit<ComponentProps<"select">, "id"> & {
  label: string;
  hint?: ReactNode;
  errors?: FieldMessage[];
  optional?: boolean;
  id?: string;
  options: readonly { value: string; label: string }[];
};

export function SelectField({ label, hint, errors, optional, id, options, className, ...props }: SelectProps) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} errors={errors} optional={optional}>
      {(describedBy, invalid) => (
        <select
          id={fieldId}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          className={cn(controlClass, className)}
          {...props}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      )}
    </FieldShell>
  );
}

type CheckboxProps = Omit<ComponentProps<"input">, "id" | "type"> & {
  label: string;
  hint?: ReactNode;
  errors?: FieldMessage[];
  id?: string;
};

export function CheckboxField({ label, hint, errors, id, ...props }: CheckboxProps) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  const hintId = hint ? `${fieldId}-hint` : undefined;
  const errorId = errors?.length ? `${fieldId}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <input
          id={fieldId}
          type="checkbox"
          aria-describedby={describedBy}
          aria-invalid={errorId ? true : undefined}
          className="size-4 rounded border focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
          {...props}
        />
        <label htmlFor={fieldId} className="text-sm font-medium">
          {label}
        </label>
      </div>
      {hint && (
        <p id={hintId} className="text-muted-foreground pl-6 text-xs">
          {hint}
        </p>
      )}
      {errorId && (
        <ul id={errorId} className="text-destructive space-y-0.5 pl-6 text-sm" data-field-error>
          {errors?.map((e) => (
            <li key={errorText(e)}>{errorText(e)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A group of checkboxes with a legend (e.g. grant types). */
export function CheckboxGroup<T extends string>({
  legend,
  options,
  value,
  onChange,
  errors,
  disabled,
}: {
  legend: string;
  options: readonly { value: T; label: string }[];
  value: readonly T[];
  onChange: (next: T[]) => void;
  errors?: FieldMessage[];
  disabled?: boolean;
}) {
  const id = useId();
  const errorId = errors?.length ? `${id}-error` : undefined;
  return (
    <fieldset className="space-y-1.5" aria-describedby={errorId}>
      <legend className="text-sm font-medium">{legend}</legend>
      <div className="flex flex-wrap gap-4">
        {options.map((o) => (
          <label key={o.value} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4 rounded border focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
              checked={value.includes(o.value)}
              disabled={disabled}
              onChange={(e) =>
                onChange(e.target.checked ? [...value, o.value] : value.filter((v) => v !== o.value))
              }
            />
            {o.label}
          </label>
        ))}
      </div>
      {errorId && (
        <ul id={errorId} className="text-destructive space-y-0.5 text-sm" data-field-error>
          {errors?.map((e) => (
            <li key={errorText(e)}>{errorText(e)}</li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/**
 * A live region for the outcome of an action (saved, revoked, test sent). It stays mounted so
 * screen readers announce changes to its text.
 */
export function StatusMessage({ message, tone = "success" }: { message: string | null; tone?: "success" | "error" }) {
  return (
    <div aria-live="polite" role="status" className="min-h-0">
      {message && (
        <p
          className={cn(
            "rounded-md border px-3 py-2 text-sm",
            tone === "error" ? "border-destructive text-destructive" : "border-border",
          )}
        >
          {message}
        </p>
      )}
    </div>
  );
}

/** Split a textarea value into trimmed, non-empty lines. */
export function lines(value: string): string[] {
  return value
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/** Split a space- or comma-separated value into tokens. */
export function tokens(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}
