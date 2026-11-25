// Live preview of a branding draft: every change of the draft is POSTed (debounced) to the scope's
// `…/branding/preview` operation, and the returned same-origin `preview_url` is framed. Responses to
// superseded drafts are ignored (request counter + abort). The preview page is the only page of
// anvilid that may be framed, and only by the same origin (frame-ancestors 'self').
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, CONSOLE_TENANT, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Skeleton } from "@/components/ui/skeleton";

export type PutBranding = components["schemas"]["PutBranding"];
export type BrandingView = components["schemas"]["BrandingView"];
export type BrandingPreview = components["schemas"]["BrandingPreview"];
export type ThemeWarning = components["schemas"]["ThemeWarningDto"];

/** Which branding is edited: the tenant's own, or one client's (overrides the tenant per field). */
export type BrandingScope = { kind: "tenant" } | { kind: "client"; clientId: string };

/** Debounce between the last edit and the preview request. */
export const PREVIEW_DEBOUNCE_MS = 300;

/** A preview token this close to its expiry is renewed before it is published. */
const EXPIRY_MARGIN_MS = 15_000;

export function brandingQueryKey(scope: BrandingScope) {
  return scope.kind === "tenant"
    ? (["branding", CONSOLE_TENANT, "tenant"] as const)
    : (["branding", CONSOLE_TENANT, "client", scope.clientId] as const);
}

/** Store the scope's draft and get a 15-minute preview URL and token. */
export async function postPreview(scope: BrandingScope, body: PutBranding, signal?: AbortSignal) {
  if (scope.kind === "tenant") {
    return unwrap(
      await api.POST("/api/admin/v1/tenants/{slug}/branding/preview", {
        params: { path: { slug: CONSOLE_TENANT } },
        body,
        signal,
      }),
    );
  }
  return unwrap(
    await api.POST("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/preview", {
      params: { path: { slug: CONSOLE_TENANT, client_id: scope.clientId } },
      body,
      signal,
    }),
  );
}

/** Publish the scope's draft identified by its preview token. */
export async function postPublish(scope: BrandingScope, token: string) {
  if (scope.kind === "tenant") {
    return unwrap(
      await api.POST("/api/admin/v1/tenants/{slug}/branding/publish", {
        params: { path: { slug: CONSOLE_TENANT } },
        body: { token },
      }),
    );
  }
  return unwrap(
    await api.POST("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/publish", {
      params: { path: { slug: CONSOLE_TENANT, client_id: scope.clientId } },
      body: { token },
    }),
  );
}

export interface PreviewState {
  /** The last successful preview of the current draft (or of an earlier one while `pending`). */
  preview: BrandingPreview | null;
  /** The error of the latest request (422 carries field errors), or null. */
  error: unknown;
  /** A request for the current draft is scheduled or in flight. */
  pending: boolean;
  /** The shown preview belongs to the current draft and is not in error. */
  current: boolean;
  /**
   * A preview token for the current draft that is valid for a while: the current one, or a fresh
   * one when it is about to expire (or the draft has no preview yet).
   */
  freshToken: () => Promise<string>;
}

/**
 * Keep a preview of `body` up to date. `refreshKey` forces a new preview without a draft change
 * (e.g. after the logo, which the draft does not carry, was replaced).
 */
export function useBrandingPreview(scope: BrandingScope, body: PutBranding, refreshKey: number): PreviewState {
  const serialized = `${refreshKey}:${JSON.stringify(body)}`;
  const [preview, setPreview] = useState<BrandingPreview | null>(null);
  const [previewOf, setPreviewOf] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [errorOf, setErrorOf] = useState<string | null>(null);
  const [inFlight, setInFlight] = useState<string | null>(null);
  const counter = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const bodyRef = useRef({ body, serialized });
  bodyRef.current = { body, serialized };

  const run = useCallback(async (draft: PutBranding, key: string): Promise<BrandingPreview | null> => {
    const id = ++counter.current;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setInFlight(key);
    try {
      const result = await postPreview(scopeRef.current, draft, abort.signal);
      if (id !== counter.current) return null; // superseded by a newer draft
      setPreview(result);
      setPreviewOf(key);
      setError(null);
      setErrorOf(null);
      return result;
    } catch (err) {
      if (id !== counter.current || abort.signal.aborted) return null;
      setError(err);
      setErrorOf(key);
      throw err;
    } finally {
      if (id === counter.current) setInFlight(null);
    }
  }, []);

  useEffect(() => {
    const { body: draft, serialized: key } = bodyRef.current;
    const timer = window.setTimeout(() => {
      run(draft, key).catch(() => {
        // Shown through `error`.
      });
    }, PREVIEW_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
    // `serialized` captures every change of the draft and the refresh key.
  }, [serialized, run]);

  useEffect(() => () => controller.current?.abort(), []);

  const settled = previewOf === serialized || errorOf === serialized;
  const pending = !settled || inFlight !== null;
  const current = previewOf === serialized && errorOf === null && inFlight === null;

  const freshToken = useCallback(async () => {
    const { body: draft, serialized: key } = bodyRef.current;
    const fresh =
      preview &&
      previewOf === key &&
      errorOf === null &&
      new Date(preview.expires_at).getTime() - Date.now() > EXPIRY_MARGIN_MS;
    if (fresh) return preview.token;
    const result = await run(draft, key);
    if (!result) throw new Error("The preview was replaced by a newer draft. Try again.");
    return result.token;
  }, [preview, previewOf, errorOf, run]);

  return { preview, error, pending, current, freshToken };
}

function pairLabel(pair: string): string {
  switch (pair) {
    case "text_on_background":
      return "Text on background";
    case "text_on_surface":
      return "Text on surface";
    case "primary_text":
      return "Text on primary";
    default:
      return pair;
  }
}

/** Contrast warnings (low WCAG contrast ratios) of a draft or of the stored branding. */
export function ContrastWarnings({ warnings, testId }: { warnings: readonly ThemeWarning[]; testId?: string }) {
  if (warnings.length === 0) return null;
  return (
    <ul className="space-y-1 rounded-md border border-amber-500/60 px-3 py-2 text-sm" data-testid={testId}>
      {warnings.map((w) => (
        <li key={`${w.scheme}:${w.pair}`}>
          <span className="font-medium">
            {w.scheme === "dark" ? "Dark: " : ""}
            {pairLabel(w.pair)} ({w.ratio.toFixed(2)}:1)
          </span>{" "}
          <span className="text-muted-foreground">{w.message}</span>
        </li>
      ))}
    </ul>
  );
}

/** The framed preview page with its state (updating, errors, warnings). */
export function ThemePreview({ state }: { state: PreviewState }) {
  const { preview, error, pending } = state;
  const validationError = error instanceof ApiError && error.status === 422;
  return (
    <div className="space-y-3" data-testid="theme-preview">
      <div aria-live="polite" role="status" className="text-muted-foreground min-h-5 text-sm" data-testid="preview-status">
        {pending
          ? "Updating preview…"
          : validationError
            ? "The preview shows the last valid draft. Fix the errors in the editor."
            : error
              ? "The preview could not be updated."
              : preview
                ? "Preview is up to date."
                : ""}
      </div>
      {error && !validationError ? <ProblemAlert error={error} /> : null}
      {validationError && (
        <ul className="text-destructive space-y-0.5 text-sm" data-testid="preview-errors">
          {error.problem.errors.map((e) => (
            <li key={`${e.field}:${e.message}`}>
              <code>{e.field}</code>: {e.message}
            </li>
          ))}
        </ul>
      )}
      {preview && <ContrastWarnings warnings={preview.warnings} testId="preview-warnings" />}
      {preview ? (
        <iframe
          key={preview.preview_url}
          src={preview.preview_url}
          title="Theme preview"
          // Same origin is needed for the page's own stylesheet; scripts, forms and navigation of
          // the console stay blocked.
          sandbox="allow-same-origin"
          referrerPolicy="no-referrer"
          className="h-[720px] w-full rounded-md border bg-white"
          data-testid="theme-preview-frame"
        />
      ) : error ? null : (
        <div role="status" aria-label="Loading preview" className="space-y-2">
          <Skeleton className="h-[720px] w-full" />
        </div>
      )}
    </div>
  );
}
