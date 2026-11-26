// Typed client for the management API (/api/admin/v1). Types come from src/api/schema.d.ts, which
// is generated from docs/openapi/admin-v1.json (`npm run gen:api`; `npm run check:api` fails on drift).
import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";

export type Problem = components["schemas"]["Problem"];
export type UserView = components["schemas"]["UserView"];
export type ClientView = components["schemas"]["ClientView"];
export type TenantView = components["schemas"]["TenantView"];

/** An RFC 9457 problem returned by the API (or synthesised for a non-problem error response). */
export class ApiError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title);
    this.name = "ApiError";
    this.problem = problem;
  }

  get status(): number {
    return this.problem.status;
  }
}

/**
 * Supplies bearer tokens. The auth layer registers one at startup; until then requests go out
 * without a token and the API answers 401.
 */
export interface AccessTokenProvider {
  /** The current access token, if signed in. */
  accessToken(): Promise<string | null>;
  /** Refresh after a 401 (refresh token rotation). Resolves to the new token, or null if signed out. */
  refresh(): Promise<string | null>;
}

let tokenProvider: AccessTokenProvider | null = null;

export function setAccessTokenProvider(provider: AccessTokenProvider | null): void {
  tokenProvider = provider;
}

function isProblem(value: unknown): value is Problem {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.title === "string" && typeof v.status === "number";
}

async function toApiError(response: Response): Promise<ApiError> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("json")) {
    try {
      const body: unknown = await response.clone().json();
      if (isProblem(body)) {
        return new ApiError({
          type: typeof body.type === "string" ? body.type : "about:blank",
          title: body.title,
          status: body.status,
          detail: typeof body.detail === "string" ? body.detail : "",
          errors: Array.isArray(body.errors) ? body.errors : [],
        });
      }
    } catch {
      // Not parseable: fall through to the synthesised problem.
    }
  }
  return new ApiError({
    type: "about:blank",
    title: response.statusText || "Request failed",
    status: response.status,
    detail: `The server answered ${response.status}.`,
    errors: [],
  });
}

// Requests are kept (cloned before they are sent) so a 401 can be retried once after a refresh.
// The retry uses plain fetch, so it never passes through this middleware again (no refresh loop).
const pending = new WeakMap<Request, Request>();

const authMiddleware: Middleware = {
  async onRequest({ request }) {
    const token = tokenProvider ? await tokenProvider.accessToken() : null;
    if (token) request.headers.set("Authorization", `Bearer ${token}`);
    pending.set(request, request.clone());
    return request;
  },
  async onResponse({ request, response }) {
    const original = pending.get(request);
    pending.delete(request);
    if (response.status === 401 && tokenProvider && original) {
      const token = await tokenProvider.refresh();
      if (token) {
        const retry = new Request(original);
        retry.headers.set("Authorization", `Bearer ${token}`);
        const retried = await fetch(retry);
        if (!retried.ok) throw await toApiError(retried);
        return retried;
      }
    }
    if (!response.ok) throw await toApiError(response);
    return response;
  },
};

export const api = createClient<paths>({ baseUrl: "" });
api.use(authMiddleware);

/**
 * Return the data of a successful openapi-fetch result. Error responses never reach here (the
 * middleware throws an ApiError), so a missing body is a protocol error.
 */
export function unwrap<T>(result: { data?: T; response: Response }): T {
  if (result.data === undefined) {
    throw new ApiError({
      type: "about:blank",
      title: "Empty response",
      status: result.response.status,
      detail: "The server returned no body.",
      errors: [],
    });
  }
  return result.data;
}
