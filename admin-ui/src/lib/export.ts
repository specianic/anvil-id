// Helpers for the user export downloads (07-20): which export actions the signed-in admin may use,
// and saving a downloaded body as a file. Exports need `admin:users:export` or `admin:write`
// (the API decides; the console only hides what it would refuse).
import { useAuth } from "@/auth/AuthProvider";

/** Scopes that allow user exports (mirror of the API's export check). */
export const EXPORT_SCOPES: readonly string[] = ["admin:users:export", "admin:write"];

/** The scope claim of a JWT access token, or "" for opaque or unreadable tokens. */
function tokenScope(accessToken: string | undefined): string {
  const payload = accessToken?.split(".")[1];
  if (!payload) return "";
  try {
    const json: unknown = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    const scope = (json as { scope?: unknown }).scope;
    return typeof scope === "string" ? scope : "";
  } catch {
    return "";
  }
}

/** The scopes granted to the console's current token (from the token response, else the token's claim). */
export function useGrantedScopes(): string[] {
  const { user } = useAuth();
  const scope = user.scope || tokenScope(user.access_token);
  return scope.split(" ").filter(Boolean);
}

/** Whether the signed-in admin's token carries a scope that allows user exports. */
export function useCanExportUsers(): boolean {
  const scopes = useGrantedScopes();
  return scopes.some((s) => EXPORT_SCOPES.includes(s));
}

/** Shown next to disabled export controls. */
export const EXPORT_SCOPE_HINT =
  "Exports need the admin:users:export or admin:write scope, which your sign-in does not carry.";

/** Saves `blob` as a file download (Blob URL; the token never appears in a URL). */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  // Revoke after the click has been handled.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
