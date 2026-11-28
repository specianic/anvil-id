// Where a tenant's email goes (C-M14): its own SMTP settings, the installation's SMTP server, or
// nowhere. One implementation shared by the SMTP page and the getting-started checklist, so both
// state the same thing. The installation side comes from `smtp_configured` of the admin-only
// GET /system/info (07.1-06); the tenant side from GET /tenants/{slug}/smtp (404 = none).
import { useQuery } from "@tanstack/react-query";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";

type SmtpSettingsView = components["schemas"]["SmtpSettingsView"];

export function smtpQueryKey(tenant: string) {
  return ["smtp", tenant] as const;
}

/** Tenant SMTP settings, or null when the tenant has none of its own (404). */
export async function fetchTenantSmtp(tenant: string, signal?: AbortSignal): Promise<SmtpSettingsView | null> {
  try {
    return unwrap(await api.GET("/api/admin/v1/tenants/{slug}/smtp", { params: { path: { slug: tenant } }, signal }));
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/** GET /system/info (version, smtp_configured); same query key as the console footer. */
export function useSystemInfo() {
  return useQuery({
    queryKey: ["system", "info"],
    queryFn: async ({ signal }) => unwrap(await api.GET("/api/admin/v1/system/info", { signal })),
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
  });
}

/**
 * `tenant`: the tenant's own server; `installation`: no tenant settings, the operator configured an
 * installation server; `none`: neither, so verification, recovery and invitation emails cannot be
 * sent; `unknown`: the installation state could not be read.
 */
export type SmtpState = "tenant" | "installation" | "none" | "unknown";

export function smtpState(tenantSmtp: SmtpSettingsView | null, smtpConfigured: boolean | undefined): SmtpState {
  if (tenantSmtp !== null) return "tenant";
  if (smtpConfigured === undefined) return "unknown";
  return smtpConfigured ? "installation" : "none";
}
