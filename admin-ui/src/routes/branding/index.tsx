// Tenant branding: theme tokens, custom CSS and logo of the tenant's sign-in and consent pages,
// with a live preview. Clients are branded from their own page (Clients -> client -> Branding).
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { CONSOLE_TENANT, api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { ThemeEditor } from "@/components/ThemeEditor";
import { type BrandingScope, brandingQueryKey } from "@/components/ThemePreview";
import { Skeleton } from "@/components/ui/skeleton";

const SCOPE: BrandingScope = { kind: "tenant" };

function TenantBrandingPage() {
  const query = useQuery({
    queryKey: brandingQueryKey(SCOPE),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/branding", {
          params: { path: { slug: CONSOLE_TENANT } },
          signal,
        }),
      ),
    // The editor keeps local edits; a background refetch must not replace its starting point.
    refetchOnWindowFocus: false,
  });

  return (
    <section aria-labelledby="branding-heading" className="space-y-4">
      <h1 id="branding-heading" className="text-xl font-semibold">
        Branding
      </h1>
      <p className="text-muted-foreground text-sm">
        The look of this tenant's sign-in and consent pages. To brand a single application, open it under{" "}
        <Link to="/clients" className="underline underline-offset-4">
          Clients
        </Link>{" "}
        and choose Branding.
      </p>
      {query.isPending ? (
        <div role="status" aria-label="Loading branding" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <ThemeEditor scope={SCOPE} view={query.data} />
      )}
    </section>
  );
}

export const Route = createFileRoute("/branding/")({ component: TenantBrandingPage });
