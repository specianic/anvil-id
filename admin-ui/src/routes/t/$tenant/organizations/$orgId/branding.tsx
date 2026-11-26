// Branding of one organization: overrides of the tenant theme on the sign-in pages of flows that
// name the organization (tokens per field; the org's custom CSS follows the tenant's; a client's own
// branding still wins). Same editor and live preview as the tenant and client branding.
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { ProblemAlert } from "@/components/ProblemAlert";
import { ThemeEditor, getBranding } from "@/components/ThemeEditor";
import { type BrandingScope, brandingQueryKey } from "@/components/ThemePreview";
import { Skeleton } from "@/components/ui/skeleton";
import { useTenant } from "@/lib/tenant";

function OrgBrandingPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const scope = useMemo<BrandingScope>(() => ({ kind: "org", tenant, orgId }), [tenant, orgId]);
  const query = useQuery({
    queryKey: brandingQueryKey(scope),
    queryFn: ({ signal }) => getBranding(scope, signal),
    // The editor keeps local edits; a background refetch must not replace its starting point.
    refetchOnWindowFocus: false,
  });

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Branding</h2>
      <p className="text-muted-foreground text-sm">
        Overrides the{" "}
        <Link to="/t/$tenant/branding" params={{ tenant }} className="underline underline-offset-4">
          tenant branding
        </Link>{" "}
        when a sign-in names this organization. A client's own branding takes precedence over it.
      </p>
      {query.isPending ? (
        <div role="status" aria-label="Loading branding" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        // Keyed by organization so another organization starts with its own stored branding.
        <ThemeEditor key={orgId} scope={scope} view={query.data} />
      )}
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/branding")({ component: OrgBrandingPage });
