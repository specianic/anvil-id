// Client branding: overrides of the tenant theme for one client's sign-in and consent pages
// (tokens per field; the client's custom CSS follows the tenant's), with a live preview.
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { CONSOLE_TENANT, api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { ThemeEditor } from "@/components/ThemeEditor";
import { type BrandingScope, brandingQueryKey } from "@/components/ThemePreview";
import { Skeleton } from "@/components/ui/skeleton";

function ClientBrandingPage() {
  const { clientId } = Route.useParams();
  const scope = useMemo<BrandingScope>(() => ({ kind: "client", clientId }), [clientId]);

  const client = useQuery({
    queryKey: ["client", CONSOLE_TENANT, clientId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
          params: { path: { slug: CONSOLE_TENANT, client_id: clientId } },
          signal,
        }),
      ),
  });
  const branding = useQuery({
    queryKey: brandingQueryKey(scope),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}/branding", {
          params: { path: { slug: CONSOLE_TENANT, client_id: clientId } },
          signal,
        }),
      ),
    // The editor keeps local edits; a background refetch must not replace its starting point.
    refetchOnWindowFocus: false,
  });

  return (
    <section aria-labelledby="client-branding-heading" className="space-y-4">
      <Link
        to="/clients/$clientId"
        params={{ clientId }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← {client.data?.name ?? "Client"}
      </Link>
      <h1 id="client-branding-heading" className="text-xl font-semibold break-all">
        Branding of {client.data?.name ?? clientId}
      </h1>
      <p className="text-muted-foreground text-sm">
        Overrides the{" "}
        <Link to="/branding" className="underline underline-offset-4">
          tenant branding
        </Link>{" "}
        on the sign-in and consent pages of this client.
      </p>
      {branding.isPending ? (
        <div role="status" aria-label="Loading branding" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : branding.isError ? (
        <ProblemAlert error={branding.error} />
      ) : (
        // Keyed by client so another client starts with its own stored branding.
        <ThemeEditor key={clientId} scope={scope} view={branding.data} />
      )}
    </section>
  );
}

export const Route = createFileRoute("/branding/$clientId")({ component: ClientBrandingPage });
