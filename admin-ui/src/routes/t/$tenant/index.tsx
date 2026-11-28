// Tenant Overview (/console/t/{slug}, C-M6): the tenant's issuer and discovery URL to configure
// relying parties with, and the getting-started checklist. The console opens here after sign-in.
import { createFileRoute } from "@tanstack/react-router";
import { CopyField } from "@/components/CopyField";
import { GettingStarted } from "@/components/GettingStarted";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SYSTEM_TENANT, useTenant, useTenantView } from "@/lib/tenant";

function OverviewPage() {
  const tenant = useTenant();
  const query = useTenantView(tenant);

  if (query.isPending) {
    return (
      <div role="status" aria-label="Loading overview" className="space-y-2">
        <Skeleton className="h-6 w-1/3" />
        <Skeleton className="h-6 w-1/2" />
      </div>
    );
  }
  if (query.isError) return <ProblemAlert error={query.error} />;
  const view = query.data;

  return (
    <section aria-labelledby="overview-heading" className="space-y-4" data-testid="tenant-overview">
      <div className="space-y-1">
        <p className="text-muted-foreground text-xs font-medium tracking-wide uppercase">Overview</p>
        <h1 id="overview-heading" className="text-xl font-semibold break-words">
          {view.display_name}
        </h1>
        <p className="text-muted-foreground text-sm">
          {view.slug === SYSTEM_TENANT ? (
            <>
              The system tenant holds the console administrators. Your applications belong in{" "}
              <code>default</code> or a tenant of their own.
            </>
          ) : (
            <>
              Tenant <code>{view.slug}</code>: its own users, apps, signing keys and issuer.
            </>
          )}
        </p>
      </div>

      <Card data-testid="tenant-integration">
        <CardHeader>
          <CardTitle>
            <h2>Connect an app</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-muted-foreground text-sm">
            Configure your app's OpenID Connect library with the issuer or the discovery URL.
          </p>
          <CopyField label="Issuer" value={view.issuer} mono />
          <CopyField label="Discovery URL" value={view.discovery_url} mono />
        </CardContent>
      </Card>

      <GettingStarted tenant={view} />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/")({ component: OverviewPage });
