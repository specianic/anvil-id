// Layout of every tenant-scoped console page (/console/t/$tenant/...). It checks that the tenant
// exists (GET /tenants/{slug}) before the pages load, shows a not-found panel otherwise, and
// remembers the tenant as the last used one for /console/.
import { Outlet, createFileRoute } from "@tanstack/react-router";
import { Fragment, useEffect } from "react";
import { ApiError } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Skeleton } from "@/components/ui/skeleton";
import { forgetTenant, rememberTenant, useTenant, useTenantView } from "@/lib/tenant";

function TenantNotFound({ slug }: { slug: string }) {
  return (
    <section aria-labelledby="tenant-not-found" className="space-y-2" data-testid="tenant-not-found">
      <h1 id="tenant-not-found" className="text-xl font-semibold">
        Tenant not found
      </h1>
      <p className="text-muted-foreground text-sm">
        There is no tenant <code>{slug}</code>. It may have been deleted.
      </p>
    </section>
  );
}

function TenantLayout() {
  const slug = useTenant();
  const query = useTenantView(slug);
  const exists = query.isSuccess;

  useEffect(() => {
    if (exists) rememberTenant(slug);
  }, [exists, slug]);

  const missing = query.error instanceof ApiError && query.error.status === 404;
  useEffect(() => {
    if (missing) forgetTenant(slug);
  }, [missing, slug]);

  if (query.isPending) {
    return (
      <div role="status" aria-label="Loading tenant" className="space-y-2">
        <Skeleton className="h-6 w-1/3" />
        <Skeleton className="h-6 w-1/2" />
      </div>
    );
  }
  if (missing) return <TenantNotFound slug={slug} />;
  if (query.isError) return <ProblemAlert error={query.error} />;
  // Keyed by tenant: switching tenants remounts the pages, so no form keeps another tenant's edits.
  return (
    <Fragment key={slug}>
      <Outlet />
    </Fragment>
  );
}

export const Route = createFileRoute("/t/$tenant")({ component: TenantLayout });
