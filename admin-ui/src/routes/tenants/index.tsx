// Tenant list (ORG-01): every tenant of the installation with its issuer and the discovery URL a
// relying party is configured with. The issuer comes from the tenant's discovery document (the
// server computes it from the public URL); host tenants also answer with `{scheme}://{host}`.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useState } from "react";
import { type TenantView, api, unwrap } from "@/api/client";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";
import { SYSTEM_TENANT, discoveryUrl, hostIssuer, useDiscovery } from "@/lib/tenant";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, TenantView>();

const linkClass =
  "font-mono font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function IssuerCell({ tenant }: { tenant: TenantView }) {
  const discovery = useDiscovery(tenant.slug);
  if (discovery.isPending) return <span className="text-muted-foreground text-xs">Loading…</span>;
  if (discovery.isError) return <span className="text-destructive text-xs">Discovery unavailable</span>;
  const issuer = discovery.data.issuer;
  return (
    <div className="space-y-0.5">
      <code className="block text-xs break-all" data-testid={`tenant-issuer-${tenant.slug}`}>
        {issuer}
      </code>
      {tenant.host && (
        <code className="text-muted-foreground block text-xs break-all" title="Issuer on the tenant's custom host">
          {hostIssuer(issuer, tenant.host)}
        </code>
      )}
    </div>
  );
}

function DiscoveryCell({ slug }: { slug: string }) {
  const url = discoveryUrl(slug);
  const [status, setStatus] = useState<string | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      setStatus("Copied.");
    } catch {
      setStatus("Copy failed; select the URL.");
    }
  };
  return (
    <div className="flex items-center gap-2">
      <code className="text-xs break-all" data-testid={`tenant-discovery-${slug}`}>
        {url}
      </code>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => void copy()}
        aria-label={`Copy discovery URL of ${slug}`}
        data-testid={`copy-discovery-${slug}`}
      >
        Copy
      </Button>
      <span role="status" className="text-muted-foreground text-xs">
        {status}
      </span>
    </div>
  );
}

const columns = col.columns([
  col.accessor("slug", {
    header: "Slug",
    cell: (info) => (
      <Link to="/t/$tenant/users" params={{ tenant: info.getValue() }} className={linkClass}>
        {info.getValue()}
      </Link>
    ),
  }),
  col.accessor("display_name", {
    header: "Display name",
    cell: (info) => (
      <span className="flex flex-wrap items-center gap-2">
        {info.getValue()}
        {info.row.original.slug === SYSTEM_TENANT && (
          <Badge variant="outline" title="The installation's own tenant: its users are the console admins">
            System
          </Badge>
        )}
      </span>
    ),
  }),
  col.display({ id: "issuer", header: "Issuer", cell: (info) => <IssuerCell tenant={info.row.original} /> }),
  col.accessor("host", {
    header: "Host",
    cell: (info) => (info.getValue() ? <code className="text-xs">{info.getValue()}</code> : "—"),
  }),
  col.display({
    id: "discovery",
    header: "Discovery URL",
    cell: (info) => <DiscoveryCell slug={info.row.original.slug} />,
  }),
  col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
]);

function TenantsPage() {
  const pager = useCursorPager();
  const query = useQuery({
    queryKey: ["tenants", "page", pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants", {
          params: { query: { limit: PAGE_SIZE, after: pager.after } },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <section aria-labelledby="tenants-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="tenants-heading" className="text-xl font-semibold">
          Tenants
        </h1>
        <Button asChild size="sm">
          <Link to="/tenants/new" data-testid="new-tenant">
            New tenant
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Each tenant is isolated: its own users, clients, signing keys and issuer. Relying parties are configured with
        the tenant's discovery URL.
      </p>
      <DataTable
        caption="Tenants"
        columns={columns}
        data={query.data?.items}
        getRowId={(t) => t.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No tenants."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
    </section>
  );
}

export const Route = createFileRoute("/tenants/")({ component: TenantsPage });
