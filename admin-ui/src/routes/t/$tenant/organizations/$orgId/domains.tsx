// Domains of one organization: DNS TXT verification and identifier-first routing per domain.
import { createFileRoute } from "@tanstack/react-router";
import { DomainPanel } from "@/components/DomainPanel";
import { useTenant } from "@/lib/tenant";

function OrgDomainsPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Domains</h2>
      <DomainPanel tenant={tenant} org={orgId} />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/domains")({ component: OrgDomainsPage });
