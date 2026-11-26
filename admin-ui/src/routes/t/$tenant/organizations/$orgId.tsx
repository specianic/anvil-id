// Layout of one organization: heading and the section navigation (Overview, Members, Invitations,
// Roles, Connections, Domains, Branding); the sections render in the Outlet. A new section adds a
// sibling route file and an entry to ORG_SECTIONS.
import { Link, Outlet, createFileRoute } from "@tanstack/react-router";
import { ApiError } from "@/api/client";
import { useOrganization } from "@/components/OrgForm";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Skeleton } from "@/components/ui/skeleton";
import { useTenant } from "@/lib/tenant";

const ORG_SECTIONS = [
  { to: "/t/$tenant/organizations/$orgId", label: "Overview", exact: true },
  { to: "/t/$tenant/organizations/$orgId/members", label: "Members", exact: false },
  { to: "/t/$tenant/organizations/$orgId/invitations", label: "Invitations", exact: false },
  { to: "/t/$tenant/organizations/$orgId/roles", label: "Roles", exact: false },
  { to: "/t/$tenant/organizations/$orgId/connections", label: "Connections", exact: false },
  { to: "/t/$tenant/organizations/$orgId/domains", label: "Domains", exact: false },
  { to: "/t/$tenant/organizations/$orgId/branding", label: "Branding", exact: false },
] as const;

const focusRing = "focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function OrganizationLayout() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const query = useOrganization(tenant, orgId);
  const missing = query.error instanceof ApiError && query.error.status === 404;

  return (
    <section aria-labelledby="org-heading" className="space-y-4">
      <Link
        to="/t/$tenant/organizations"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Organizations
      </Link>
      {query.isPending ? (
        <div role="status" aria-label="Loading organization" className="space-y-2">
          <Skeleton className="h-7 w-1/3" />
          <Skeleton className="h-6 w-1/2" />
        </div>
      ) : missing ? (
        <div className="space-y-2" data-testid="org-not-found">
          <h1 id="org-heading" className="text-xl font-semibold">
            Organization not found
          </h1>
          <p className="text-muted-foreground text-sm">It may have been deleted.</p>
        </div>
      ) : query.isError ? (
        <>
          <h1 id="org-heading" className="text-xl font-semibold">
            Organization
          </h1>
          <ProblemAlert error={query.error} />
        </>
      ) : (
        <>
          <div>
            <h1 id="org-heading" className="text-xl font-semibold break-all">
              {query.data.display_name}
            </h1>
            <p className="text-muted-foreground text-sm">
              <code>{query.data.slug}</code>
            </p>
          </div>
          <nav aria-label="Organization sections" className="border-b">
            <ul className="flex flex-wrap gap-1">
              {ORG_SECTIONS.map((s) => (
                <li key={s.to}>
                  <Link
                    to={s.to}
                    params={{ tenant, orgId }}
                    activeOptions={{ exact: s.exact }}
                    className={`text-muted-foreground -mb-px inline-block border-b-2 border-transparent px-3 py-2 text-sm ${focusRing}`}
                    activeProps={{ className: "border-foreground! text-foreground! font-medium", "aria-current": "page" }}
                  >
                    {s.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
          <Outlet />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId")({ component: OrganizationLayout });
