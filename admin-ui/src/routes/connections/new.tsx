// Pre-0.4 console link: tenant pages moved to /console/t/$tenant/... (05-04). Redirects to the
// default tenant for this release. TRANSITIONAL: remove in 0.5.
import { createFileRoute, redirect } from "@tanstack/react-router";
import { DEFAULT_TENANT } from "@/lib/tenant";

export const Route = createFileRoute("/connections/new")({
  beforeLoad: () => {
    throw redirect({
      to: "/t/$tenant/connections/new",
      params: { tenant: DEFAULT_TENANT },
      search: true,
      replace: true,
    });
  },
});
