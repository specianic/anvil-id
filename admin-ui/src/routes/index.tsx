import { createFileRoute, redirect } from "@tanstack/react-router";
import { lastTenant } from "@/lib/tenant";

// /console/ opens the tenant used last in this browser tab, or `default`.
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    throw redirect({ to: "/t/$tenant/users", params: { tenant: lastTenant() }, replace: true });
  },
});
