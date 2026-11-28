import { createFileRoute, redirect } from "@tanstack/react-router";
import { lastTenant } from "@/lib/tenant";

// /console/ (also where the sign-in callback lands) opens the Overview of the tenant used last in
// this browser tab, or `default`: its getting-started checklist is the console's first page (C-M6).
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    throw redirect({ to: "/t/$tenant", params: { tenant: lastTenant() }, replace: true });
  },
});
