import { createFileRoute, redirect } from "@tanstack/react-router";

// /console/t/{slug} opens the tenant's user list.
export const Route = createFileRoute("/t/$tenant/")({
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/t/$tenant/users", params: { tenant: params.tenant }, replace: true });
  },
});
