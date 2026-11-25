import { Outlet, createRootRoute, useRouterState } from "@tanstack/react-router";
import { AuthProvider } from "@/auth/AuthProvider";
import { currentReturnTo } from "@/auth/oidc";
import { AppShell } from "@/components/AppShell";

function Root() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  // The OIDC callback runs before a session exists; every other route requires a signed-in admin.
  if (pathname === "/callback") return <Outlet />;
  return (
    <AuthProvider returnTo={currentReturnTo()}>
      <AppShell>
        <Outlet />
      </AppShell>
    </AuthProvider>
  );
}

function NotFound() {
  return (
    <div className="space-y-2">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <p className="text-muted-foreground text-sm">This console page does not exist.</p>
    </div>
  );
}

export const Route = createRootRoute({
  component: Root,
  notFoundComponent: NotFound,
});
