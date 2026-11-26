import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { TenantSwitcher } from "@/components/TenantSwitcher";
import { Button } from "@/components/ui/button";
import { TENANT_PAGES, lastTenant, useOptionalTenant } from "@/lib/tenant";

// Tenant-scoped pages; the tenant comes from the route (or the last used one on the tenant list pages).
// Password hash profiles (07-20) sit between Signing keys and Login settings; they are a navigation
// entry only (the tenant switcher keeps the TENANT_PAGES sections).
const NAV = [
  ...TENANT_PAGES.slice(0, -1),
  { to: "/t/$tenant/password-profiles", label: "Password hash profiles" },
  ...TENANT_PAGES.slice(-1),
] as const;

const focusRing = "focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

export function AppShell({ children }: { children: ReactNode }) {
  const { user, signOut } = useAuth();
  const who = user.profile.email ?? user.profile.preferred_username ?? user.profile.sub;
  const tenant = useOptionalTenant() ?? lastTenant();

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className={`bg-background sr-only rounded-md border px-3 py-2 focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 ${focusRing}`}
      >
        Skip to content
      </a>
      <header className="border-b">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 pt-3">
          <span className="font-semibold">AnvilID</span>
          <TenantSwitcher />
          <div className="ml-auto flex items-center gap-3">
            <span className="text-muted-foreground text-sm">{who}</span>
            <Button variant="outline" size="sm" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </div>
        <div className="mx-auto max-w-6xl px-4 py-2">
          <nav aria-label="Main">
            <ul className="flex flex-wrap gap-1">
              {NAV.map((item) => (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    params={{ tenant }}
                    className={`text-muted-foreground hover:text-foreground rounded-md px-3 py-1.5 text-sm ${focusRing}`}
                    activeProps={{ className: "bg-accent text-foreground", "aria-current": "page" }}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto max-w-6xl px-4 py-6 focus:outline-none">
        {children}
      </main>
    </div>
  );
}
