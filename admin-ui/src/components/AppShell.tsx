import { useQuery } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import { Menu, X } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { api, unwrap } from "@/api/client";
import { useAuth } from "@/auth/AuthProvider";
import { TenantSwitcher } from "@/components/TenantSwitcher";
import { Button } from "@/components/ui/button";
import { lastTenant, navGroupsFor, useOptionalTenant } from "@/lib/tenant";

// The main navigation is rendered from TENANT_PAGES (lib/tenant.ts), grouped under eyebrow headings;
// the tenant comes from the route (or the last used one on the tenant list pages). Below 768px the
// navigation collapses behind a "Menu" button (aria-expanded / aria-controls).

const NAV_ID = "main-nav";
const focusRing = "focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

// The running server version, from the admin-only GET /api/admin/v1/system/info. The shell renders
// only for a signed-in administrator, so the version never reaches the unauthenticated console;
// on any error (e.g. a token without admin scopes) the footer shows nothing.
function VersionFooter() {
  const { data } = useQuery({
    queryKey: ["system", "info"],
    queryFn: async ({ signal }) => unwrap(await api.GET("/api/admin/v1/system/info", { signal })),
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
  });
  if (!data?.version) return null;
  return (
    <footer className="mx-auto max-w-7xl px-4 pb-6">
      <p className="text-muted-foreground text-xs" data-testid="console-version">
        AnvilID {data.version}
      </p>
    </footer>
  );
}

/** Text of the signed-in admin in the header: email, else name, else the subject. */
function adminLabel(profile: { email?: string; name?: string; preferred_username?: string; sub: string }): string {
  return profile.email ?? profile.name ?? profile.preferred_username ?? profile.sub;
}

function MainNav({ tenant, id, className }: { tenant: string; id: string; className: string }) {
  return (
    <nav aria-label="Main" id={id} className={className}>
      <div className="space-y-5">
        {navGroupsFor(tenant).map(({ group, pages }) => {
          const headingId = `${id}-${group.toLowerCase().replaceAll(" ", "-")}`;
          return (
            <div key={group}>
              <h2
                id={headingId}
                className="text-muted-foreground mb-1 px-3 text-xs font-semibold tracking-[0.14em] uppercase"
              >
                {group}
              </h2>
              <ul aria-labelledby={headingId} className="space-y-0.5">
                {pages.map((item) => (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      params={{ tenant }}
                      activeOptions={{ exact: item.to === "/t/$tenant" }}
                      className={`text-muted-foreground hover:text-foreground hover:bg-accent block rounded-md border-l-2 border-transparent px-3 py-1.5 text-sm ${focusRing}`}
                      activeProps={{
                        className: "border-link! bg-accent text-foreground font-medium",
                        "aria-current": "page",
                      }}
                    >
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </nav>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { user, signOut } = useAuth();
  const who = adminLabel(user.profile);
  const tenant = useOptionalTenant() ?? lastTenant();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  // Following a link closes the mobile menu.
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className={`bg-background sr-only rounded-md border px-3 py-2 focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 ${focusRing}`}
      >
        Skip to content
      </a>
      <header className="border-b">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="font-semibold tracking-[0.14em] uppercase">AnvilID</span>
          <TenantSwitcher />
          <div className="ml-auto flex items-center gap-3">
            <span className="text-muted-foreground max-w-64 truncate text-sm" data-testid="console-admin" title={who}>
              {who}
            </span>
            <Button variant="outline" size="sm" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
          <Button
            ref={menuButton}
            variant="outline"
            size="sm"
            className="md:hidden"
            aria-expanded={menuOpen}
            aria-controls={NAV_ID}
            onClick={() => setMenuOpen((open) => !open)}
          >
            {menuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
            Menu
          </Button>
        </div>
      </header>
      <div className="mx-auto flex max-w-7xl flex-col md:flex-row">
        <div
          onKeyDown={(e) => {
            if (e.key === "Escape" && menuOpen) {
              setMenuOpen(false);
              menuButton.current?.focus();
            }
          }}
        >
          <MainNav
            tenant={tenant}
            id={NAV_ID}
            className={`${menuOpen ? "block" : "hidden"} border-b px-1 py-4 md:block md:w-60 md:shrink-0 md:border-r md:border-b-0`}
          />
        </div>
        <main id="main" tabIndex={-1} className="min-w-0 flex-1 px-4 py-6 focus:outline-none md:px-8">
          {children}
        </main>
      </div>
      <VersionFooter />
    </div>
  );
}
