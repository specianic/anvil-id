import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/button";

// Only built pages are linked. Sessions, Audit and Email settings join this list in plan 03-25.
const NAV = [
  { to: "/users", label: "Users" },
  { to: "/clients", label: "Clients" },
] as const;

const focusRing = "focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

export function AppShell({ children }: { children: ReactNode }) {
  const { user, signOut } = useAuth();
  const who = user.profile.email ?? user.profile.preferred_username ?? user.profile.sub;

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className={`bg-background sr-only rounded-md border px-3 py-2 focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 ${focusRing}`}
      >
        Skip to content
      </a>
      <header className="border-b">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-4 py-3">
          <span className="font-semibold">AnvilID</span>
          <nav aria-label="Main">
            <ul className="flex gap-1">
              {NAV.map((item) => (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    className={`text-muted-foreground hover:text-foreground rounded-md px-3 py-1.5 text-sm ${focusRing}`}
                    activeProps={{ className: "bg-accent text-foreground", "aria-current": "page" }}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <span className="text-muted-foreground text-sm">{who}</span>
            <Button variant="outline" size="sm" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto max-w-6xl px-4 py-6 focus:outline-none">
        {children}
      </main>
    </div>
  );
}
