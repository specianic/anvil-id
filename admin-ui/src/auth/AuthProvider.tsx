import type { User } from "oidc-client-ts";
import { type ReactNode, createContext, useContext, useEffect, useState } from "react";
import { signIn, signOut, userManager } from "./oidc";

interface AuthContextValue {
  user: User;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** The signed-in admin. Only usable below <AuthProvider>. */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}

type AuthState = { status: "loading" } | { status: "signed-in"; user: User } | { status: "signed-out" };

/**
 * Renders its children only for a signed-in admin. Without a usable session it starts the
 * authorization code flow and returns to the current page afterwards.
 */
export function AuthProvider({ returnTo, children }: { returnTo: string; children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    userManager
      .getUser()
      .then((user) => {
        if (!active) return;
        // An expired access token is fine while a refresh token remains: the API client refreshes on 401.
        if (user && (!user.expired || user.refresh_token)) setState({ status: "signed-in", user });
        else setState({ status: "signed-out" });
      })
      .catch(() => active && setState({ status: "signed-out" }));

    const onLoaded = (user: User) => setState({ status: "signed-in", user });
    const onUnloaded = () => setState({ status: "signed-out" });
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onUnloaded);
    return () => {
      active = false;
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onUnloaded);
    };
  }, []);

  useEffect(() => {
    if (state.status !== "signed-out") return;
    signIn(returnTo).catch((e: unknown) => {
      setError(e instanceof Error ? e.message : "The sign-in request could not be started.");
    });
    // returnTo is read once per sign-out; later navigation must not restart the redirect.
  }, [state.status]);

  if (state.status === "signed-in") {
    return <AuthContext.Provider value={{ user: state.user, signOut }}>{children}</AuthContext.Provider>;
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-8">
      {error ? (
        <div role="alert" className="max-w-md space-y-3 text-center">
          <h1 className="text-lg font-semibold">Sign-in is unavailable</h1>
          <p className="text-muted-foreground text-sm">{error}</p>
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-sm focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
            onClick={() => window.location.reload()}
          >
            Try again
          </button>
        </div>
      ) : (
        <p role="status" className="text-muted-foreground text-sm">
          Signing in…
        </p>
      )}
    </main>
  );
}
