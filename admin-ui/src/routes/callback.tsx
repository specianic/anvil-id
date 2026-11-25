import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { type SigninState, completeSignIn, safeReturnTo } from "@/auth/oidc";

function Callback() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    completeSignIn()
      .then((user) => {
        const state = user.state as Partial<SigninState> | undefined;
        // returnTo is a browser path under /console/; anything else is replaced by the console home.
        router.history.replace(safeReturnTo(state?.returnTo));
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Sign-in failed."));
  }, [router]);

  return (
    <main className="flex min-h-screen items-center justify-center p-8">
      {error ? (
        <div role="alert" className="max-w-md space-y-3 text-center">
          <h1 className="text-lg font-semibold">Sign-in failed</h1>
          <p className="text-muted-foreground text-sm">{error}</p>
          <a className="text-sm underline underline-offset-4" href="/console/">
            Start again
          </a>
        </div>
      ) : (
        <p role="status" className="text-muted-foreground text-sm">
          Completing sign-in…
        </p>
      )}
    </main>
  );
}

export const Route = createFileRoute("/callback")({ component: Callback });
