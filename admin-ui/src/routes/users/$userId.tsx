import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { CONSOLE_TENANT, type UserView, api, unwrap } from "@/api/client";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 py-2">
      <dt className="text-muted-foreground text-sm">{label}</dt>
      <dd className="col-span-2 text-sm break-all">{children}</dd>
    </div>
  );
}

function claimValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function UserDetails({ user }: { user: UserView }) {
  // Only claims that are set; v1 shows the profile read-only.
  const claims = Object.entries(user.claims).filter(([, v]) => v !== null && v !== undefined);
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y">
            <Field label="ID">
              <code>{user.id}</code>
            </Field>
            <Field label="Email">{user.email}</Field>
            <Field label="Email verified">{user.email_verified ? "Yes" : "No"}</Field>
            <Field label="Username">{user.username ?? "—"}</Field>
            <Field label="Status">
              <Badge variant={user.status === "blocked" ? "destructive" : "secondary"}>{user.status}</Badge>
            </Field>
            <Field label="Created">{formatDateTime(user.created_at)}</Field>
            <Field label="Updated">{formatDateTime(user.updated_at)}</Field>
            <Field label="Last login">{formatDateTime(user.last_login_at)}</Field>
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardContent>
          {claims.length === 0 ? (
            <p className="text-muted-foreground text-sm">No profile claims set.</p>
          ) : (
            <dl className="divide-y">
              {claims.map(([name, value]) => (
                <Field key={name} label={name}>
                  {claimValue(value)}
                </Field>
              ))}
            </dl>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function UserPage() {
  const { userId } = Route.useParams();
  const query = useQuery({
    queryKey: ["user", CONSOLE_TENANT, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}", {
          params: { path: { slug: CONSOLE_TENANT, user_id: userId } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="user-heading" className="space-y-4">
      <Link to="/users" className="text-muted-foreground text-sm underline-offset-4 hover:underline">
        ← Users
      </Link>
      <h1 id="user-heading" className="text-xl font-semibold break-all">
        {query.data?.email ?? "User"}
      </h1>
      {query.isPending ? (
        <div role="status" aria-label="Loading user" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-6 w-1/3" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <UserDetails user={query.data} />
      )}
    </section>
  );
}

export const Route = createFileRoute("/users/$userId")({ component: UserPage });
