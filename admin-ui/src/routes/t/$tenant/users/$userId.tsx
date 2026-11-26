import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { type KeyboardEvent, type ReactNode, useRef, useState } from "react";
import { type UserView, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";

type SessionView = components["schemas"]["SessionView"];
type CredentialView = components["schemas"]["CredentialView"];

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "sessions", label: "Sessions" },
  { id: "credentials", label: "Credentials" },
] as const;
type TabId = (typeof TABS)[number]["id"];

function validateSearch(search: Record<string, unknown>): { tab?: TabId } {
  const tab = TABS.find((t) => t.id === search.tab)?.id;
  return tab && tab !== "overview" ? { tab } : {};
}

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

const CREDENTIAL_KIND_LABELS: Record<CredentialView["kind"], string> = {
  password: "Password",
  webauthn: "Passkey",
  totp: "Authenticator app (TOTP)",
};

function UserSessions({ userId }: { userId: string }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState<SessionView | "all" | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const query = useQuery({
    queryKey: ["user-sessions", tenant, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/sessions", {
          params: { path: { slug: tenant, user_id: userId } },
          signal,
        }),
      ),
  });

  const revoke = useMutation({
    mutationFn: async (which: SessionView | "all"): Promise<string> => {
      if (which === "all") {
        const result = unwrap(
          await api.DELETE("/api/admin/v1/tenants/{slug}/users/{user_id}/sessions", {
            params: { path: { slug: tenant, user_id: userId } },
          }),
        );
        return `${result.revoked} ${result.revoked === 1 ? "session" : "sessions"} revoked.`;
      }
      await api.DELETE("/api/admin/v1/tenants/{slug}/sessions/{session_id}", {
        params: { path: { slug: tenant, session_id: which.id } },
      });
      return "Session revoked.";
    },
    onSuccess: async (message) => {
      setTarget(null);
      setStatus(message);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["user-sessions", tenant, userId] }),
        queryClient.invalidateQueries({ queryKey: ["sessions"] }),
      ]);
    },
  });

  if (query.isError) return <ProblemAlert error={query.error} />;
  const items = query.data?.items ?? [];

  return (
    <div className="space-y-3">
      <StatusMessage message={status} />
      <div className="flex justify-end">
        <Button variant="outline" size="sm" disabled={items.length === 0} onClick={() => setTarget("all")}>
          Revoke all sessions
        </Button>
      </div>
      <div className="rounded-md border">
        <Table aria-busy={query.isFetching}>
          <TableCaption className="sr-only">Active sessions of this user</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Signed in</TableHead>
              <TableHead scope="col">Last seen</TableHead>
              <TableHead scope="col">IP address</TableHead>
              <TableHead scope="col">User agent</TableHead>
              <TableHead scope="col">Methods</TableHead>
              <TableHead scope="col">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {query.isPending ? (
              <TableRow>
                <TableCell colSpan={6}>
                  <Skeleton className="h-5 w-full" />
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground h-20 text-center">
                  No active sessions.
                </TableCell>
              </TableRow>
            ) : (
              items.map((s) => (
                <TableRow key={s.id} data-session-id={s.id}>
                  <TableCell>{formatDateTime(s.created_at)}</TableCell>
                  <TableCell>{formatDateTime(s.last_seen_at)}</TableCell>
                  <TableCell>{s.ip ?? "—"}</TableCell>
                  <TableCell>
                    <span className="line-clamp-2 max-w-xs text-xs break-all">{s.user_agent ?? "—"}</span>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs">{s.amr.join(", ")}</code>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setTarget(s)}
                      aria-label={`Revoke session from ${formatDateTime(s.created_at)}`}
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <ConfirmDialog
        open={target !== null}
        title={target === "all" ? "Revoke all sessions?" : "Revoke session?"}
        description={
          <p>
            {target === "all"
              ? "The user is signed out everywhere and every refresh token issued from these sessions stops working."
              : "The user is signed out on that device and its refresh tokens stop working."}
          </p>
        }
        confirmLabel={target === "all" ? "Revoke all" : "Revoke session"}
        onConfirm={() => target && revoke.mutate(target)}
        onCancel={() => {
          revoke.reset();
          setTarget(null);
        }}
        pending={revoke.isPending}
        error={revoke.error}
      />
    </div>
  );
}

function UserCredentials({ userId }: { userId: string }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState<CredentialView | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const query = useQuery({
    queryKey: ["user-credentials", tenant, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/credentials", {
          params: { path: { slug: tenant, user_id: userId } },
          signal,
        }),
      ),
  });

  const remove = useMutation({
    mutationFn: async (credential: CredentialView) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/users/{user_id}/credentials/{credential_id}", {
        params: { path: { slug: tenant, user_id: userId, credential_id: credential.id } },
      });
      return credential;
    },
    onSuccess: async (credential) => {
      setTarget(null);
      setStatus(`${CREDENTIAL_KIND_LABELS[credential.kind]} “${credential.label}” removed.`);
      await queryClient.invalidateQueries({ queryKey: ["user-credentials", tenant, userId] });
    },
  });

  if (query.isError) return <ProblemAlert error={query.error} />;
  const items = query.data?.items ?? [];

  return (
    <div className="space-y-3">
      <StatusMessage message={status} />
      <div className="rounded-md border">
        <Table aria-busy={query.isFetching}>
          <TableCaption className="sr-only">Credentials of this user</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Kind</TableHead>
              <TableHead scope="col">Label</TableHead>
              <TableHead scope="col">Added</TableHead>
              <TableHead scope="col">Last used</TableHead>
              <TableHead scope="col">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {query.isPending ? (
              <TableRow>
                <TableCell colSpan={5}>
                  <Skeleton className="h-5 w-full" />
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground h-20 text-center">
                  No credentials.
                </TableCell>
              </TableRow>
            ) : (
              items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>{CREDENTIAL_KIND_LABELS[c.kind]}</TableCell>
                  <TableCell className="break-all">{c.label}</TableCell>
                  <TableCell>{formatDateTime(c.created_at)}</TableCell>
                  <TableCell>{formatDateTime(c.last_used_at)}</TableCell>
                  <TableCell>
                    {c.kind === "password" ? (
                      <span className="text-muted-foreground text-xs">Changed by the user</span>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setTarget(c)}
                        aria-label={`Remove ${CREDENTIAL_KIND_LABELS[c.kind]} ${c.label}`}
                      >
                        Remove
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <ConfirmDialog
        open={target !== null}
        title="Remove credential?"
        description={
          <p>
            {target?.kind === "totp"
              ? "The authenticator app and the user's recovery codes are removed. The user can enroll again."
              : "The user can no longer sign in with this passkey."}
          </p>
        }
        confirmLabel="Remove credential"
        onConfirm={() => target && remove.mutate(target)}
        onCancel={() => {
          remove.reset();
          setTarget(null);
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </div>
  );
}

/** WAI-ARIA tabs (manual activation is not needed: panels are cheap, arrows select directly). */
function Tabs({ active, onSelect }: { active: TabId; onSelect: (tab: TabId) => void }) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const index = TABS.findIndex((t) => t.id === active);
    let next: number | null = null;
    if (e.key === "ArrowRight") next = (index + 1) % TABS.length;
    else if (e.key === "ArrowLeft") next = (index - 1 + TABS.length) % TABS.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = TABS.length - 1;
    const target = next === null ? undefined : TABS[next];
    if (!target) return;
    e.preventDefault();
    const tab = target.id;
    onSelect(tab);
    refs.current[tab]?.focus();
  };
  return (
    <div role="tablist" aria-label="User sections" className="flex gap-1 border-b">
      {TABS.map((t) => (
        <button
          key={t.id}
          ref={(el) => {
            refs.current[t.id] = el;
          }}
          type="button"
          role="tab"
          id={`tab-${t.id}`}
          aria-selected={active === t.id}
          aria-controls={active === t.id ? `panel-${t.id}` : undefined}
          tabIndex={active === t.id ? 0 : -1}
          onClick={() => onSelect(t.id)}
          onKeyDown={onKeyDown}
          className={`-mb-px border-b-2 px-3 py-2 text-sm focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none ${
            active === t.id ? "border-foreground font-medium" : "text-muted-foreground border-transparent"
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function UserPage() {
  const tenant = useTenant();
  const { userId } = Route.useParams();
  const { tab = "overview" } = Route.useSearch();
  const navigate = useNavigate({ from: "/users/$userId" });
  const query = useQuery({
    queryKey: ["user", tenant, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}", {
          params: { path: { slug: tenant, user_id: userId } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="user-heading" className="space-y-4">
      <Link
        to="/t/$tenant/users"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
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
        <>
          <Tabs
            active={tab}
            onSelect={(next) => void navigate({ search: next === "overview" ? {} : { tab: next }, replace: true })}
          />
          <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0} className="focus:outline-none">
            {tab === "overview" && <UserDetails user={query.data} />}
            {tab === "sessions" && <UserSessions userId={userId} />}
            {tab === "credentials" && <UserCredentials userId={userId} />}
          </div>
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/users/$userId")({ validateSearch, component: UserPage });
