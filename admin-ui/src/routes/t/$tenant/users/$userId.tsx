import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { Ban, CircleCheck, KeyRound, MailCheck, Pencil, ShieldOff } from "lucide-react";
import { type FormEvent, type KeyboardEvent, type ReactNode, useRef, useState } from "react";
import { ApiError, type UserView, api, unwrap } from "@/api/client";
import { useAuth } from "@/auth/AuthProvider";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ADMINISTRATOR_ROLE } from "@/components/AddAdministrator";
import { DangerZone } from "@/components/DangerZone";
import { UserForm, type UserFormValues, NEW_USER, NoSmtpWarning, useSmtpAvailable } from "@/components/UserForm";
import {
  type AttributeDefinition,
  AttributeValueInput,
  attributeShape,
  pointerAttribute,
  textToValue,
  toApiJson,
  valueToText,
} from "@/components/AttributeForm";
import { ConfirmDialog, Modal } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { type RoleDto, RoleProblem } from "@/components/RoleForm";
import { type FieldErrors, SelectField, StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EXPORT_SCOPE_HINT, saveBlob, useCanExportUsers } from "@/lib/export";
import { formatDateTime } from "@/lib/format";

type SessionView = components["schemas"]["SessionView"];
type CredentialView = components["schemas"]["CredentialView"];

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "sessions", label: "Sessions" },
  { id: "credentials", label: "Credentials" },
  { id: "roles", label: "Roles" },
  { id: "attributes", label: "Attributes" },
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

type Confirm = "block" | "mfa" | null;

/** Summary of removed second factors, e.g. "an authenticator app and 2 passkeys". */
function removedSummary(removed: CredentialView[]): string {
  const totp = removed.filter((c) => c.kind === "totp").length;
  const passkeys = removed.filter((c) => c.kind === "webauthn").length;
  const parts = [
    totp ? (totp === 1 ? "the authenticator app (with its recovery codes)" : `${totp} authenticator apps`) : "",
    passkeys ? (passkeys === 1 ? "1 passkey" : `${passkeys} passkeys`) : "",
  ].filter(Boolean);
  return parts.join(" and ");
}

/**
 * Account actions of the user page (C-H1): edit email/username, mark the email verified,
 * block/unblock, send a password reset, reset MFA and delete. Each goes through the existing admin
 * API and shows the server's refusal (e.g. the last-administrator guard) inline.
 */
function UserAccountActions({ user }: { user: UserView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const smtpAvailable = useSmtpAvailable(tenant);
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [status, setStatus] = useState<string | null>(null);
  const userKey = ["user", tenant, user.id];

  const afterChange = async (saved?: UserView) => {
    if (saved) queryClient.setQueryData(userKey, saved);
    await queryClient.invalidateQueries({ queryKey: ["users", tenant] });
  };

  const update = useMutation({
    mutationFn: async (args: { body: components["schemas"]["UpdateUser"]; message: string }) => {
      const saved = unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/users/{user_id}", {
          params: { path: { slug: tenant, user_id: user.id } },
          body: args.body,
        }),
      );
      return { saved, message: args.message };
    },
    onMutate: () => setStatus(null),
    onSuccess: async ({ saved, message }) => {
      setEditing(false);
      setConfirm(null);
      setStatus(message);
      await afterChange(saved);
    },
  });

  const edit = (values: UserFormValues) => {
    const body: components["schemas"]["UpdateUser"] = {};
    if (values.email !== user.email) {
      body.email = values.email;
      // A new address is not verified until the user proves it (or an admin marks it).
      body.email_verified = false;
    }
    if (values.username !== (user.username ?? "")) body.username = values.username || null;
    if (Object.keys(body).length === 0) {
      setEditing(false);
      return;
    }
    update.mutate({ body, message: "Account saved." });
  };

  const recovery = useMutation({
    mutationFn: async () => {
      await api.POST("/api/admin/v1/tenants/{slug}/users/{user_id}/recovery", {
        params: { path: { slug: tenant, user_id: user.id } },
      });
    },
    onMutate: () => setStatus(null),
    onSuccess: () => setStatus(`Reset email sent to ${user.email}.`),
  });

  // Reset MFA: remove every TOTP and passkey credential (TOTP removal also drops the recovery codes).
  const resetMfa = useMutation({
    mutationFn: async () => {
      const credentials = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/credentials", {
          params: { path: { slug: tenant, user_id: user.id } },
        }),
      ).items.filter((c) => c.kind !== "password");
      const removed: CredentialView[] = [];
      try {
        for (const c of credentials) {
          await api.DELETE("/api/admin/v1/tenants/{slug}/users/{user_id}/credentials/{credential_id}", {
            params: { path: { slug: tenant, user_id: user.id, credential_id: c.id } },
          });
          removed.push(c);
        }
      } finally {
        await queryClient.invalidateQueries({ queryKey: ["user-credentials", tenant, user.id] });
      }
      return removed;
    },
    onMutate: () => setStatus(null),
    onSuccess: (removed) => {
      setConfirm(null);
      setStatus(
        removed.length === 0
          ? "The user has no authenticator app or passkey; nothing was removed."
          : `MFA reset: removed ${removedSummary(removed)}. The user can enroll again at the next sign-in.`,
      );
    },
  });

  const remove = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/users/{user_id}", {
        params: { path: { slug: tenant, user_id: user.id } },
      });
    },
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: userKey });
      await queryClient.invalidateQueries({ queryKey: ["users", tenant] });
      await navigate({ to: "/t/$tenant/users", params: { tenant } });
    },
  });

  const blocked = user.status === "blocked";
  const actionError = (update.error && !editing && confirm === null ? update.error : null) ?? recovery.error;

  return (
    <div className="space-y-4">
      <Card data-testid="user-account-actions">
        <CardHeader>
          <CardTitle>
            <h2>Account actions</h2>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <StatusMessage message={status} />
          {actionError ? <RoleProblem error={actionError} /> : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditing(true)} data-testid="user-edit">
              <Pencil aria-hidden="true" />
              Edit
            </Button>
            {!user.email_verified && (
              <Button
                variant="outline"
                size="sm"
                disabled={update.isPending}
                onClick={() => update.mutate({ body: { email_verified: true }, message: "Email marked as verified." })}
                data-testid="user-mark-verified"
              >
                <MailCheck aria-hidden="true" />
                Mark email verified
              </Button>
            )}
            {blocked ? (
              <Button
                variant="outline"
                size="sm"
                disabled={update.isPending}
                onClick={() => update.mutate({ body: { status: "active" }, message: "User unblocked. They can sign in again." })}
                data-testid="user-unblock"
              >
                <CircleCheck aria-hidden="true" />
                Unblock
              </Button>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setConfirm("block")} data-testid="user-block">
                <Ban aria-hidden="true" />
                Block
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              disabled={recovery.isPending}
              onClick={() => recovery.mutate()}
              data-testid="user-send-reset"
            >
              <KeyRound aria-hidden="true" />
              {recovery.isPending ? "Sending…" : "Send password reset"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setConfirm("mfa")} data-testid="user-reset-mfa">
              <ShieldOff aria-hidden="true" />
              Reset MFA
            </Button>
          </div>
          {smtpAvailable === false && <NoSmtpWarning action="Sending a password reset" />}
          <p className="text-muted-foreground text-xs">
            The password reset email links to the tenant's recovery page and is valid for one hour. Blocked users get no
            reset email.
          </p>
        </CardContent>
      </Card>

      <DangerZone
        title="Delete this user"
        description="Deletes the user with their credentials, sessions, role assignments and organization memberships. Their tokens stop working. This cannot be undone."
        confirmText={user.email}
        actionLabel="Delete user"
        onConfirm={() => remove.mutate()}
        pending={remove.isPending}
        error={remove.error}
      />

      <Modal
        open={editing}
        onClose={() => {
          setEditing(false);
          update.reset();
        }}
        title="Edit account"
      >
        <UserForm
          mode="edit"
          initial={{ ...NEW_USER, email: user.email, username: user.username ?? "" }}
          pending={update.isPending}
          error={editing ? update.error : null}
          onSubmit={edit}
        />
        <div className="flex justify-end">
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setEditing(false);
              update.reset();
            }}
            disabled={update.isPending}
          >
            Cancel
          </Button>
        </div>
      </Modal>

      <ConfirmDialog
        open={confirm === "block"}
        title="Block this user?"
        description={
          <p>
            {user.email} can no longer sign in or get new tokens until you unblock the account. Nothing else changes.
          </p>
        }
        confirmLabel="Block user"
        onConfirm={() => update.mutate({ body: { status: "blocked" }, message: "User blocked. They can no longer sign in." })}
        onCancel={() => {
          update.reset();
          setConfirm(null);
        }}
        pending={update.isPending}
        error={confirm === "block" ? update.error : null}
      />
      <ConfirmDialog
        open={confirm === "mfa"}
        title="Reset MFA?"
        description={
          <p>
            Removes the user's authenticator app (with its recovery codes) and every passkey. Their password stays. If
            the tenant requires MFA, they enroll again at the next sign-in.
          </p>
        }
        confirmLabel="Reset MFA"
        onConfirm={() => resetMfa.mutate()}
        onCancel={() => {
          resetMfa.reset();
          setConfirm(null);
        }}
        pending={resetMfa.isPending}
        error={resetMfa.error}
      />
    </div>
  );
}

/** The user's organization memberships with their roles in each: one request. */
async function fetchMemberships(tenant: string, userId: string, signal: AbortSignal) {
  return unwrap(
    await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/organizations", {
      params: { path: { slug: tenant, user_id: userId } },
      signal,
    }),
  ).items;
}

function UserOrganizations({ userId }: { userId: string }) {
  const tenant = useTenant();
  const query = useQuery({
    queryKey: ["user-orgs", tenant, userId],
    queryFn: ({ signal }) => fetchMemberships(tenant, userId, signal),
    enabled: tenant !== SYSTEM_TENANT,
  });
  if (tenant === SYSTEM_TENANT) return null;
  return (
    <Card data-testid="user-organizations">
      <CardHeader>
        <CardTitle>Organizations</CardTitle>
      </CardHeader>
      <CardContent>
        {query.isError ? (
          <ProblemAlert error={query.error} />
        ) : query.isPending ? (
          <Skeleton className="h-5 w-1/2" />
        ) : query.data.length === 0 ? (
          <p className="text-muted-foreground text-sm">Not a member of any organization.</p>
        ) : (
          <ul className="divide-y">
            {query.data.map(({ organization: org, roles }) => (
              <li key={org.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 text-sm">
                <Link
                  to="/t/$tenant/organizations/$orgId/members"
                  params={{ tenant, orgId: org.id }}
                  className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                >
                  {org.display_name}
                </Link>
                <code className="text-muted-foreground text-xs">{org.slug}</code>
                <span className="text-muted-foreground">
                  {roles.length === 0 ? "No roles" : `Roles: ${roles.map((r) => r.name).join(", ")}`}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
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

function UserRoles({ userId }: { userId: string }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const { user: admin } = useAuth();
  const [selected, setSelected] = useState("");
  const [target, setTarget] = useState<RoleDto | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const held = useQuery({
    queryKey: ["user-roles", tenant, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/roles", {
          params: { path: { slug: tenant, user_id: userId } },
          signal,
        }),
      ),
  });
  const all = useQuery({
    queryKey: ["roles", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/roles", { params: { path: { slug: tenant } }, signal })),
  });
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["user-roles", tenant, userId] });
    await queryClient.invalidateQueries({ queryKey: ["role-users", tenant] });
  };

  const assign = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/users/{user_id}/roles/{name}", {
          params: { path: { slug: tenant, user_id: userId, name } },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (a) => {
      setSelected("");
      setStatus(`Role ${a.role.name} assigned.`);
      await refresh();
    },
  });
  const unassign = useMutation({
    mutationFn: async (role: RoleDto) => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/users/{user_id}/roles/{name}", {
        params: { path: { slug: tenant, user_id: userId, name: role.name } },
      });
      return role;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (role) => {
      setTarget(null);
      setStatus(`Role ${role.name} removed.`);
      await refresh();
    },
  });

  // Removing your own administrator role in the system tenant locks you out of the console.
  const removingOwnAdmin = tenant === SYSTEM_TENANT && userId === admin.profile.sub && target?.name === ADMINISTRATOR_ROLE;

  if (held.isError) return <ProblemAlert error={held.error} />;
  const items = held.data?.items ?? [];
  const available = (all.data?.items ?? []).filter((r) => !items.some((h) => h.id === r.id));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (selected) assign.mutate(selected);
  };

  return (
    <div className="space-y-3">
      <StatusMessage message={status} />
      {assign.error ? <RoleProblem error={assign.error} /> : null}
      {available.length > 0 ? (
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Assign role">
          <div className="min-w-56">
            <SelectField
              label="Role"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              options={[{ value: "", label: "Choose a role" }, ...available.map((r) => ({ value: r.name, label: r.name }))]}
              data-testid="assign-role-select"
            />
          </div>
          <Button type="submit" disabled={!selected || assign.isPending} data-testid="assign-role">
            {assign.isPending ? "Assigning…" : "Assign role"}
          </Button>
          <Link to="/t/$tenant/roles" params={{ tenant }} className="text-sm underline underline-offset-4">
            Manage roles
          </Link>
        </form>
      ) : all.isSuccess && held.isSuccess ? (
        // C-L5: no empty select when there is nothing to assign.
        <p className="text-muted-foreground text-sm" data-testid="no-assignable-roles">
          {all.data.items.length === 0 ? "This tenant has no roles yet. " : "The user holds every role of this tenant. "}
          <Link to="/t/$tenant/roles" params={{ tenant }} className="text-link underline underline-offset-4">
            Manage roles
          </Link>
        </p>
      ) : null}
      {all.isError ? <ProblemAlert error={all.error} /> : null}
      <div className="rounded-md border">
        <Table aria-busy={held.isFetching}>
          <TableCaption className="sr-only">Roles of this user</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Role</TableHead>
              <TableHead scope="col">Permissions</TableHead>
              <TableHead scope="col">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {held.isPending ? (
              <TableRow>
                <TableCell colSpan={3}>
                  <Skeleton className="h-5 w-full" />
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="text-muted-foreground h-20 text-center">
                  No roles assigned.
                </TableCell>
              </TableRow>
            ) : (
              items.map((r) => (
                <TableRow key={r.id} data-testid={`user-role-${r.name}`}>
                  <TableCell>
                    <Link
                      to="/t/$tenant/roles/$roleName"
                      params={{ tenant, roleName: r.name }}
                      className="font-mono underline-offset-4 hover:underline"
                    >
                      {r.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs break-all">{r.permissions.join(" ") || "—"}</code>
                  </TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => setTarget(r)} aria-label={`Remove role ${r.name}`}>
                      Remove
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
        title={removingOwnAdmin ? "Remove your own administrator role?" : "Remove role?"}
        description={
          <div className="space-y-3">
            {removingOwnAdmin ? (
              <div className="space-y-2" data-testid="own-admin-warning">
                <p>
                  You are signed in to this console with this role. Once it is removed, your next sign-in loses access to
                  the console unless another of your roles grants admin scopes.
                </p>
                <p>
                  At least one active user must keep a role granting <code>admin:write</code>: if you are the last one, the
                  server refuses. Add another administrator first (Users, Add administrator).
                </p>
              </div>
            ) : null}
            <p>{`Tokens issued from now on no longer carry ${target?.name ?? "the role"}.`}</p>
            {unassign.error ? <RoleProblem error={unassign.error} /> : null}
          </div>
        }
        confirmLabel={removingOwnAdmin ? "Remove my administrator role" : "Remove role"}
        onConfirm={() => target && unassign.mutate(target)}
        onCancel={() => {
          unassign.reset();
          setTarget(null);
        }}
        pending={unassign.isPending}
      />
    </div>
  );
}

function UserAttributesForm({
  userId,
  definitions,
  stored,
}: {
  userId: string;
  definitions: AttributeDefinition[];
  stored: Record<string, unknown>;
}) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const initial = () =>
    Object.fromEntries(definitions.map((d) => [d.name, valueToText(attributeShape(d.schema), stored[d.name])]));
  const [texts, setTexts] = useState<Record<string, string>>(initial);
  const [local, setLocal] = useState<FieldErrors>({});
  const [status, setStatus] = useState<string | null>(null);
  const orphans = Object.entries(stored).filter(([k]) => !definitions.some((d) => d.name === k));

  const save = useMutation({
    mutationFn: async (values: Record<string, unknown>) =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/users/{user_id}/attributes", {
          params: { path: { slug: tenant, user_id: userId } },
          body: { values: toApiJson(values) },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: (saved) => {
      queryClient.setQueryData(["user-attributes", tenant, userId], saved);
      setStatus("Attributes saved.");
    },
  });

  // Field errors of a 422 name JSON pointers (`/department`, `/tags/0`); group them by attribute.
  const server: FieldErrors = {};
  if (save.error instanceof ApiError) {
    for (const e of save.error.problem.errors) {
      if (e.field.startsWith("/")) (server[pointerAttribute(e.field)] ??= []).push({ message: e.message });
    }
  }
  const otherError = save.error && Object.keys(server).length === 0 ? save.error : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const issues: FieldErrors = {};
    const values: Record<string, unknown> = {};
    for (const d of definitions) {
      const parsed = textToValue(attributeShape(d.schema), texts[d.name] ?? "");
      if (parsed.error) issues[d.name] = [{ message: parsed.error }];
      else if (parsed.value !== undefined) values[d.name] = parsed.value;
      else if (d.required) issues[d.name] = [{ message: "A value is required." }];
    }
    setLocal(issues);
    if (Object.keys(issues).length > 0) return;
    save.mutate(values);
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate aria-label="User attributes" data-testid="user-attributes-form">
      {save.error instanceof ApiError && Object.keys(server).length > 0 && (
        <p role="alert" className="text-destructive text-sm">
          The values were not saved. Fix the marked attributes.
        </p>
      )}
      {otherError ? <ProblemAlert error={otherError} /> : null}
      {definitions.map((d) => (
        <AttributeValueInput
          key={d.name}
          definition={d}
          text={texts[d.name] ?? ""}
          onChange={(text) => setTexts((t) => ({ ...t, [d.name]: text }))}
          errors={local[d.name] ?? server[d.name]}
        />
      ))}
      {orphans.length > 0 && (
        <div className="space-y-1 text-sm">
          <p className="font-medium">Stored values without a definition</p>
          <p className="text-muted-foreground text-xs">Kept as they are; they cannot be edited here.</p>
          <dl className="divide-y">
            {orphans.map(([k, v]) => (
              <Field key={k} label={k}>
                <code className="text-xs">{JSON.stringify(v)}</code>
              </Field>
            ))}
          </dl>
        </div>
      )}
      <Button type="submit" disabled={save.isPending} data-testid="save-user-attributes">
        {save.isPending ? "Saving…" : "Save attributes"}
      </Button>
      <StatusMessage message={status} />
    </form>
  );
}

function UserAttributes({ userId }: { userId: string }) {
  const tenant = useTenant();
  const definitions = useQuery({
    queryKey: ["attributes", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/attributes", { params: { path: { slug: tenant } }, signal })),
  });
  const values = useQuery({
    queryKey: ["user-attributes", tenant, userId],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/attributes", {
          params: { path: { slug: tenant, user_id: userId } },
          signal,
        }),
      ),
  });
  if (definitions.isError) return <ProblemAlert error={definitions.error} />;
  if (values.isError) return <ProblemAlert error={values.error} />;
  if (definitions.isPending || values.isPending) {
    return (
      <div role="status" aria-label="Loading attributes" className="space-y-2">
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-6 w-2/3" />
      </div>
    );
  }
  if (definitions.data.items.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        This tenant defines no attributes.{" "}
        <Link to="/t/$tenant/attributes" params={{ tenant }} className="underline underline-offset-4">
          Define attributes
        </Link>
      </p>
    );
  }
  return (
    <UserAttributesForm
      userId={userId}
      definitions={definitions.data.items}
      stored={values.data.values as unknown as Record<string, unknown>}
    />
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

/**
 * "Export" (the user's record) and "GDPR export" (the data-subject bundle) downloads. Disabled with
 * an explanation when the token lacks admin:users:export / admin:write. Never password hashes.
 */
function UserExport({ userId }: { userId: string }) {
  const tenant = useTenant();
  const canExport = useCanExportUsers();
  const [status, setStatus] = useState<string | null>(null);
  const download = useMutation({
    mutationFn: async (profile: "user" | "gdpr") => {
      const blob = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}/export", {
          params: { path: { slug: tenant, user_id: userId }, query: profile === "gdpr" ? { profile: "gdpr" } : {} },
          parseAs: "blob",
        }),
      );
      const filename = profile === "gdpr" ? `user-${userId}.gdpr.json` : `user-${userId}.json`;
      saveBlob(new Blob([blob], { type: "application/json" }), filename);
      return filename;
    },
    onMutate: () => setStatus(null),
    onSuccess: (filename) => setStatus(`Downloaded ${filename}.`),
  });
  const hintId = `user-export-hint-${userId}`;
  return (
    <div className="space-y-2" data-testid="user-export">
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => download.mutate("user")}
          disabled={!canExport || download.isPending}
          aria-describedby={canExport ? undefined : hintId}
          data-testid="export-user"
        >
          Export
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => download.mutate("gdpr")}
          disabled={!canExport || download.isPending}
          aria-describedby={canExport ? undefined : hintId}
          data-testid="export-user-gdpr"
        >
          GDPR export
        </Button>
      </div>
      {!canExport && (
        <p id={hintId} className="text-muted-foreground text-xs" data-testid="export-scope-missing">
          {EXPORT_SCOPE_HINT}
        </p>
      )}
      {download.error ? <ProblemAlert error={download.error} /> : null}
      <StatusMessage message={status} />
    </div>
  );
}

function UserPage() {
  const tenant = useTenant();
  const { userId } = Route.useParams();
  const { tab = "overview" } = Route.useSearch();
  const navigate = useNavigate({ from: "/t/$tenant/users/$userId" });
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
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h1 id="user-heading" className="text-xl font-semibold break-all">
          {query.data?.email ?? "User"}
        </h1>
        {query.isSuccess ? <UserExport userId={userId} /> : null}
      </div>
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
            {tab === "overview" && (
              <div className="space-y-4">
                <UserDetails user={query.data} />
                <UserOrganizations userId={userId} />
                <UserAccountActions user={query.data} />
              </div>
            )}
            {tab === "sessions" && <UserSessions userId={userId} />}
            {tab === "credentials" && <UserCredentials userId={userId} />}
            {tab === "roles" && <UserRoles userId={userId} />}
            {tab === "attributes" && <UserAttributes userId={userId} />}
          </div>
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/users/$userId")({ validateSearch, component: UserPage });
