// Users of a tenant: create (password or invitation), exact email search, the import page and the
// bulk NDJSON export. In the system tenant also "Add administrator" (C-H2).
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { Search, UserPlus, X } from "lucide-react";
import { type FormEvent, useId, useMemo, useState } from "react";
import { type UserView, api, unwrap } from "@/api/client";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";
import { AddAdministrator } from "@/components/AddAdministrator";
import { Modal } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { ProblemAlert } from "@/components/ProblemAlert";
import { NEW_USER, UserForm, type UserFormValues, useSmtpAvailable } from "@/components/UserForm";
import { StatusMessage, controlClass } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EXPORT_SCOPE_HINT, saveBlob, useCanExportUsers } from "@/lib/export";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, UserView>();

function columnsFor(tenant: string) {
  return col.columns([
    col.accessor("email", {
      header: "Email",
      cell: (info) => (
        <Link
          to="/t/$tenant/users/$userId"
          params={{ tenant, userId: info.row.original.id }}
          className="font-medium underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {info.getValue()}
        </Link>
      ),
    }),
    col.accessor("email_verified", {
      header: "Verified",
      cell: (info) => (info.getValue() ? "Yes" : "No"),
    }),
    col.accessor("status", {
      header: "Status",
      cell: (info) => (
        <Badge variant={info.getValue() === "blocked" ? "destructive" : "secondary"}>{info.getValue()}</Badge>
      ),
    }),
    col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
    col.accessor("last_login_at", { header: "Last login", cell: (info) => formatDateTime(info.getValue()) }),
  ]);
}

/** The failure marker the server appends when a bulk export breaks off mid-stream. */
const EXPORT_FAILED_MARKER = '{"error":"export_failed"}';

/** "Export all (NDJSON)": downloads every user (never password hashes) through the typed client. */
function ExportAll({ tenant }: { tenant: string }) {
  const canExport = useCanExportUsers();
  const [status, setStatus] = useState<string | null>(null);
  const exportAll = useMutation({
    mutationFn: async () => {
      const blob = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users/export", {
          params: { path: { slug: tenant } },
          parseAs: "blob",
        }),
      );
      const tail = (await blob.slice(Math.max(0, blob.size - 64)).text()).trim();
      if (tail.endsWith(EXPORT_FAILED_MARKER)) {
        throw new Error("The export broke off on the server before every user was written. Try again.");
      }
      const filename = `${tenant}.users.ndjson`;
      saveBlob(new Blob([blob], { type: "application/x-ndjson" }), filename);
      return filename;
    },
    onMutate: () => setStatus(null),
    onSuccess: (filename) => setStatus(`Downloaded ${filename}.`),
  });
  const hintId = `export-all-hint-${tenant}`;
  return (
    <div className="space-y-2">
      <Button
        variant="outline"
        size="sm"
        onClick={() => exportAll.mutate()}
        disabled={!canExport || exportAll.isPending}
        aria-describedby={canExport ? undefined : hintId}
        data-testid="export-all-users"
      >
        {exportAll.isPending ? "Exporting…" : "Export all (NDJSON)"}
      </Button>
      {!canExport && (
        <p id={hintId} className="text-muted-foreground text-xs" data-testid="export-scope-missing">
          {EXPORT_SCOPE_HINT}
        </p>
      )}
      {exportAll.error ? <ProblemAlert error={exportAll.error} /> : null}
      <StatusMessage message={status} />
    </div>
  );
}

interface Created {
  user: UserView;
  invited: boolean;
}

/** "Create user": UserForm in a dialog; the outcome is announced on the list. */
function CreateUser({
  tenant,
  onCreated,
  variant = "default",
  testId = "create-user",
}: {
  tenant: string;
  onCreated: (c: Created) => void;
  variant?: "default" | "outline";
  testId?: string;
}) {
  const queryClient = useQueryClient();
  const smtpAvailable = useSmtpAvailable(tenant);
  const [open, setOpen] = useState(false);
  const create = useMutation({
    mutationFn: async (values: UserFormValues): Promise<Created> => {
      const invited = values.method === "invite";
      const user = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/users", {
          params: { path: { slug: tenant } },
          body: {
            email: values.email,
            ...(values.username ? { username: values.username } : {}),
            ...(values.emailVerified ? { email_verified: true } : {}),
            ...(invited ? { invite: true } : { password: values.password }),
          },
        }),
      );
      return { user, invited };
    },
    onSuccess: async (created) => {
      setOpen(false);
      onCreated(created);
      await queryClient.invalidateQueries({ queryKey: ["users", tenant] });
    },
  });
  const close = () => {
    setOpen(false);
    create.reset();
  };
  return (
    <>
      <Button size="sm" variant={variant} onClick={() => setOpen(true)} data-testid={testId}>
        <UserPlus aria-hidden="true" />
        Create user
      </Button>
      <Modal open={open} onClose={close} title="Create user">
        <UserForm
          mode="create"
          initial={NEW_USER}
          pending={create.isPending}
          error={create.error}
          onSubmit={(values) => create.mutate(values)}
          smtpAvailable={smtpAvailable}
        />
        <div className="flex justify-end">
          <Button type="button" variant="outline" onClick={close} disabled={create.isPending}>
            Cancel
          </Button>
        </div>
      </Modal>
    </>
  );
}

/** Exact email lookup (`?email=`): at most one user. */
function EmailSearch({ value, onSearch }: { value: string; onSearch: (email: string) => void }) {
  const id = useId();
  const [draft, setDraft] = useState(value);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSearch(draft.trim());
  };
  return (
    <form role="search" onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Find a user by email">
      <div className="min-w-64 flex-1 space-y-1.5 sm:max-w-sm">
        <label htmlFor={id} className="block text-sm font-medium">
          Find by email
        </label>
        <input
          id={id}
          type="search"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="name@example.com"
          autoComplete="off"
          className={controlClass}
          aria-describedby={`${id}-hint`}
          data-testid="user-search"
        />
        <p id={`${id}-hint`} className="text-muted-foreground text-xs">
          The exact address (not case-sensitive).
        </p>
      </div>
      <div className="flex gap-2 pb-5">
        <Button type="submit" variant="outline" size="sm" data-testid="user-search-submit">
          <Search aria-hidden="true" />
          Search
        </Button>
        {value && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              setDraft("");
              onSearch("");
            }}
            data-testid="user-search-clear"
          >
            <X aria-hidden="true" />
            Clear search
          </Button>
        )}
      </div>
    </form>
  );
}

function UsersPage() {
  const tenant = useTenant();
  const columns = useMemo(() => columnsFor(tenant), [tenant]);
  const pager = useCursorPager();
  const [email, setEmail] = useState("");
  const [created, setCreated] = useState<Created | null>(null);
  const query = useQuery({
    queryKey: ["users", tenant, email ? { email } : pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/users", {
          params: {
            path: { slug: tenant },
            query: email ? { email } : { limit: PAGE_SIZE, after: pager.after },
          },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  const noUsersAtAll = !email && pager.page === 1 && query.isSuccess && query.data.items.length === 0;

  return (
    <section aria-labelledby="users-heading" className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h1 id="users-heading" className="text-xl font-semibold">
          Users
        </h1>
        <div className="flex flex-wrap items-start gap-2">
          <CreateUser tenant={tenant} onCreated={setCreated} />
          {tenant === SYSTEM_TENANT && <AddAdministrator />}
          <Button asChild variant="outline" size="sm">
            <Link to="/t/$tenant/users/import" params={{ tenant }} data-testid="import-users-link">
              Import users
            </Link>
          </Button>
          <ExportAll tenant={tenant} />
        </div>
      </div>
      <div aria-live="polite" role="status" data-testid="user-created-status">
        {created && (
          <p className="rounded-md border px-3 py-2 text-sm">
            {created.invited ? "Invitation sent to " : "User created: "}
            <Link
              to="/t/$tenant/users/$userId"
              params={{ tenant, userId: created.user.id }}
              className="text-link underline underline-offset-4"
            >
              {created.user.email}
            </Link>
            .
          </p>
        )}
      </div>
      <EmailSearch value={email} onSearch={setEmail} />
      {noUsersAtAll ? (
        <div className="space-y-3 rounded-md border p-6 text-center" data-testid="users-empty">
          <p className="font-medium">No users yet</p>
          <p className="text-muted-foreground text-sm">
            Create a user with a password, invite someone by email, or import users from another system.
          </p>
          <div className="flex justify-center">
            <CreateUser tenant={tenant} onCreated={setCreated} variant="outline" testId="create-user-empty" />
          </div>
        </div>
      ) : (
        <DataTable
          caption={email ? `Users with the email ${email}` : "Users"}
          columns={columns}
          data={query.data?.items}
          getRowId={(u) => u.id}
          isPending={query.isPending}
          isFetching={query.isFetching}
          error={query.error}
          emptyMessage={email ? `No user has the email ${email}.` : "No users on this page."}
          pager={pager}
          nextCursor={email ? null : query.data?.next_cursor}
        />
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/users/")({ component: UsersPage });
