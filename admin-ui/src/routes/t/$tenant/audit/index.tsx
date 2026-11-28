// Audit log of a tenant: filters kept in the URL, readable action labels and groups
// (lib/audit-labels.ts), and actors/targets resolved to emails and client names (C-M8). Each
// unique id is fetched once per session through react-query (a record that does not exist is
// remembered as such), and the lookups are paced (see `paced`) so a page of events never bursts past
// the admin API rate limit; ids that do not resolve (deleted users, sessions, keys) are shown
// shortened, with the full value and a copy button in the details.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { type FormEvent, useId, useMemo, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { SYSTEM_TENANT, useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { Modal } from "@/components/ConfirmDialog";
import { CopyField } from "@/components/CopyField";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { SelectField, TextField, controlClass } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AUDIT_ACTIONS, type AuditAction, auditActionGroups, auditTargetKind, isAuditAction } from "@/lib/audit-labels";
import { formatDateTime } from "@/lib/format";

type AuditEventView = components["schemas"]["AuditEventView"];
type AuditActorView = components["schemas"]["AuditActorView"];
type AuditOutcome = components["schemas"]["AuditOutcome"];

const ACTION_GROUPS = auditActionGroups();

const OUTCOMES: readonly AuditOutcome[] = ["success", "failure"];

/** Filters as kept in the URL (`from`/`to` are datetime-local values in the browser's time zone). */
interface AuditSearch {
  from?: string;
  to?: string;
  action?: AuditAction;
  outcome?: AuditOutcome;
  actor?: string;
  target?: string;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function validateSearch(search: Record<string, unknown>): AuditSearch {
  const action = str(search.action);
  const outcome = str(search.outcome);
  return {
    from: str(search.from),
    to: str(search.to),
    action: action && isAuditAction(action) ? action : undefined,
    outcome: outcome && (OUTCOMES as readonly string[]).includes(outcome) ? (outcome as AuditOutcome) : undefined,
    actor: str(search.actor),
    target: str(search.target),
  };
}

/** datetime-local value -> RFC 3339 (UTC); invalid values are dropped. */
function toRfc3339(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

const PAGE_SIZE = 50;
const col = createColumnHelper<DataTableFeatures, AuditEventView>();

/** The action filter: labelled actions grouped by area (optgroups); the value is the API name. */
function ActionSelect({ value, onChange }: { value: string; onChange: (e: { target: { value: string } }) => void }) {
  const id = useId();
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        Action
      </label>
      <select id={id} name="action" value={value} onChange={onChange} className={controlClass} data-testid="audit-action-filter">
        <option value="">Any action</option>
        {ACTION_GROUPS.map(({ group, actions }) => (
          <optgroup key={group} label={group}>
            {actions.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </div>
  );
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** First characters of a long id, for table cells (the details show the full value). */
function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

type RefKind = "user" | "client";

/** A user or client the console can look up: which tenant it lives in and its id. */
interface Ref {
  kind: RefKind;
  tenant: string;
  id: string;
}

/**
 * The record an actor names. Admin actors are console administrators (users of the system tenant,
 * by id) or management API clients (client ids of the system tenant); user and client actors
 * belong to this tenant.
 */
function actorRef(actor: AuditActorView, tenant: string): Ref | null {
  if (!actor.id) return null;
  if (actor.kind === "admin") return { kind: UUID.test(actor.id) ? "user" : "client", tenant: SYSTEM_TENANT, id: actor.id };
  if (actor.kind === "user") return { kind: "user", tenant, id: actor.id };
  if (actor.kind === "client") return { kind: "client", tenant, id: actor.id };
  return null;
}

function targetRef(event: AuditEventView, tenant: string): Ref | null {
  if (!event.target) return null;
  const kind = auditTargetKind(event.action);
  if (kind === "user" && !UUID.test(event.target)) return null;
  return kind ? { kind, tenant, id: event.target } : null;
}

/**
 * Lookups share the admin API's per-IP rate limit (default 20 requests per second, burst 20) with
 * everything else the console loads, and one page of 50 events can name up to 100 different users
 * and clients. Starting them all at once would exhaust the limit and make the console's own
 * requests fail, so each lookup starts at least LOOKUP_INTERVAL_MS after the previous one (at most
 * 10 per second, half of the default limit); names fill in as they arrive.
 */
const LOOKUP_INTERVAL_MS = 100;
let nextLookupAt = 0;

function paced<T>(signal: AbortSignal, run: () => Promise<T>): Promise<T> {
  const now = Date.now();
  const at = Math.max(now, nextLookupAt);
  nextLookupAt = at + LOOKUP_INTERVAL_MS;
  if (at === now) return run();
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, at - now);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  }).then(run);
}

const isNotFound = (error: unknown) => error instanceof ApiError && error.status === 404;
const isTooManyRequests = (error: unknown) => error instanceof ApiError && error.status === 429;

/**
 * Email or client name of a ref, or null when the record does not exist (any more). Both answers
 * are cached for the session, so every unique id costs one request; a refused lookup (429) is
 * retried after a pause, other errors leave the id unresolved.
 */
function useResolved(ref: Ref | null): string | null {
  const query = useQuery({
    queryKey: ["audit-ref", ref?.kind, ref?.tenant, ref?.id],
    enabled: ref !== null,
    staleTime: Number.POSITIVE_INFINITY,
    retry: (failureCount, error) => isTooManyRequests(error) && failureCount < 3,
    retryDelay: (attempt) => 1000 * 2 ** attempt,
    // A failed lookup is not repeated whenever the table mounts again (filter change, paging).
    retryOnMount: false,
    queryFn: ({ signal }) =>
      paced(signal, async () => {
        if (!ref) return null;
        try {
          if (ref.kind === "user") {
            return unwrap(
              await api.GET("/api/admin/v1/tenants/{slug}/users/{user_id}", {
                params: { path: { slug: ref.tenant, user_id: ref.id } },
                signal,
              }),
            ).email;
          }
          return unwrap(
            await api.GET("/api/admin/v1/tenants/{slug}/clients/{client_id}", {
              params: { path: { slug: ref.tenant, client_id: ref.id } },
              signal,
            }),
          ).name;
        } catch (error) {
          if (isNotFound(error)) return null;
          throw error;
        }
      }),
  });
  return query.data ?? null;
}

/** An actor or target cell: the resolved name linked to its page, or the shortened raw id. */
function RefCell({ target, raw, prefix }: { target: Ref | null; raw: string | null | undefined; prefix?: string }) {
  const name = useResolved(target);
  if (target && name) {
    const className = "text-link underline-offset-4 hover:underline";
    return (
      <span className="text-xs break-all" data-testid="audit-ref" data-resolved="true">
        {prefix ? <span className="text-muted-foreground">{prefix} </span> : null}
        {target.kind === "user" ? (
          <Link to="/t/$tenant/users/$userId" params={{ tenant: target.tenant, userId: target.id }} className={className}>
            {name}
          </Link>
        ) : (
          <Link to="/t/$tenant/clients/$clientId" params={{ tenant: target.tenant, clientId: target.id }} className={className}>
            {name}
          </Link>
        )}
      </span>
    );
  }
  if (!raw) return <span className="text-xs">{prefix ?? "—"}</span>;
  return (
    <span className="text-xs" data-testid="audit-ref" data-resolved="false">
      {prefix ? <span className="text-muted-foreground">{prefix} </span> : null}
      <span className="font-mono" title={raw}>
        {shortId(raw)}
      </span>
      {raw.length > 12 && <span className="sr-only"> (shortened; the full id is in the details)</span>}
    </span>
  );
}

const ACTOR_KIND_LABELS: Record<AuditActorView["kind"], string> = {
  user: "User",
  client: "Client",
  admin: "Admin",
  system: "System",
};

function AuditFilters({ search }: { search: AuditSearch }) {
  const navigate = useNavigate({ from: Route.fullPath });
  const [draft, setDraft] = useState<AuditSearch>(search);
  const set = (key: keyof AuditSearch) => (e: { target: { value: string } }) =>
    setDraft((d) => ({ ...d, [key]: e.target.value || undefined }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void navigate({ search: validateSearch({ ...draft }) });
  };

  return (
    <form onSubmit={submit} aria-label="Filter audit events" className="grid gap-3 rounded-md border p-4 sm:grid-cols-3">
      <TextField
        label="From"
        name="from"
        type="datetime-local"
        optional
        value={draft.from ?? ""}
        onChange={set("from")}
      />
      <TextField label="To" name="to" type="datetime-local" optional value={draft.to ?? ""} onChange={set("to")} />
      <ActionSelect value={draft.action ?? ""} onChange={set("action")} />
      <SelectField
        label="Outcome"
        name="outcome"
        value={draft.outcome ?? ""}
        onChange={set("outcome")}
        options={[{ value: "", label: "Any outcome" }, ...OUTCOMES.map((o) => ({ value: o, label: o }))]}
      />
      <TextField
        label="Actor"
        name="actor"
        optional
        hint="User id, client id or admin subject."
        value={draft.actor ?? ""}
        onChange={set("actor")}
      />
      <TextField
        label="Target"
        name="target"
        optional
        hint="User, client or session id."
        value={draft.target ?? ""}
        onChange={set("target")}
      />
      <div className="flex gap-2 sm:col-span-3">
        <Button type="submit">Apply filters</Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setDraft({});
            void navigate({ search: {} });
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}

function AuditTable({ search }: { search: AuditSearch }) {
  const tenant = useTenant();
  const pager = useCursorPager();
  const [selected, setSelected] = useState<AuditEventView | null>(null);

  const query = useQuery({
    queryKey: ["audit-events", tenant, search, pager.after],
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/audit-events", {
          params: {
            path: { slug: tenant },
            query: {
              limit: PAGE_SIZE,
              cursor: pager.after,
              from: toRfc3339(search.from),
              to: toRfc3339(search.to),
              action: search.action,
              outcome: search.outcome,
              actor: search.actor,
              target: search.target,
            },
          },
          signal,
        }),
      ),
    placeholderData: keepPreviousData,
  });

  const columns = useMemo(
    () =>
      col.columns([
        col.accessor("at", { header: "Time", cell: (info) => formatDateTime(info.getValue()) }),
        col.accessor("action", {
          header: "Action",
          cell: (info) => (
            <span className="flex flex-col">
              <span>{AUDIT_ACTIONS[info.getValue()].label}</span>
              <span className="text-muted-foreground font-mono text-xs">{info.getValue()}</span>
            </span>
          ),
        }),
        col.accessor("outcome", {
          header: "Outcome",
          cell: (info) => (
            <Badge variant={info.getValue() === "failure" ? "destructive" : "secondary"}>{info.getValue()}</Badge>
          ),
        }),
        col.accessor("actor", {
          header: "Actor",
          cell: (info) => (
            <RefCell
              target={actorRef(info.getValue(), tenant)}
              raw={info.getValue().id}
              prefix={`${ACTOR_KIND_LABELS[info.getValue().kind]}${info.getValue().id ? ":" : ""}`}
            />
          ),
        }),
        col.accessor("target", {
          header: "Target",
          cell: (info) => <RefCell target={targetRef(info.row.original, tenant)} raw={info.getValue()} />,
        }),
        col.accessor("ip", { header: "IP address", cell: (info) => info.getValue() ?? "—" }),
        col.display({
          id: "details",
          header: () => <span className="sr-only">Details</span>,
          cell: (info) => (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSelected(info.row.original)}
              aria-label={`Details of ${AUDIT_ACTIONS[info.row.original.action].label} at ${formatDateTime(info.row.original.at)}`}
            >
              Details
            </Button>
          ),
        }),
      ]),
    [tenant],
  );

  return (
    <>
      <DataTable
        caption="Audit events"
        columns={columns}
        data={query.data?.items}
        getRowId={(e) => e.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No audit events match these filters."
        pager={pager}
        nextCursor={query.data?.next_cursor}
      />
      <Modal open={selected !== null} onClose={() => setSelected(null)} title="Audit event" placement="side">
        {selected && (
          <>
            <dl className="divide-y text-sm">
              {(
                [
                  ["ID", selected.id],
                  ["Time", formatDateTime(selected.at)],
                  ["Action", `${AUDIT_ACTIONS[selected.action].label} (${selected.action})`],
                  ["Outcome", selected.outcome],
                  ["Actor", ACTOR_KIND_LABELS[selected.actor.kind]],
                  ["IP address", selected.ip ?? "—"],
                  ["User agent", selected.user_agent ?? "—"],
                  ["Trace ID", selected.trace_id ?? "—"],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="grid grid-cols-3 gap-4 py-2">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="col-span-2 break-all">{value}</dd>
                </div>
              ))}
            </dl>
            <div className="space-y-2">
              {selected.actor.id ? <CopyField label="Actor id" value={selected.actor.id} mono /> : null}
              {selected.target ? <CopyField label="Target id" value={selected.target} mono /> : null}
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-medium">Details</h3>
              <pre
                // Focusable so keyboard users can scroll long details.
                tabIndex={0}
                aria-label="Event details (JSON)"
                className="bg-muted overflow-x-auto rounded-md p-3 text-xs focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                data-testid="audit-details"
              >
                {JSON.stringify(selected.details, null, 2)}
              </pre>
            </div>
            <div className="flex justify-end">
              <Button variant="outline" onClick={() => setSelected(null)} autoFocus>
                Close
              </Button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}

function AuditPage() {
  const search = Route.useSearch();
  // A filter change starts again at the newest page (the cursor stack belongs to one filter set).
  const key = JSON.stringify(search);
  return (
    <section aria-labelledby="audit-heading" className="space-y-4">
      <h1 id="audit-heading" className="text-xl font-semibold">
        Audit log
      </h1>
      <AuditFilters key={`f-${key}`} search={search} />
      <AuditTable key={`t-${key}`} search={search} />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/audit/")({ validateSearch, component: AuditPage });
