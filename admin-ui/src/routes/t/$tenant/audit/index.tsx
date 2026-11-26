import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { type FormEvent, useMemo, useState } from "react";
import { api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { Modal } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { SelectField, TextField } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";

type AuditEventView = components["schemas"]["AuditEventView"];
type AuditAction = components["schemas"]["AuditAction"];
type AuditOutcome = components["schemas"]["AuditOutcome"];

// Every AuditAction of the generated schema; the Record type makes the compiler flag a missing or
// unknown name when the API enum changes.
const ACTION_SET: Record<AuditAction, true> = {
  login_succeeded: true,
  login_failed: true,
  second_factor_failed: true,
  passkey_registered: true,
  passkey_removed: true,
  passkey_clone_suspected: true,
  totp_enrolled: true,
  totp_removed: true,
  recovery_code_used: true,
  recovery_codes_regenerated: true,
  password_changed: true,
  user_registered: true,
  email_verified: true,
  consent_granted: true,
  consent_revoked: true,
  session_revoked: true,
  sessions_revoked_all: true,
  token_revoked: true,
  refresh_reuse_detected: true,
  code_reuse_detected: true,
  key_generated: true,
  key_activated: true,
  key_retired: true,
  key_rotation_requested: true,
  rate_limit_lockout: true,
  captcha_failed: true,
  user_created: true,
  user_updated: true,
  user_deleted: true,
  client_created: true,
  client_updated: true,
  client_deleted: true,
  client_secret_rotated: true,
  tenant_created: true,
  tenant_updated: true,
  tenant_deleted: true,
  email_template_updated: true,
  email_template_reset: true,
  smtp_settings_updated: true,
  smtp_test_sent: true,
  admin_setup_completed: true,
  identity_linked: true,
  identity_unlinked: true,
  upstream_login_failed: true,
  connection_created: true,
  connection_updated: true,
  connection_deleted: true,
  connection_secret_rotated: true,
  branding_updated: true,
  logout: true,
  backchannel_logout_failed: true,
  email_change_requested: true,
  email_changed: true,
  profile_updated: true,
  step_up_completed: true,
  email_code_sent: true,
  admin_recovery_issued: true,
  attribute_defined: true,
  attribute_deleted: true,
  cimd_client_refreshed: true,
  client_registered: true,
  client_registration_deleted: true,
  client_registration_updated: true,
  initial_access_token_created: true,
  initial_access_token_revoked: true,
  role_assigned: true,
  role_created: true,
  role_deleted: true,
  role_unassigned: true,
  role_updated: true,
  tenant_config_applied: true,
  user_attributes_updated: true,
  webhook_delivery_failed: true,
  webhook_endpoint_created: true,
  webhook_endpoint_deleted: true,
  webhook_endpoint_disabled: true,
  webhook_endpoint_updated: true,
  webhook_redelivered: true,
  webhook_secret_rotated: true,
  webhook_test_sent: true,
  organization_created: true,
  organization_updated: true,
  organization_deleted: true,
  org_member_added: true,
  org_member_removed: true,
  org_role_assigned: true,
  org_role_unassigned: true,
  org_invitation_created: true,
  org_invitation_revoked: true,
  org_invitation_accepted: true,
  org_domain_created: true,
  org_domain_verified: true,
  org_domain_verification_failed: true,
  org_domain_unverified: true,
  org_domain_updated: true,
  org_domain_deleted: true,
  saml_login_succeeded: true,
  saml_login_failed: true,
};
const ACTIONS = Object.keys(ACTION_SET).sort() as AuditAction[];
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
    action: action && action in ACTION_SET ? (action as AuditAction) : undefined,
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

function AuditFilters({ search }: { search: AuditSearch }) {
  const navigate = useNavigate({ from: "/audit/" });
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
      <SelectField
        label="Action"
        name="action"
        value={draft.action ?? ""}
        onChange={set("action")}
        options={[{ value: "", label: "Any action" }, ...ACTIONS.map((a) => ({ value: a, label: a }))]}
      />
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
        col.accessor("action", { header: "Action", cell: (info) => <code className="text-xs">{info.getValue()}</code> }),
        col.accessor("outcome", {
          header: "Outcome",
          cell: (info) => (
            <Badge variant={info.getValue() === "failure" ? "destructive" : "secondary"}>{info.getValue()}</Badge>
          ),
        }),
        col.accessor("actor", {
          header: "Actor",
          cell: (info) => (
            <span className="text-xs break-all">
              {info.getValue().kind}
              {info.getValue().id ? `: ${info.getValue().id}` : ""}
            </span>
          ),
        }),
        col.accessor("target", {
          header: "Target",
          cell: (info) => <span className="font-mono text-xs break-all">{info.getValue() ?? "—"}</span>,
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
              aria-label={`Details of ${info.row.original.action} at ${formatDateTime(info.row.original.at)}`}
            >
              Details
            </Button>
          ),
        }),
      ]),
    [],
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
                  ["Action", selected.action],
                  ["Outcome", selected.outcome],
                  ["Actor", `${selected.actor.kind}${selected.actor.id ? `: ${selected.actor.id}` : ""}`],
                  ["Target", selected.target ?? "—"],
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
