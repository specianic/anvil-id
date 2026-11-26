// Verified domains of one organization: claim a domain, publish the shown DNS TXT record
// (`_anvilid-challenge.{domain}.` = `anvilid-domain-verification={token}`), verify it, and edit its
// routing (target connection, routing on/off, allow local password). Every verification failure
// looks the same (the API does not say why), so the page only says "not found yet".
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { type ConnectionView, useOrgConnections } from "@/components/ConnectionForm";
import { ProblemAlert } from "@/components/ProblemAlert";
import { CheckboxField, SelectField, StatusMessage, TextField, fieldErrors } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";

export type DomainView = components["schemas"]["DomainView"];

export function domainsQueryKey(tenant: string, org: string) {
  return ["org-domains", tenant, org] as const;
}

/** The trade-off behind "Allow local password" (default on). */
const ALLOW_PASSWORD_HINT =
  "On (default): users of this domain can choose single sign-on or their password here, so a broken or " +
  "misconfigured IdP cannot lock them out; the IdP's own policies (MFA, deprovisioning) do not cover " +
  "password sign-ins. Off: they must sign in through the connection, and password, email-code and " +
  "magic-link sign-in are refused for their addresses. It can only be turned off after someone has " +
  "signed in through the connection.";

function CopyLine({ label, value, testId }: { label: string; value: string; testId: string }) {
  const [status, setStatus] = useState<string | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setStatus(`${label} copied.`);
    } catch {
      setStatus("Copying failed; select the value and copy it manually.");
    }
  };
  return (
    <div className="space-y-1">
      <dt className="text-sm font-medium">{label}</dt>
      <dd className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <code className="bg-muted rounded px-2 py-1 text-sm break-all" data-testid={testId}>
            {value}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void copy()}
            aria-label={`Copy ${label.toLowerCase()}`}
            data-testid={`copy-${testId}`}
          >
            Copy
          </Button>
        </div>
        <StatusMessage message={status} />
      </dd>
    </div>
  );
}

function StatusBadge({ domain }: { domain: DomainView }) {
  return domain.status === "verified" ? (
    <Badge data-testid="domain-status">Verified</Badge>
  ) : (
    <Badge variant="outline" data-testid="domain-status">
      Pending
    </Badge>
  );
}

function DnsInstructions({ domain }: { domain: DomainView }) {
  return (
    <section className="space-y-2" aria-label={`DNS record for ${domain.domain}`}>
      <p className="text-sm">
        {domain.status === "pending"
          ? "Publish this TXT record at the domain's DNS provider, then choose Verify."
          : "Keep this TXT record published: the domain is checked again regularly."}
      </p>
      <dl className="space-y-2">
        <CopyLine label="Record name" value={domain.record_name} testId="domain-record-name" />
        <div className="space-y-1">
          <dt className="text-sm font-medium">Record type</dt>
          <dd>
            <code className="bg-muted rounded px-2 py-1 text-sm">TXT</code>
          </dd>
        </div>
        <CopyLine label="Record value" value={domain.record_value} testId="domain-record-value" />
      </dl>
    </section>
  );
}

function CheckState({ domain }: { domain: DomainView }) {
  return (
    <dl className="text-muted-foreground grid grid-cols-3 gap-x-2 gap-y-1 text-sm" data-testid="domain-checks">
      {domain.verified_at && (
        <>
          <dt>Verified</dt>
          <dd className="col-span-2">{formatDateTime(domain.verified_at)}</dd>
        </>
      )}
      <dt>Last check</dt>
      <dd className="col-span-2">{domain.last_checked_at ? formatDateTime(domain.last_checked_at) : "Not checked yet"}</dd>
      {domain.failing_since && (
        <>
          <dt className="text-destructive">Failing since</dt>
          <dd className="text-destructive col-span-2" data-testid="domain-failing-since">
            {formatDateTime(domain.failing_since)} (the record was not found in the re-checks since then)
          </dd>
        </>
      )}
    </dl>
  );
}

function RoutingEditor({
  tenant,
  org,
  domain,
  connections,
}: {
  tenant: string;
  org: string;
  domain: DomainView;
  connections: ConnectionView[];
}) {
  const queryClient = useQueryClient();
  const [connectionId, setConnectionId] = useState(domain.connection_id ?? "");
  const [routing, setRouting] = useState(domain.routing);
  const [allowPassword, setAllowPassword] = useState(domain.allow_local_password);
  const [status, setStatus] = useState<string | null>(null);
  const verified = domain.status === "verified";

  // Only enabled connections can be targets; a disabled current target stays visible as such.
  const options = [
    { value: "", label: "No connection" },
    ...connections
      .filter((c) => c.enabled || c.id === domain.connection_id)
      .map((c) => ({ value: c.id, label: c.enabled ? c.display_name : `${c.display_name} (disabled)` })),
  ];

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}", {
          params: { path: { slug: tenant, org, id: domain.id } },
          body: { connection_id: connectionId === "" ? null : connectionId, routing, allow_local_password: allowPassword },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      setStatus("Routing saved.");
      setConnectionId(saved.connection_id ?? "");
      setRouting(saved.routing);
      setAllowPassword(saved.allow_local_password);
      await queryClient.invalidateQueries({ queryKey: domainsQueryKey(tenant, org) });
    },
  });

  const errors = fieldErrors(save.error);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <form
      onSubmit={submit}
      aria-label={`Routing of ${domain.domain}`}
      className="space-y-4 rounded-md border p-4"
      noValidate
      data-testid="domain-routing-form"
    >
      <h4 className="text-sm font-semibold">Routing</h4>
      {!verified && (
        <p className="text-muted-foreground text-sm">Routing can be turned on once the domain is verified.</p>
      )}
      <SelectField
        label="Target connection"
        name="connection_id"
        hint="Users whose email is on this domain are sent to this connection's sign-in. Only enabled connections of this organization are offered."
        options={options}
        value={connectionId}
        onChange={(e) => setConnectionId(e.target.value)}
        errors={errors.connection_id}
        data-testid="domain-connection"
      />
      <CheckboxField
        label="Route sign-ins for this domain"
        name="routing"
        hint="The sign-in page asks for the email first and offers this organization's single sign-on to addresses on this domain."
        checked={routing}
        onChange={(e) => setRouting(e.target.checked)}
        errors={errors.routing}
        data-testid="domain-routing"
      />
      <CheckboxField
        label="Allow local password"
        name="allow_local_password"
        hint={ALLOW_PASSWORD_HINT}
        checked={allowPassword}
        onChange={(e) => setAllowPassword(e.target.checked)}
        errors={errors.allow_local_password}
        data-testid="domain-allow-password"
      />
      {save.error instanceof ApiError && save.error.status === 409 ? (
        <p role="alert" className="text-destructive text-sm" data-testid="domain-routing-error">
          Not saved: {save.error.problem.detail ?? save.error.problem.title}
        </p>
      ) : save.error && !(save.error instanceof ApiError && save.error.status === 422) ? (
        <ProblemAlert error={save.error} />
      ) : null}
      <Button type="submit" disabled={save.isPending} data-testid="save-domain-routing">
        {save.isPending ? "Saving…" : "Save routing"}
      </Button>
      <StatusMessage message={status} />
    </form>
  );
}

function DomainCard({
  tenant,
  org,
  domain,
  connections,
}: {
  tenant: string;
  org: string;
  domain: DomainView;
  connections: ConnectionView[];
}) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const invalidate = () => queryClient.invalidateQueries({ queryKey: domainsQueryKey(tenant, org) });

  const verify = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}/verify", {
          params: { path: { slug: tenant, org, id: domain.id } },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (result) => {
      setStatus(
        result.status === "verified"
          ? `${domain.domain} is verified.`
          : "The record was not found yet. DNS changes can take a while to propagate; try again later.",
      );
      await invalidate();
    },
  });

  const remove = useMutation({
    mutationFn: async () => {
      // Errors are thrown by the client middleware; a 204 has no body to unwrap.
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}", {
        params: { path: { slug: tenant, org, id: domain.id } },
      });
    },
    onSuccess: async () => {
      setConfirmDelete(false);
      await invalidate();
    },
  });

  return (
    <Card data-testid="domain-card" data-domain={domain.domain} data-status={domain.status}>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <h3 className="break-all">{domain.domain}</h3>
          <StatusBadge domain={domain} />
          {domain.routing && <Badge variant="secondary">Routed</Badge>}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <DnsInstructions domain={domain} />
        <CheckState domain={domain} />
        {domain.status === "pending" && (
          <div className="space-y-2">
            {verify.error ? <ProblemAlert error={verify.error} /> : null}
            <Button type="button" onClick={() => verify.mutate()} disabled={verify.isPending} data-testid="verify-domain">
              {verify.isPending ? "Checking…" : "Verify"}
            </Button>
          </div>
        )}
        <StatusMessage message={status} />
        <RoutingEditor
          // Verification restarts the editor from the server state.
          key={domain.status}
          tenant={tenant}
          org={org}
          domain={domain}
          connections={connections}
        />
        <Button type="button" variant="outline" onClick={() => setConfirmDelete(true)} data-testid="delete-domain">
          Remove domain
        </Button>
        <ConfirmDialog
          open={confirmDelete}
          title={`Remove ${domain.domain}?`}
          description={
            <p>The claim and its routing are deleted. Sign-ins for this domain are no longer sent to the organization.</p>
          }
          confirmLabel="Remove domain"
          onConfirm={() => remove.mutate()}
          onCancel={() => {
            remove.reset();
            setConfirmDelete(false);
          }}
          pending={remove.isPending}
          error={remove.error}
        />
      </CardContent>
    </Card>
  );
}

function AddDomain({ tenant, org }: { tenant: string; org: string }) {
  const queryClient = useQueryClient();
  const [domain, setDomain] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const add = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/domains", {
          params: { path: { slug: tenant, org } },
          body: { domain: name },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (created) => {
      setDomain("");
      setStatus(`${created.domain} added. Publish its DNS record, then verify it.`);
      await queryClient.invalidateQueries({ queryKey: domainsQueryKey(tenant, org) });
    },
  });
  const errors = fieldErrors(add.error);
  const otherError = add.error && !(add.error instanceof ApiError && errors.domain) ? add.error : null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (domain.trim() === "") return;
    add.mutate(domain.trim());
  };
  return (
    <form onSubmit={submit} aria-label="Add a domain" className="space-y-3" noValidate data-testid="add-domain-form">
      {otherError ? <ProblemAlert error={otherError} /> : null}
      <TextField
        label="Domain"
        name="domain"
        autoComplete="off"
        spellCheck={false}
        placeholder="example.com"
        hint="A domain the organization controls, without scheme or path (for example example.com)."
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        errors={errors.domain}
        data-testid="add-domain-input"
      />
      <Button type="submit" disabled={add.isPending || domain.trim() === ""} data-testid="add-domain">
        {add.isPending ? "Adding…" : "Add domain"}
      </Button>
      <StatusMessage message={status} />
    </form>
  );
}

/** The domains section of an organization. */
export function DomainPanel({ tenant, org }: { tenant: string; org: string }) {
  const domains = useQuery({
    queryKey: domainsQueryKey(tenant, org),
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/organizations/{org}/domains", {
          params: { path: { slug: tenant, org } },
          signal,
        }),
      ),
  });
  const connections = useOrgConnections(tenant, org);

  return (
    <div className="space-y-4" data-testid="domain-panel">
      <p className="text-muted-foreground text-sm">
        A verified domain proves the organization controls it (DNS TXT record). Sign-ins with an email on a verified,
        routed domain are sent to the organization's connection.
      </p>
      <AddDomain tenant={tenant} org={org} />
      {connections.isError ? <ProblemAlert error={connections.error} /> : null}
      {domains.isPending ? (
        <div role="status" aria-label="Loading domains" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : domains.isError ? (
        <ProblemAlert error={domains.error} />
      ) : domains.data.items.length === 0 ? (
        <p className="text-muted-foreground text-sm">No domains yet.</p>
      ) : (
        domains.data.items.map((d) => (
          <DomainCard key={d.id} tenant={tenant} org={org} domain={d} connections={connections.data?.items ?? []} />
        ))
      )}
    </div>
  );
}
