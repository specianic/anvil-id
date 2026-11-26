// Enterprise connections of one organization: OpenID Connect (the Phase 4 form; write-only secret)
// and SAML 2.0 (experimental; only offered while the operator flag is on). A connection opens in a
// side panel with the values to register at the IdP, its settings and, for OIDC, the secret.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useId, useMemo, useRef, useState } from "react";
import { api, unwrap } from "@/api/client";
import { ConfirmDialog, Modal } from "@/components/ConfirmDialog";
import {
  ConnectionForm,
  type ConnectionFormValues,
  type ConnectionView,
  KIND_DESCRIPTIONS,
  ORG_KINDS,
  SecretRotation,
  createBody,
  newConnectionValues,
  orgConnectionsQueryKey,
  updateBody,
  useOrgConnections,
  valuesFromConnection,
} from "@/components/ConnectionForm";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { ProblemAlert } from "@/components/ProblemAlert";
import {
  ExperimentalBadge,
  SAML_DISABLED_NOTE,
  SamlConnectionForm,
  type SamlFormValues,
  SamlSpValues,
  newSamlValues,
  samlCreateBody,
  samlUpdateBody,
  samlValuesFromConnection,
} from "@/components/SamlConnectionForm";
import { StatusMessage } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTenant, useTenantView } from "@/lib/tenant";

type OrgKind = (typeof ORG_KINDS)[number];

const ORG_KIND_LABELS: Record<OrgKind, string> = { oidc: "OpenID Connect", saml: "SAML 2.0" };

function useInvalidateConnections(tenant: string, org: string) {
  const queryClient = useQueryClient();
  return async () => {
    await queryClient.invalidateQueries({ queryKey: orgConnectionsQueryKey(tenant, org) });
    await queryClient.invalidateQueries({ queryKey: ["connections", tenant] });
  };
}

function KindPicker({
  value,
  onChange,
  samlEnabled,
}: {
  value: OrgKind | null;
  onChange: (kind: OrgKind) => void;
  samlEnabled: boolean;
}) {
  const noteId = useId();
  return (
    <fieldset className="space-y-2" data-testid="org-connection-kind-picker">
      <legend className="mb-2 text-base font-semibold">Protocol</legend>
      <div className="grid gap-2 sm:grid-cols-2">
        {ORG_KINDS.map((kind) => {
          const disabled = kind === "saml" && !samlEnabled;
          return (
            <label
              key={kind}
              className={`has-[:checked]:border-primary has-[:focus-visible]:ring-ring/50 flex gap-3 rounded-md border p-3 text-sm has-[:focus-visible]:ring-[3px] ${disabled ? "cursor-not-allowed opacity-70" : "cursor-pointer"}`}
            >
              <input
                type="radio"
                name="org-connection-kind"
                value={kind}
                checked={value === kind}
                disabled={disabled}
                onChange={() => onChange(kind)}
                aria-describedby={disabled ? noteId : undefined}
                className="mt-0.5 size-4 focus-visible:outline-none"
                data-testid={`org-connection-kind-${kind}`}
              />
              <span className="space-y-1">
                <span className="flex items-center gap-2 font-medium">
                  {ORG_KIND_LABELS[kind]}
                  {kind === "saml" && <ExperimentalBadge />}
                </span>
                <span className="text-muted-foreground block">{KIND_DESCRIPTIONS[kind]}</span>
              </span>
            </label>
          );
        })}
      </div>
      {!samlEnabled && (
        <p id={noteId} className="text-muted-foreground text-sm" data-testid="saml-unavailable">
          {SAML_DISABLED_NOTE}
        </p>
      )}
    </fieldset>
  );
}

function AddConnection({
  tenant,
  org,
  samlEnabled,
  onCreated,
}: {
  tenant: string;
  org: string;
  samlEnabled: boolean;
  onCreated: (created: ConnectionView) => void;
}) {
  const invalidate = useInvalidateConnections(tenant, org);
  const [kind, setKind] = useState<OrgKind | null>(null);
  // The OIDC secret reaches the request through a ref, never the mutation variables (cache).
  const secretRef = useRef<string | null>(null);
  const create = useMutation({
    mutationFn: async (body: { oidc: ConnectionFormValues } | { saml: SamlFormValues }) => {
      const secret = secretRef.current;
      secretRef.current = null;
      return unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/organizations/{org}/connections", {
          params: { path: { slug: tenant, org } },
          body: "oidc" in body ? createBody(body.oidc, secret) : samlCreateBody(body.saml),
        }),
      );
    },
    onSuccess: async (created) => {
      setKind(null);
      await invalidate();
      onCreated(created);
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h3>Add a connection</h3>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <KindPicker
          value={kind}
          samlEnabled={samlEnabled}
          onChange={(next) => {
            create.reset();
            setKind(next);
          }}
        />
        {kind === "oidc" && (
          <ConnectionForm
            key="oidc"
            mode="create"
            initial={newConnectionValues("oidc")}
            submitLabel="Create connection"
            pending={create.isPending}
            error={create.error}
            onSubmit={(values, secret) => {
              secretRef.current = secret;
              create.mutate({ oidc: values });
            }}
          />
        )}
        {kind === "saml" && (
          <SamlConnectionForm
            key="saml"
            mode="create"
            tenant={tenant}
            org={org}
            initial={newSamlValues()}
            samlEnabled={samlEnabled}
            submitLabel="Create connection"
            pending={create.isPending}
            error={create.error}
            onSubmit={(values) => create.mutate({ saml: values })}
          />
        )}
      </CardContent>
    </Card>
  );
}

function RedirectUri({ connection }: { connection: ConnectionView }) {
  const [status, setStatus] = useState<string | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(connection.redirect_uri);
      setStatus("Redirect URI copied.");
    } catch {
      setStatus("Copying failed; select the URI and copy it manually.");
    }
  };
  return (
    <section className="space-y-2" aria-labelledby="org-connection-redirect-heading">
      <h3 id="org-connection-redirect-heading" className="text-base font-semibold">
        Redirect URI
      </h3>
      <p className="text-muted-foreground text-sm">Register this callback URL at the provider.</p>
      <div className="flex flex-wrap items-center gap-2">
        <code className="bg-muted rounded px-2 py-1 text-sm break-all" data-testid="connection-redirect-uri">
          {connection.redirect_uri}
        </code>
        <Button type="button" variant="outline" size="sm" onClick={() => void copy()} data-testid="copy-redirect-uri">
          Copy
        </Button>
      </div>
      <StatusMessage message={status} />
    </section>
  );
}

function ConnectionDetails({
  tenant,
  org,
  connection,
  samlEnabled,
}: {
  tenant: string;
  org: string;
  connection: ConnectionView;
  samlEnabled: boolean;
}) {
  const invalidate = useInvalidateConnections(tenant, org);
  const [status, setStatus] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: async (body: { oidc: ConnectionFormValues } | { saml: SamlFormValues }) =>
      unwrap(
        await api.PATCH("/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}", {
          params: { path: { slug: tenant, org, id: connection.id } },
          body: "oidc" in body ? updateBody(body.oidc) : samlUpdateBody(body.saml),
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async () => {
      setStatus("Connection saved.");
      await invalidate();
    },
  });
  const saml = connection.kind === "saml";

  return (
    <div className="space-y-6" data-testid="org-connection-details">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary">{saml ? ORG_KIND_LABELS.saml : ORG_KIND_LABELS.oidc}</Badge>
        {saml && <ExperimentalBadge />}
        {connection.enabled ? <Badge>Enabled</Badge> : <Badge variant="outline">Disabled</Badge>}
        <code className="text-xs">{connection.slug}</code>
      </div>
      {saml && connection.sp ? <SamlSpValues sp={connection.sp} /> : null}
      {!saml && <RedirectUri connection={connection} />}
      <section className="space-y-3" aria-labelledby="org-connection-settings-heading">
        <h3 id="org-connection-settings-heading" className="text-base font-semibold">
          Settings
        </h3>
        {saml ? (
          <SamlConnectionForm
            mode="edit"
            tenant={tenant}
            org={org}
            initial={samlValuesFromConnection(connection)}
            samlEnabled={samlEnabled}
            submitLabel="Save changes"
            pending={update.isPending}
            error={update.error}
            onSubmit={(values) => update.mutate({ saml: values })}
            status={status}
          />
        ) : (
          <ConnectionForm
            mode="edit"
            initial={valuesFromConnection(connection)}
            submitLabel="Save changes"
            pending={update.isPending}
            error={update.error}
            onSubmit={(values) => update.mutate({ oidc: values })}
            status={status}
          />
        )}
      </section>
      {!saml && (
        <section className="space-y-3" aria-labelledby="org-connection-secret-heading">
          <h3 id="org-connection-secret-heading" className="text-base font-semibold">
            Client secret
          </h3>
          <SecretRotation
            kind={connection.kind}
            configured={connection.secret_configured}
            put={async (secret) =>
              unwrap(
                await api.PUT("/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}/secret", {
                  params: { path: { slug: tenant, org, id: connection.id } },
                  body: { secret },
                }),
              )
            }
            onSaved={invalidate}
          />
        </section>
      )}
    </div>
  );
}

const col = createColumnHelper<DataTableFeatures, ConnectionView>();

function OrgConnectionsPage() {
  const tenant = useTenant();
  const { orgId } = Route.useParams();
  const tenantView = useTenantView(tenant);
  const samlEnabled = tenantView.data?.features.saml ?? false;
  const query = useOrgConnections(tenant, orgId);
  const invalidate = useInvalidateConnections(tenant, orgId);
  const pager = useCursorPager();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [removing, setRemoving] = useState<ConnectionView | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const selected = query.data?.items.find((c) => c.id === selectedId) ?? null;

  const remove = useMutation({
    mutationFn: async (c: ConnectionView) => {
      // Errors are thrown by the client middleware; a 204 has no body to unwrap.
      await api.DELETE("/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}", {
        params: { path: { slug: tenant, org: orgId, id: c.id } },
      });
      return `${c.display_name} deleted.`;
    },
    onMutate: () => setStatus(null),
    onSuccess: async (message) => {
      setRemoving(null);
      setStatus(message);
      await invalidate();
    },
  });

  const columns = useMemo(
    () =>
      col.columns([
        col.accessor("display_name", {
          header: "Name",
          cell: (info) => <span className="font-medium">{info.getValue()}</span>,
        }),
        col.accessor("slug", { header: "Slug", cell: (info) => <code className="text-xs">{info.getValue()}</code> }),
        col.accessor("kind", {
          header: "Protocol",
          cell: (info) => (
            <span className="flex flex-wrap items-center gap-1">
              <Badge variant="secondary">{info.getValue() === "saml" ? ORG_KIND_LABELS.saml : ORG_KIND_LABELS.oidc}</Badge>
              {info.getValue() === "saml" && <ExperimentalBadge />}
            </span>
          ),
        }),
        col.accessor("enabled", {
          header: "Status",
          cell: (info) => (info.getValue() ? <Badge>Enabled</Badge> : <Badge variant="outline">Disabled</Badge>),
        }),
        col.display({
          id: "actions",
          header: () => <span className="sr-only">Actions</span>,
          cell: (info) => {
            const c = info.row.original;
            return (
              <div className="flex justify-end gap-2" data-testid={`org-connection-${c.slug}`}>
                <Button variant="outline" size="sm" onClick={() => setSelectedId(c.id)} aria-label={`Open ${c.display_name}`}>
                  Open
                </Button>
                <Button variant="outline" size="sm" onClick={() => setRemoving(c)} aria-label={`Delete ${c.display_name}`}>
                  Delete
                </Button>
              </div>
            );
          },
        }),
      ]),
    [],
  );

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Connections</h2>
      <p className="text-muted-foreground text-sm">
        The organization's own identity providers. Users of a verified domain can be routed to one of them (see
        Domains). These connections are listed under the tenant's Connections too, read-only.
      </p>
      {tenantView.isError ? <ProblemAlert error={tenantView.error} /> : null}
      <StatusMessage message={status} />
      <DataTable
        caption="Connections"
        columns={columns}
        data={query.data?.items}
        getRowId={(c) => c.id}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No connections yet."
        pager={pager}
        nextCursor={null}
      />
      {tenantView.isSuccess && (
        <AddConnection
          tenant={tenant}
          org={orgId}
          samlEnabled={samlEnabled}
          onCreated={(created) => {
            setStatus(`${created.display_name} created.`);
            setSelectedId(created.id);
          }}
        />
      )}
      <Modal
        open={selected !== null}
        onClose={() => setSelectedId(null)}
        title={`Connection ${selected?.display_name ?? ""}`}
        placement="side"
      >
        {selected && (
          <ConnectionDetails
            key={selected.id}
            tenant={tenant}
            org={orgId}
            connection={selected}
            samlEnabled={samlEnabled}
          />
        )}
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setSelectedId(null)} data-testid="close-org-connection">
            Close
          </Button>
        </div>
      </Modal>
      <ConfirmDialog
        open={removing !== null}
        title="Delete this connection?"
        description={
          <p>
            {removing?.display_name} is removed with every account link to it. Domains routed to it stop routing.
            This cannot be undone.
          </p>
        }
        confirmLabel="Delete connection"
        onConfirm={() => removing && remove.mutate(removing)}
        onCancel={() => {
          setRemoving(null);
          remove.reset();
        }}
        pending={remove.isPending}
        error={remove.error}
      />
    </div>
  );
}

export const Route = createFileRoute("/t/$tenant/organizations/$orgId/connections")({ component: OrgConnectionsPage });
