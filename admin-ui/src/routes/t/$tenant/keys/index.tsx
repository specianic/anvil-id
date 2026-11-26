// Signing keys of a tenant (06-11 keys API): lifecycle and timestamps only. The API has no field
// for private material or the JWK; the public keys are served by the tenant's /jwks.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type DataTableFeatures, useCursorPager } from "@/components/DataTable";
import { CheckboxField, SelectField, StatusMessage } from "@/components/form";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";
import { useTenant, useTenantView } from "@/lib/tenant";

type KeyView = components["schemas"]["KeyView"];
type KeyState = components["schemas"]["KeyState"];
type SigningAlg = components["schemas"]["SigningAlg"];

const SIGNING_ALGS: readonly SigningAlg[] = ["RS256", "ES256", "Ed25519"];

function isSigningAlg(value: string): value is SigningAlg {
  return (SIGNING_ALGS as readonly string[]).includes(value);
}

const STATE_LABELS: Record<KeyState, string> = { next: "Next", active: "Active", retired: "Retired" };

function StateBadge({ state }: { state: KeyState }) {
  const variant = state === "active" ? "default" : state === "next" ? "secondary" : "outline";
  return (
    <Badge variant={variant} data-testid="key-state">
      {STATE_LABELS[state]}
    </Badge>
  );
}

const col = createColumnHelper<DataTableFeatures, KeyView>();

const COLUMNS = col.columns([
  col.accessor("kid", {
    header: "Key ID",
    cell: (info) => <code className="text-xs break-all">{info.getValue()}</code>,
  }),
  col.accessor("alg", { header: "Algorithm" }),
  col.accessor("state", { header: "State", cell: (info) => <StateBadge state={info.getValue()} /> }),
  col.accessor("created_at", { header: "Created", cell: (info) => formatDateTime(info.getValue()) }),
  col.accessor("activated_at", { header: "Activated", cell: (info) => formatDateTime(info.getValue()) }),
  col.accessor("retired_at", { header: "Retired", cell: (info) => formatDateTime(info.getValue()) }),
  col.accessor("expires_at", { header: "Leaves JWKS", cell: (info) => formatDateTime(info.getValue()) }),
]);

function KeysPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  // Every key of the tenant comes in one list (no cursor); the pager stays on page 1.
  const pager = useCursorPager();
  const tenantView = useTenantView(tenant);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [alg, setAlg] = useState<SigningAlg>("RS256");
  const [immediate, setImmediate] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const enabledAlgs = useMemo(
    () => (tenantView.data?.settings.signing_algs ?? []).filter(isSigningAlg),
    [tenantView.data],
  );

  const query = useQuery({
    queryKey: ["keys", tenant],
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/api/admin/v1/tenants/{slug}/keys", { params: { path: { slug: tenant } }, signal })),
  });

  const rotate = useMutation({
    mutationFn: async (body: { alg: SigningAlg; immediate: boolean }) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/keys/rotate", {
          params: { path: { slug: tenant } },
          body,
        }),
      ),
    onSuccess: async ({ kid }, body) => {
      setDialogOpen(false);
      setStatus(
        body.immediate
          ? `New ${body.alg} key ${kid} is active. The previous key was retired and removed from the JWKS.`
          : `New ${body.alg} key ${kid} is published and becomes active after the prepublish period.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["keys", tenant] });
    },
  });

  function openDialog() {
    rotate.reset();
    setStatus(null);
    setAlg(enabledAlgs[0] ?? "RS256");
    setImmediate(false);
    setDialogOpen(true);
  }

  return (
    <section aria-labelledby="keys-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="keys-heading" className="text-xl font-semibold">
          Signing keys
        </h1>
        <Button size="sm" onClick={openDialog} disabled={enabledAlgs.length === 0} data-testid="rotate-key">
          Rotate key
        </Button>
      </div>
      <p className="text-muted-foreground text-sm">
        Keys that sign this tenant's tokens. Private keys never leave the server; the public keys are published in
        the tenant's JWKS.
      </p>
      {tenantView.error ? <ProblemAlert error={tenantView.error} /> : null}
      <StatusMessage message={status} />
      <DataTable
        caption="Signing keys"
        columns={COLUMNS}
        data={query.data?.items}
        getRowId={(k) => k.kid}
        isPending={query.isPending}
        isFetching={query.isFetching}
        error={query.error}
        emptyMessage="No signing keys."
        pager={pager}
        nextCursor={null}
      />
      <ConfirmDialog
        open={dialogOpen}
        title="Rotate signing key?"
        description={
          <div className="space-y-4" data-testid="rotate-key-dialog">
            <p>A new key pair is generated on the server for the chosen algorithm.</p>
            <SelectField
              label="Algorithm"
              hint="Only the algorithms enabled in this tenant's login settings."
              value={alg}
              onChange={(e) => {
                if (isSigningAlg(e.target.value)) setAlg(e.target.value);
              }}
              options={enabledAlgs.map((a) => ({ value: a, label: a }))}
              data-testid="rotate-key-alg"
            />
            <CheckboxField
              label="Activate immediately"
              hint={
                immediate
                  ? "Use this after a key compromise: the new key signs at once and the current key leaves the JWKS, so tokens it signed stop verifying."
                  : "Off: the new key is published in the JWKS first and starts signing after the prepublish period, so relying parties pick it up without failed verifications."
              }
              checked={immediate}
              onChange={(e) => setImmediate(e.target.checked)}
              data-testid="rotate-key-immediate"
            />
          </div>
        }
        confirmLabel="Rotate key"
        onConfirm={() => rotate.mutate({ alg, immediate })}
        onCancel={() => {
          rotate.reset();
          setDialogOpen(false);
        }}
        pending={rotate.isPending}
        error={rotate.error}
      />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/keys/")({ component: KeysPage });
