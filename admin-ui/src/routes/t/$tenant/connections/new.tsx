import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import {
  ConnectionForm,
  type ConnectionFormValues,
  type ConnectionKind,
  KINDS,
  KIND_DESCRIPTIONS,
  KIND_LABELS,
  createBody,
  newConnectionValues,
} from "@/components/ConnectionForm";

const linkClass =
  "text-sm underline-offset-4 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none";

function KindPicker({ value, onChange }: { value: ConnectionKind | null; onChange: (kind: ConnectionKind) => void }) {
  return (
    <fieldset className="space-y-2" data-testid="connection-kind-picker">
      <legend className="mb-2 text-base font-semibold">Provider</legend>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {KINDS.map((kind) => (
          <label
            key={kind}
            className="has-[:checked]:border-primary has-[:focus-visible]:ring-ring/50 flex cursor-pointer gap-3 rounded-md border p-3 text-sm has-[:focus-visible]:ring-[3px]"
          >
            <input
              type="radio"
              name="kind"
              value={kind}
              checked={value === kind}
              onChange={() => onChange(kind)}
              className="mt-0.5 size-4 focus-visible:outline-none"
              data-testid={`connection-kind-${kind}`}
            />
            <span className="space-y-1">
              <span className="block font-medium">{KIND_LABELS[kind]}</span>
              <span className="text-muted-foreground block">{KIND_DESCRIPTIONS[kind]}</span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function NewConnectionPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [kind, setKind] = useState<ConnectionKind | null>(null);
  // The secret is handed to the request through a ref, not the mutation variables, so it does not
  // stay in the query client's mutation cache after the submit.
  const secretRef = useRef<string | null>(null);

  const create = useMutation({
    mutationFn: async (values: ConnectionFormValues) => {
      const secret = secretRef.current;
      secretRef.current = null;
      return unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/connections", {
          params: { path: { slug: tenant } },
          body: createBody(values, secret),
        }),
      );
    },
    onSuccess: async (created) => {
      queryClient.setQueryData(["connection", tenant, created.id], created);
      await queryClient.invalidateQueries({ queryKey: ["connections"] });
      await navigate({ to: "/t/$tenant/connections/$connectionId", params: { tenant, connectionId: created.id } });
    },
  });

  return (
    <section aria-labelledby="new-connection-heading" className="space-y-4">
      <Link to="/t/$tenant/connections" params={{ tenant }} className={`text-muted-foreground ${linkClass}`}>
        ← Connections
      </Link>
      <h1 id="new-connection-heading" className="text-xl font-semibold">
        New connection
      </h1>
      <KindPicker
        value={kind}
        onChange={(next) => {
          create.reset();
          setKind(next);
        }}
      />
      {kind && (
        <>
          <p className="text-muted-foreground text-sm">
            After saving, the connection page shows the redirect URI to register at {KIND_LABELS[kind]}.
          </p>
          <ConnectionForm
            // A new kind starts from that kind's defaults.
            key={kind}
            mode="create"
            initial={newConnectionValues(kind)}
            submitLabel="Create connection"
            pending={create.isPending}
            error={create.error}
            onSubmit={(values, secret) => {
              secretRef.current = secret;
              create.mutate(values);
            }}
          />
        </>
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/connections/new")({ component: NewConnectionPage });
