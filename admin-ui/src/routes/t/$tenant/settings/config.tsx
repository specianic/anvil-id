// Declarative tenant configuration (ADM-06): download the tenant as a JSON document (the YAML form
// is the CLI's job), preview the plan of an uploaded document and apply it behind a confirmation.
// An uploaded document may carry inline secrets, so it is kept in a ref (never in query or mutation
// state) and dropped after apply or when another file is chosen. Secrets the server generates
// during an apply are shown once and kept only in component state.
import { useMutation } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { toApiJson } from "@/components/AttributeForm";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { OneTimeSecret } from "@/components/WebhookForm";
import { CheckboxField, StatusMessage } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTenant } from "@/lib/tenant";

type ConfigPlan = components["schemas"]["ConfigPlanDto"];
type ConfigChange = components["schemas"]["ConfigChangeDto"];
type GeneratedSecret = components["schemas"]["GeneratedSecretDto"];

/** Uploaded documents are JSON; the API body limit is 64 KiB (use the CLI for larger documents). */
const MAX_DOCUMENT_BYTES = 64 * 1024;

function Download() {
  const tenant = useTenant();
  const [status, setStatus] = useState<string | null>(null);
  const download = useMutation({
    mutationFn: async () => {
      const doc = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/config", { params: { path: { slug: tenant } } }),
      );
      const blob = new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${tenant}.tenant.json`;
      document.body.append(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },
    onMutate: () => setStatus(null),
    onSuccess: () => setStatus(`Downloaded ${tenant}.tenant.json.`),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Export</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          The tenant's settings, clients, connections, branding, roles, attributes, email templates, SMTP and webhooks
          as a version 1 document. Secrets appear as <code>{"{configured: true}"}</code>; users and dynamic clients are
          not included.
        </p>
        {download.error ? <ProblemAlert error={download.error} /> : null}
        <Button onClick={() => download.mutate()} disabled={download.isPending} data-testid="download-config">
          {download.isPending ? "Preparing…" : "Download JSON"}
        </Button>
        <StatusMessage message={status} />
        <p className="text-muted-foreground">YAML, with secrets from environment variables or files, through the CLI:</p>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 text-xs" data-testid="config-cli">
          {`anvilid tenant export ${tenant} -o ${tenant}.yaml\nanvilid tenant plan -f ${tenant}.yaml\nanvilid tenant apply -f ${tenant}.yaml`}
        </pre>
      </CardContent>
    </Card>
  );
}

function ChangeList({ title, changes }: { title: string; changes: ConfigChange[] }) {
  if (changes.length === 0) return null;
  return (
    <div className="space-y-1">
      <h3 className="text-sm font-medium">
        {title} ({changes.length})
      </h3>
      <ul className="space-y-1 text-sm">
        {changes.map((c) => (
          <li key={`${c.kind}:${c.key}`}>
            <code className="text-xs">
              {c.kind} {c.key}
            </code>
            {c.fields.length > 0 && (
              <span className="text-muted-foreground text-xs">
                {" "}
                ({c.fields.map((f) => (f.secret ? `${f.field} (secret)` : f.field)).join(", ")})
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function PlanView({ plan }: { plan: ConfigPlan }) {
  if (plan.empty) {
    return (
      <p className="text-sm" role="status" data-testid="config-plan-empty">
        No changes: the tenant already matches the document.
      </p>
    );
  }
  return (
    <div className="space-y-3" data-testid="config-plan">
      <ChangeList title="Create" changes={plan.creates} />
      <ChangeList title="Update" changes={plan.updates} />
      <ChangeList title="Delete (only with prune)" changes={plan.deletes} />
      <details>
        <summary className="cursor-pointer text-sm">Plan as text</summary>
        <pre className="bg-muted mt-2 overflow-x-auto rounded-md p-3 text-xs">{plan.text}</pre>
      </details>
    </div>
  );
}

function PlanAndApply() {
  const tenant = useTenant();
  const documentRef = useRef<unknown>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileIssue, setFileIssue] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [prune, setPrune] = useState(false);
  const [generated, setGenerated] = useState<GeneratedSecret[]>([]);
  const [status, setStatus] = useState<string | null>(null);

  const plan = useMutation({
    mutationFn: async () => {
      const doc = documentRef.current;
      if (doc === null) throw new Error("Choose a document first.");
      return unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/config/plan", {
          params: { path: { slug: tenant } },
          body: toApiJson(doc),
        }),
      );
    },
    onMutate: () => setStatus(null),
  });

  const apply = useMutation({
    mutationFn: async (withPrune: boolean) => {
      const doc = documentRef.current;
      if (doc === null) throw new Error("Choose a document first.");
      const result = unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/config/apply", {
          params: { path: { slug: tenant }, query: { prune: withPrune } },
          body: toApiJson(doc),
        }),
      );
      // Generated secrets go to component state only; the cached result carries none.
      setGenerated(result.generated_secrets);
      return { ...result, generated_secrets: [] };
    },
    onSuccess: (result) => {
      documentRef.current = null;
      setFileName(null);
      if (fileInput.current) fileInput.current.value = "";
      setConfirm(false);
      plan.reset();
      setStatus(
        result.applied
          ? `Applied: ${result.plan.creates.length} created, ${result.plan.updates.length} updated, ${
              result.pruned ? result.plan.deletes.length : 0
            } deleted.`
          : result.pruned || result.plan.deletes.length === 0
            ? "No changes."
            : "Nothing to apply without prune.",
      );
    },
  });

  const choose = async (file: File | undefined) => {
    documentRef.current = null;
    plan.reset();
    apply.reset();
    setGenerated([]);
    setStatus(null);
    setFileIssue(null);
    setFileName(null);
    if (!file) return;
    if (file.size > MAX_DOCUMENT_BYTES) {
      setFileIssue("The document is larger than 64 KiB; plan and apply it with the CLI.");
      return;
    }
    try {
      documentRef.current = JSON.parse(await file.text()) as unknown;
      setFileName(file.name);
      plan.mutate();
    } catch {
      setFileIssue("The file is not valid JSON. YAML documents are planned and applied with the CLI.");
    }
  };

  const issues =
    plan.error instanceof ApiError && plan.error.status === 422 ? plan.error.problem.errors : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Plan and apply</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="space-y-1.5">
          <label htmlFor="config-file" className="block font-medium">
            Document (JSON)
          </label>
          <input
            id="config-file"
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            onChange={(e) => void choose(e.target.files?.[0])}
            aria-describedby="config-file-hint"
            className="text-sm"
            data-testid="config-file"
          />
          <p id="config-file-hint" className="text-muted-foreground text-xs">
            Planning changes nothing. Inline secrets in the document are sent to the server only, never stored by the
            console.
          </p>
          {fileIssue && (
            <p role="alert" className="text-destructive">
              {fileIssue}
            </p>
          )}
        </div>
        {plan.isPending && <p role="status">Planning…</p>}
        {issues.length > 0 ? (
          <div role="alert" className="space-y-1" data-testid="config-issues">
            <p className="text-destructive font-medium">The document is invalid; nothing would be changed.</p>
            <ul className="list-disc pl-5">
              {issues.map((i) => (
                <li key={`${i.field}:${i.message}`}>
                  <code>{i.field}</code>: {i.message}
                </li>
              ))}
            </ul>
          </div>
        ) : plan.error ? (
          <ProblemAlert error={plan.error} />
        ) : null}
        {plan.data && fileName && (
          <>
            <p className="text-muted-foreground">
              Plan for <code>{fileName}</code>:
            </p>
            <PlanView plan={plan.data} />
            <Button
              onClick={() => setConfirm(true)}
              disabled={plan.data.empty && plan.data.deletes.length === 0}
              data-testid="apply-config"
            >
              Apply…
            </Button>
          </>
        )}
        <StatusMessage message={status} />
        {generated.map((g) => (
          <OneTimeSecret
            key={`${g.kind}:${g.key}:${g.field}`}
            title={`Generated ${g.field} of ${g.kind} ${g.key}. It is not shown again.`}
            label="Secret"
            value={g.value}
            testId={`generated-${g.kind}-${g.key}`}
            onDone={() => setGenerated((list) => list.filter((x) => x !== g))}
          />
        ))}
      </CardContent>
      <ConfirmDialog
        open={confirm}
        title="Apply this document?"
        description={
          <div className="space-y-3">
            <p>
              The changes of the plan are written through the same checks as the admin API. Without prune, objects
              missing from the document are kept.
            </p>
            <CheckboxField
              label="Prune: also delete objects that are not in the document"
              checked={prune}
              onChange={(e) => setPrune(e.target.checked)}
              data-testid="apply-prune"
            />
          </div>
        }
        confirmLabel={prune ? "Apply and prune" : "Apply"}
        onConfirm={() => apply.mutate(prune)}
        onCancel={() => {
          apply.reset();
          setConfirm(false);
        }}
        pending={apply.isPending}
        error={apply.error}
      />
    </Card>
  );
}

function ConfigPage() {
  const tenant = useTenant();
  return (
    <section aria-labelledby="config-heading" className="space-y-4">
      <Link
        to="/t/$tenant/settings"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Login settings
      </Link>
      <h1 id="config-heading" className="text-xl font-semibold">
        Configuration
      </h1>
      <Download />
      <PlanAndApply />
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/settings/config")({ component: ConfigPage });
