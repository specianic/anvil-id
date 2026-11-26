// Import users with their existing password hashes (07-17 API, docs/IMPORT-EXPORT.md): one NDJSON
// batch per upload, checked here against the server's limits (1 MiB, 1,000 records) before it is
// sent. The report lists every line's outcome and reason; it never contains a hash.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useId, useState } from "react";
import { api, unwrap } from "@/api/client";
import type { components } from "@/api/schema";
import { ProblemAlert } from "@/components/ProblemAlert";
import { CheckboxField, TextField, controlClass } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTenant } from "@/lib/tenant";

type ImportReportView = components["schemas"]["ImportReportView"];
type ImportCountsView = components["schemas"]["ImportCountsView"];

/** Server limits (IMPORT_BODY_LIMIT and IMPORT_BATCH_MAX); the server enforces them too. */
const MAX_BYTES = 1024 * 1024;
const MAX_RECORDS = 1000;

const COUNT_LABELS: readonly { key: keyof ImportCountsView; label: string }[] = [
  { key: "created", label: "Created" },
  { key: "updated", label: "Updated" },
  { key: "unchanged", label: "Unchanged" },
  { key: "conflict", label: "Conflict" },
  { key: "rejected", label: "Rejected" },
  { key: "weak", label: "Weak hashes" },
];

const REASON_TEXT: Record<string, string> = {
  invalid_email: "The email address is invalid.",
  invalid_record: "The line is not a valid user record.",
  unknown_scheme: "The password hash scheme is not supported.",
  weak_parameters: "The hash parameters are below the import floors.",
  over_cap: "The hash parameters are above the server's cost caps.",
  refused_variant: "This hash variant is refused.",
  unknown_profile: "The Firebase hash profile does not exist in this tenant.",
  id_conflict: "The user id is already used by another user.",
};

/** Non-blank lines (the server counts records the same way). */
function countRecords(text: string): number {
  let n = 0;
  for (const line of text.split("\n")) if (line.trim() !== "") n += 1;
  return n;
}

interface Upload {
  name: string;
  text: string;
  records: number;
}

function outcomeVariant(outcome: string): "default" | "secondary" | "destructive" | "outline" {
  if (outcome === "rejected") return "destructive";
  if (outcome === "conflict") return "outline";
  if (outcome === "created" || outcome === "updated") return "default";
  return "secondary";
}

function Report({ report, tenant }: { report: ImportReportView; tenant: string }) {
  return (
    <Card data-testid="import-report" data-dry-run={report.dry_run ? "true" : "false"}>
      <CardHeader>
        <CardTitle>
          <h2>{report.dry_run ? "Dry run report (nothing was written)" : "Import report"}</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="grid grid-cols-2 gap-2 sm:grid-cols-6">
          {COUNT_LABELS.map(({ key, label }) => (
            <div key={key} className="rounded-md border p-2">
              <dt className="text-muted-foreground text-xs">{label}</dt>
              <dd className="text-lg font-semibold" data-testid={`import-count-${key}`}>
                {report.counts[key]}
              </dd>
            </div>
          ))}
        </dl>
        {report.counts.weak > 0 && (
          <p className="text-muted-foreground text-sm">
            Weak hashes are accepted but below today's recommended parameters; each is replaced by an Argon2id hash at
            the user's first sign-in.
          </p>
        )}
        <Table>
          <TableCaption>Records by line</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Line</TableHead>
              <TableHead>Outcome</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Weak hash</TableHead>
              <TableHead>User</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {report.records.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground">
                  The file holds no records.
                </TableCell>
              </TableRow>
            ) : (
              report.records.map((r) => (
                <TableRow
                  key={r.line}
                  data-testid="import-row"
                  data-line={r.line}
                  data-outcome={r.outcome}
                  data-reason={r.reason ?? ""}
                  data-weak={r.weak ? "true" : "false"}
                >
                  <TableCell>{r.line}</TableCell>
                  <TableCell>
                    <Badge variant={outcomeVariant(r.outcome)}>{r.outcome}</Badge>
                  </TableCell>
                  <TableCell>
                    {r.reason ? (
                      <>
                        <code className="text-xs">{r.reason}</code>{" "}
                        <span className="text-muted-foreground text-xs">{REASON_TEXT[r.reason] ?? ""}</span>
                      </>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell>{r.weak ? "Weak" : "—"}</TableCell>
                  <TableCell>
                    {r.user_id && !report.dry_run ? (
                      <Link
                        to="/t/$tenant/users/$userId"
                        params={{ tenant, userId: r.user_id }}
                        className="underline underline-offset-4"
                      >
                        <code className="text-xs">{r.user_id}</code>
                      </Link>
                    ) : r.user_id ? (
                      <code className="text-xs">{r.user_id}</code>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function ImportUsersPage() {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const fileId = useId();
  const [upload, setUpload] = useState<Upload | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [dryRun, setDryRun] = useState(true);
  const [update, setUpdate] = useState(false);
  const [source, setSource] = useState("");

  const run = useMutation({
    mutationFn: async (args: { text: string; dryRun: boolean; update: boolean; source: string }) =>
      unwrap(
        await api.POST("/api/admin/v1/tenants/{slug}/users/import", {
          params: {
            path: { slug: tenant },
            query: {
              ...(args.dryRun ? { dry_run: true } : {}),
              ...(args.update ? { update: true } : {}),
              ...(args.source ? { source: args.source } : {}),
            },
          },
          body: args.text,
          // The body is the NDJSON file as is (openapi-fetch would JSON-encode it otherwise).
          bodySerializer: (body: string) => body,
          headers: { "Content-Type": "application/x-ndjson" },
        }),
      ),
    onSuccess: async (report) => {
      if (!report.dry_run) await queryClient.invalidateQueries({ queryKey: ["users", tenant] });
    },
  });

  const chooseFile = async (file: File | undefined) => {
    run.reset();
    setUpload(null);
    setFileError(null);
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setFileError(`The file is ${file.size.toLocaleString()} bytes; one import holds at most 1 MiB. Split it into several files.`);
      return;
    }
    const text = await file.text();
    const records = countRecords(text);
    if (records > MAX_RECORDS) {
      setFileError(`The file holds ${records.toLocaleString()} records; one import holds at most 1,000. Split it into several files.`);
      return;
    }
    setUpload({ name: file.name, text, records });
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!upload) {
      setFileError("Choose an NDJSON file first.");
      return;
    }
    run.mutate({ text: upload.text, dryRun, update, source: source.trim() });
  };

  const fileHintId = `${fileId}-hint`;
  const fileErrorId = `${fileId}-error`;

  return (
    <section aria-labelledby="import-heading" className="space-y-4">
      <Link
        to="/t/$tenant/users"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Users
      </Link>
      <h1 id="import-heading" className="text-xl font-semibold">
        Import users
      </h1>
      <p className="text-muted-foreground text-sm">
        Upload users with their existing password hashes as NDJSON, one user per line (see IMPORT-EXPORT.md in the
        documentation). Users sign in with their old passwords; each hash is replaced by an Argon2id hash at the first
        sign-in. Firebase hashes need a{" "}
        <Link to="/t/$tenant/password-profiles" params={{ tenant }} className="underline underline-offset-4">
          password hash profile
        </Link>
        .
      </p>
      <form onSubmit={submit} noValidate aria-label="Import users" className="space-y-4" data-testid="import-form">
        <div className="space-y-1.5">
          <label htmlFor={fileId} className="block text-sm font-medium">
            NDJSON file
          </label>
          <input
            id={fileId}
            type="file"
            accept=".ndjson,.jsonl,application/x-ndjson,text/plain"
            className={controlClass}
            aria-describedby={fileError ? `${fileHintId} ${fileErrorId}` : fileHintId}
            aria-invalid={fileError ? true : undefined}
            onChange={(e) => void chooseFile(e.target.files?.[0])}
            data-testid="import-file"
          />
          <p id={fileHintId} className="text-muted-foreground text-xs">
            At most 1 MiB and 1,000 records per file.
          </p>
          {fileError && (
            <p id={fileErrorId} className="text-destructive text-sm" data-testid="import-file-error">
              {fileError}
            </p>
          )}
          {upload && (
            <p className="text-sm" data-testid="import-file-summary">
              {upload.name}: {upload.records} {upload.records === 1 ? "record" : "records"}.
            </p>
          )}
        </div>
        <CheckboxField
          label="Dry run"
          hint="Check every record and show the report without creating or changing users."
          checked={dryRun}
          onChange={(e) => setDryRun(e.target.checked)}
          data-testid="import-dry-run"
        />
        <CheckboxField
          label="Update existing users"
          hint="Users that already exist (same email) with different data are overwritten instead of reported as conflicts."
          checked={update}
          onChange={(e) => setUpdate(e.target.checked)}
          data-testid="import-update"
        />
        <TextField
          label="Source label"
          optional
          value={source}
          maxLength={64}
          onChange={(e) => setSource(e.target.value)}
          hint="Names the source system in the audit log, for example auth0 or firebase."
          autoComplete="off"
          data-testid="import-source"
        />
        {run.error ? <ProblemAlert error={run.error} /> : null}
        <Button type="submit" disabled={run.isPending || !upload} data-testid="import-submit">
          {run.isPending ? "Importing…" : dryRun ? "Run dry run" : "Import users"}
        </Button>
      </form>
      {run.data ? <Report report={run.data} tenant={tenant} /> : null}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/users/import")({ component: ImportUsersPage });
