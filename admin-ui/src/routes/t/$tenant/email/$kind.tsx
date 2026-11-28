import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { ApiError, api, unwrap } from "@/api/client";
import { useTenant } from "@/lib/tenant";
import type { components } from "@/api/schema";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";
import { StatusMessage, TextField, TextareaField, fieldErrors } from "@/components/form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { EMAIL_KIND_LABELS, type EmailKind, isEmailKind } from "@/lib/email";
import { formatDateTime } from "@/lib/format";
import { useUnsavedChanges } from "@/lib/unsaved";

type EmailTemplateView = components["schemas"]["EmailTemplateView"];

function TemplateEditor({ kind, template }: { kind: EmailKind; template: EmailTemplateView }) {
  const tenant = useTenant();
  const queryClient = useQueryClient();
  const [subject, setSubject] = useState(template.subject);
  const [bodyHtml, setBodyHtml] = useState(template.body_html);
  const [bodyText, setBodyText] = useState(template.body_text);
  const [status, setStatus] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);

  const invalidate = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["email-templates", tenant] }),
      queryClient.invalidateQueries({ queryKey: ["email-template", tenant, kind] }),
    ]);

  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/api/admin/v1/tenants/{slug}/email-templates/{kind}", {
          params: { path: { slug: tenant, kind } },
          body: { subject, body_html: bodyHtml, body_text: bodyText },
        }),
      ),
    onMutate: () => setStatus(null),
    onSuccess: async (saved) => {
      queryClient.setQueryData(["email-template", tenant, kind], saved);
      // Show what is stored (the server may normalise), so the form is clean after a save.
      setSubject(saved.subject);
      setBodyHtml(saved.body_html);
      setBodyText(saved.body_text);
      setStatus("Template saved.");
      await invalidate();
    },
  });

  const reset = useMutation({
    mutationFn: async () => {
      await api.DELETE("/api/admin/v1/tenants/{slug}/email-templates/{kind}", {
        params: { path: { slug: tenant, kind } },
      });
    },
    onSuccess: async () => {
      setConfirmReset(false);
      save.reset();
      const fresh = unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/email-templates/{kind}", {
          params: { path: { slug: tenant, kind } },
        }),
      );
      queryClient.setQueryData(["email-template", tenant, kind], fresh);
      setSubject(fresh.subject);
      setBodyHtml(fresh.body_html);
      setBodyText(fresh.body_text);
      setStatus("Template reset to the default.");
      await invalidate();
    },
  });

  const errors = fieldErrors(save.error);
  const known = new Set(["subject", "body_html", "body_text"]);
  const otherError =
    save.error && !(save.error instanceof ApiError && save.error.problem.errors.every((e) => known.has(e.field)))
      ? save.error
      : null;
  const invalid = save.error instanceof ApiError && save.error.status === 422;
  // The parent's query data: updated by setQueryData after a save or reset.
  const current = template;
  // Unsaved edits (C-M13): compared with the stored template, which a save or reset replaces.
  const dirty =
    subject !== current.subject || bodyHtml !== current.body_html || bodyText !== current.body_text;
  const blocker = useUnsavedChanges(dirty && !save.isPending && !reset.isPending);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <div className="space-y-4">
      <UnsavedChangesGuard blocker={blocker} />
      <p className="text-sm">
        {current.customized ? (
          <Badge data-testid="template-status">Customized</Badge>
        ) : (
          <Badge variant="secondary" data-testid="template-status">
            Default
          </Badge>
        )}
        {current.updated_at && (
          <span className="text-muted-foreground ml-2">Saved {formatDateTime(current.updated_at)}</span>
        )}
      </p>
      <div className="text-sm">
        <h2 className="font-medium">Available variables</h2>
        <ul className="mt-1 flex flex-wrap gap-2" aria-label="Available variables">
          {current.variables.map((v) => (
            <li key={v}>
              <code className="bg-muted rounded px-1.5 py-0.5 text-xs">{`{{ ${v} }}`}</code>
            </li>
          ))}
        </ul>
      </div>
      <form onSubmit={submit} aria-label={`${EMAIL_KIND_LABELS[kind]} template`} className="space-y-4" noValidate>
        {invalid && (
          <p role="alert" className="text-destructive text-sm">
            The template was not saved. Fix the errors below.
          </p>
        )}
        {otherError ? <ProblemAlert error={otherError} /> : null}
        <TextField
          label="Subject"
          name="subject"
          required
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          errors={errors.subject}
        />
        <TextareaField
          label="HTML body"
          name="body_html"
          rows={12}
          value={bodyHtml}
          onChange={(e) => setBodyHtml(e.target.value)}
          errors={errors.body_html}
          hint="minijinja syntax; values are HTML-escaped."
        />
        <TextareaField
          label="Text body"
          name="body_text"
          rows={8}
          value={bodyText}
          onChange={(e) => setBodyText(e.target.value)}
          errors={errors.body_text}
        />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save template"}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!current.customized || reset.isPending}
            onClick={() => setConfirmReset(true)}
          >
            Reset to default
          </Button>
        </div>
        <StatusMessage message={status} />
      </form>
      <ConfirmDialog
        open={confirmReset}
        title="Reset template?"
        description={<p>The tenant's customized template is deleted and the theme default is used again.</p>}
        confirmLabel="Reset to default"
        onConfirm={() => reset.mutate()}
        onCancel={() => {
          reset.reset();
          setConfirmReset(false);
        }}
        pending={reset.isPending}
        error={reset.error}
      />
    </div>
  );
}

function TemplatePage() {
  const tenant = useTenant();
  const { kind: param } = Route.useParams();
  const kind = isEmailKind(param) ? param : null;
  const query = useQuery({
    queryKey: ["email-template", tenant, param],
    enabled: kind !== null,
    // Edits live in local state; a background refetch must not overwrite them.
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async ({ signal }) =>
      unwrap(
        await api.GET("/api/admin/v1/tenants/{slug}/email-templates/{kind}", {
          params: { path: { slug: tenant, kind: kind as EmailKind } },
          signal,
        }),
      ),
  });

  return (
    <section aria-labelledby="template-heading" className="space-y-4">
      <Link
        to="/t/$tenant/email"
        params={{ tenant }}
        className="text-muted-foreground text-sm underline-offset-4 hover:underline"
      >
        ← Email
      </Link>
      <h1 id="template-heading" className="text-xl font-semibold">
        {kind ? EMAIL_KIND_LABELS[kind] : "Unknown template"}
      </h1>
      {kind === null ? (
        <p className="text-muted-foreground text-sm">There is no email template named “{param}”.</p>
      ) : query.isPending ? (
        <div role="status" aria-label="Loading template" className="space-y-2">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : query.isError ? (
        <ProblemAlert error={query.error} />
      ) : (
        <TemplateEditor kind={kind} template={query.data} />
      )}
    </section>
  );
}

export const Route = createFileRoute("/t/$tenant/email/$kind")({ component: TemplatePage });
