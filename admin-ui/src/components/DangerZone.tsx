// The "Danger zone" section of a detail page (C-M9): one place for irreversible actions such as
// deleting a tenant, client or organization. Usage:
//
//   <DangerZone
//     title="Delete this tenant"
//     description="Deletes the tenant with its users, clients and keys. This cannot be undone."
//     confirmText={tenant.slug}
//     actionLabel="Delete tenant"
//     onConfirm={() => remove.mutate()}
//     pending={remove.isPending}
//     error={remove.error}
//   />
//
// The action opens a confirmation (the console's Modal from components/ConfirmDialog.tsx) where the
// admin types `confirmText` exactly before the destructive button enables. Danger is never colour
// alone: the section and the button carry an icon and a text label.
import { Trash2, TriangleAlert } from "lucide-react";
import { type ReactNode, useId, useState } from "react";
import { Modal } from "@/components/ConfirmDialog";
import { ProblemAlert } from "@/components/ProblemAlert";
import { controlClass } from "@/components/form";
import { Button } from "@/components/ui/button";

interface DangerZoneProps {
  /** What the action does, e.g. "Delete this tenant". */
  title: string;
  description: ReactNode;
  /** The exact text the admin must type to confirm (usually the slug or name). */
  confirmText: string;
  /** Verb label of the destructive button, e.g. "Delete tenant". */
  actionLabel: string;
  onConfirm: () => void;
  pending?: boolean;
  /** Error of the last attempt, shown in the dialog. */
  error?: unknown;
}

export function DangerZone({ title, description, confirmText, actionLabel, onConfirm, pending, error }: DangerZoneProps) {
  const headingId = useId();
  const descriptionId = useId();
  const inputId = useId();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const matches = typed === confirmText;

  // Escape closes the native dialog even while pending; the state follows so it can reopen.
  const close = () => {
    setOpen(false);
    setTyped("");
  };

  return (
    <section aria-labelledby={headingId} className="border-destructive space-y-3 rounded-none border p-6" data-testid="danger-zone">
      <h2 id={headingId} className="text-destructive flex items-center gap-2 text-lg font-semibold">
        <TriangleAlert aria-hidden="true" className="size-5" />
        Danger zone
      </h2>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-prose space-y-1">
          <h3 className="font-semibold">{title}</h3>
          <div className="text-muted-foreground text-sm">{description}</div>
        </div>
        <Button variant="destructive" onClick={() => setOpen(true)}>
          <Trash2 aria-hidden="true" />
          {actionLabel}
        </Button>
      </div>

      <Modal open={open} onClose={close} title={`${title}?`} role="alertdialog" describedBy={descriptionId}>
        <div id={descriptionId} className="text-muted-foreground space-y-2 text-sm">
          <div>{description}</div>
          <p>
            Type <code className="text-foreground bg-muted px-1 font-mono">{confirmText}</code> to confirm.
          </p>
        </div>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (matches && !pending) onConfirm();
          }}
        >
          <div className="space-y-1.5">
            <label htmlFor={inputId} className="block text-sm font-medium">
              Confirmation
            </label>
            <input
              id={inputId}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              className={`${controlClass} font-mono`}
              data-testid="danger-zone-confirm-input"
            />
          </div>
          {error ? <ProblemAlert error={error} /> : null}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={close} autoFocus disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={!matches || pending}>
              <Trash2 aria-hidden="true" />
              {pending ? "Working…" : actionLabel}
            </Button>
          </div>
        </form>
      </Modal>
    </section>
  );
}
