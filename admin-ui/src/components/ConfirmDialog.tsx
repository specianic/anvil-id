// Modal dialogs on the native <dialog> element: showModal() gives focus trapping, Escape to close,
// an inert background and the dialog role without a positioning library or inline styles.
import { type ReactNode, useEffect, useId, useRef } from "react";
import { ProblemAlert } from "@/components/ProblemAlert";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  /** `center` for confirmations, `side` for a detail drawer at the right edge. */
  placement?: "center" | "side";
  role?: "dialog" | "alertdialog";
  describedBy?: string;
}

export function Modal({ open, onClose, title, children, placement = "center", role, describedBy }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      role={role}
      aria-labelledby={titleId}
      aria-describedby={describedBy}
      onClose={() => open && onClose()}
      className={cn(
        "bg-background text-foreground border shadow-lg backdrop:bg-black/50",
        placement === "center"
          ? "m-auto w-full max-w-md rounded-lg p-6"
          : "my-0 mr-0 ml-auto h-full max-h-full w-full max-w-xl overflow-y-auto p-6",
      )}
    >
      {open && (
        <div className="space-y-4">
          <h2 id={titleId} className="text-lg font-semibold">
            {title}
          </h2>
          {children}
        </div>
      )}
    </dialog>
  );
}

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  pending?: boolean;
  error?: unknown;
}

/** Confirmation for a destructive action. The cancel button has initial focus. */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onCancel,
  pending,
  error,
}: ConfirmDialogProps) {
  const descriptionId = useId();
  return (
    <Modal open={open} onClose={onCancel} title={title} role="alertdialog" describedBy={descriptionId}>
      <div id={descriptionId} className="text-muted-foreground text-sm">
        {description}
      </div>
      {error ? <ProblemAlert error={error} /> : null}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel} autoFocus disabled={pending}>
          Cancel
        </Button>
        <Button variant="destructive" onClick={onConfirm} disabled={pending}>
          {pending ? "Working…" : confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
