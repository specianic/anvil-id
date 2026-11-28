// The confirmation shown when an admin navigates away from a form with unsaved changes. Pair it with
// useUnsavedChanges (lib/unsaved.ts):
//
//   const blocker = useUnsavedChanges(isDirty);
//   return (<form>...<UnsavedChangesGuard blocker={blocker} /></form>);
//
// It uses the console's Modal (components/ConfirmDialog.tsx), so focus trapping, Escape (= stay) and
// the inert background are the same as every other confirmation. "Stay" has initial focus.
import { LogOut } from "lucide-react";
import { useId } from "react";
import { Modal } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import type { UnsavedChangesBlocker } from "@/lib/unsaved";

export function UnsavedChangesGuard({ blocker }: { blocker: UnsavedChangesBlocker }) {
  const descriptionId = useId();
  const open = blocker.status === "blocked";
  const stay = () => blocker.reset?.();
  return (
    <Modal open={open} onClose={stay} title="Leave without saving?" role="alertdialog" describedBy={descriptionId}>
      <p id={descriptionId} className="text-muted-foreground text-sm">
        Your changes on this page have not been saved. If you leave now, they are lost.
      </p>
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={stay} autoFocus>
          Stay
        </Button>
        <Button variant="destructive" onClick={() => blocker.proceed?.()}>
          <LogOut aria-hidden="true" />
          Leave
        </Button>
      </div>
    </Modal>
  );
}
