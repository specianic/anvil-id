// Unsaved-changes protection for console forms (C-M13): one implementation, used by every editing
// screen. Usage:
//
//   const blocker = useUnsavedChanges(form.isDirty);
//   ...
//   <UnsavedChangesGuard blocker={blocker} />
//
// While `isDirty` is true, in-app navigation (links, back/forward) is held until the admin confirms
// in UnsavedChangesGuard, and closing or reloading the tab triggers the browser's own beforeunload
// prompt. After a successful save, make `isDirty` false before navigating away programmatically.
import { useBlocker } from "@tanstack/react-router";
import { useEffect, useRef } from "react";

export type UnsavedChangesBlocker = ReturnType<typeof useUnsavedChanges>;

/** Blocks navigation away from the page while `isDirty` is true (TanStack Router useBlocker). */
export function useUnsavedChanges(isDirty: boolean) {
  // The blocker callbacks read the latest value through a ref, so a save that clears the dirty
  // state in the same render as a navigation is not blocked by a stale closure.
  const dirty = useRef(isDirty);
  useEffect(() => {
    dirty.current = isDirty;
  }, [isDirty]);

  return useBlocker({
    shouldBlockFn: () => dirty.current,
    enableBeforeUnload: () => dirty.current,
    withResolver: true,
  });
}
