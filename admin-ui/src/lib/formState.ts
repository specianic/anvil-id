// Form values with a saved baseline, so a form knows whether it has unsaved changes (C-M13).
// Usage in a form component:
//
//   const form = useFormState(initial);
//   const blocker = useUnsavedChanges(form.isDirty && !pending);
//   ... form.values / form.setValues ...
//   const submit = () => { form.markSubmitted(); onSubmit(form.values); };
//
// `initial` is what the server holds (the loaded record, or the empty values of a create form).
// When it changes (a save refreshed the query, or another admin's change arrived), it becomes the
// new baseline. The visible values follow it if the admin had no unsaved edits or just submitted
// them (the saved record may normalise what was typed); otherwise the edits are kept.
//
// Pass `isDirty && !pending` to useUnsavedChanges: TanStack Query runs a mutation's onSuccess
// (where the pages navigate after a save) while it is still pending, so a successful save never
// prompts, and a failed one makes the form dirty again.
import { type SetStateAction, useCallback, useState } from "react";

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function useFormState<T>(initial: T) {
  const [values, setValuesState] = useState<T>(initial);
  const [baseline, setBaseline] = useState<T>(initial);
  const [submitted, setSubmitted] = useState(false);

  // Adopt a changed `initial` during render (React's "adjust state when a prop changes" pattern).
  if (!same(initial, baseline)) {
    const hadEdits = !same(values, baseline);
    setBaseline(initial);
    if (!hadEdits || submitted) setValuesState(initial);
    setSubmitted(false);
  }

  const setValues = useCallback((next: SetStateAction<T>) => setValuesState(next), []);
  const markSubmitted = useCallback(() => setSubmitted(true), []);

  return { values, setValues, isDirty: !same(values, baseline), markSubmitted };
}
