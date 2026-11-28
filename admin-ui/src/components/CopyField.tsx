// A read-only value with a copy button (client ids, issuer and discovery URLs, redirect URIs). Usage:
//
//   <CopyField label="Issuer" value={tenant.issuer} mono />
//
// The button copies with navigator.clipboard; when the clipboard is unavailable (insecure context,
// denied permission) it selects the text so the admin can copy it by hand, and says so. The outcome is
// announced through a polite live region.
import { Check, Copy } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { controlClass } from "@/components/form";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CopyFieldProps {
  label: string;
  value: string;
  /** Monospace value (ids, URLs, keys). */
  mono?: boolean;
}

type CopyStatus = "idle" | "copied" | "selected";

const STATUS_TEXT: Record<CopyStatus, string> = {
  idle: "",
  copied: "Copied",
  selected: "Copying is not available here. The text is selected: press Ctrl+C (or Cmd+C) to copy it.",
};

export function CopyField({ label, value, mono }: CopyFieldProps) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<CopyStatus>("idle");

  // "Copied" fades after a few seconds; the select-all hint stays until the next attempt.
  useEffect(() => {
    if (status !== "copied") return;
    const timer = window.setTimeout(() => setStatus("idle"), 3000);
    return () => window.clearTimeout(timer);
  }, [status]);

  const selectAll = () => {
    input.current?.focus();
    input.current?.select();
    setStatus("selected");
  };

  const copy = async () => {
    if (!navigator.clipboard?.writeText) {
      selectAll();
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setStatus("copied");
    } catch {
      selectAll();
    }
  };

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <div className="flex gap-2">
        <input
          ref={input}
          id={id}
          readOnly
          value={value}
          onFocus={(e) => e.currentTarget.select()}
          className={cn(controlClass, "bg-muted min-w-0 flex-1", mono && "font-mono")}
        />
        <Button type="button" variant="outline" onClick={() => void copy()} aria-label={`Copy ${label}`}>
          {status === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
          Copy
        </Button>
      </div>
      <p role="status" aria-live="polite" className="text-muted-foreground min-h-0 text-xs">
        {STATUS_TEXT[status]}
      </p>
    </div>
  );
}
