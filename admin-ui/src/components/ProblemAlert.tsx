import { ApiError } from "@/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/** Error state for a failed query: shows the RFC 9457 problem (title, detail, field errors). */
export function ProblemAlert({ error }: { error: unknown }) {
  if (error instanceof ApiError) {
    const { problem } = error;
    return (
      <Alert variant="destructive">
        <AlertTitle>
          {problem.title} ({problem.status})
        </AlertTitle>
        <AlertDescription>
          {problem.detail && <p>{problem.detail}</p>}
          {problem.status === 403 && <p>Your account lacks the admin scope required for this page.</p>}
          {problem.errors.length > 0 && (
            <ul className="list-disc pl-5">
              {problem.errors.map((e) => (
                <li key={`${e.field}:${e.message}`}>
                  <code>{e.field}</code>: {e.message}
                </li>
              ))}
            </ul>
          )}
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <Alert variant="destructive">
      <AlertTitle>Request failed</AlertTitle>
      <AlertDescription>
        <p>{error instanceof Error ? error.message : "The server could not be reached."}</p>
      </AlertDescription>
    </Alert>
  );
}
