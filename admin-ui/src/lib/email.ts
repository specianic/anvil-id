import type { components } from "@/api/schema";

export type EmailKind = components["schemas"]["EmailKind"];

/** Human names of the transactional email kinds (Record: the compiler flags new API kinds). */
export const EMAIL_KIND_LABELS: Record<EmailKind, string> = {
  verification: "Email verification",
  recovery: "Account recovery",
  invitation: "Invitation",
  password_changed: "Password changed",
  recovery_code_used: "Recovery code used",
  login_code: "Sign-in code",
  email_change: "Email change confirmation",
  email_changed: "Email changed",
  org_invitation: "Organization invitation",
};

export function isEmailKind(value: string): value is EmailKind {
  return value in EMAIL_KIND_LABELS;
}
