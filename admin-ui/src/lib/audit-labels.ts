// Readable names of audit actions (C-M8): one table for the audit log's filter and cells. The
// Record type makes the compiler flag a missing or unknown action whenever the API enum changes.
import type { components } from "@/api/schema";

export type AuditAction = components["schemas"]["AuditAction"];

export const AUDIT_GROUPS = [
  "Sign-in",
  "Users",
  "Clients",
  "Connections",
  "Organizations",
  "Settings",
  "Keys",
  "Webhooks",
  "System",
] as const;
export type AuditGroup = (typeof AUDIT_GROUPS)[number];

export const AUDIT_ACTIONS: Record<AuditAction, { label: string; group: AuditGroup }> = {
  // Sign-in and the user's own account
  login_succeeded: { label: "Signed in", group: "Sign-in" },
  login_failed: { label: "Sign-in failed", group: "Sign-in" },
  second_factor_failed: { label: "Second factor failed", group: "Sign-in" },
  passkey_registered: { label: "Passkey registered", group: "Sign-in" },
  passkey_removed: { label: "Passkey removed", group: "Sign-in" },
  passkey_clone_suspected: { label: "Passkey clone suspected", group: "Sign-in" },
  totp_enrolled: { label: "Authenticator app enrolled", group: "Sign-in" },
  totp_removed: { label: "Authenticator app removed", group: "Sign-in" },
  recovery_code_used: { label: "Recovery code used", group: "Sign-in" },
  recovery_codes_regenerated: { label: "Recovery codes regenerated", group: "Sign-in" },
  password_changed: { label: "Password changed", group: "Sign-in" },
  consent_granted: { label: "Consent granted", group: "Sign-in" },
  consent_revoked: { label: "Consent revoked", group: "Sign-in" },
  session_revoked: { label: "Session revoked", group: "Sign-in" },
  sessions_revoked_all: { label: "All sessions revoked", group: "Sign-in" },
  token_revoked: { label: "Token revoked", group: "Sign-in" },
  refresh_reuse_detected: { label: "Refresh token reuse detected", group: "Sign-in" },
  code_reuse_detected: { label: "Authorization code reuse detected", group: "Sign-in" },
  rate_limit_lockout: { label: "Locked out by rate limit", group: "Sign-in" },
  captcha_failed: { label: "CAPTCHA failed", group: "Sign-in" },
  logout: { label: "Signed out", group: "Sign-in" },
  backchannel_logout_failed: { label: "Back-channel logout failed", group: "Sign-in" },
  step_up_completed: { label: "Step-up completed", group: "Sign-in" },
  email_code_sent: { label: "Email code sent", group: "Sign-in" },
  saml_login_succeeded: { label: "SAML sign-in succeeded", group: "Sign-in" },
  saml_login_failed: { label: "SAML sign-in failed", group: "Sign-in" },
  upstream_login_failed: { label: "Upstream sign-in failed", group: "Sign-in" },

  // Users
  user_registered: { label: "User registered", group: "Users" },
  user_created: { label: "User created", group: "Users" },
  user_updated: { label: "User updated", group: "Users" },
  user_deleted: { label: "User deleted", group: "Users" },
  user_recovery_sent: { label: "Password reset sent", group: "Users" },
  user_exported: { label: "User exported", group: "Users" },
  users_imported: { label: "Users imported", group: "Users" },
  user_attributes_updated: { label: "User attributes updated", group: "Users" },
  email_verified: { label: "Email verified", group: "Users" },
  email_change_requested: { label: "Email change requested", group: "Users" },
  email_changed: { label: "Email changed", group: "Users" },
  profile_updated: { label: "Profile updated", group: "Users" },
  identity_linked: { label: "Identity linked", group: "Users" },
  identity_unlinked: { label: "Identity unlinked", group: "Users" },
  role_assigned: { label: "Role assigned", group: "Users" },
  role_unassigned: { label: "Role removed", group: "Users" },

  // Clients
  client_created: { label: "Client created", group: "Clients" },
  client_updated: { label: "Client updated", group: "Clients" },
  client_deleted: { label: "Client deleted", group: "Clients" },
  client_secret_rotated: { label: "Client secret rotated", group: "Clients" },
  client_registered: { label: "Client registered (dynamic)", group: "Clients" },
  client_registration_updated: { label: "Client registration updated", group: "Clients" },
  client_registration_deleted: { label: "Client registration deleted", group: "Clients" },
  cimd_client_refreshed: { label: "Client metadata document refreshed", group: "Clients" },
  initial_access_token_created: { label: "Initial access token created", group: "Clients" },
  initial_access_token_revoked: { label: "Initial access token revoked", group: "Clients" },

  // Connections
  connection_created: { label: "Connection created", group: "Connections" },
  connection_updated: { label: "Connection updated", group: "Connections" },
  connection_deleted: { label: "Connection deleted", group: "Connections" },
  connection_secret_rotated: { label: "Connection secret rotated", group: "Connections" },

  // Organizations
  organization_created: { label: "Organization created", group: "Organizations" },
  organization_updated: { label: "Organization updated", group: "Organizations" },
  organization_deleted: { label: "Organization deleted", group: "Organizations" },
  org_member_added: { label: "Member added", group: "Organizations" },
  org_member_removed: { label: "Member removed", group: "Organizations" },
  org_role_assigned: { label: "Organization role assigned", group: "Organizations" },
  org_role_unassigned: { label: "Organization role removed", group: "Organizations" },
  org_invitation_created: { label: "Invitation created", group: "Organizations" },
  org_invitation_revoked: { label: "Invitation revoked", group: "Organizations" },
  org_invitation_accepted: { label: "Invitation accepted", group: "Organizations" },
  org_domain_created: { label: "Domain added", group: "Organizations" },
  org_domain_verified: { label: "Domain verified", group: "Organizations" },
  org_domain_verification_failed: { label: "Domain verification failed", group: "Organizations" },
  org_domain_unverified: { label: "Domain no longer verified", group: "Organizations" },
  org_domain_updated: { label: "Domain updated", group: "Organizations" },
  org_domain_deleted: { label: "Domain deleted", group: "Organizations" },

  // Settings
  tenant_updated: { label: "Tenant settings updated", group: "Settings" },
  email_template_updated: { label: "Email template updated", group: "Settings" },
  email_template_reset: { label: "Email template reset", group: "Settings" },
  smtp_settings_updated: { label: "SMTP settings updated", group: "Settings" },
  smtp_test_sent: { label: "SMTP test email sent", group: "Settings" },
  branding_updated: { label: "Branding updated", group: "Settings" },
  role_created: { label: "Role created", group: "Settings" },
  role_updated: { label: "Role updated", group: "Settings" },
  role_deleted: { label: "Role deleted", group: "Settings" },
  attribute_defined: { label: "Attribute defined", group: "Settings" },
  attribute_deleted: { label: "Attribute deleted", group: "Settings" },
  password_profile_created: { label: "Password hash profile created", group: "Settings" },
  password_profile_deleted: { label: "Password hash profile deleted", group: "Settings" },

  // Keys
  key_generated: { label: "Signing key generated", group: "Keys" },
  key_activated: { label: "Signing key activated", group: "Keys" },
  key_retired: { label: "Signing key retired", group: "Keys" },
  key_rotation_requested: { label: "Key rotation requested", group: "Keys" },

  // Webhooks
  webhook_endpoint_created: { label: "Webhook endpoint created", group: "Webhooks" },
  webhook_endpoint_updated: { label: "Webhook endpoint updated", group: "Webhooks" },
  webhook_endpoint_deleted: { label: "Webhook endpoint deleted", group: "Webhooks" },
  webhook_secret_rotated: { label: "Webhook secret rotated", group: "Webhooks" },
  webhook_endpoint_disabled: { label: "Webhook endpoint disabled", group: "Webhooks" },
  webhook_delivery_failed: { label: "Webhook delivery failed", group: "Webhooks" },
  webhook_test_sent: { label: "Webhook test sent", group: "Webhooks" },
  webhook_redelivered: { label: "Webhook event redelivered", group: "Webhooks" },

  // System
  tenant_created: { label: "Tenant created", group: "System" },
  tenant_deleted: { label: "Tenant deleted", group: "System" },
  tenant_config_applied: { label: "Configuration file applied", group: "System" },
  admin_setup_completed: { label: "Initial setup completed", group: "System" },
  admin_recovery_issued: { label: "Admin recovery link issued", group: "System" },
};

/** Whether a string is an audit action of the API enum. */
export function isAuditAction(value: string): value is AuditAction {
  return Object.hasOwn(AUDIT_ACTIONS, value);
}

/** Actions per group, groups in AUDIT_GROUPS order and actions sorted by label (for the filter). */
export function auditActionGroups(): { group: AuditGroup; actions: { value: AuditAction; label: string }[] }[] {
  const entries = Object.entries(AUDIT_ACTIONS) as [AuditAction, { label: string; group: AuditGroup }][];
  return AUDIT_GROUPS.map((group) => ({
    group,
    actions: entries
      .filter(([, v]) => v.group === group)
      .map(([value, v]) => ({ value, label: v.label }))
      .sort((a, b) => a.label.localeCompare(b.label)),
  }));
}

/** Sign-in actions whose target is not a user (a session or a token). */
const NON_USER_TARGETS: readonly AuditAction[] = ["session_revoked", "token_revoked", "users_imported"];

/**
 * What kind of record an action's `target` names, so the console can resolve and link it: user ids
 * for user and sign-in events, client ids for client events; null when the target is something
 * else (sessions, keys, organizations, ...), which the console shows as the raw id.
 */
export function auditTargetKind(action: AuditAction): "user" | "client" | null {
  const { group } = AUDIT_ACTIONS[action];
  if (NON_USER_TARGETS.includes(action)) return null;
  if (group === "Users" || group === "Sign-in") return "user";
  if (group === "Clients" && action !== "initial_access_token_created" && action !== "initial_access_token_revoked") return "client";
  return null;
}
