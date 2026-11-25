//! Names of installation-wide background jobs guarded by `JobRepo` leases.

/// Name of a leased background job.
pub struct JobName;

impl JobName {
    /// Signing key rotation (generate, promote, delete expired keys).
    pub const KEY_ROTATION: &'static str = "key_rotation";
    /// `Storage::purge_expired`.
    pub const PURGE_EXPIRED: &'static str = "purge_expired";
    /// Audit retention (`AuditRepo::purge_before`).
    pub const AUDIT_RETENTION: &'static str = "audit_retention";
}
