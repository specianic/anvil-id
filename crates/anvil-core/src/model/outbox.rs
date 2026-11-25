//! Transactional email outbox.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::ids::{OutboxId, TenantId};

/// An email to be enqueued (in the same transaction as the change that triggers it).
/// `payload` holds the template variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEmail {
    pub id: OutboxId,
    pub to: String,
    pub template: String,
    pub payload: BTreeMap<String, String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A stored outbox email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEmail {
    pub id: OutboxId,
    pub tenant_id: TenantId,
    pub to: String,
    pub template: String,
    pub payload: BTreeMap<String, String>,
    pub attempts: u32,
    pub next_attempt_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub sent_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}
