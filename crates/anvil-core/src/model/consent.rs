//! Consent grants: which scopes a user granted to a client.

use time::OffsetDateTime;

use super::ids::{ConsentId, UserId};

/// A stored consent grant, one per (tenant, user, client). `scopes` is the union of everything
/// granted so far; a revoked grant has `revoked_at` set and is ignored until granted again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrant {
    pub id: ConsentId,
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// A consent to be granted (merged into an existing grant by `GrantRepo::upsert_consent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConsent {
    pub id: ConsentId,
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
}
