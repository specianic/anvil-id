//! RP sessions and back-channel logout deliveries (OIDC-12).
//!
//! An [`RpSession`] records that a browser session signed in to a relying party (written by
//! `GrantRepo::create_code`). When a session is revoked, storage enqueues one
//! [`LogoutDelivery`] per RP session whose client registered a `backchannel_logout_uri`, in the
//! same transaction (see `LogoutRepo` in the ports). The `sid` claim is the browser session id.

use time::OffsetDateTime;

use super::ids::{LogoutDeliveryId, SessionId, TenantId};

/// How long a delivery is retried before it is given up.
pub const LOGOUT_DELIVERY_TTL: time::Duration = time::Duration::hours(24);

/// A browser session that signed in to a relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpSession {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub client_id: String,
    /// The issuer of the ID tokens this RP got for the session (the latest authorization code's
    /// issuer). `None` only for rows written before migration 0006 (SQLite) / 0005 (Postgres).
    pub issuer: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A queued back-channel logout token delivery. The logout token itself is built and signed at
/// delivery time from `sub`/`sid`; nothing secret is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutDelivery {
    pub id: LogoutDeliveryId,
    pub tenant_id: TenantId,
    pub client_id: String,
    /// The client's `backchannel_logout_uri` when the delivery was enqueued.
    pub uri: String,
    /// The user id (logout token `sub`).
    pub sub: String,
    /// The browser session id (logout token `sid`).
    pub sid: String,
    /// The logout token `iss`, copied from the RP session when the delivery was enqueued (it
    /// must equal the ID token's `iss`). `None` only for rows written before migration 0006
    /// (SQLite) / 0005 (Postgres).
    pub issuer: Option<String>,
    pub attempts: u32,
    pub next_attempt_at: OffsetDateTime,
    pub give_up_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub delivered_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}

/// Outcome of one delivery attempt (`LogoutRepo::complete_delivery`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryResult {
    /// The RP answered 200/204: sets `delivered_at`.
    Delivered,
    /// Transient failure: increments `attempts`, reschedules, records the error.
    Retry {
        next_attempt_at: OffsetDateTime,
        error: String,
    },
    /// Permanent failure: sets `give_up_at = now` and records the error.
    GiveUp { error: String },
}
