//! Domain model: identifiers and records shared by the protocol logic and the storage ports.
//!
//! Pure data. Callers generate identifiers and timestamps (truncated with [`truncate_to_ms`]);
//! repositories only persist them.

mod audit;
mod client;
mod consent;
mod credential;
mod flow;
mod grant;
mod ids;
mod job;
mod key;
mod mail_settings;
mod outbox;
mod session;
mod setup;
mod tenant;
mod user;

pub use audit::*;
pub use client::*;
pub use consent::*;
pub use credential::*;
pub use flow::*;
pub use grant::*;
pub use ids::{
    AuditEventId, AuthRequestId, ClientId, CodeHash, ConsentId, CredentialId, FlowId,
    InvalidLength, OutboxId, Page, PageRequest, SecretHash, SessionId, SigningKeyId, TenantId,
    TokenFamilyId, UserId,
};
pub use job::*;
pub use key::*;
pub use mail_settings::*;
pub use outbox::*;
pub use session::*;
pub use setup::*;
pub use tenant::*;
pub use user::*;

use time::OffsetDateTime;

/// Truncates a timestamp to whole milliseconds.
///
/// The storage contract is **millisecond precision**: SQLite stores timestamps as integer
/// milliseconds since the Unix epoch, while Postgres `timestamptz` keeps microseconds. Callers
/// truncate timestamps with this function before persisting them so a stored value round-trips
/// unchanged on every backend.
pub fn truncate_to_ms(t: OffsetDateTime) -> OffsetDateTime {
    let millis = t.millisecond();
    t.replace_millisecond(millis)
        .expect("a millisecond value read from a valid timestamp is always in range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn truncate_to_ms_drops_sub_millisecond_precision() {
        let t = datetime!(2026-11-25 12:00:00.123456789 UTC);
        assert_eq!(truncate_to_ms(t), datetime!(2026-11-25 12:00:00.123 UTC));
    }

    #[test]
    fn truncate_to_ms_keeps_whole_milliseconds_and_offset() {
        let t = datetime!(2026-11-25 12:00:00.5 +02:00);
        assert_eq!(truncate_to_ms(t), t);
        assert_eq!(truncate_to_ms(t).offset(), t.offset());
    }
}
