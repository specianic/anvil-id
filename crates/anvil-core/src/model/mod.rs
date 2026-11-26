//! Domain model: identifiers and records shared by the protocol logic and the storage ports.
//!
//! Pure data. Callers generate identifiers and timestamps (truncated with [`truncate_to_ms`]);
//! repositories only persist them.

mod attribute;
mod audit;
mod branding;
mod client;
mod config_doc;
mod connection;
mod consent;
mod credential;
mod flow;
mod grant;
mod ids;
mod job;
mod key;
mod logout;
mod mail_settings;
mod organization;
mod outbox;
mod par;
mod password_profile;
mod registration;
mod role;
mod saml;
mod session;
mod setup;
mod tenant;
mod user;
mod webhook;

/// Stable string names for enums, shared with core modules outside `model` (e.g.
/// `saml::validate::SamlReject`).
pub(crate) use ids::str_enum;

pub use attribute::*;
pub use audit::*;
pub use branding::*;
pub use client::*;
pub use config_doc::*;
pub use connection::*;
pub use consent::*;
pub use credential::*;
pub use flow::*;
pub use grant::*;
pub use ids::{
    AuditEventId, AuthRequestId, ClientId, CodeHash, ConnectionId, ConsentId, CredentialId, FlowId,
    IdentityLinkId, InitialAccessTokenId, InvalidLength, LogoutDeliveryId, OrgDomainId, OrgId,
    OrgInvitationId, OutboxId, Page, PageRequest, RoleId, SecretHash, SessionId, SigningKeyId,
    TenantId, TokenFamilyId, UserId, WebhookDeliveryId, WebhookEndpointId,
};
pub use job::*;
pub use key::*;
pub use logout::*;
pub use mail_settings::*;
pub use organization::*;
pub use outbox::*;
pub use par::*;
pub use password_profile::*;
pub use registration::*;
pub use role::*;
pub use saml::*;
pub use session::*;
pub use setup::*;
pub use tenant::*;
pub use user::*;
pub use webhook::*;

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
