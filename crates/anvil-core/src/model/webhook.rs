//! Webhooks (AGT-01/ops): per-tenant endpoints, lifecycle events and the leased delivery queue.
//!
//! Payloads carry identifiers only (event type, tenant, subject ids, timestamps), never email,
//! names or other personal data. Endpoint secrets are sealed with the KEK under
//! [`WEBHOOK_SECRET_PURPOSE`] and [`webhook_aad`]; only sealed bytes are stored.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{TenantId, WebhookDeliveryId, WebhookEndpointId, str_enum};

/// KEK purpose for a sealed webhook signing secret (AAD = [`webhook_aad`]).
pub const WEBHOOK_SECRET_PURPOSE: &str = "anvilid/webhook-secret/v1";

/// AAD binding a sealed webhook secret to its tenant and endpoint (tenant id bytes followed by
/// endpoint id bytes).
pub fn webhook_aad(tenant: TenantId, endpoint_id: WebhookEndpointId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(endpoint_id.0.as_bytes());
    aad
}

/// Delay before each attempt, by attempt index: the first attempt is immediate, the last one
/// about three days after the event. After the last entry the delivery fails for good.
pub const WEBHOOK_RETRY_SCHEDULE: [Duration; 10] = [
    Duration::from_secs(0),
    Duration::from_secs(5),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 3600),
    Duration::from_secs(5 * 3600),
    Duration::from_secs(10 * 3600),
    Duration::from_secs(14 * 3600),
    Duration::from_secs(20 * 3600),
    Duration::from_secs(24 * 3600),
];

/// Timeout of one delivery request (connect + response).
pub const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(15);

/// Deliveries leased per worker poll.
pub const WEBHOOK_BATCH: usize = 8;

/// Deliveries sent concurrently by one worker.
pub const WEBHOOK_CONCURRENCY: usize = 8;

/// Safety margin added to the lease on top of the worst-case send time.
const WEBHOOK_LEASE_MARGIN_SECS: u64 = 30;

/// How long a leased batch stays invisible to other nodes: long enough to send the whole batch
/// at the configured concurrency, each request taking up to [`WEBHOOK_TIMEOUT`], plus a margin.
pub const WEBHOOK_LEASE: Duration = Duration::from_secs(
    WEBHOOK_TIMEOUT.as_secs() * WEBHOOK_BATCH.div_ceil(WEBHOOK_CONCURRENCY) as u64
        + WEBHOOK_LEASE_MARGIN_SECS,
);

/// Lifecycle event types a webhook endpoint can subscribe to. Wire names are dotted
/// (`user.created`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WebhookEventType {
    #[serde(rename = "user.created")]
    UserCreated,
    #[serde(rename = "user.updated")]
    UserUpdated,
    #[serde(rename = "user.deleted")]
    UserDeleted,
    #[serde(rename = "user.email_verified")]
    UserEmailVerified,
    #[serde(rename = "user.email_changed")]
    UserEmailChanged,
    #[serde(rename = "user.password_changed")]
    UserPasswordChanged,
    #[serde(rename = "session.created")]
    SessionCreated,
    #[serde(rename = "session.revoked")]
    SessionRevoked,
    #[serde(rename = "session.logged_out")]
    SessionLoggedOut,
    /// Sent by the console's "send test event" action only.
    #[serde(rename = "test")]
    Test,
}

str_enum!(WebhookEventType {
    UserCreated => "user.created",
    UserUpdated => "user.updated",
    UserDeleted => "user.deleted",
    UserEmailVerified => "user.email_verified",
    UserEmailChanged => "user.email_changed",
    UserPasswordChanged => "user.password_changed",
    SessionCreated => "session.created",
    SessionRevoked => "session.revoked",
    SessionLoggedOut => "session.logged_out",
    Test => "test",
});

/// An event to fan out to the subscribed endpoints. `payload_json` is the ids-only body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEvent {
    pub event_type: WebhookEventType,
    pub payload_json: String,
}

/// A persisted webhook endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookEndpoint {
    pub id: WebhookEndpointId,
    pub tenant_id: TenantId,
    /// Unique per tenant (natural key of the declarative config).
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub enabled: bool,
    /// The signing secret sealed with the KEK ([`WEBHOOK_SECRET_PURPOSE`], [`webhook_aad`]).
    pub secret_enc: Vec<u8>,
    /// The previous secret during a rotation grace period (both sign until it expires).
    pub previous_secret_enc: Option<Vec<u8>>,
    pub previous_secret_expires_at: Option<OffsetDateTime>,
    /// Fixed reason when the system disabled the endpoint (e.g. `gone` after HTTP 410).
    pub disabled_reason: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for WebhookEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEndpoint")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("name", &self.name)
            .field("url", &self.url)
            .field("events", &self.events)
            .field("enabled", &self.enabled)
            .field("secret_enc", &"<redacted>")
            .field(
                "previous_secret_enc",
                &self.previous_secret_enc.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "previous_secret_expires_at",
                &self.previous_secret_expires_at,
            )
            .field("disabled_reason", &self.disabled_reason)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A webhook endpoint to be created. `updated_at` starts equal to `created_at`.
#[derive(Clone, PartialEq, Eq)]
pub struct NewWebhookEndpoint {
    pub id: WebhookEndpointId,
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub enabled: bool,
    /// Sealed with [`webhook_aad`] over the tenant and this `id`.
    pub secret_enc: Vec<u8>,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for NewWebhookEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewWebhookEndpoint")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("url", &self.url)
            .field("events", &self.events)
            .field("enabled", &self.enabled)
            .field("secret_enc", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Partial endpoint update; `None` leaves a field unchanged. The secret changes only through
/// rotation. Re-enabling clears `disabled_reason`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebhookEndpointUpdate {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<WebhookEventType>>,
    pub enabled: Option<bool>,
}

/// State of a queued delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
}

str_enum!(DeliveryStatus {
    Pending => "pending",
    Delivered => "delivered",
    Failed => "failed",
});

/// One queued delivery of an event to one endpoint (the delivery log in the console).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub id: WebhookDeliveryId,
    pub tenant_id: TenantId,
    pub endpoint_id: WebhookEndpointId,
    pub event_type: WebhookEventType,
    pub payload_json: String,
    /// Attempts made so far.
    pub attempts: u32,
    pub next_attempt_at: OffsetDateTime,
    pub status: DeliveryStatus,
    pub last_http_status: Option<u16>,
    /// Error class only (`timeout`, `connect`, `blocked`, `status`, ...), never response bodies.
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

/// Outcome of one delivery attempt, decided by the worker and applied by the repository.
/// `error_class` is a fixed, code-defined string (never a response body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookResult {
    /// 2xx: done.
    Delivered { http_status: u16 },
    /// Retry at `next_attempt_at` (next entry of [`WEBHOOK_RETRY_SCHEDULE`]).
    Retry {
        next_attempt_at: OffsetDateTime,
        http_status: Option<u16>,
        error_class: &'static str,
    },
    /// Schedule exhausted or a permanent failure: mark failed.
    GiveUp {
        http_status: Option<u16>,
        error_class: &'static str,
    },
    /// The endpoint answered 410 Gone: fail this delivery and disable the endpoint.
    DisableEndpoint { http_status: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_wire_names_round_trip() {
        for t in WebhookEventType::ALL {
            assert_eq!(WebhookEventType::parse(t.as_str()), Some(*t));
            let json = serde_json::to_string(t).unwrap();
            assert_eq!(json, format!("\"{}\"", t.as_str()));
            assert_eq!(serde_json::from_str::<WebhookEventType>(&json).unwrap(), *t);
        }
        assert_eq!(WebhookEventType::ALL.len(), 10);
        assert_eq!(WebhookEventType::UserCreated.as_str(), "user.created");
        for s in DeliveryStatus::ALL {
            assert_eq!(DeliveryStatus::parse(s.as_str()), Some(*s));
        }
    }

    #[test]
    fn lease_covers_a_whole_batch() {
        let rounds = WEBHOOK_BATCH.div_ceil(WEBHOOK_CONCURRENCY) as u32;
        assert!(WEBHOOK_LEASE > WEBHOOK_TIMEOUT * rounds);
        assert!(WEBHOOK_LEASE >= WEBHOOK_TIMEOUT * rounds + Duration::from_secs(30));
    }

    #[test]
    fn retry_schedule_is_increasing_and_starts_immediately() {
        assert_eq!(WEBHOOK_RETRY_SCHEDULE[0], Duration::ZERO);
        assert!(WEBHOOK_RETRY_SCHEDULE.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(WEBHOOK_RETRY_SCHEDULE[9], Duration::from_secs(24 * 3600));
    }

    #[test]
    fn aad_binds_tenant_and_endpoint() {
        let t = TenantId::new_v7();
        let a = WebhookEndpointId::new_v7();
        let b = WebhookEndpointId::new_v7();
        assert_eq!(webhook_aad(t, a).len(), 32);
        assert_ne!(webhook_aad(t, a), webhook_aad(t, b));
        assert_ne!(webhook_aad(t, a), webhook_aad(TenantId::new_v7(), a));
    }

    #[test]
    fn debug_redacts_sealed_secrets() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let e = WebhookEndpoint {
            id: WebhookEndpointId::new_v7(),
            tenant_id: TenantId::new_v7(),
            name: "n".into(),
            url: "https://hooks.example/x".into(),
            events: vec![WebhookEventType::UserCreated],
            enabled: true,
            secret_enc: vec![0xAB; 4],
            previous_secret_enc: Some(vec![0xCD; 4]),
            previous_secret_expires_at: None,
            disabled_reason: None,
            created_at: now,
            updated_at: now,
        };
        let d = format!("{e:?}");
        assert!(!d.contains("171") && !d.contains("205"), "{d}");
        assert!(d.contains("<redacted>"));
    }
}
