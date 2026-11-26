//! Audit events (ADM-04): [`AuditService`] records typed events through
//! [`AuditRepo`](crate::ports::AuditRepo) and mirrors each one as a JSON line.
//!
//! # When events are written
//!
//! Events are appended **right after the state change commits**: the storage intent methods do
//! not take audit rows, so a state change and its event are two writes. An append failure is
//! returned to the caller (and the event is not mirrored); callers that must not fail after a
//! committed change log it at error level and continue.
//!
//! # Stdout mirror
//!
//! The core has no logging dependency. The binary installs an
//! [`AuditMirror`](crate::ports::AuditMirror) once ([`install_mirror`]) that emits
//! `tracing::info!(target: "audit", event = %json)`; without one, events are only stored.
//! The JSON ([`event_json`]) holds only the typed fields of the event; details can only be built
//! from typed constructors without secrets ([`AuditDetails`]).

use std::sync::{Arc, OnceLock};

use serde_json::{Map, Value, json};

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditEvent, AuditEventId, AuditOutcome, AuditQuery,
    NewAuditEvent, Page, PageRequest, RequestContext, TenantId, truncate_to_ms,
};
use crate::ports::{AuditMirror, Clock, Storage};
use crate::service::tenant::admin_page;

static MIRROR: OnceLock<Box<dyn AuditMirror>> = OnceLock::new();

/// Installs the process-wide audit mirror. Only the first call wins; returns `false` if a mirror
/// was already installed.
pub fn install_mirror(mirror: Box<dyn AuditMirror>) -> bool {
    MIRROR.set(mirror).is_ok()
}

/// Records and queries audit events.
#[derive(Clone)]
pub struct AuditService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl AuditService {
    /// Records one event: a new UUIDv7 id and `at = now`, appended through
    /// `storage.audit().append`, then mirrored. See the module docs for the write order.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call per audited action; every argument is a typed part of the event"
    )]
    pub async fn record(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        action: AuditAction,
        target: Option<String>,
        outcome: AuditOutcome,
        ctx: &RequestContext,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        let event = NewAuditEvent {
            id: AuditEventId::new_v7(),
            at: truncate_to_ms(self.clock.now()),
            actor,
            action,
            target,
            outcome,
            ctx: ctx.clone(),
            details,
            webhook: None,
        };
        self.storage.audit().append(tenant, &event).await?;
        if let Some(mirror) = MIRROR.get() {
            mirror.emit(&event_json(tenant, &event));
        }
        Ok(())
    }

    /// Queries the tenant's events, newest first. The limit follows the management-API page
    /// rules (`0` → 50, otherwise clamped to `1..=200`).
    pub async fn query(
        &self,
        tenant: TenantId,
        mut query: AuditQuery,
    ) -> Result<Page<AuditEvent>, CoreError> {
        query.limit = admin_page(PageRequest {
            after: None,
            limit: query.limit,
        })
        .limit;
        Ok(self.storage.audit().query(tenant, &query).await?)
    }
}

/// The mirrored JSON line of an event. `at` is Unix milliseconds.
pub fn event_json(tenant: TenantId, e: &NewAuditEvent) -> String {
    let at_ms = e.at.unix_timestamp_nanos() / 1_000_000;
    let mut actor = Map::new();
    actor.insert("kind".into(), Value::from(e.actor.kind.as_str()));
    actor.insert(
        "id".into(),
        e.actor.id.clone().map_or(Value::Null, Value::from),
    );
    json!({
        "id": e.id.to_string(),
        "tenant_id": tenant.to_string(),
        "at": at_ms as i64,
        "actor": actor,
        "action": e.action.as_str(),
        "target": e.target,
        "outcome": e.outcome.as_str(),
        "ip": e.ctx.ip.map(|ip| ip.to_string()),
        "user_agent": e.ctx.user_agent,
        "trace_id": e.ctx.trace_id,
        "details": Value::Object(e.details.as_map().clone()),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use time::macros::datetime;

    use super::*;
    use crate::model::ActorKind;

    #[test]
    fn mirrored_login_failed_has_only_typed_fields() {
        let tenant = TenantId::new_v7();
        let event = NewAuditEvent {
            id: AuditEventId::new_v7(),
            at: datetime!(2026-11-25 12:00:00.123 UTC),
            actor: AuditActor::anonymous(ActorKind::User),
            action: AuditAction::LoginFailed,
            target: None,
            outcome: AuditOutcome::Failure,
            ctx: RequestContext::new(
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
                Some("Mozilla/5.0"),
                Some("trace-1".into()),
            ),
            details: AuditDetails::login("password").with(AuditDetails::reason("wrong_password")),
            webhook: None,
        };
        let json: Value = serde_json::from_str(&event_json(tenant, &event)).unwrap();
        let obj = json.as_object().unwrap();
        let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "id",
                "tenant_id",
                "at",
                "actor",
                "action",
                "target",
                "outcome",
                "ip",
                "user_agent",
                "trace_id",
                "details",
            ])
        );
        let details: BTreeSet<&str> = obj["details"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(details, BTreeSet::from(["method", "reason"]));
        assert_eq!(obj["action"], "login_failed");
        assert_eq!(obj["outcome"], "failure");
        assert_eq!(obj["actor"]["kind"], "user");
        assert_eq!(obj["actor"]["id"], Value::Null);
        assert_eq!(obj["ip"], "192.0.2.7");
        assert_eq!(obj["at"], 1_795_608_000_123_i64);
        assert_eq!(obj["tenant_id"], tenant.to_string());
    }
}
