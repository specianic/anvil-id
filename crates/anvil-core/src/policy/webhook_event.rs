//! Mapping of audit actions to webhook lifecycle events and their ids-only payloads (AGT-01).
//!
//! Pure: `AuditService` calls [`webhook_event`] for every event it records and puts the result
//! in `NewAuditEvent.webhook`; storage enqueues it in the same transaction as the audit row.
//! Only successful actions emit.
//!
//! Payload (Standard Webhooks shape):
//!
//! ```json
//! {"type": "user.created", "timestamp": "2026-11-26T10:00:00Z",
//!  "data": {"tenant": "<tenant id (UUID)>", "user_id": "...",
//!           "actor": {"kind": "admin", "id": "..."}}}
//! ```
//!
//! `data` holds the tenant id (the tenant's `id` in the admin API; not the slug), the subject
//! ids that apply (`user_id`, `session_id`, `client_id`, `org_id`, `domain_id`) and the actor.
//!
//! Organization events follow fixed audit conventions: `organization.created|deleted` have the
//! org id as target; `organization.member_added|removed` have the user id as target and the org
//! in the details ([`crate::model::AuditDetails::org`]); `organization.domain_verified|unverified`
//! have the domain id as target and the org in the details. Never an email address,
//! name, IP address, user agent or any other audit detail. Ids are copied only when they look like identifiers (bounded, no `@`, no
//! whitespace), so a mis-built audit event cannot smuggle personal data into a payload.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::model::{
    AuditAction, AuditActor, AuditOutcome, NewAuditEvent, WebhookEvent, WebhookEventType,
};

/// Longest id copied into a payload, in bytes (CIMD client ids are URLs).
pub const MAX_PAYLOAD_ID_LEN: usize = 512;

/// Where the audit target goes in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    /// The target is a user id.
    User,
    /// The target is a session id.
    Session,
    /// The target is an organization id.
    Org,
    /// The target is a user id; the org id comes from the details.
    Member,
    /// The target is an organization domain id; the org id comes from the details.
    Domain,
}

/// The event type and the meaning of the audit target for an action, or `None` when the action
/// is not a webhook event. Exhaustive on purpose: a new action needs an explicit decision.
fn classify(action: AuditAction) -> Option<(WebhookEventType, Subject)> {
    use AuditAction as A;
    use WebhookEventType as W;
    match action {
        // Admin-created, self-registered and JIT-provisioned (upstream) users.
        A::UserCreated | A::UserRegistered => Some((W::UserCreated, Subject::User)),
        A::UserUpdated | A::ProfileUpdated | A::UserAttributesUpdated => {
            Some((W::UserUpdated, Subject::User))
        }
        A::UserDeleted => Some((W::UserDeleted, Subject::User)),
        A::EmailVerified => Some((W::UserEmailVerified, Subject::User)),
        A::EmailChanged => Some((W::UserEmailChanged, Subject::User)),
        // Account-page change and recovery reset both audit PasswordChanged.
        A::PasswordChanged => Some((W::UserPasswordChanged, Subject::User)),
        A::LoginSucceeded => Some((W::SessionCreated, Subject::User)),
        A::SessionRevoked => Some((W::SessionRevoked, Subject::Session)),
        A::SessionsRevokedAll => Some((W::SessionRevoked, Subject::User)),
        A::Logout => Some((W::SessionLoggedOut, Subject::Session)),
        A::OrganizationCreated => Some((W::OrganizationCreated, Subject::Org)),
        A::OrganizationDeleted => Some((W::OrganizationDeleted, Subject::Org)),
        A::OrgMemberAdded => Some((W::OrganizationMemberAdded, Subject::Member)),
        A::OrgMemberRemoved => Some((W::OrganizationMemberRemoved, Subject::Member)),
        A::OrgDomainVerified => Some((W::OrganizationDomainVerified, Subject::Domain)),
        A::OrgDomainUnverified => Some((W::OrganizationDomainUnverified, Subject::Domain)),
        A::LoginFailed
        | A::SecondFactorFailed
        | A::PasskeyRegistered
        | A::PasskeyRemoved
        | A::PasskeyCloneSuspected
        | A::TotpEnrolled
        | A::TotpRemoved
        | A::RecoveryCodeUsed
        | A::RecoveryCodesRegenerated
        | A::ConsentGranted
        | A::ConsentRevoked
        | A::TokenRevoked
        | A::RefreshReuseDetected
        | A::CodeReuseDetected
        | A::KeyGenerated
        | A::KeyActivated
        | A::KeyRetired
        | A::KeyRotationRequested
        | A::RateLimitLockout
        | A::CaptchaFailed
        | A::ClientCreated
        | A::ClientUpdated
        | A::ClientDeleted
        | A::ClientSecretRotated
        | A::TenantCreated
        | A::TenantUpdated
        | A::TenantDeleted
        | A::EmailTemplateUpdated
        | A::EmailTemplateReset
        | A::SmtpSettingsUpdated
        | A::SmtpTestSent
        | A::AdminSetupCompleted
        | A::IdentityLinked
        | A::IdentityUnlinked
        | A::UpstreamLoginFailed
        | A::ConnectionCreated
        | A::ConnectionUpdated
        | A::ConnectionDeleted
        | A::ConnectionSecretRotated
        | A::BrandingUpdated
        | A::BackchannelLogoutFailed
        | A::EmailChangeRequested
        | A::StepUpCompleted
        | A::EmailCodeSent
        | A::RoleCreated
        | A::RoleUpdated
        | A::RoleDeleted
        | A::RoleAssigned
        | A::RoleUnassigned
        | A::AttributeDefined
        | A::AttributeDeleted
        | A::WebhookEndpointCreated
        | A::WebhookEndpointUpdated
        | A::WebhookEndpointDeleted
        | A::WebhookSecretRotated
        | A::WebhookEndpointDisabled
        | A::WebhookDeliveryFailed
        | A::WebhookTestSent
        | A::WebhookRedelivered
        | A::ClientRegistered
        | A::ClientRegistrationUpdated
        | A::ClientRegistrationDeleted
        | A::CimdClientRefreshed
        | A::InitialAccessTokenCreated
        | A::InitialAccessTokenRevoked
        | A::TenantConfigApplied
        | A::AdminRecoveryIssued
        | A::OrganizationUpdated
        | A::OrgRoleAssigned
        | A::OrgRoleUnassigned
        | A::OrgInvitationCreated
        | A::OrgInvitationRevoked
        | A::OrgInvitationAccepted
        | A::OrgDomainCreated
        | A::OrgDomainVerificationFailed
        | A::OrgDomainUpdated
        | A::OrgDomainDeleted
        | A::SamlLoginSucceeded
        | A::SamlLoginFailed
        // Bulk admin operations and tenant hash profiles: not lifecycle events (like
        // TenantConfigApplied). Import and export are audited, not webhooked.
        | A::UsersImported
        | A::UserExported
        | A::PasswordProfileCreated
        | A::PasswordProfileDeleted
        // An administrator-triggered password reset email: audited, not a lifecycle event.
        | A::UserRecoverySent => None,
    }
}

/// An identifier fit for a payload: non-empty, bounded, printable, no `@` and no whitespace.
fn safe_id(id: &str) -> Option<&str> {
    let ok = !id.is_empty()
        && id.len() <= MAX_PAYLOAD_ID_LEN
        && id
            .chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && c != '@');
    ok.then_some(id)
}

fn timestamp(at: OffsetDateTime) -> String {
    // RFC 3339 formatting of an in-range OffsetDateTime cannot fail; fall back to unix seconds.
    at.format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

fn actor_json(actor: &AuditActor) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), actor.kind.as_str().into());
    if let Some(id) = actor.id.as_deref().and_then(safe_id) {
        m.insert("id".into(), id.into());
    }
    Value::Object(m)
}

fn payload(event_type: WebhookEventType, at: OffsetDateTime, data: Map<String, Value>) -> String {
    json!({
        "type": event_type.as_str(),
        "timestamp": timestamp(at),
        "data": data,
    })
    .to_string()
}

/// The webhook event for an audit event of the tenant `tenant_id` (its id, not its slug), or
/// `None` when the action is not a lifecycle event or did not succeed.
pub fn webhook_event(tenant_id: &str, e: &NewAuditEvent) -> Option<WebhookEvent> {
    if e.outcome != AuditOutcome::Success {
        return None;
    }
    let (event_type, subject) = classify(e.action)?;
    let mut data = Map::new();
    data.insert("tenant".into(), tenant_id.into());
    if let Some(target) = e.target.as_deref().and_then(safe_id) {
        let key = match subject {
            Subject::User | Subject::Member => "user_id",
            Subject::Session => "session_id",
            Subject::Org => "org_id",
            Subject::Domain => "domain_id",
        };
        data.insert(key.into(), target.into());
    }
    // Member and domain events name their organization (from the typed `org` details).
    if matches!(subject, Subject::Member | Subject::Domain)
        && let Some(org_id) = e
            .details
            .as_map()
            .get("org_id")
            .and_then(Value::as_str)
            .and_then(safe_id)
    {
        data.insert("org_id".into(), org_id.into());
    }
    // A session ends on behalf of its user: name them when the user is the actor.
    if subject == Subject::Session
        && e.actor.kind == crate::model::ActorKind::User
        && let Some(id) = e.actor.id.as_deref().and_then(safe_id)
    {
        data.insert("user_id".into(), id.into());
    }
    // RP-initiated logout records the relying party in its details.
    if e.action == AuditAction::Logout
        && let Some(client_id) = e
            .details
            .as_map()
            .get("client_id")
            .and_then(Value::as_str)
            .and_then(safe_id)
    {
        data.insert("client_id".into(), client_id.into());
    }
    data.insert("actor".into(), actor_json(&e.actor));
    Some(WebhookEvent {
        event_type,
        payload_json: payload(event_type, e.at, data),
    })
}

/// The `test` event sent by the console's "send test event" action for the tenant `tenant_id`.
pub fn test_event(tenant_id: &str, at: OffsetDateTime) -> WebhookEvent {
    let mut data = Map::new();
    data.insert("tenant".into(), tenant_id.into());
    data.insert("actor".into(), actor_json(&AuditActor::system()));
    WebhookEvent {
        event_type: WebhookEventType::Test,
        payload_json: payload(WebhookEventType::Test, at, data),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use serde_json::Value;

    use super::*;
    use crate::model::{AuditDetails, AuditEventId, RequestContext};

    const USER: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a50";
    const SESSION: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a51";

    fn at() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
    }

    fn event(
        action: AuditAction,
        outcome: AuditOutcome,
        actor: AuditActor,
        target: Option<&str>,
        details: AuditDetails,
    ) -> NewAuditEvent {
        NewAuditEvent {
            id: AuditEventId::new_v7(),
            at: at(),
            actor,
            action,
            target: target.map(str::to_owned),
            outcome,
            ctx: RequestContext::new(
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
                Some("Mozilla/5.0 (alice@example.test)"),
                Some("trace-1".into()),
            ),
            details,
            webhook: None,
        }
    }

    fn ok(action: AuditAction, target: &str) -> NewAuditEvent {
        event(
            action,
            AuditOutcome::Success,
            AuditActor::user(USER),
            Some(target),
            AuditDetails::empty(),
        )
    }

    fn parse(e: &WebhookEvent) -> Value {
        serde_json::from_str(&e.payload_json).unwrap()
    }

    #[test]
    fn every_action_maps_as_specified() {
        use AuditAction as A;
        use WebhookEventType as W;
        let expected: &[(AuditAction, WebhookEventType)] = &[
            (A::UserCreated, W::UserCreated),
            (A::UserRegistered, W::UserCreated),
            (A::UserUpdated, W::UserUpdated),
            (A::ProfileUpdated, W::UserUpdated),
            (A::UserAttributesUpdated, W::UserUpdated),
            (A::UserDeleted, W::UserDeleted),
            (A::EmailVerified, W::UserEmailVerified),
            (A::EmailChanged, W::UserEmailChanged),
            (A::PasswordChanged, W::UserPasswordChanged),
            (A::LoginSucceeded, W::SessionCreated),
            (A::SessionRevoked, W::SessionRevoked),
            (A::SessionsRevokedAll, W::SessionRevoked),
            (A::Logout, W::SessionLoggedOut),
            (A::OrganizationCreated, W::OrganizationCreated),
            (A::OrganizationDeleted, W::OrganizationDeleted),
            (A::OrgMemberAdded, W::OrganizationMemberAdded),
            (A::OrgMemberRemoved, W::OrganizationMemberRemoved),
            (A::OrgDomainVerified, W::OrganizationDomainVerified),
            (A::OrgDomainUnverified, W::OrganizationDomainUnverified),
        ];
        for action in AuditAction::ALL {
            let got = webhook_event("acme", &ok(*action, USER)).map(|e| e.event_type);
            let want = expected.iter().find(|(a, _)| a == action).map(|(_, w)| *w);
            assert_eq!(got, want, "{action:?}");
        }
        // Nothing maps to the console-only test event.
        assert!(
            AuditAction::ALL
                .iter()
                .filter_map(|a| classify(*a))
                .all(|(t, _)| t != W::Test)
        );
    }

    #[test]
    fn failures_never_emit() {
        for action in AuditAction::ALL {
            let e = event(
                *action,
                AuditOutcome::Failure,
                AuditActor::user(USER),
                Some(USER),
                AuditDetails::empty(),
            );
            assert_eq!(webhook_event("acme", &e), None, "{action:?}");
        }
    }

    #[test]
    fn user_event_payload_shape() {
        let e = event(
            AuditAction::UserCreated,
            AuditOutcome::Success,
            AuditActor::admin("0192f0c2-0000-7000-8000-000000000001"),
            Some(USER),
            AuditDetails::reason("admin"),
        );
        let w = webhook_event("acme", &e).unwrap();
        assert_eq!(
            parse(&w),
            json!({
                "type": "user.created",
                "timestamp": "2026-09-21T14:13:20Z",
                "data": {
                    "tenant": "acme",
                    "user_id": USER,
                    "actor": {"kind": "admin", "id": "0192f0c2-0000-7000-8000-000000000001"},
                },
            })
        );
    }

    #[test]
    fn session_events_carry_session_and_user_ids() {
        let w = webhook_event("acme", &ok(AuditAction::SessionRevoked, SESSION)).unwrap();
        let v = parse(&w);
        assert_eq!(v["data"]["session_id"], SESSION);
        assert_eq!(v["data"]["user_id"], USER);

        // Revoked by an admin: the admin is the actor, no user id is guessed.
        let e = event(
            AuditAction::SessionRevoked,
            AuditOutcome::Success,
            AuditActor::admin("adm"),
            Some(SESSION),
            AuditDetails::empty(),
        );
        let v = parse(&webhook_event("acme", &e).unwrap());
        assert_eq!(v["data"]["session_id"], SESSION);
        assert!(v["data"].get("user_id").is_none());

        let all = webhook_event("acme", &ok(AuditAction::SessionsRevokedAll, USER)).unwrap();
        let v = parse(&all);
        assert_eq!(v["data"]["user_id"], USER);
        assert!(v["data"].get("session_id").is_none());
    }

    #[test]
    fn logout_carries_the_client_id() {
        let e = event(
            AuditAction::Logout,
            AuditOutcome::Success,
            AuditActor::user(USER),
            Some(SESSION),
            AuditDetails::logout(Some("https://app.example.test/client.json")),
        );
        let v = parse(&webhook_event("acme", &e).unwrap());
        assert_eq!(v["type"], "session.logged_out");
        assert_eq!(
            v["data"]["client_id"],
            "https://app.example.test/client.json"
        );
        assert_eq!(v["data"]["session_id"], SESSION);
    }

    fn assert_only_allowed_keys(v: &Value) {
        let top: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(top, ["data", "timestamp", "type"]);
        for k in v["data"].as_object().unwrap().keys() {
            assert!(
                [
                    "tenant",
                    "user_id",
                    "session_id",
                    "client_id",
                    "org_id",
                    "domain_id",
                    "actor"
                ]
                .contains(&k.as_str()),
                "{k}"
            );
        }
        for k in v["data"]["actor"].as_object().unwrap().keys() {
            assert!(["kind", "id"].contains(&k.as_str()), "{k}");
        }
    }

    #[test]
    fn payloads_never_carry_personal_data() {
        // Details, request context and ids that look like emails must never reach the payload.
        for action in AuditAction::ALL {
            for (actor, target) in [
                (AuditActor::user(USER), USER),
                (AuditActor::user("alice@example.test"), "alice@example.test"),
                (AuditActor::client("bob@example.test"), "has space"),
            ] {
                let mut details = AuditDetails::logout(Some("carol@example.test"));
                details = details.with(AuditDetails::reason("x"));
                let e = event(*action, AuditOutcome::Success, actor, Some(target), details);
                let Some(w) = webhook_event("acme", &e) else {
                    continue;
                };
                assert!(
                    !w.payload_json.contains('@'),
                    "{action:?}: {}",
                    w.payload_json
                );
                assert!(!w.payload_json.contains("192.0.2.7"));
                assert!(!w.payload_json.contains("Mozilla"));
                assert!(!w.payload_json.contains("trace-1"));
                assert_only_allowed_keys(&parse(&w));
            }
        }
    }

    const ORG: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a52";
    const DOMAIN: &str = "0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a53";

    fn org_details() -> AuditDetails {
        AuditDetails::org(
            crate::model::OrgId(uuid::Uuid::parse_str(ORG).unwrap()),
            "acme",
        )
    }

    fn admin_event(action: AuditAction, target: &str, details: AuditDetails) -> NewAuditEvent {
        event(
            action,
            AuditOutcome::Success,
            AuditActor::admin("adm"),
            Some(target),
            details,
        )
    }

    #[test]
    fn organization_lifecycle_events_carry_the_org_id() {
        for (action, ty) in [
            (AuditAction::OrganizationCreated, "organization.created"),
            (AuditAction::OrganizationDeleted, "organization.deleted"),
        ] {
            let w = webhook_event("acme", &admin_event(action, ORG, org_details())).unwrap();
            let v = parse(&w);
            assert_eq!(v["type"], ty);
            assert_eq!(v["data"]["org_id"], ORG);
            assert!(v["data"].get("user_id").is_none());
            assert!(v["data"].get("org_slug").is_none());
            assert_only_allowed_keys(&v);
        }
    }

    #[test]
    fn organization_member_events_carry_user_and_org_ids() {
        for (action, ty) in [
            (AuditAction::OrgMemberAdded, "organization.member_added"),
            (AuditAction::OrgMemberRemoved, "organization.member_removed"),
        ] {
            let w = webhook_event("acme", &admin_event(action, USER, org_details())).unwrap();
            let v = parse(&w);
            assert_eq!(v["type"], ty);
            assert_eq!(v["data"]["user_id"], USER);
            assert_eq!(v["data"]["org_id"], ORG);
            assert_only_allowed_keys(&v);
        }
    }

    #[test]
    fn organization_domain_events_carry_domain_and_org_ids_not_the_name() {
        for (action, ty) in [
            (
                AuditAction::OrgDomainVerified,
                "organization.domain_verified",
            ),
            (
                AuditAction::OrgDomainUnverified,
                "organization.domain_unverified",
            ),
        ] {
            let details = org_details().with(AuditDetails::domain("acme.example"));
            let w = webhook_event("acme", &admin_event(action, DOMAIN, details)).unwrap();
            let v = parse(&w);
            assert_eq!(v["type"], ty);
            assert_eq!(v["data"]["domain_id"], DOMAIN);
            assert_eq!(v["data"]["org_id"], ORG);
            assert!(!w.payload_json.contains("acme.example"));
            assert_only_allowed_keys(&v);
        }
    }

    #[test]
    fn other_organization_and_saml_actions_do_not_emit() {
        for action in [
            AuditAction::OrganizationUpdated,
            AuditAction::OrgRoleAssigned,
            AuditAction::OrgRoleUnassigned,
            AuditAction::OrgInvitationCreated,
            AuditAction::OrgInvitationRevoked,
            AuditAction::OrgInvitationAccepted,
            AuditAction::OrgDomainCreated,
            AuditAction::OrgDomainVerificationFailed,
            AuditAction::OrgDomainUpdated,
            AuditAction::OrgDomainDeleted,
            AuditAction::SamlLoginSucceeded,
            AuditAction::SamlLoginFailed,
            AuditAction::UsersImported,
            AuditAction::UserExported,
            AuditAction::PasswordProfileCreated,
            AuditAction::PasswordProfileDeleted,
            AuditAction::UserRecoverySent,
        ] {
            assert_eq!(
                webhook_event("acme", &admin_event(action, ORG, org_details())),
                None,
                "{action:?}"
            );
        }
    }

    #[test]
    fn org_id_detail_that_is_not_an_id_is_dropped() {
        // A details map whose org_id is not id-shaped never reaches the payload.
        let details = AuditDetails::from_stored(
            [("org_id".to_owned(), Value::from("alice@example.test"))]
                .into_iter()
                .collect(),
        );
        let w = webhook_event(
            "acme",
            &admin_event(AuditAction::OrgMemberAdded, USER, details),
        )
        .unwrap();
        let v = parse(&w);
        assert!(v["data"].get("org_id").is_none());
        assert!(!w.payload_json.contains('@'));
    }

    #[test]
    fn test_event_shape() {
        let w = test_event("acme", at());
        assert_eq!(w.event_type, WebhookEventType::Test);
        let v = parse(&w);
        assert_eq!(v["type"], "test");
        assert_eq!(v["data"]["tenant"], "acme");
        assert_eq!(v["data"]["actor"], json!({"kind": "system"}));
        assert_only_allowed_keys(&v);
    }
}
