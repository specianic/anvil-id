//! Audit events: typed security and administration events (ADM-04).
//!
//! Every event has a typed [`AuditAction`]; [`AuditDetails`] can only be built through typed
//! constructors, none of which accepts a secret, token or code, so an audit row or its stdout
//! mirror cannot carry one.

use std::net::IpAddr;

use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::credential::CredentialKind;
use super::ids::{AuditEventId, ConnectionId, OrgId, TenantId, WebhookDeliveryId, str_enum};
use super::mail_settings::EmailKind;
use super::registration::ClientSource;
use super::webhook::{WebhookEvent, WebhookEventType};

/// Longest stored user agent, in characters.
pub const MAX_USER_AGENT_CHARS: usize = 256;

/// Where a request came from. Built by the web layer (client IP from the trusted-proxy
/// extractor).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestContext {
    pub ip: Option<IpAddr>,
    /// Truncated to [`MAX_USER_AGENT_CHARS`] by [`RequestContext::new`].
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
}

impl RequestContext {
    /// Builds a context, truncating the user agent to [`MAX_USER_AGENT_CHARS`] characters.
    pub fn new(ip: Option<IpAddr>, user_agent: Option<&str>, trace_id: Option<String>) -> Self {
        Self {
            ip,
            user_agent: user_agent.map(|ua| ua.chars().take(MAX_USER_AGENT_CHARS).collect()),
            trace_id,
        }
    }

    /// A context without request data (background jobs, CLI).
    pub fn system() -> Self {
        Self::default()
    }
}

/// Who performed an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    User,
    Client,
    Admin,
    System,
}

str_enum!(ActorKind {
    User => "user",
    Client => "client",
    Admin => "admin",
    System => "system",
});

/// The actor of an event: kind plus an identifier (user id, client id) when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActor {
    pub kind: ActorKind,
    pub id: Option<String>,
}

impl AuditActor {
    /// The installation itself (background jobs, startup).
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: None,
        }
    }

    pub fn user(id: impl std::fmt::Display) -> Self {
        Self {
            kind: ActorKind::User,
            id: Some(id.to_string()),
        }
    }

    pub fn admin(id: impl std::fmt::Display) -> Self {
        Self {
            kind: ActorKind::Admin,
            id: Some(id.to_string()),
        }
    }

    pub fn client(client_id: &str) -> Self {
        Self {
            kind: ActorKind::Client,
            id: Some(client_id.to_owned()),
        }
    }

    /// An actor whose identity is unknown (e.g. a failed sign-in for an unknown account).
    pub fn anonymous(kind: ActorKind) -> Self {
        Self { kind, id: None }
    }
}

/// Whether the audited action succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    Success,
    Failure,
}

str_enum!(AuditOutcome {
    Success => "success",
    Failure => "failure",
});

/// Every audited action. Wire and storage names are snake_case ([`AuditAction::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditAction {
    LoginSucceeded,
    LoginFailed,
    SecondFactorFailed,
    PasskeyRegistered,
    PasskeyRemoved,
    PasskeyCloneSuspected,
    TotpEnrolled,
    TotpRemoved,
    RecoveryCodeUsed,
    RecoveryCodesRegenerated,
    PasswordChanged,
    UserRegistered,
    EmailVerified,
    ConsentGranted,
    ConsentRevoked,
    SessionRevoked,
    SessionsRevokedAll,
    TokenRevoked,
    RefreshReuseDetected,
    CodeReuseDetected,
    KeyGenerated,
    KeyActivated,
    KeyRetired,
    KeyRotationRequested,
    RateLimitLockout,
    CaptchaFailed,
    UserCreated,
    UserUpdated,
    UserDeleted,
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    ClientSecretRotated,
    TenantCreated,
    TenantUpdated,
    TenantDeleted,
    EmailTemplateUpdated,
    EmailTemplateReset,
    SmtpSettingsUpdated,
    SmtpTestSent,
    AdminSetupCompleted,
    IdentityLinked,
    IdentityUnlinked,
    UpstreamLoginFailed,
    ConnectionCreated,
    ConnectionUpdated,
    ConnectionDeleted,
    ConnectionSecretRotated,
    BrandingUpdated,
    Logout,
    BackchannelLogoutFailed,
    EmailChangeRequested,
    EmailChanged,
    ProfileUpdated,
    StepUpCompleted,
    EmailCodeSent,
    RoleCreated,
    RoleUpdated,
    RoleDeleted,
    RoleAssigned,
    RoleUnassigned,
    AttributeDefined,
    AttributeDeleted,
    UserAttributesUpdated,
    WebhookEndpointCreated,
    WebhookEndpointUpdated,
    WebhookEndpointDeleted,
    WebhookSecretRotated,
    WebhookEndpointDisabled,
    WebhookDeliveryFailed,
    WebhookTestSent,
    WebhookRedelivered,
    ClientRegistered,
    ClientRegistrationUpdated,
    ClientRegistrationDeleted,
    CimdClientRefreshed,
    InitialAccessTokenCreated,
    InitialAccessTokenRevoked,
    TenantConfigApplied,
    AdminRecoveryIssued,
    OrganizationCreated,
    OrganizationUpdated,
    OrganizationDeleted,
    OrgMemberAdded,
    OrgMemberRemoved,
    OrgRoleAssigned,
    OrgRoleUnassigned,
    OrgInvitationCreated,
    OrgInvitationRevoked,
    OrgInvitationAccepted,
    OrgDomainCreated,
    OrgDomainVerified,
    OrgDomainVerificationFailed,
    OrgDomainUnverified,
    OrgDomainUpdated,
    OrgDomainDeleted,
    SamlLoginSucceeded,
    SamlLoginFailed,
    /// A bulk user import ran (ADM-08). Details carry counts only, never a hash.
    UsersImported,
    /// A user's data was exported (ADM-09).
    UserExported,
    /// A tenant password hash profile (legacy import parameters) was created.
    PasswordProfileCreated,
    /// A tenant password hash profile was deleted.
    PasswordProfileDeleted,
}

str_enum!(AuditAction {
    LoginSucceeded => "login_succeeded",
    LoginFailed => "login_failed",
    SecondFactorFailed => "second_factor_failed",
    PasskeyRegistered => "passkey_registered",
    PasskeyRemoved => "passkey_removed",
    PasskeyCloneSuspected => "passkey_clone_suspected",
    TotpEnrolled => "totp_enrolled",
    TotpRemoved => "totp_removed",
    RecoveryCodeUsed => "recovery_code_used",
    RecoveryCodesRegenerated => "recovery_codes_regenerated",
    PasswordChanged => "password_changed",
    UserRegistered => "user_registered",
    EmailVerified => "email_verified",
    ConsentGranted => "consent_granted",
    ConsentRevoked => "consent_revoked",
    SessionRevoked => "session_revoked",
    SessionsRevokedAll => "sessions_revoked_all",
    TokenRevoked => "token_revoked",
    RefreshReuseDetected => "refresh_reuse_detected",
    CodeReuseDetected => "code_reuse_detected",
    KeyGenerated => "key_generated",
    KeyActivated => "key_activated",
    KeyRetired => "key_retired",
    KeyRotationRequested => "key_rotation_requested",
    RateLimitLockout => "rate_limit_lockout",
    CaptchaFailed => "captcha_failed",
    UserCreated => "user_created",
    UserUpdated => "user_updated",
    UserDeleted => "user_deleted",
    ClientCreated => "client_created",
    ClientUpdated => "client_updated",
    ClientDeleted => "client_deleted",
    ClientSecretRotated => "client_secret_rotated",
    TenantCreated => "tenant_created",
    TenantUpdated => "tenant_updated",
    TenantDeleted => "tenant_deleted",
    EmailTemplateUpdated => "email_template_updated",
    EmailTemplateReset => "email_template_reset",
    SmtpSettingsUpdated => "smtp_settings_updated",
    SmtpTestSent => "smtp_test_sent",
    AdminSetupCompleted => "admin_setup_completed",
    IdentityLinked => "identity_linked",
    IdentityUnlinked => "identity_unlinked",
    UpstreamLoginFailed => "upstream_login_failed",
    ConnectionCreated => "connection_created",
    ConnectionUpdated => "connection_updated",
    ConnectionDeleted => "connection_deleted",
    ConnectionSecretRotated => "connection_secret_rotated",
    BrandingUpdated => "branding_updated",
    Logout => "logout",
    BackchannelLogoutFailed => "backchannel_logout_failed",
    EmailChangeRequested => "email_change_requested",
    EmailChanged => "email_changed",
    ProfileUpdated => "profile_updated",
    StepUpCompleted => "step_up_completed",
    EmailCodeSent => "email_code_sent",
    RoleCreated => "role_created",
    RoleUpdated => "role_updated",
    RoleDeleted => "role_deleted",
    RoleAssigned => "role_assigned",
    RoleUnassigned => "role_unassigned",
    AttributeDefined => "attribute_defined",
    AttributeDeleted => "attribute_deleted",
    UserAttributesUpdated => "user_attributes_updated",
    WebhookEndpointCreated => "webhook_endpoint_created",
    WebhookEndpointUpdated => "webhook_endpoint_updated",
    WebhookEndpointDeleted => "webhook_endpoint_deleted",
    WebhookSecretRotated => "webhook_secret_rotated",
    WebhookEndpointDisabled => "webhook_endpoint_disabled",
    WebhookDeliveryFailed => "webhook_delivery_failed",
    WebhookTestSent => "webhook_test_sent",
    WebhookRedelivered => "webhook_redelivered",
    ClientRegistered => "client_registered",
    ClientRegistrationUpdated => "client_registration_updated",
    ClientRegistrationDeleted => "client_registration_deleted",
    CimdClientRefreshed => "cimd_client_refreshed",
    InitialAccessTokenCreated => "initial_access_token_created",
    InitialAccessTokenRevoked => "initial_access_token_revoked",
    TenantConfigApplied => "tenant_config_applied",
    AdminRecoveryIssued => "admin_recovery_issued",
    OrganizationCreated => "organization_created",
    OrganizationUpdated => "organization_updated",
    OrganizationDeleted => "organization_deleted",
    OrgMemberAdded => "org_member_added",
    OrgMemberRemoved => "org_member_removed",
    OrgRoleAssigned => "org_role_assigned",
    OrgRoleUnassigned => "org_role_unassigned",
    OrgInvitationCreated => "org_invitation_created",
    OrgInvitationRevoked => "org_invitation_revoked",
    OrgInvitationAccepted => "org_invitation_accepted",
    OrgDomainCreated => "org_domain_created",
    OrgDomainVerified => "org_domain_verified",
    OrgDomainVerificationFailed => "org_domain_verification_failed",
    OrgDomainUnverified => "org_domain_unverified",
    OrgDomainUpdated => "org_domain_updated",
    OrgDomainDeleted => "org_domain_deleted",
    SamlLoginSucceeded => "saml_login_succeeded",
    SamlLoginFailed => "saml_login_failed",
    UsersImported => "users_imported",
    UserExported => "user_exported",
    PasswordProfileCreated => "password_profile_created",
    PasswordProfileDeleted => "password_profile_deleted",
});

/// Structured event details. Only typed constructors build it, and none of them accepts a
/// secret, token, code or password; values are identifiers, enum names and counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditDetails(Map<String, Value>);

impl AuditDetails {
    /// No details.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Sign-in method (`password`, `passkey`, `totp`, `recovery_code`, ...).
    pub fn login(method: &'static str) -> Self {
        Self::one("method", Value::from(method))
    }

    /// A signing key by kid and algorithm.
    pub fn key(kid: &str, alg: &str) -> Self {
        let mut d = Self::one("kid", Value::from(kid));
        d.0.insert("alg".into(), Value::from(alg));
        d
    }

    /// A fixed, code-defined reason (`unknown_user`, `wrong_password`, `counter_regressed`, ...).
    pub fn reason(reason: &'static str) -> Self {
        Self::one("reason", Value::from(reason))
    }

    /// Granted or revoked scopes (scope names are not secrets).
    pub fn scopes(scopes: &[String]) -> Self {
        Self::one(
            "scopes",
            Value::Array(scopes.iter().map(|s| Value::from(s.as_str())).collect()),
        )
    }

    /// The kind of credential involved.
    pub fn credential(kind: CredentialKind) -> Self {
        Self::one("credential", Value::from(kind.as_str()))
    }

    /// Names of the fields changed by an update (never their values).
    pub fn fields(names: &[&'static str]) -> Self {
        Self::one(
            "fields",
            Value::Array(names.iter().map(|n| Value::from(*n)).collect()),
        )
    }

    /// A count (`sessions`, `remaining_codes`, ...).
    pub fn count(name: &'static str, n: u64) -> Self {
        Self::one(name, Value::from(n))
    }

    /// An email template kind.
    pub fn template(kind: EmailKind) -> Self {
        Self::one("template", Value::from(kind.as_str()))
    }

    /// An identity link change: the connection slug and how the link was made (`auto`: verified
    /// email match; `confirmed`: the user signed in to the existing account; `account`: linked
    /// from the account page).
    pub fn link(connection_slug: &str, mode: &'static str) -> Self {
        let mut d = Self::one("connection", Value::from(connection_slug));
        d.0.insert("mode".into(), Value::from(mode));
        d
    }

    /// A connection by slug and kind (`google`, `oidc`, ...). Never its configuration or secret.
    pub fn connection(slug: &str, kind: &'static str) -> Self {
        let mut d = Self::one("connection", Value::from(slug));
        d.0.insert("kind".into(), Value::from(kind));
        d
    }

    /// A logout, optionally initiated by a relying party.
    pub fn logout(client_id: Option<&str>) -> Self {
        match client_id {
            Some(c) => Self::one("client_id", Value::from(c)),
            None => Self::empty(),
        }
    }

    /// A back-channel logout delivery: the RP, the attempts made and a fixed reason
    /// (`timeout`, `status`, `blocked`, `expired`, ...).
    pub fn delivery(client_id: &str, attempts: u32, reason: &'static str) -> Self {
        let mut d = Self::one("client_id", Value::from(client_id));
        d.0.insert("attempts".into(), Value::from(attempts));
        d.0.insert("reason".into(), Value::from(reason));
        d
    }

    /// A role by name.
    pub fn role(name: &str) -> Self {
        Self::one("role", Value::from(name))
    }

    /// A custom attribute definition by name (never a user's value).
    pub fn attribute(name: &str) -> Self {
        Self::one("attribute", Value::from(name))
    }

    /// A webhook endpoint by name (never its URL secret or signing secret).
    pub fn webhook_endpoint(name: &str) -> Self {
        Self::one("endpoint", Value::from(name))
    }

    /// A webhook event type.
    pub fn webhook_event(event_type: WebhookEventType) -> Self {
        Self::one("event_type", Value::from(event_type.as_str()))
    }

    /// A webhook delivery: its id, the attempts made and a fixed error class (`timeout`,
    /// `status`, `blocked`, ...). Never a response body.
    pub fn webhook_delivery(
        id: WebhookDeliveryId,
        attempts: u32,
        error_class: &'static str,
    ) -> Self {
        let mut d = Self::one("delivery_id", Value::from(id.to_string()));
        d.0.insert("attempts".into(), Value::from(attempts));
        d.0.insert("error_class".into(), Value::from(error_class));
        d
    }

    /// How a client was registered (`static`, `dynamic`, `cimd`).
    pub fn client_source(source: ClientSource) -> Self {
        Self::one("source", Value::from(source.as_str()))
    }

    /// Counts of an applied configuration plan.
    pub fn config_plan(creates: u64, updates: u64, deletes: u64) -> Self {
        let mut d = Self::one("creates", Value::from(creates));
        d.0.insert("updates".into(), Value::from(updates));
        d.0.insert("deletes".into(), Value::from(deletes));
        d
    }

    /// A user export (ADM-09): the mode (`single`, `bulk`, `gdpr`), the number of users exported
    /// and whether password hashes were included (CLI bulk export only). Never exported data.
    pub fn user_export(mode: &'static str, count: u64, include_password_hashes: bool) -> Self {
        let mut d = Self::one("mode", Value::from(mode));
        d.0.insert("count".into(), Value::from(count));
        d.0.insert(
            "include_password_hashes".into(),
            Value::from(include_password_hashes),
        );
        d
    }

    /// An organization by id and slug.
    pub fn org(id: OrgId, slug: &str) -> Self {
        let mut d = Self::one("org_id", Value::from(id.to_string()));
        d.0.insert("org_slug".into(), Value::from(slug));
        d
    }

    /// An organization domain (normalised A-label; public DNS data).
    pub fn domain(domain: &str) -> Self {
        Self::one("domain", Value::from(domain))
    }

    /// A connection by id (SAML/OIDC sign-in through an org connection). Never its
    /// configuration, assertion, NameID or attribute values.
    pub fn connection_id(id: ConnectionId) -> Self {
        Self::one("connection_id", Value::from(id.to_string()))
    }

    /// Merges `other` into `self` (later keys win).
    pub fn with(mut self, other: AuditDetails) -> Self {
        self.0.extend(other.0);
        self
    }

    /// Rebuilds details read back from storage. Storage backends only: the stored map was written
    /// from an `AuditDetails` built by the typed constructors.
    pub fn from_stored(map: Map<String, Value>) -> Self {
        Self(map)
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn one(key: &'static str, value: Value) -> Self {
        let mut m = Map::new();
        m.insert(key.to_owned(), value);
        Self(m)
    }
}

/// An audit event to be appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub id: AuditEventId,
    pub at: OffsetDateTime,
    pub actor: AuditActor,
    pub action: AuditAction,
    /// What the action was applied to (user id, client id, session id, kid, ...).
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub ctx: RequestContext,
    pub details: AuditDetails,
    /// The webhook event this action fans out to, computed inside `AuditService` (05-14).
    /// Construction sites set `None`.
    pub webhook: Option<WebhookEvent>,
}

/// A stored audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub tenant_id: TenantId,
    pub at: OffsetDateTime,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub ctx: RequestContext,
    pub details: AuditDetails,
}

/// Audit query: all filters are optional and combined with AND. Results are newest first
/// (id descending); `before` is the cursor (the last id of the previous page).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditQuery {
    /// Inclusive lower bound on `at`.
    pub from: Option<OffsetDateTime>,
    /// Exclusive upper bound on `at`.
    pub to: Option<OffsetDateTime>,
    pub actor_id: Option<String>,
    pub action: Option<AuditAction>,
    pub outcome: Option<AuditOutcome>,
    pub target: Option<String>,
    pub before: Option<AuditEventId>,
    pub limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_round_trip() {
        for v in AuditAction::ALL {
            assert_eq!(AuditAction::parse(v.as_str()), Some(*v));
        }
        for v in ActorKind::ALL {
            assert_eq!(ActorKind::parse(v.as_str()), Some(*v));
        }
        for v in AuditOutcome::ALL {
            assert_eq!(AuditOutcome::parse(v.as_str()), Some(*v));
        }
        assert_eq!(AuditAction::ALL.len(), 102);
        for (action, name) in [
            (AuditAction::UsersImported, "users_imported"),
            (AuditAction::UserExported, "user_exported"),
            (
                AuditAction::PasswordProfileCreated,
                "password_profile_created",
            ),
            (
                AuditAction::PasswordProfileDeleted,
                "password_profile_deleted",
            ),
        ] {
            assert_eq!(action.as_str(), name);
            assert_eq!(AuditAction::parse(name), Some(action));
        }
        assert_eq!(
            AuditAction::OrgDomainVerificationFailed.as_str(),
            "org_domain_verification_failed"
        );
        assert_eq!(AuditAction::SamlLoginFailed.as_str(), "saml_login_failed");
        assert_eq!(
            AuditAction::OrganizationCreated.as_str(),
            "organization_created"
        );
        assert_eq!(
            AuditAction::AdminRecoveryIssued.as_str(),
            "admin_recovery_issued"
        );
        assert_eq!(
            AuditAction::PasskeyCloneSuspected.as_str(),
            "passkey_clone_suspected"
        );
    }

    #[test]
    fn user_agent_is_truncated() {
        let long = "x".repeat(1000);
        let ctx = RequestContext::new(None, Some(&long), None);
        assert_eq!(
            ctx.user_agent.unwrap().chars().count(),
            MAX_USER_AGENT_CHARS
        );
        let multibyte = "é".repeat(300);
        let ctx = RequestContext::new(None, Some(&multibyte), None);
        assert_eq!(
            ctx.user_agent.unwrap().chars().count(),
            MAX_USER_AGENT_CHARS
        );
        assert_eq!(
            RequestContext::new(None, Some("ua"), None)
                .user_agent
                .as_deref(),
            Some("ua")
        );
    }

    #[test]
    fn details_constructors() {
        let d = AuditDetails::key("kid-1", "RS256").with(AuditDetails::reason("scheduled"));
        assert_eq!(d.as_map()["kid"], "kid-1");
        assert_eq!(d.as_map()["alg"], "RS256");
        assert_eq!(d.as_map()["reason"], "scheduled");
        assert!(AuditDetails::empty().is_empty());
        assert_eq!(AuditDetails::login("passkey").as_map()["method"], "passkey");
        assert_eq!(AuditDetails::count("sessions", 3).as_map()["sessions"], 3);
        let l = AuditDetails::link("google", "auto");
        assert_eq!(l.as_map()["connection"], "google");
        assert_eq!(l.as_map()["mode"], "auto");
        let c = AuditDetails::connection("corp", "oidc");
        assert_eq!(c.as_map()["kind"], "oidc");
        assert!(AuditDetails::logout(None).is_empty());
        assert_eq!(AuditDetails::logout(Some("rp")).as_map()["client_id"], "rp");
        let d = AuditDetails::delivery("rp", 3, "timeout");
        assert_eq!(d.as_map()["attempts"], 3);
        assert_eq!(d.as_map()["reason"], "timeout");
        assert_eq!(
            AuditAction::BackchannelLogoutFailed.as_str(),
            "backchannel_logout_failed"
        );
        assert_eq!(AuditDetails::role("ops").as_map()["role"], "ops");
        assert_eq!(
            AuditDetails::attribute("dept").as_map()["attribute"],
            "dept"
        );
        assert_eq!(
            AuditDetails::webhook_endpoint("crm").as_map()["endpoint"],
            "crm"
        );
        assert_eq!(
            AuditDetails::webhook_event(WebhookEventType::UserCreated).as_map()["event_type"],
            "user.created"
        );
        let id = WebhookDeliveryId::new_v7();
        let w = AuditDetails::webhook_delivery(id, 10, "timeout");
        assert_eq!(w.as_map()["delivery_id"], id.to_string());
        assert_eq!(w.as_map()["error_class"], "timeout");
        assert_eq!(
            AuditDetails::client_source(ClientSource::Cimd).as_map()["source"],
            "cimd"
        );
        let org = OrgId::new_v7();
        let o = AuditDetails::org(org, "acme").with(AuditDetails::domain("acme.example"));
        assert_eq!(o.as_map()["org_id"], org.to_string());
        assert_eq!(o.as_map()["org_slug"], "acme");
        assert_eq!(o.as_map()["domain"], "acme.example");
        let conn = ConnectionId::new_v7();
        let c = AuditDetails::connection_id(conn).with(AuditDetails::reason("audience"));
        assert_eq!(c.as_map()["connection_id"], conn.to_string());
        assert_eq!(c.as_map()["reason"], "audience");
        let p = AuditDetails::config_plan(1, 2, 0);
        assert_eq!(
            (p.as_map()["creates"].clone(), p.as_map()["deletes"].clone()),
            (1.into(), 0.into())
        );
    }
}
