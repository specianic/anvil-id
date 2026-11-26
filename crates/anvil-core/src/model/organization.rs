//! Organizations: business customers inside a tenant (ORG-02, ORG-03, ORG-04).
//!
//! A tenant is the isolation boundary with its own issuer; an organization is a customer inside
//! it, with members, invitations, org-scoped roles, enterprise connections and verified email
//! domains. Organizations never exist in the `system` tenant (service rule).

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::audit::AuditActor;
use super::ids::{
    ConnectionId, OrgDomainId, OrgId, OrgInvitationId, RoleId, SecretHash, TenantId, UserId,
    str_enum,
};
use super::tenant::MfaPolicy;
use crate::error::CoreError;

/// Longest organization display name, in characters.
pub const MAX_ORG_DISPLAY_NAME: usize = 200;

/// How long an organization invitation stays valid (same as the 0.1 user invitation).
pub const ORG_INVITATION_TTL: Duration = Duration::days(7);

/// How long a verified domain may keep failing its daily re-check before it drops back to
/// `pending` and routing stops.
pub const DOMAIN_RECHECK_GRACE: Duration = Duration::days(7);

/// Validates an organization slug with the tenant slug rule: 2-63 characters of `a-z`, `0-9`
/// and `-`, starting with a letter or digit. The slug is unique per tenant.
pub fn validate_org_slug(slug: &str) -> Result<(), CoreError> {
    let bytes = slug.as_bytes();
    let ok = (2..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation {
            field: "slug",
            message: "must be 2-63 characters of a-z, 0-9 and '-', starting with a letter or digit"
                .to_owned(),
        })
    }
}

/// Organization settings, stored as JSON. Missing fields take their defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OrgSettings {
    /// Roles assigned (in this org) to a member created by just-in-time provisioning.
    pub default_role_ids: Vec<RoleId>,
}

/// A persisted organization. `slug` is unique per tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: OrgId,
    pub tenant_id: TenantId,
    pub slug: String,
    pub display_name: String,
    /// The org's MFA policy; `None` = no org requirement. Strictest of tenant, org and client
    /// wins.
    pub mfa_policy: Option<MfaPolicy>,
    pub settings: OrgSettings,
    /// Free-form JSON object for the integrator (never interpreted by the server).
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// An organization to be created. `updated_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOrganization {
    pub id: OrgId,
    pub slug: String,
    pub display_name: String,
    pub mfa_policy: Option<MfaPolicy>,
    pub settings: OrgSettings,
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
}

/// Partial organization update; `None` leaves a field unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrganizationUpdate {
    pub slug: Option<String>,
    pub display_name: Option<String>,
    /// `Some(None)` removes the org's MFA requirement.
    pub mfa_policy: Option<Option<MfaPolicy>>,
    pub settings: Option<OrgSettings>,
    pub metadata: Option<serde_json::Value>,
}

/// A user's membership of an organization. (tenant, org, user) is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgMembership {
    pub tenant_id: TenantId,
    pub org_id: OrgId,
    pub user_id: UserId,
    pub created_at: OffsetDateTime,
}

/// A membership to be created, with the roles assigned in the org in the same intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMembership {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role_ids: Vec<RoleId>,
    pub created_at: OffsetDateTime,
}

/// A pending or settled invitation to join an organization. The token is stored only as its
/// SHA-256 hash; no user is created when inviting.
#[derive(Clone, PartialEq, Eq)]
pub struct OrgInvitation {
    pub id: OrgInvitationId,
    pub tenant_id: TenantId,
    pub org_id: OrgId,
    /// The invited address, normalised to lowercase.
    pub email: String,
    /// Roles assigned in the org on acceptance.
    pub role_ids: Vec<RoleId>,
    pub token_hash: SecretHash,
    pub invited_by: AuditActor,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
    pub accepted_user_id: Option<UserId>,
    pub revoked_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for OrgInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgInvitation")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("org_id", &self.org_id)
            .field("email", &self.email)
            .field("role_ids", &self.role_ids)
            .field("token_hash", &"<redacted>")
            .field("invited_by", &self.invited_by)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("accepted_at", &self.accepted_at)
            .field("accepted_user_id", &self.accepted_user_id)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// An invitation to be stored.
#[derive(Clone, PartialEq, Eq)]
pub struct NewOrgInvitation {
    pub id: OrgInvitationId,
    pub org_id: OrgId,
    pub email: String,
    pub role_ids: Vec<RoleId>,
    pub token_hash: SecretHash,
    pub invited_by: AuditActor,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for NewOrgInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewOrgInvitation")
            .field("id", &self.id)
            .field("org_id", &self.org_id)
            .field("email", &self.email)
            .field("role_ids", &self.role_ids)
            .field("token_hash", &"<redacted>")
            .field("invited_by", &self.invited_by)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The outcome of accepting an invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationAccept {
    /// The token was consumed and the membership (with its roles) created.
    Accepted(OrgMembership),
    /// Unknown, already used, revoked or expired: one outcome, so nothing is revealed.
    Invalid,
    /// The signed-in user's verified email is not the invited address; the token is kept.
    EmailMismatch,
    /// The user is already a member; the token is kept.
    AlreadyMember,
}

/// Verification state of an organization domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgDomainStatus {
    #[default]
    Pending,
    Verified,
}

str_enum!(OrgDomainStatus {
    Pending => "pending",
    Verified => "verified",
});

/// A domain claimed by an organization. Several orgs of a tenant may hold pending claims on a
/// domain; at most one may hold it verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgDomain {
    pub id: OrgDomainId,
    pub tenant_id: TenantId,
    pub org_id: OrgId,
    /// Lowercase A-label.
    pub domain: String,
    /// The public challenge value published in DNS (not a secret).
    pub token: String,
    pub status: OrgDomainStatus,
    /// The connection users of this domain are routed to.
    pub connection_id: Option<ConnectionId>,
    /// Whether home-realm discovery routes this domain to `connection_id`.
    pub routing: bool,
    /// Whether password sign-in stays available for this domain. Defaults to `true` (decision
    /// Q6/Q7): routing starts once the domain is verified, but forcing SSO is an explicit org
    /// admin choice.
    pub allow_local_password: bool,
    pub verified_at: Option<OffsetDateTime>,
    pub last_checked_at: Option<OffsetDateTime>,
    /// Start of the current run of failed re-checks; `None` while the record is found.
    pub failing_since: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// A domain claim to be created (always `pending`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOrgDomain {
    pub id: OrgDomainId,
    pub org_id: OrgId,
    pub domain: String,
    pub token: String,
    pub connection_id: Option<ConnectionId>,
    pub routing: bool,
    pub allow_local_password: bool,
    pub created_at: OffsetDateTime,
}

/// Partial domain update; `None` leaves a field unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrgDomainUpdate {
    /// `Some(None)` removes the routing target.
    pub connection_id: Option<Option<ConnectionId>>,
    pub routing: Option<bool>,
    pub allow_local_password: Option<bool>,
}

/// Per-client organization policy for the `organization` authorization parameter and the org
/// claims.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OrgClientPolicy {
    /// No org claims; the `organization` parameter is refused. Default (0.4 behaviour).
    #[default]
    Off,
    /// An org is selected when the user belongs to one; users without orgs still sign in.
    Optional,
    /// Every authorization needs an org; a user in no org is denied.
    Required,
}

str_enum!(OrgClientPolicy {
    Off => "off",
    Optional => "optional",
    Required => "required",
});

impl OrgClientPolicy {
    /// Whether this is the default (`off`), for `skip_serializing_if`.
    pub fn is_off(&self) -> bool {
        *self == Self::Off
    }
}

/// The org claims of one issuance (computed per issuance, never stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgClaims {
    pub org_id: OrgId,
    pub org_slug: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_slugs_accept_and_reject() {
        for good in ["acme", "a1", "00", "acme-corp", &"a".repeat(63)] {
            assert!(validate_org_slug(good).is_ok(), "{good:?} must be accepted");
        }
        for bad in [
            "",
            "a",
            "-acme",
            "Acme",
            "acme_corp",
            "acme.corp",
            "ümlaut",
            "a b",
            &"a".repeat(64),
        ] {
            assert!(validate_org_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn enum_names_round_trip_and_defaults() {
        for v in OrgDomainStatus::ALL {
            assert_eq!(OrgDomainStatus::parse(v.as_str()), Some(*v));
        }
        for v in OrgClientPolicy::ALL {
            assert_eq!(OrgClientPolicy::parse(v.as_str()), Some(*v));
            assert_eq!(
                serde_json::to_value(v).unwrap(),
                serde_json::Value::String(v.as_str().to_owned())
            );
        }
        assert_eq!(OrgClientPolicy::default(), OrgClientPolicy::Off);
        assert!(OrgClientPolicy::default().is_off());
        assert!(OrgClientPolicy::Required > OrgClientPolicy::Optional);
        assert!(OrgClientPolicy::Optional > OrgClientPolicy::Off);
        assert_eq!(OrgDomainStatus::default(), OrgDomainStatus::Pending);
    }

    #[test]
    fn settings_parse_from_empty_and_partial_json() {
        assert_eq!(
            serde_json::from_str::<OrgSettings>("{}").unwrap(),
            OrgSettings::default()
        );
        let id = RoleId::new_v7();
        let s: OrgSettings =
            serde_json::from_str(&format!(r#"{{"default_role_ids":["{id}"]}}"#)).unwrap();
        assert_eq!(s.default_role_ids, vec![id]);
    }

    #[test]
    fn ttls() {
        assert_eq!(ORG_INVITATION_TTL, Duration::days(7));
        assert_eq!(DOMAIN_RECHECK_GRACE, Duration::days(7));
    }

    #[test]
    fn invitation_debug_hides_the_token_hash() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let inv = OrgInvitation {
            id: OrgInvitationId::new_v7(),
            tenant_id: TenantId::new_v7(),
            org_id: OrgId::new_v7(),
            email: "a@example.test".into(),
            role_ids: vec![],
            token_hash: SecretHash([0xAB; 32]),
            invited_by: AuditActor::system(),
            created_at: now,
            expires_at: now + ORG_INVITATION_TTL,
            accepted_at: None,
            accepted_user_id: None,
            revoked_at: None,
        };
        let dbg = format!("{inv:?}");
        // The hash bytes would print as `171, 171, ...`; ids may contain "171" by chance.
        assert!(
            dbg.contains("<redacted>") && !dbg.contains("171, 171"),
            "{dbg}"
        );
        let new = NewOrgInvitation {
            id: inv.id,
            org_id: inv.org_id,
            email: inv.email.clone(),
            role_ids: vec![],
            token_hash: inv.token_hash,
            invited_by: AuditActor::system(),
            created_at: now,
            expires_at: inv.expires_at,
        };
        let dbg = format!("{new:?}");
        // The hash bytes would print as `171, 171, ...`; ids may contain "171" by chance.
        assert!(
            dbg.contains("<redacted>") && !dbg.contains("171, 171"),
            "{dbg}"
        );
    }
}
