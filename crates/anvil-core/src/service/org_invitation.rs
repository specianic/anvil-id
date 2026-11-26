//! Organization invitations: [`OrgInvitationService`] (create, list, revoke: plan 06-12; preview
//! and accept: plan 06-20).
//!
//! - **Create**: the token is 32 random bytes (base64url, [`random_token`]); only its SHA-256 is
//!   stored ([`SecretHash`]). The address is normalised (trim + lowercase); the invitation expires
//!   after [`ORG_INVITATION_TTL`] (7 days). The `org_invitation` email carries the link
//!   `{issuer}/ui/invitation?token=…`, so its payload is sealed ([`seal_payload`], KEK purpose
//!   `anvilid/outbox-payload/v1`). No user is looked up or created: the answer is the same
//!   whether or not an account exists for the address.
//! - **Roles** are checked by the same function as role assignments
//!   ([`super::organization::check_assignable`]): org-owned roles of this org or tenant roles,
//!   never another org's role, never a role carrying an `admin:*` permission.
//! - **List** never returns the token or its hash (the [`OrgInvitation`] Debug redacts it; the
//!   admin API view has no such field). **Revoke** closes an open invitation.
//!
//! `OrgInvitationRepo::create_invitation` takes no email, so the email is enqueued right after
//! the invitation commits (the 0.1 admin-invite precedent sends in the same intent only because
//! `UserRepo` takes the email); if enqueueing fails the invitation is revoked again, so no
//! invitation is left open without its email.
//!
//! Audited `org_invitation_created` / `org_invitation_revoked` (target = invitation id, org in the
//! details; never the address or token).
//!
//! # Acceptance (plan 06-20)
//!
//! The presented token is hashed and looked up; only an **open** invitation (not accepted, not
//! revoked, `expires_at > now`) is ever described. Unknown, used, revoked and expired tokens are
//! one outcome ([`AcceptOutcome::Invalid`] / `None`), so nothing about them is revealed.
//!
//! - [`OrgInvitationService::preview`] reads only (the GET page: link scanners consume nothing).
//! - [`OrgInvitationService::accept`] binds the invitation to the **signed-in** user: their email
//!   must be verified and equal the invited address. The storage intent
//!   (`OrgRepo::accept_invitation`) consumes the token and adds the membership with the
//!   invitation's roles in one transaction, so of concurrent accepts exactly one wins. Another
//!   account, an unverified address or an existing membership keep the token.
//! - [`OrgInvitationService::accept_with_registration`] registers a **new** user for the invited
//!   address (taken from the invitation, never from the form) with a verified email (the link
//!   proves inbox control). The password passes the policy and the breach check; user, password,
//!   token consumption and membership are one storage intent
//!   (`OrgRepo::accept_invitation_with_new_user`). Allowed when registration is `open` or
//!   `invite_only`, refused when it is `disabled`. An existing account for the address is
//!   [`RegisterOutcome::EmailTaken`] (sign in instead): only the holder of a valid invitation for
//!   that address learns it, so no other address can be probed.
//!
//! An acceptance is audited `org_invitation_accepted` (target = invitation id) and
//! `org_member_added` (target = user, so the `organization.member_added` webhook fires), with
//! the user as actor; a registration also `user_registered`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::flow::registration::MAX_NAME_LEN;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, EmailKind, InvitationAccept, NewEmail,
    NewOrgInvitation, NewPasswordCredential, NewUser, ORG_INVITATION_TTL, OrgId, OrgInvitation,
    OrgInvitationId, Organization, OutboxId, RegistrationMode, RequestContext, RoleId, SecretHash,
    StandardClaims, Tenant, TenantId, UserId, UserStatus, normalize_email, seal_payload,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{BreachChecker, PasswordHasher, Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::organization::{OrgActor, OrgService};

/// Human-readable form of [`ORG_INVITATION_TTL`] for the email.
pub const ORG_INVITATION_TTL_TEXT: &str = "7 days";

/// Most roles one invitation may carry.
pub const MAX_INVITATION_ROLES: usize = 20;

/// An invitation to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationInput {
    pub email: String,
    /// Roles assigned in the org on acceptance.
    pub role_ids: Vec<RoleId>,
}

/// The `org_invitation` email payload (before sealing). `inviter` is a display string (the org
/// admin's address, or the tenant's name for a tenant administrator).
pub fn invitation_payload(
    tenant: &Tenant,
    org: &Organization,
    email: &str,
    inviter: &str,
    issuer: &str,
    token: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("tenant_name".to_owned(), tenant.display_name.clone()),
        ("org_name".to_owned(), org.display_name.clone()),
        ("email".to_owned(), email.to_owned()),
        ("inviter".to_owned(), inviter.to_owned()),
        (
            "link".to_owned(),
            format!(
                "{}/ui/invitation?token={token}",
                issuer.trim_end_matches('/')
            ),
        ),
        ("expires_in".to_owned(), ORG_INVITATION_TTL_TEXT.to_owned()),
    ])
}

/// Longest token accepted from a link or form (a real token is 43 characters).
pub const MAX_TOKEN_LEN: usize = 128;

/// What the invitation page shows about an open invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationPreview {
    /// The organization's display name.
    pub org_name: String,
    /// The invited address (the signed-out page prefills and locks it; the link holder received
    /// the email at this address).
    pub email: String,
}

/// The result of accepting while signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// The token was consumed; the user is now a member (with the invited roles).
    Accepted { org_name: String },
    /// Unknown, used, revoked or expired: one outcome.
    Invalid,
    /// The signed-in account is not the invited one. The token is kept.
    WrongAccount,
    /// The signed-in account is the invited address, but its email is not verified yet. The
    /// token is kept.
    VerifyEmailFirst,
    /// The user already belongs to the organization. The token is kept.
    AlreadyMember { org_name: String },
}

/// The result of registering through an invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The user was created with a verified email and is now a member.
    Registered { org_name: String, user: UserId },
    /// Unknown, used, revoked or expired: one outcome.
    Invalid,
    /// The tenant's registration mode is `disabled`. Nothing written, the token is kept.
    RegistrationDisabled,
    /// An account already exists for the invited address (sign in instead). Nothing written,
    /// the token is kept.
    EmailTaken,
    /// The password was refused; the message key (`password.too_short`, `password.too_long`,
    /// `password.breached`). Nothing written.
    PasswordRejected(&'static str),
    /// The password hasher or breach check is overloaded; try again.
    Overloaded,
}

/// What registering through an invitation needs besides storage: the same password policy,
/// hasher and breach check as self-registration.
pub struct RegistrationChecks<'a> {
    pub policy: PasswordPolicy,
    pub hasher: &'a dyn PasswordHasher,
    pub breach: &'a dyn BreachChecker,
}

/// The message key of a password the policy refuses (the self-registration keys).
fn password_problem(policy: &PasswordPolicy, password: &str) -> Option<&'static str> {
    match check_password(policy, password) {
        Ok(()) => None,
        Err(_) if password.chars().count() < policy.min_len => Some("password.too_short"),
        Err(_) => Some("password.too_long"),
    }
}

/// The SHA-256 of a presented token, or `None` for a value that cannot be a token.
fn presented_hash(token: &str) -> Option<SecretHash> {
    (!token.is_empty() && token.len() <= MAX_TOKEN_LEN).then(|| SecretHash(secret_hash(token)))
}

/// Organization invitation administration.
#[derive(Clone)]
pub struct OrgInvitationService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
}

impl OrgInvitationService {
    fn orgs(&self) -> OrgService {
        OrgService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    async fn record(
        &self,
        tenant: TenantId,
        actor: &OrgActor,
        action: AuditAction,
        id: OrgInvitationId,
        org: &Organization,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant,
            actor.audit_actor(),
            action,
            Some(id.to_string()),
            AuditOutcome::Success,
            ctx,
            AuditDetails::org(org.id, &org.slug),
        )
        .await
    }

    /// Creates an invitation and enqueues its sealed `org_invitation` email. `issuer` is the
    /// tenant's issuer (the link base). The result never depends on whether an account exists
    /// for the address.
    pub async fn create(
        &self,
        tenant: &Tenant,
        org: &Organization,
        issuer: &str,
        input: InvitationInput,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<OrgInvitation, CoreError> {
        let email = normalize_email(&input.email)?;
        let role_ids: Vec<RoleId> = input
            .role_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if role_ids.len() > MAX_INVITATION_ROLES {
            return Err(CoreError::Validation {
                field: "role_ids",
                message: format!("at most {MAX_INVITATION_ROLES} roles"),
            });
        }
        let orgs = self.orgs();
        for id in &role_ids {
            orgs.assignable_role_by_id(tenant.id, org.id, *id).await?;
        }
        let inviter = match actor {
            OrgActor::OrgAdmin(user) => self
                .storage
                .users()
                .get(tenant.id, *user)
                .await?
                .map(|u| u.email)
                .unwrap_or_else(|| tenant.display_name.clone()),
            OrgActor::TenantAdmin(_) => tenant.display_name.clone(),
        };
        let token = random_token();
        let now = self.clock.now();
        let expires_at = now + ORG_INVITATION_TTL;
        let payload = invitation_payload(tenant, org, &email, &inviter, issuer, &token);
        let mail = NewEmail {
            id: OutboxId::new_v7(),
            to: email.clone(),
            template: EmailKind::OrgInvitation.as_str().to_owned(),
            payload: seal_payload(&self.kek, tenant.id, &payload)?,
            created_at: now,
            expires_at,
        };
        let invitation = self
            .storage
            .organizations()
            .create_invitation(
                tenant.id,
                &NewOrgInvitation {
                    id: OrgInvitationId::new_v7(),
                    org_id: org.id,
                    email,
                    role_ids,
                    token_hash: SecretHash(secret_hash(&token)),
                    invited_by: actor.audit_actor(),
                    created_at: now,
                    expires_at,
                },
            )
            .await?;
        if let Err(e) = self.storage.outbox().enqueue(tenant.id, &mail).await {
            // Close the invitation again: it must not stay open without its email. The enqueue
            // failure is the error reported; a failing revoke here means storage is down, and
            // the unsent invitation then simply expires.
            let _ = self
                .storage
                .organizations()
                .revoke_invitation(tenant.id, org.id, invitation.id, now)
                .await;
            return Err(e.into());
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrgInvitationCreated,
            invitation.id,
            org,
            ctx,
        )
        .await?;
        Ok(invitation)
    }

    /// The org's invitations, newest first (`include_closed = false`: only open ones).
    pub async fn list(
        &self,
        tenant: TenantId,
        org: OrgId,
        include_closed: bool,
    ) -> Result<Vec<OrgInvitation>, CoreError> {
        Ok(self
            .storage
            .organizations()
            .list_invitations(tenant, org, include_closed)
            .await?)
    }

    /// Revokes an open invitation of the org (`NotFound` otherwise).
    pub async fn revoke(
        &self,
        tenant: &Tenant,
        org: &Organization,
        id: OrgInvitationId,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let revoked = self
            .storage
            .organizations()
            .revoke_invitation(tenant.id, org.id, id, self.clock.now())
            .await?;
        if !revoked {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrgInvitationRevoked,
            id,
            org,
            ctx,
        )
        .await
    }
}

impl OrgInvitationService {
    /// The open invitation behind `token` and its organization, or `None` (unknown, accepted,
    /// revoked, expired, or its organization is gone).
    async fn open_invitation(
        &self,
        tenant: TenantId,
        hash: &SecretHash,
    ) -> Result<Option<(OrgInvitation, Organization)>, CoreError> {
        let orgs = self.storage.organizations();
        let Some(inv) = orgs.invitation_by_hash(tenant, hash).await? else {
            return Ok(None);
        };
        let open = inv.accepted_at.is_none()
            && inv.revoked_at.is_none()
            && inv.expires_at > self.clock.now();
        if !open {
            return Ok(None);
        }
        Ok(orgs.get(tenant, inv.org_id).await?.map(|org| (inv, org)))
    }

    /// Describes the open invitation behind `token`. Reads only: nothing is consumed.
    pub async fn preview(
        &self,
        tenant: TenantId,
        token: &str,
    ) -> Result<Option<InvitationPreview>, CoreError> {
        let Some(hash) = presented_hash(token) else {
            return Ok(None);
        };
        Ok(self
            .open_invitation(tenant, &hash)
            .await?
            .map(|(inv, org)| InvitationPreview {
                org_name: org.display_name,
                email: inv.email,
            }))
    }

    /// Audits an acceptance by `user` (module docs).
    async fn record_accepted(
        &self,
        tenant: TenantId,
        inv: &OrgInvitation,
        org: &Organization,
        user: UserId,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let audit = AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        };
        audit
            .record(
                tenant,
                AuditActor::user(user),
                AuditAction::OrgInvitationAccepted,
                Some(inv.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::org(org.id, &org.slug),
            )
            .await?;
        audit
            .record(
                tenant,
                AuditActor::user(user),
                AuditAction::OrgMemberAdded,
                Some(user.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::org(org.id, &org.slug),
            )
            .await
    }

    /// Accepts the invitation behind `token` for the signed-in `user` (module docs).
    pub async fn accept(
        &self,
        tenant: &Tenant,
        token: &str,
        user: UserId,
        ctx: &RequestContext,
    ) -> Result<AcceptOutcome, CoreError> {
        let Some(hash) = presented_hash(token) else {
            return Ok(AcceptOutcome::Invalid);
        };
        let Some((inv, org)) = self.open_invitation(tenant.id, &hash).await? else {
            return Ok(AcceptOutcome::Invalid);
        };
        let Some(account) = self.storage.users().get(tenant.id, user).await? else {
            return Ok(AcceptOutcome::WrongAccount);
        };
        if account.status != UserStatus::Active {
            return Ok(AcceptOutcome::WrongAccount);
        }
        if !account.email_verified {
            // Only the invited address is told to verify; any other account is the wrong one.
            return Ok(if account.email == inv.email {
                AcceptOutcome::VerifyEmailFirst
            } else {
                AcceptOutcome::WrongAccount
            });
        }
        let outcome = self
            .storage
            .organizations()
            .accept_invitation(tenant.id, &hash, user, &account.email, self.clock.now())
            .await?;
        Ok(match outcome {
            InvitationAccept::Accepted(_) => {
                self.record_accepted(tenant.id, &inv, &org, user, ctx)
                    .await?;
                AcceptOutcome::Accepted {
                    org_name: org.display_name,
                }
            }
            InvitationAccept::Invalid => AcceptOutcome::Invalid,
            InvitationAccept::EmailMismatch => AcceptOutcome::WrongAccount,
            InvitationAccept::AlreadyMember => AcceptOutcome::AlreadyMember {
                org_name: org.display_name,
            },
        })
    }

    /// Registers a new user for the invited address and accepts the invitation in one storage
    /// intent (module docs). `name` is the optional display name.
    pub async fn accept_with_registration(
        &self,
        tenant: &Tenant,
        token: &str,
        password: &str,
        name: Option<&str>,
        checks: &RegistrationChecks<'_>,
        ctx: &RequestContext,
    ) -> Result<RegisterOutcome, CoreError> {
        let Some(hash) = presented_hash(token) else {
            return Ok(RegisterOutcome::Invalid);
        };
        let Some((inv, org)) = self.open_invitation(tenant.id, &hash).await? else {
            return Ok(RegisterOutcome::Invalid);
        };
        if tenant.settings.registration == RegistrationMode::Disabled {
            return Ok(RegisterOutcome::RegistrationDisabled);
        }
        if let Some(key) = password_problem(&checks.policy, password) {
            return Ok(RegisterOutcome::PasswordRejected(key));
        }
        match checks.breach.is_breached(password).await {
            Ok(false) => {}
            Ok(true) => return Ok(RegisterOutcome::PasswordRejected("password.breached")),
            Err(CoreError::Overloaded) => return Ok(RegisterOutcome::Overloaded),
            Err(e) => return Err(e),
        }
        let phc = match checks.hasher.hash(password).await {
            Ok(p) => p,
            Err(CoreError::Overloaded) => return Ok(RegisterOutcome::Overloaded),
            Err(e) => return Err(e),
        };
        let now = self.clock.now();
        let name = name
            .map(|n| n.trim().chars().take(MAX_NAME_LEN).collect::<String>())
            .filter(|n| !n.is_empty());
        let user = NewUser {
            id: UserId::new_v7(),
            email: inv.email.clone(),
            email_verified: true,
            username: None,
            claims: StandardClaims {
                name,
                ..StandardClaims::default()
            },
            status: UserStatus::Active,
            created_at: now,
        };
        let credential = NewPasswordCredential {
            phc,
            created_at: now,
        };
        let outcome = match self
            .storage
            .organizations()
            .accept_invitation_with_new_user(tenant.id, &hash, &user, &credential, now)
            .await
        {
            Ok(o) => o,
            Err(StorageError::Conflict(_)) => return Ok(RegisterOutcome::EmailTaken),
            Err(e) => return Err(e.into()),
        };
        match outcome {
            InvitationAccept::Accepted(_) => {
                AuditService {
                    storage: self.storage.clone(),
                    clock: self.clock.clone(),
                }
                .record(
                    tenant.id,
                    AuditActor::user(user.id),
                    AuditAction::UserRegistered,
                    Some(user.id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                    AuditDetails::org(org.id, &org.slug),
                )
                .await?;
                self.record_accepted(tenant.id, &inv, &org, user.id, ctx)
                    .await?;
                Ok(RegisterOutcome::Registered {
                    org_name: org.display_name,
                    user: user.id,
                })
            }
            // The address comes from the invitation, so a mismatch means it changed under us:
            // treat it like any other closed invitation.
            InvitationAccept::Invalid | InvitationAccept::EmailMismatch => {
                Ok(RegisterOutcome::Invalid)
            }
            InvitationAccept::AlreadyMember => Ok(RegisterOutcome::EmailTaken),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OrgSettings, TenantSettings};
    use time::OffsetDateTime;

    #[test]
    fn payload_carries_the_link_and_contract_fields() {
        let tenant = Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let org = Organization {
            id: OrgId::new_v7(),
            tenant_id: tenant.id,
            slug: "globex".into(),
            display_name: "Globex".into(),
            mfa_policy: None,
            settings: OrgSettings::default(),
            metadata: serde_json::json!({}),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let p = invitation_payload(
            &tenant,
            &org,
            "bob@example.test",
            "ada@example.test",
            "https://op.test/t/acme/",
            "TOKEN",
        );
        assert_eq!(
            p["link"],
            "https://op.test/t/acme/ui/invitation?token=TOKEN"
        );
        assert_eq!(p["org_name"], "Globex");
        assert_eq!(p["tenant_name"], "Acme");
        assert_eq!(p["inviter"], "ada@example.test");
        assert_eq!(p["email"], "bob@example.test");
        assert_eq!(p["expires_in"], "7 days");
    }

    #[test]
    fn presented_tokens_are_bounded() {
        assert!(presented_hash("").is_none());
        assert!(presented_hash(&"a".repeat(MAX_TOKEN_LEN + 1)).is_none());
        assert_eq!(presented_hash("tok"), Some(SecretHash(secret_hash("tok"))));
    }

    #[test]
    fn password_problems_use_the_registration_keys() {
        let p = PasswordPolicy::default();
        assert_eq!(password_problem(&p, "1234567"), Some("password.too_short"));
        assert_eq!(
            password_problem(&p, &"a".repeat(1025)),
            Some("password.too_long")
        );
        assert_eq!(password_problem(&p, "12345678"), None);
    }

    #[test]
    fn invitation_ttl_is_seven_days() {
        assert_eq!(ORG_INVITATION_TTL, time::Duration::days(7));
    }

    #[test]
    fn emails_are_normalised() {
        assert_eq!(
            normalize_email("  Bob@Example.TEST ").unwrap(),
            "bob@example.test"
        );
        assert!(normalize_email("not an email").is_err());
    }
}
