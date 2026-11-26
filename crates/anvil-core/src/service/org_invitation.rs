//! Organization invitations: [`OrgInvitationService`] (create, list, revoke: plan 06-12; accept:
//! plan 06-20).
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditDetails, AuditOutcome, EmailKind, NewEmail, NewOrgInvitation,
    ORG_INVITATION_TTL, OrgId, OrgInvitation, OrgInvitationId, Organization, OutboxId,
    RequestContext, RoleId, SecretHash, Tenant, TenantId, normalize_email, seal_payload,
};
use crate::ports::Storage;
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
