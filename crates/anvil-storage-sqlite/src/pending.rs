//! TRANSITIONAL(06-07): `OrgRepo` on SQLite before the 1.0 schema exists.
//!
//! Organizations, memberships, invitations and domains need the tables 06-07 adds. Until then
//! every method is refused with an explicit [`StorageError::Unsupported`]; nothing is read or
//! written and nothing reports success. 06-07 replaces this module with the real
//! implementation (and deletes it).

use anvil_core::model::{
    Connection, InvitationAccept, NewMembership, NewOrgDomain, NewOrgInvitation, NewOrganization,
    NewPasswordCredential, NewUser, OrgDomain, OrgDomainId, OrgDomainUpdate, OrgId, OrgInvitation,
    OrgInvitationId, OrgMembership, Organization, OrganizationUpdate, Page, PageRequest,
    SecretHash, TenantId, UserId,
};
use anvil_core::ports::{AddMemberOutcome, OrgRepo, StorageError};
use time::OffsetDateTime;

/// The refusal every method returns.
fn pending<T>() -> Result<T, StorageError> {
    Err(StorageError::Unsupported("organizations (06-07)"))
}

/// `OrgRepo` that refuses every call until 06-07.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PendingOrgs;

#[async_trait::async_trait]
impl OrgRepo for PendingOrgs {
    async fn create(&self, _: TenantId, _: &NewOrganization) -> Result<Organization, StorageError> {
        pending()
    }
    async fn get(&self, _: TenantId, _: OrgId) -> Result<Option<Organization>, StorageError> {
        pending()
    }
    async fn get_by_slug(
        &self,
        _: TenantId,
        _: &str,
    ) -> Result<Option<Organization>, StorageError> {
        pending()
    }
    async fn list(&self, _: TenantId, _: PageRequest) -> Result<Page<Organization>, StorageError> {
        pending()
    }
    async fn update(
        &self,
        _: TenantId,
        _: OrgId,
        _: &OrganizationUpdate,
        _: OffsetDateTime,
    ) -> Result<Option<Organization>, StorageError> {
        pending()
    }
    async fn delete(&self, _: TenantId, _: OrgId, _: OffsetDateTime) -> Result<bool, StorageError> {
        pending()
    }
    async fn add_member(
        &self,
        _: TenantId,
        _: &NewMembership,
    ) -> Result<AddMemberOutcome, StorageError> {
        pending()
    }
    async fn remove_member(
        &self,
        _: TenantId,
        _: OrgId,
        _: UserId,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        pending()
    }
    async fn is_member(&self, _: TenantId, _: OrgId, _: UserId) -> Result<bool, StorageError> {
        pending()
    }
    async fn list_members(
        &self,
        _: TenantId,
        _: OrgId,
        _: PageRequest,
    ) -> Result<Page<OrgMembership>, StorageError> {
        pending()
    }
    async fn memberships_of_user(
        &self,
        _: TenantId,
        _: UserId,
    ) -> Result<Vec<Organization>, StorageError> {
        pending()
    }
    async fn create_invitation(
        &self,
        _: TenantId,
        _: &NewOrgInvitation,
    ) -> Result<OrgInvitation, StorageError> {
        pending()
    }
    async fn list_invitations(
        &self,
        _: TenantId,
        _: OrgId,
        _: bool,
    ) -> Result<Vec<OrgInvitation>, StorageError> {
        pending()
    }
    async fn revoke_invitation(
        &self,
        _: TenantId,
        _: OrgId,
        _: OrgInvitationId,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        pending()
    }
    async fn invitation_by_hash(
        &self,
        _: TenantId,
        _: &SecretHash,
    ) -> Result<Option<OrgInvitation>, StorageError> {
        pending()
    }
    async fn accept_invitation(
        &self,
        _: TenantId,
        _: &SecretHash,
        _: UserId,
        _: &str,
        _: OffsetDateTime,
    ) -> Result<InvitationAccept, StorageError> {
        pending()
    }
    async fn accept_invitation_with_new_user(
        &self,
        _: TenantId,
        _: &SecretHash,
        _: &NewUser,
        _: &NewPasswordCredential,
        _: OffsetDateTime,
    ) -> Result<InvitationAccept, StorageError> {
        pending()
    }
    async fn create_domain(
        &self,
        _: TenantId,
        _: &NewOrgDomain,
    ) -> Result<OrgDomain, StorageError> {
        pending()
    }
    async fn list_domains(&self, _: TenantId, _: OrgId) -> Result<Vec<OrgDomain>, StorageError> {
        pending()
    }
    async fn get_domain(
        &self,
        _: TenantId,
        _: OrgDomainId,
    ) -> Result<Option<OrgDomain>, StorageError> {
        pending()
    }
    async fn update_domain(
        &self,
        _: TenantId,
        _: OrgDomainId,
        _: &OrgDomainUpdate,
        _: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        pending()
    }
    async fn delete_domain(&self, _: TenantId, _: OrgDomainId) -> Result<bool, StorageError> {
        pending()
    }
    async fn mark_verified(
        &self,
        _: TenantId,
        _: OrgDomainId,
        _: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        pending()
    }
    async fn record_check(
        &self,
        _: TenantId,
        _: OrgDomainId,
        _: bool,
        _: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        pending()
    }
    async fn unverify(
        &self,
        _: TenantId,
        _: OrgDomainId,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        pending()
    }
    async fn routed_domain(
        &self,
        _: TenantId,
        _: &str,
    ) -> Result<Option<(OrgDomain, Connection)>, StorageError> {
        pending()
    }
    async fn tenant_has_routing(&self, _: TenantId) -> Result<bool, StorageError> {
        pending()
    }
    async fn verified_domains_of_org(
        &self,
        _: TenantId,
        _: OrgId,
    ) -> Result<Vec<String>, StorageError> {
        pending()
    }
    async fn due_for_recheck(
        &self,
        _: OffsetDateTime,
        _: u32,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_org_method_is_refused_explicitly() {
        let repo = PendingOrgs;
        let t = TenantId::new_v7();
        let refused = |r: Result<(), StorageError>| {
            assert!(matches!(r, Err(StorageError::Unsupported(m)) if m.contains("06-07")));
        };
        refused(repo.get(t, OrgId::new_v7()).await.map(drop));
        refused(repo.tenant_has_routing(t).await.map(drop));
        refused(
            repo.due_for_recheck(OffsetDateTime::UNIX_EPOCH, 10)
                .await
                .map(drop),
        );
        refused(
            repo.is_member(t, OrgId::new_v7(), UserId::new_v7())
                .await
                .map(drop),
        );
        refused(
            repo.accept_invitation(
                t,
                &SecretHash([0; 32]),
                UserId::new_v7(),
                "a@example.test",
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
            .map(drop),
        );
    }
}
