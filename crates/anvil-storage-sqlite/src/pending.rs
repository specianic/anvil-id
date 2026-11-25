//! TRANSITIONAL(04-04): Phase 4 storage the sqlite backend does not implement yet. Every method
//! here returns `StorageError::Unsupported`, never a success, and the write guards refuse
//! Phase 4 values that have no column yet instead of silently dropping them. Plan 04-04 adds
//! the 0.3 migration and real implementations and deletes this module.

use anvil_core::model::{
    Branding, BrandingDraft, BrandingUpdate, ClientUpdate, Connection, ConnectionId,
    ConnectionUpdate, DeliveryResult, IdentityLink, IdentityLinkId, Logo, LogoutDelivery,
    LogoutDeliveryId, NewClient, NewConnection, NewIdentityLink, NewUser, RpSession, SecretHash,
    SessionId, TenantId, User, UserId,
};
use anvil_core::ports::{BrandingRepo, ConnectionRepo, LogoutRepo, StorageError};
use time::OffsetDateTime;

/// TRANSITIONAL(04-04): refuses Phase 4 client fields that have no column yet.
pub(crate) fn refuse_phase4_client(c: &NewClient) -> Result<(), StorageError> {
    if !c.post_logout_redirect_uris.is_empty()
        || c.backchannel_logout_uri.is_some()
        || c.backchannel_logout_session_required
        || !c.allowed_resources.is_empty()
        || c.mfa_policy.is_some()
    {
        return Err(StorageError::Unsupported(
            "phase 4 client fields are not stored by this backend yet",
        ));
    }
    Ok(())
}

/// TRANSITIONAL(04-04): refuses Phase 4 client updates that have no column yet.
pub(crate) fn refuse_phase4_client_update(u: &ClientUpdate) -> Result<(), StorageError> {
    if u.post_logout_redirect_uris.is_some()
        || u.backchannel_logout_uri.is_some()
        || u.backchannel_logout_session_required.is_some()
        || u.allowed_resources.is_some()
        || u.mfa_policy.is_some()
    {
        return Err(StorageError::Unsupported(
            "phase 4 client fields are not stored by this backend yet",
        ));
    }
    Ok(())
}

/// TRANSITIONAL(04-04): refuses RFC 8707 resources on codes, families and access tokens.
pub(crate) fn refuse_resource(resource: &[String]) -> Result<(), StorageError> {
    if resource.is_empty() {
        Ok(())
    } else {
        Err(StorageError::Unsupported(
            "resource indicators are not stored by this backend yet",
        ))
    }
}

/// TRANSITIONAL(04-04): `SessionRepo::upgrade_auth` until the backend implements it.
pub(crate) fn upgrade_auth_unsupported() -> Result<bool, StorageError> {
    Err(StorageError::Unsupported("SessionRepo::upgrade_auth"))
}

/// TRANSITIONAL(04-04): `UserRepo::complete_email_change` until the backend implements it.
pub(crate) fn complete_email_change_unsupported() -> Result<Option<User>, StorageError> {
    Err(StorageError::Unsupported("UserRepo::complete_email_change"))
}

/// TRANSITIONAL(04-04): connections and identity links are not stored yet.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PendingConnections;

const CONNECTIONS: StorageError = StorageError::Unsupported("ConnectionRepo");

#[async_trait::async_trait]
impl ConnectionRepo for PendingConnections {
    async fn create(&self, _: TenantId, _: &NewConnection) -> Result<Connection, StorageError> {
        Err(CONNECTIONS)
    }
    async fn get(&self, _: TenantId, _: ConnectionId) -> Result<Option<Connection>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn get_by_slug(&self, _: TenantId, _: &str) -> Result<Option<Connection>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn list(&self, _: TenantId) -> Result<Vec<Connection>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn update(
        &self,
        _: TenantId,
        _: ConnectionId,
        _: &ConnectionUpdate,
        _: OffsetDateTime,
    ) -> Result<Option<Connection>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn set_secret(
        &self,
        _: TenantId,
        _: ConnectionId,
        _: Option<&[u8]>,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(CONNECTIONS)
    }
    async fn delete(&self, _: TenantId, _: ConnectionId) -> Result<bool, StorageError> {
        Err(CONNECTIONS)
    }
    async fn find_link(
        &self,
        _: TenantId,
        _: ConnectionId,
        _: &str,
    ) -> Result<Option<IdentityLink>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn create_link(
        &self,
        _: TenantId,
        _: &NewIdentityLink,
    ) -> Result<IdentityLink, StorageError> {
        Err(CONNECTIONS)
    }
    async fn links_for_user(
        &self,
        _: TenantId,
        _: UserId,
    ) -> Result<Vec<IdentityLink>, StorageError> {
        Err(CONNECTIONS)
    }
    async fn touch_link(
        &self,
        _: TenantId,
        _: IdentityLinkId,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(CONNECTIONS)
    }
    async fn delete_link(
        &self,
        _: TenantId,
        _: UserId,
        _: IdentityLinkId,
    ) -> Result<bool, StorageError> {
        Err(CONNECTIONS)
    }
    async fn create_user_with_link(
        &self,
        _: TenantId,
        _: &NewUser,
        _: &NewIdentityLink,
    ) -> Result<User, StorageError> {
        Err(CONNECTIONS)
    }
}

/// TRANSITIONAL(04-04): branding is not stored yet.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PendingBranding;

const BRANDING: StorageError = StorageError::Unsupported("BrandingRepo");

#[async_trait::async_trait]
impl BrandingRepo for PendingBranding {
    async fn get(&self, _: TenantId, _: &str) -> Result<Option<Branding>, StorageError> {
        Err(BRANDING)
    }
    async fn put(
        &self,
        _: TenantId,
        _: &str,
        _: &BrandingUpdate,
        _: OffsetDateTime,
    ) -> Result<Branding, StorageError> {
        Err(BRANDING)
    }
    async fn delete(&self, _: TenantId, _: &str) -> Result<bool, StorageError> {
        Err(BRANDING)
    }
    async fn logo(&self, _: TenantId, _: &str) -> Result<Option<Logo>, StorageError> {
        Err(BRANDING)
    }
    async fn put_draft(
        &self,
        _: TenantId,
        _: &str,
        _: &BrandingDraft,
        _: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(BRANDING)
    }
    async fn draft_by_preview(
        &self,
        _: TenantId,
        _: &SecretHash,
        _: OffsetDateTime,
    ) -> Result<Option<(String, BrandingDraft)>, StorageError> {
        Err(BRANDING)
    }
}

/// TRANSITIONAL(04-04): RP sessions and logout deliveries are not stored yet.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PendingLogout;

const LOGOUT: StorageError = StorageError::Unsupported("LogoutRepo");

#[async_trait::async_trait]
impl LogoutRepo for PendingLogout {
    async fn rp_sessions(&self, _: TenantId, _: SessionId) -> Result<Vec<RpSession>, StorageError> {
        Err(LOGOUT)
    }
    async fn claim_due_deliveries(
        &self,
        _: OffsetDateTime,
        _: OffsetDateTime,
        _: u32,
    ) -> Result<Vec<LogoutDelivery>, StorageError> {
        Err(LOGOUT)
    }
    async fn complete_delivery(
        &self,
        _: LogoutDeliveryId,
        _: &DeliveryResult,
        _: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(LOGOUT)
    }
    async fn deliveries_for_client(
        &self,
        _: TenantId,
        _: &str,
    ) -> Result<Vec<LogoutDelivery>, StorageError> {
        Err(LOGOUT)
    }
}
