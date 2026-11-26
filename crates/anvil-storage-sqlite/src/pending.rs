//! TRANSITIONAL(05-06): the Phase 5 repositories (roles, attributes, webhooks, dynamic client
//! registration) are not implemented on SQLite yet. Every method returns
//! [`StorageError::Unsupported`], never a success; plan 05-06 replaces this module with the real
//! implementations.

use anvil_core::model::{
    AttributeDefinition, ClientSource, InitialAccessToken, InitialAccessTokenId,
    NewInitialAccessToken, NewRole, NewWebhookEndpoint, Page, PageRequest, Role, RoleId,
    RoleUpdate, SecretHash, TenantId, User, UserId, WebhookDelivery, WebhookDeliveryId,
    WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEvent, WebhookResult,
};
use anvil_core::ports::{
    AttributeRepo, ClaimedWebhookDelivery, RegistrationRepo, RoleRepo, StorageError, WebhookRepo,
};
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// TRANSITIONAL(05-06): refuses every Phase 5 repository call.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SqlitePending;

fn unsupported<T>(what: &'static str) -> Result<T, StorageError> {
    Err(StorageError::Unsupported(what))
}

#[async_trait::async_trait]
impl RoleRepo for SqlitePending {
    async fn create(&self, _t: TenantId, _role: &NewRole) -> Result<Role, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn get(&self, _t: TenantId, _id: RoleId) -> Result<Option<Role>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn get_by_name(&self, _t: TenantId, _name: &str) -> Result<Option<Role>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn list(&self, _t: TenantId) -> Result<Vec<Role>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn update(
        &self,
        _t: TenantId,
        _id: RoleId,
        _update: &RoleUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<Role>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn delete(&self, _t: TenantId, _id: RoleId) -> Result<bool, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn assign(
        &self,
        _t: TenantId,
        _role: RoleId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn unassign(
        &self,
        _t: TenantId,
        _role: RoleId,
        _user: UserId,
    ) -> Result<bool, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn roles_for_user(&self, _t: TenantId, _user: UserId) -> Result<Vec<Role>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn users_with_role(
        &self,
        _t: TenantId,
        _role: RoleId,
        _page: PageRequest,
    ) -> Result<Page<User>, StorageError> {
        unsupported("roles (plan 05-06)")
    }
    async fn holders_of_permission(
        &self,
        _t: TenantId,
        _permission: &str,
    ) -> Result<u64, StorageError> {
        unsupported("roles (plan 05-06)")
    }
}

#[async_trait::async_trait]
impl AttributeRepo for SqlitePending {
    async fn list(&self, _t: TenantId) -> Result<Vec<AttributeDefinition>, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
    async fn get(
        &self,
        _t: TenantId,
        _name: &str,
    ) -> Result<Option<AttributeDefinition>, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
    async fn upsert(
        &self,
        _t: TenantId,
        _definition: &AttributeDefinition,
        _now: OffsetDateTime,
    ) -> Result<AttributeDefinition, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
    async fn delete(&self, _t: TenantId, _name: &str) -> Result<bool, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
    async fn user_values(
        &self,
        _t: TenantId,
        _user: UserId,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
    async fn set_user_values(
        &self,
        _t: TenantId,
        _user: UserId,
        _values: &Map<String, Value>,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("attributes (plan 05-06)")
    }
}

#[async_trait::async_trait]
impl WebhookRepo for SqlitePending {
    async fn create_endpoint(
        &self,
        _t: TenantId,
        _endpoint: &NewWebhookEndpoint,
    ) -> Result<WebhookEndpoint, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn get_endpoint(
        &self,
        _t: TenantId,
        _id: WebhookEndpointId,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn list_endpoints(&self, _t: TenantId) -> Result<Vec<WebhookEndpoint>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn update_endpoint(
        &self,
        _t: TenantId,
        _id: WebhookEndpointId,
        _update: &WebhookEndpointUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn rotate_secret(
        &self,
        _t: TenantId,
        _id: WebhookEndpointId,
        _new_secret_enc: &[u8],
        _previous_expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn disable_endpoint(
        &self,
        _t: TenantId,
        _id: WebhookEndpointId,
        _reason: &str,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn delete_endpoint(
        &self,
        _t: TenantId,
        _id: WebhookEndpointId,
    ) -> Result<bool, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn claim_due(
        &self,
        _owner_lease_until: OffsetDateTime,
        _now: OffsetDateTime,
        _limit: u32,
    ) -> Result<Vec<ClaimedWebhookDelivery>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn complete(
        &self,
        _id: WebhookDeliveryId,
        _result: &WebhookResult,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn deliveries(
        &self,
        _t: TenantId,
        _endpoint: WebhookEndpointId,
        _page: PageRequest,
    ) -> Result<Page<WebhookDelivery>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn redeliver(
        &self,
        _t: TenantId,
        _id: WebhookDeliveryId,
        _now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
    async fn enqueue_test(
        &self,
        _t: TenantId,
        _endpoint: WebhookEndpointId,
        _event: &WebhookEvent,
        _now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        unsupported("webhooks (plan 05-06)")
    }
}

#[async_trait::async_trait]
impl RegistrationRepo for SqlitePending {
    async fn create_iat(
        &self,
        _t: TenantId,
        _token: &NewInitialAccessToken,
    ) -> Result<InitialAccessToken, StorageError> {
        unsupported("registration (plan 05-06)")
    }
    async fn list_iats(&self, _t: TenantId) -> Result<Vec<InitialAccessToken>, StorageError> {
        unsupported("registration (plan 05-06)")
    }
    async fn revoke_iat(
        &self,
        _t: TenantId,
        _id: InitialAccessTokenId,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        unsupported("registration (plan 05-06)")
    }
    async fn consume_iat(
        &self,
        _t: TenantId,
        _token_hash: &SecretHash,
        _now: OffsetDateTime,
    ) -> Result<Option<InitialAccessToken>, StorageError> {
        unsupported("registration (plan 05-06)")
    }
    async fn count_clients_by_source(
        &self,
        _t: TenantId,
        _source: ClientSource,
    ) -> Result<u64, StorageError> {
        unsupported("registration (plan 05-06)")
    }
}
