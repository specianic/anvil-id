//! Webhook endpoints, secret rotation, test sends and the delivery log of a tenant (ADM-05):
//!
//! - `GET|POST …/tenants/{slug}/webhooks`: list (name order) and create; the create response
//!   carries the signing secret (`whsec_…`) **once**;
//! - `GET|PATCH|DELETE …/webhooks/{id}`: view, update (name, URL, events, enabled), delete (with
//!   its delivery log);
//! - `POST …/webhooks/{id}/secret`: rotate the secret; the new one is returned once and the
//!   previous one keeps signing for 24 hours (both signatures are sent);
//! - `POST …/webhooks/{id}/test`: queue the `test` event regardless of the subscriptions;
//! - `GET …/webhooks/{id}/deliveries`: the delivery log (newest first, cursor pagination) with
//!   status, attempts, last HTTP status, error class and next attempt; payloads are not returned;
//! - `POST …/webhooks/deliveries/{delivery_id}/redeliver`: queue the delivery's event again
//!   (new delivery id, fresh attempts).
//!
//! Scopes: `admin:settings:{read,write}` (or `admin:read` / `admin:write`). URLs are checked at
//! write time with the same outbound policy the delivery worker uses (https only in production,
//! no private, loopback or link-local literals, no credentials); every send re-checks the
//! resolved address. Secrets are stored sealed with the KEK and never returned after the
//! response that created them (`secret_configured` only). Everything is audited by
//! `WebhookService` in the tenant.

use anvil_core::error::CoreError;
use anvil_core::model::{
    DeliveryStatus as CoreDeliveryStatus, Tenant, WebhookDelivery, WebhookDeliveryId,
    WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate,
    WebhookEventType as CoreWebhookEventType,
};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::webhook::{EndpointWithSecret, NewWebhookInput};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{ListQuery, Problem, ts};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_webhooks, create_webhook))
        .routes(routes!(get_webhook, update_webhook, delete_webhook))
        .routes(routes!(rotate_webhook_secret))
        .routes(routes!(send_webhook_test))
        .routes(routes!(list_webhook_deliveries))
        .routes(routes!(redeliver_webhook_delivery))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// A webhook event type. `test` is only sent by the test action and cannot be subscribed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    #[serde(rename = "organization.created")]
    OrganizationCreated,
    #[serde(rename = "organization.deleted")]
    OrganizationDeleted,
    #[serde(rename = "organization.member_added")]
    OrganizationMemberAdded,
    #[serde(rename = "organization.member_removed")]
    OrganizationMemberRemoved,
    #[serde(rename = "organization.domain_verified")]
    OrganizationDomainVerified,
    #[serde(rename = "organization.domain_unverified")]
    OrganizationDomainUnverified,
    #[serde(rename = "test")]
    Test,
}

macro_rules! event_map {
    ($($v:ident),+ $(,)?) => {
        impl From<WebhookEventType> for CoreWebhookEventType {
            fn from(v: WebhookEventType) -> Self {
                match v { $(WebhookEventType::$v => Self::$v),+ }
            }
        }
        impl From<CoreWebhookEventType> for WebhookEventType {
            fn from(v: CoreWebhookEventType) -> Self {
                match v { $(CoreWebhookEventType::$v => Self::$v),+ }
            }
        }
    };
}

event_map!(
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserEmailVerified,
    UserEmailChanged,
    UserPasswordChanged,
    SessionCreated,
    SessionRevoked,
    SessionLoggedOut,
    OrganizationCreated,
    OrganizationDeleted,
    OrganizationMemberAdded,
    OrganizationMemberRemoved,
    OrganizationDomainVerified,
    OrganizationDomainUnverified,
    Test,
);

/// State of a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Queued or waiting for a retry (`next_attempt_at`).
    Pending,
    /// A 2xx answer was received.
    Delivered,
    /// Retries exhausted, or the endpoint answered 410 Gone (it is then disabled).
    Failed,
}

impl From<CoreDeliveryStatus> for DeliveryStatus {
    fn from(s: CoreDeliveryStatus) -> Self {
        match s {
            CoreDeliveryStatus::Pending => Self::Pending,
            CoreDeliveryStatus::Delivered => Self::Delivered,
            CoreDeliveryStatus::Failed => Self::Failed,
        }
    }
}

/// A webhook endpoint. The signing secret is write-only.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointDto {
    pub id: Uuid,
    /// Unique in the tenant: `^[a-z0-9][a-z0-9_-]{0,63}$`.
    pub name: String,
    pub url: String,
    /// Subscribed event types, sorted.
    pub events: Vec<WebhookEventType>,
    pub enabled: bool,
    /// Why the system disabled the endpoint (`gone` after an HTTP 410); `null` otherwise.
    /// Re-enabling clears it.
    pub disabled_reason: Option<String>,
    /// Always `true`: a secret is stored (sealed); it cannot be read back.
    pub secret_configured: bool,
    /// End of the rotation window during which the previous secret still signs; `null` if none.
    #[schema(format = DateTime)]
    pub previous_secret_expires_at: Option<String>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl From<WebhookEndpoint> for WebhookEndpointDto {
    fn from(e: WebhookEndpoint) -> Self {
        Self {
            id: e.id.0,
            name: e.name,
            url: e.url,
            events: e.events.into_iter().map(Into::into).collect(),
            enabled: e.enabled,
            disabled_reason: e.disabled_reason,
            secret_configured: true,
            previous_secret_expires_at: e
                .previous_secret_enc
                .as_ref()
                .and(e.previous_secret_expires_at)
                .map(ts),
            created_at: ts(e.created_at),
            updated_at: ts(e.updated_at),
        }
    }
}

/// Webhook endpoints, in name order.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointList {
    pub items: Vec<WebhookEndpointDto>,
}

/// An endpoint with its signing secret: returned by create and secret rotation only.
#[derive(Serialize, ToSchema)]
pub struct WebhookEndpointWithSecret {
    pub endpoint: WebhookEndpointDto,
    /// The Standard Webhooks signing secret (`whsec_…`). Shown once; store it now.
    pub secret: String,
}

impl std::fmt::Debug for WebhookEndpointWithSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEndpointWithSecret")
            .field("endpoint", &self.endpoint)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl From<EndpointWithSecret> for WebhookEndpointWithSecret {
    fn from(e: EndpointWithSecret) -> Self {
        Self {
            secret: e.secret.expose_secret().to_owned(),
            endpoint: e.endpoint.into(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Body of `POST /tenants/{slug}/webhooks`. The secret is generated by the server.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWebhookEndpoint {
    /// `^[a-z0-9][a-z0-9_-]{0,63}$`, unique in the tenant.
    pub name: String,
    /// `https` URL (plain `http` only in development mode); private, loopback and link-local
    /// addresses are refused.
    pub url: String,
    /// At least one lifecycle event type (`test` is refused).
    pub events: Vec<WebhookEventType>,
    /// Default `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Body of `PATCH /tenants/{slug}/webhooks/{id}`. Absent fields stay unchanged; `events`
/// replaces the whole set.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpointPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<WebhookEventType>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// One delivery of an event to an endpoint. The payload (ids only) is not returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookDeliveryDto {
    /// Also the `webhook-id` header of every attempt.
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_type: WebhookEventType,
    pub status: DeliveryStatus,
    /// Attempts made so far (at most 10).
    pub attempts: u32,
    /// HTTP status of the last attempt; `null` if none was received.
    pub last_http_status: Option<u16>,
    /// Error class of the last failed attempt (`status_5xx`, `status_4xx`, `status_429`,
    /// `redirect`, `timeout`, `network`, `blocked`, `gone`, `internal`); never a response body.
    pub error_class: Option<String>,
    /// When the next attempt is due (pending deliveries only).
    #[schema(format = DateTime)]
    pub next_attempt_at: Option<String>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub completed_at: Option<String>,
}

impl From<WebhookDelivery> for WebhookDeliveryDto {
    fn from(d: WebhookDelivery) -> Self {
        Self {
            id: d.id.0,
            endpoint_id: d.endpoint_id.0,
            event_type: d.event_type.into(),
            status: d.status.into(),
            attempts: d.attempts,
            last_http_status: d.last_http_status,
            error_class: d.last_error,
            next_attempt_at: (d.status == CoreDeliveryStatus::Pending)
                .then(|| ts(d.next_attempt_at)),
            created_at: ts(d.created_at),
            completed_at: d.completed_at.map(ts),
        }
    }
}

/// One page of deliveries, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookDeliveryList {
    pub items: Vec<WebhookDeliveryDto>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Settings, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// An id from the path; anything that is not a UUID cannot name an object (404).
fn uuid(raw: &str) -> AdminResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| CoreError::NotFound.into())
}

fn endpoint_id(raw: &str) -> AdminResult<WebhookEndpointId> {
    uuid(raw).map(WebhookEndpointId)
}

fn events(v: Vec<WebhookEventType>) -> Vec<CoreWebhookEventType> {
    v.into_iter().map(Into::into).collect()
}

// ---------------------------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------------------------

/// List the webhook endpoints of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/webhooks",
    tag = "webhooks",
    operation_id = "listWebhooks",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every endpoint, in name order", body = WebhookEndpointList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_webhooks(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let items = state.webhook_service().list(tenant.id).await?;
    Ok(json(
        StatusCode::OK,
        &WebhookEndpointList {
            items: items.into_iter().map(Into::into).collect(),
        },
    ))
}

/// Create a webhook endpoint. The response carries the signing secret once.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/webhooks",
    tag = "webhooks",
    operation_id = "createWebhook",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = NewWebhookEndpoint,
    responses(
        (status = 201, description = "Created; `secret` is shown only in this response", body = WebhookEndpointWithSecret, headers(("Location" = String, description = "URL of the new endpoint"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "An endpoint with this name already exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid name, events, or a URL refused by the outbound policy", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_webhook(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<NewWebhookEndpoint>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let created_endpoint = state
        .webhook_service()
        .create(
            tenant.id,
            NewWebhookInput {
                name: body.name,
                url: body.url,
                events: events(body.events),
                enabled: body.enabled,
                secret: None,
            },
            auth.actor(),
            &ctx,
        )
        .await?;
    let location = format!(
        "/api/admin/v1/tenants/{}/webhooks/{}",
        tenant.slug, created_endpoint.endpoint.id.0
    );
    Ok(created(
        &location,
        &WebhookEndpointWithSecret::from(created_endpoint),
    ))
}

/// Get a webhook endpoint (without its secret).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}",
    tag = "webhooks",
    operation_id = "getWebhook",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
    ),
    responses(
        (status = 200, description = "The endpoint", body = WebhookEndpointDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_webhook(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let endpoint = state
        .webhook_service()
        .get(tenant.id, endpoint_id(&id)?)
        .await?;
    Ok(json(StatusCode::OK, &WebhookEndpointDto::from(endpoint)))
}

/// Update a webhook endpoint. Re-enabling clears the system's disabled reason.
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}",
    tag = "webhooks",
    operation_id = "updateWebhook",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
    ),
    request_body = WebhookEndpointPatch,
    responses(
        (status = 200, description = "The updated endpoint", body = WebhookEndpointDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid name, events, or a URL refused by the outbound policy", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_webhook(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
    AdminJson(body): AdminJson<WebhookEndpointPatch>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let endpoint = state
        .webhook_service()
        .update(
            tenant.id,
            endpoint_id(&id)?,
            WebhookEndpointUpdate {
                name: body.name,
                url: body.url,
                events: body.events.map(events),
                enabled: body.enabled,
            },
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &WebhookEndpointDto::from(endpoint)))
}

/// Delete a webhook endpoint and its delivery log.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}",
    tag = "webhooks",
    operation_id = "deleteWebhook",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_webhook(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    state
        .webhook_service()
        .delete(tenant.id, endpoint_id(&id)?, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Rotate the signing secret. The new secret is returned once; the previous one keeps signing
/// (as a second signature) for 24 hours.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}/secret",
    tag = "webhooks",
    operation_id = "rotateWebhookSecret",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
    ),
    responses(
        (status = 200, description = "The new secret, shown only in this response", body = WebhookEndpointWithSecret),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn rotate_webhook_secret(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let rotated = state
        .webhook_service()
        .rotate_secret(tenant.id, endpoint_id(&id)?, auth.actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &WebhookEndpointWithSecret::from(rotated),
    ))
}

/// Queue the `test` event for the endpoint, whatever its subscriptions.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}/test",
    tag = "webhooks",
    operation_id = "sendWebhookTest",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
    ),
    responses(
        (status = 202, description = "Queued; follow it in the delivery log", body = WebhookDeliveryDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn send_webhook_test(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let delivery = state
        .webhook_service()
        .send_test(tenant.id, endpoint_id(&id)?, auth.actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::ACCEPTED,
        &WebhookDeliveryDto::from(delivery),
    ))
}

// ---------------------------------------------------------------------------------------------
// Delivery log
// ---------------------------------------------------------------------------------------------

/// The delivery log of an endpoint, newest first.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/webhooks/{id}/deliveries",
    tag = "webhooks",
    operation_id = "listWebhookDeliveries",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Endpoint id"),
        ListQuery,
    ),
    responses(
        (status = 200, description = "One page of deliveries, newest first", body = WebhookDeliveryList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or endpoint", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_webhook_deliveries(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let page = state
        .webhook_service()
        .deliveries(tenant.id, endpoint_id(&id)?, page_request(q)?)
        .await?;
    Ok(json(
        StatusCode::OK,
        &WebhookDeliveryList {
            items: page.items.into_iter().map(Into::into).collect(),
            next_cursor: page.next_cursor,
        },
    ))
}

/// Queue a delivery's event again (new delivery id, fresh attempts). The original delivery is
/// unchanged.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/webhooks/deliveries/{delivery_id}/redeliver",
    tag = "webhooks",
    operation_id = "redeliverWebhookDelivery",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("delivery_id" = uuid::Uuid, Path, description = "Delivery id"),
    ),
    responses(
        (status = 202, description = "The new delivery", body = WebhookDeliveryDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or delivery", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn redeliver_webhook_delivery(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, delivery_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let delivery = state
        .webhook_service()
        .redeliver(
            tenant.id,
            WebhookDeliveryId(uuid(&delivery_id)?),
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(
        StatusCode::ACCEPTED,
        &WebhookDeliveryDto::from(delivery),
    ))
}
