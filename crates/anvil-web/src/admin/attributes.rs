//! Custom user attribute definitions of a tenant and the attribute values of its users (AUTH-14):
//!
//! - `GET …/tenants/{slug}/attributes`: every definition (position, then name);
//! - `GET|PUT|DELETE …/attributes/{name}`: view, create or replace, delete a definition;
//! - `GET|PUT …/users/{user_id}/attributes`: a user's values (`PUT` replaces every defined value).
//!
//! Scopes: definitions use `admin:settings:{read,write}`, user values `admin:users:{read,write}`
//! (or `admin:read` / `admin:write`). Validation is `AttributeService`'s: a definition's schema is
//! meta-validated offline (16 KiB / depth 32, no remote `$ref`, reserved claim names refused,
//! claim rule collision-checked); values are validated per definition, and a refusal is a 422
//! problem whose `errors` name each failing JSON pointer (`/department`, `/tags/0`), never the
//! value. Deleting a definition or narrowing its schema never rewrites stored values: a value that
//! no longer validates is left out of tokens until it is corrected.
//!
//! A definition or user of another tenant is a 404. Every change is audited by
//! `AttributeService` in the tenant (`attribute_defined`, `attribute_deleted`,
//! `user_attributes_updated` with the number of changed attributes, never values).

use anvil_core::error::CoreError;
use anvil_core::model::{AttributeDefinition, Tenant, UserId};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::attribute::{AttributeError, AttributeService, WriteMode};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::auth::{AdminAuth, AdminJson, AdminResult, json, no_content};
use super::dto::Problem;
use super::tenants::TokenClaimRule;
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_attributes))
        .routes(routes!(get_attribute, put_attribute, delete_attribute))
        .routes(routes!(get_user_attributes, put_user_attributes))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// A custom attribute definition.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttributeDefinitionDto {
    /// Unique in the tenant: `^[a-z][a-z0-9_]{0,63}$`, not a protocol or standard claim name.
    pub name: String,
    /// JSON Schema (draft 2020-12) every value must satisfy.
    #[schema(value_type = Object)]
    pub schema: Value,
    /// Every user must have a value (checked when a user's values are written).
    pub required: bool,
    /// The user may edit the value on the account page.
    pub user_editable: bool,
    /// How the value is mapped into tokens; `null` = not emitted. A value is emitted only while
    /// it validates against the current schema.
    pub claim: Option<TokenClaimRule>,
    /// Display order (ascending).
    pub position: u32,
}

impl From<AttributeDefinition> for AttributeDefinitionDto {
    fn from(d: AttributeDefinition) -> Self {
        Self {
            name: d.name,
            schema: d.schema,
            required: d.required,
            user_editable: d.user_editable,
            claim: d.claim.map(Into::into),
            position: d.position,
        }
    }
}

/// Attribute definitions, by position then name.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttributeDefinitionList {
    pub items: Vec<AttributeDefinitionDto>,
}

/// Body of `PUT /tenants/{slug}/attributes/{name}` (create or replace; the name is the path's).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutAttributeDefinition {
    /// JSON Schema (draft 2020-12): at most 16 KiB and depth 32, local `#/$defs` references only.
    #[schema(value_type = Object)]
    pub schema: Value,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub user_editable: bool,
    /// Claim name, tokens and gating scope; the name must not collide with protocol, standard or
    /// other mapped claims.
    #[serde(default)]
    pub claim: Option<TokenClaimRule>,
    #[serde(default)]
    pub position: u32,
}

/// A user's attribute values. Keys without a current definition (left by a deleted definition)
/// are kept and shown.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserAttributes {
    pub user_id: Uuid,
    #[schema(value_type = Object)]
    pub values: Map<String, Value>,
}

/// Body of `PUT /tenants/{slug}/users/{user_id}/attributes`: the complete set of defined values
/// (an absent defined attribute is removed; unknown keys are refused).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutUserAttributes {
    #[schema(value_type = Object)]
    pub values: Map<String, Value>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

impl AppState {
    fn admin_attributes(&self) -> AdminResult<AttributeService> {
        Ok(self.attribute_service()?)
    }
}

async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    resource: Resource,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(resource, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// A user id from the path; anything that is not a UUID cannot name a user (404).
fn user_id(raw: &str) -> AdminResult<UserId> {
    Uuid::parse_str(raw)
        .map(UserId)
        .map_err(|_| CoreError::NotFound.into())
}

/// The 422 problem of refused values: one field error per failing JSON pointer (no values).
fn invalid_values(pointers: &[String]) -> Response {
    let errors: Vec<Value> = pointers
        .iter()
        .map(|p| json!({"field": p, "message": "does not satisfy the attribute schema"}))
        .collect();
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    let body = json!({
        "type": "urn:anvilid:problem:invalid_request",
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "detail": format!("{} attribute value(s) are invalid", pointers.len()),
        "errors": errors,
    });
    let mut resp = (status, body.to_string()).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ---------------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------------

/// List the attribute definitions of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/attributes",
    tag = "attributes",
    operation_id = "listAttributes",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every definition, by position then name", body = AttributeDefinitionList),
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
pub(crate) async fn list_attributes(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Settings, &slug, Access::Read).await?;
    let items = state.admin_attributes()?.list(tenant.id).await?;
    Ok(json(
        StatusCode::OK,
        &AttributeDefinitionList {
            items: items.into_iter().map(Into::into).collect(),
        },
    ))
}

/// Get an attribute definition.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/attributes/{name}",
    tag = "attributes",
    operation_id = "getAttribute",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Attribute name"),
    ),
    responses(
        (status = 200, description = "The definition", body = AttributeDefinitionDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or attribute", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_attribute(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, name)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Settings, &slug, Access::Read).await?;
    let def = state.admin_attributes()?.get(tenant.id, &name).await?;
    Ok(json(StatusCode::OK, &AttributeDefinitionDto::from(def)))
}

/// Create or replace an attribute definition. Stored user values are never rewritten: a value
/// that no longer validates is omitted from tokens until it is corrected.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/attributes/{name}",
    tag = "attributes",
    operation_id = "putAttribute",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Attribute name"),
    ),
    request_body = PutAttributeDefinition,
    responses(
        (status = 200, description = "The stored definition", body = AttributeDefinitionDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid name, schema or claim rule (the field error names it)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_attribute(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, name)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutAttributeDefinition>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Settings, &slug, Access::Write).await?;
    let def = AttributeDefinition {
        name,
        schema: body.schema,
        required: body.required,
        user_editable: body.user_editable,
        claim: body.claim.map(Into::into),
        position: body.position,
    };
    let stored = state
        .admin_attributes()?
        .define(tenant.id, auth.actor(), &def, &ctx)
        .await?;
    Ok(json(StatusCode::OK, &AttributeDefinitionDto::from(stored)))
}

/// Delete an attribute definition. Users' stored values are kept (a re-created definition sees
/// them again) but no longer reach tokens.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/attributes/{name}",
    tag = "attributes",
    operation_id = "deleteAttribute",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("name" = String, Path, description = "Attribute name"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or attribute", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_attribute(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, name)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Settings, &slug, Access::Write).await?;
    state
        .admin_attributes()?
        .delete(tenant.id, auth.actor(), &name, &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// User values
// ---------------------------------------------------------------------------------------------

/// Get a user's attribute values.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/attributes",
    tag = "attributes",
    operation_id = "getUserAttributes",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "The stored values", body = UserAttributes),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:read"]),
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_user_attributes(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Users, &slug, Access::Read).await?;
    let user = user_id(&id)?;
    let values = state
        .admin_attributes()?
        .user_values(tenant.id, user)
        .await?;
    Ok(json(
        StatusCode::OK,
        &UserAttributes {
            user_id: user.0,
            values,
        },
    ))
}

/// Replace a user's attribute values. Every value is validated against its definition; a refusal
/// changes nothing and lists each failing JSON pointer.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/users/{user_id}/attributes",
    tag = "attributes",
    operation_id = "putUserAttributes",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    request_body = PutUserAttributes,
    responses(
        (status = 200, description = "The stored values", body = UserAttributes),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or user", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid values: `errors` lists each failing JSON pointer (`/department`); nothing was stored", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_user_attributes(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutUserAttributes>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, Resource::Users, &slug, Access::Write).await?;
    let user = user_id(&id)?;
    let result = state
        .admin_attributes()?
        .set_user_values(
            tenant.id,
            auth.actor(),
            user,
            &body.values,
            WriteMode::Replace,
            &ctx,
        )
        .await;
    match result {
        Ok(values) => Ok(json(
            StatusCode::OK,
            &UserAttributes {
                user_id: user.0,
                values,
            },
        )),
        Err(AttributeError::Invalid(pointers)) => Ok(invalid_values(&pointers)),
        // Replace mode never checks editability or a settings flow; both would be bugs.
        Err(AttributeError::NotEditable(_) | AttributeError::FlowExpired) => Err(
            CoreError::Internal("unexpected self-service refusal in an admin write".into()).into(),
        ),
        Err(AttributeError::Core(e)) => Err(e.into()),
    }
}
