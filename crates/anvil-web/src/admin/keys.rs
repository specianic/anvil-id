//! Signing keys API of a tenant (ADM-02, tag `keys`):
//!
//! - `GET …/tenants/{slug}/keys`: every key of the tenant (next, active and retired), newest
//!   first, with its lifecycle timestamps;
//! - `POST …/tenants/{slug}/keys/rotate` (`{"alg": "RS256", "immediate": false}`): on-demand
//!   rotation through [`KeyRotationService::rotate_now`], the same call as `anvilid keys rotate`,
//!   audited as `key_rotation_requested` with the admin client as actor. Answers the kid of the
//!   key that signs next.
//!
//! No response ever carries private key material: [`KeyView`] has no field for the sealed key or
//! the JWK. The public keys are published by the tenant's `/jwks`.
//!
//! Scope: `admin:settings:{read,write}` (or `admin:read` / `admin:write`). Rotating the system
//! tenant's keys needs `admin:write`: they sign the console's and the admin API's tokens.

use anvil_core::model::{SYSTEM_TENANT_SLUG, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::key_rotation::{KeyRotationService, RotationPolicy};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::auth::{AdminAuth, AdminJson, AdminResult, json};
use super::dto::{KeyList, KeyView, Problem, RotateKeyRequest, RotateKeyResponse};
use crate::state::AppState;

impl AppState {
    /// The rotation service for on-demand rotation. `rotate_now` does not consult the policy
    /// (it is only used by the scheduled job's plan), so the default timings are passed.
    fn admin_key_rotation(&self) -> KeyRotationService {
        KeyRotationService {
            storage: self.storage_arc(),
            kek: self.kek_arc(),
            clock: self.clock_arc(),
            policy: RotationPolicy::default(),
        }
    }
}

/// Checks the settings scope for `access` and resolves the tenant. Rotating the system tenant's
/// keys needs full administration.
async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Settings, access)?;
    if access == Access::Write && slug == SYSTEM_TENANT_SLUG {
        auth.require_full_admin()?;
    }
    Ok(state.admin_tenants().get(slug).await?)
}

/// List the signing keys of a tenant (never any private key material).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/keys",
    tag = "keys",
    operation_id = "listKeys",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every signing key of the tenant, newest first", body = KeyList),
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
pub(crate) async fn list_keys(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let mut keys = state
        .storage()
        .keys()
        .list(tenant.id)
        .await
        .map_err(anvil_core::error::CoreError::from)?;
    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
    let items = keys.into_iter().map(KeyView::from).collect();
    Ok(json(StatusCode::OK, &KeyList { items }))
}

/// Rotate a signing key of a tenant. Without `immediate`, a next key is published now and the
/// scheduled job activates it after the prepublish period (an existing next key is kept). With
/// `immediate` (key compromise), a new key signs at once and the old one leaves the JWKS, so
/// tokens it signed stop verifying.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/keys/rotate",
    tag = "keys",
    operation_id = "rotateKey",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = RotateKeyRequest,
    responses(
        (status = 200, description = "The kid of the key that signs next", body = RotateKeyResponse),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The active key changed during rotation; retry", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "The algorithm is not enabled for the tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn rotate_key(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<RotateKeyRequest>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let kid = state
        .admin_key_rotation()
        .rotate_now(&tenant, body.alg.into(), body.immediate, auth.actor())
        .await?;
    Ok(json(StatusCode::OK, &RotateKeyResponse { kid }))
}

/// The signing key routes.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_keys))
        .routes(routes!(rotate_key))
}
