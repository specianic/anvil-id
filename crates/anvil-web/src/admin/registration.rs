//! Initial access tokens for dynamic client registration (RFC 7591 §3, OIDC-17):
//!
//! - `GET|POST …/tenants/{slug}/initial-access-tokens`: list (values never shown) and issue (the
//!   value is returned **once**);
//! - `DELETE …/initial-access-tokens/{id}`: revoke.
//!
//! The registration and Client ID Metadata Document policies themselves are tenant settings
//! (`settings.dcr`, `settings.cimd` on `PATCH /tenants/{slug}`), always `disabled` for the system
//! tenant. Dynamic and CIMD clients appear in the client list with their `registration_source`
//! and are deleted like any client.
//!
//! Scopes: `admin:clients:write` issues and revokes, `admin:clients:read` lists (or `admin:write`
//! / `admin:read`). Tokens are stored hashed, always expire (default 24 hours, 1 minute to 365
//! days), may be limited to 1-100000 uses, and are never issued for the system tenant. Issuing
//! and revoking are audited by `RegistrationService` (`initial_access_token_created`,
//! `initial_access_token_revoked`, target = the token id).

use anvil_core::error::CoreError;
use anvil_core::model::{InitialAccessToken, InitialAccessTokenId, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::registration::IatRequest;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::auth::{AdminAuth, AdminJson, AdminResult, json, no_content};
use super::dto::{Problem, ts};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(
            list_initial_access_tokens,
            create_initial_access_token
        ))
        .routes(routes!(revoke_initial_access_token))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// An initial access token (never its value).
#[derive(Debug, Serialize, ToSchema)]
pub struct InitialAccessTokenDto {
    pub id: Uuid,
    pub description: String,
    #[schema(format = DateTime)]
    pub expires_at: Option<String>,
    /// Remaining uses; `null` = unlimited until expiry or revocation.
    pub uses_remaining: Option<u32>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub revoked_at: Option<String>,
    /// `true` while the token can still authorize a registration (not revoked, not expired,
    /// uses left).
    pub usable: bool,
}

impl InitialAccessTokenDto {
    fn new(t: InitialAccessToken, now: OffsetDateTime) -> Self {
        let usable = t.revoked_at.is_none()
            && t.expires_at.is_none_or(|e| e > now)
            && t.uses_remaining != Some(0);
        Self {
            id: t.id.0,
            description: t.description,
            expires_at: t.expires_at.map(ts),
            uses_remaining: t.uses_remaining,
            created_at: ts(t.created_at),
            revoked_at: t.revoked_at.map(ts),
            usable,
        }
    }
}

/// Initial access tokens, in id (creation) order.
#[derive(Debug, Serialize, ToSchema)]
pub struct InitialAccessTokenList {
    pub items: Vec<InitialAccessTokenDto>,
}

/// An issued token with its value: returned once, by `POST`.
#[derive(Serialize, ToSchema)]
pub struct IssuedInitialAccessToken {
    pub token: InitialAccessTokenDto,
    /// The bearer value for `POST /register` (`Authorization: Bearer …`). Shown once; only its
    /// hash is stored.
    pub value: String,
}

impl std::fmt::Debug for IssuedInitialAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInitialAccessToken")
            .field("token", &self.token)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Body of `POST /tenants/{slug}/initial-access-tokens`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewInitialAccessToken {
    /// At most 200 characters, no control characters.
    #[serde(default)]
    pub description: String,
    /// Lifetime in seconds, 60 to 31536000 (365 days); default 86400 (24 hours).
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Number of registrations it authorizes, 1 to 100000; `null` = unlimited until expiry.
    #[serde(default)]
    pub uses: Option<u32>,
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
    auth.require(Resource::Clients, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

fn expires_in(secs: Option<u64>) -> AdminResult<Option<time::Duration>> {
    secs.map(|s| {
        i64::try_from(s).map(time::Duration::seconds).map_err(|_| {
            CoreError::Validation {
                field: "expires_in",
                message: "must be between one minute and 365 days".to_owned(),
            }
            .into()
        })
    })
    .transpose()
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------

/// List the initial access tokens of a tenant (values are never returned).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/initial-access-tokens",
    tag = "registration",
    operation_id = "listInitialAccessTokens",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every token of the tenant, including revoked and expired ones", body = InitialAccessTokenList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:read"]),
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_initial_access_tokens(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let now = state.clock().now();
    let items = state.registration_service().list_iats(tenant.id).await?;
    Ok(json(
        StatusCode::OK,
        &InitialAccessTokenList {
            items: items
                .into_iter()
                .map(|t| InitialAccessTokenDto::new(t, now))
                .collect(),
        },
    ))
}

/// Issue an initial access token. The value is returned once. Tokens can be issued under any
/// registration policy (to prepare a switch to `allow_listed`), never for the system tenant.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/initial-access-tokens",
    tag = "registration",
    operation_id = "createInitialAccessToken",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = NewInitialAccessToken,
    responses(
        (status = 201, description = "Issued; `value` is shown only in this response", body = IssuedInitialAccessToken),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid description, lifetime or use count, or the system tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_initial_access_token(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<NewInitialAccessToken>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let issued = state
        .registration_service()
        .issue_iat(
            &tenant,
            IatRequest {
                description: body.description,
                expires_in: expires_in(body.expires_in)?,
                uses: body.uses,
            },
            auth.actor(),
            &ctx,
        )
        .await?;
    let now = state.clock().now();
    Ok(json(
        StatusCode::CREATED,
        &IssuedInitialAccessToken {
            value: issued.value.expose_secret().to_owned(),
            token: InitialAccessTokenDto::new(issued.token, now),
        },
    ))
}

/// Revoke an initial access token. Clients it already registered are not affected.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/initial-access-tokens/{id}",
    tag = "registration",
    operation_id = "revokeInitialAccessToken",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Token id"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or token, or already revoked", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn revoke_initial_access_token(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let id = Uuid::parse_str(&id).map_err(|_| CoreError::NotFound)?;
    state
        .registration_service()
        .revoke_iat(tenant.id, InitialAccessTokenId(id), auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}
