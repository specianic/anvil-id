//! Admin API for branding: theme tokens, custom CSS, logo and preview drafts (UI-03).
//!
//! Per tenant (`…/tenants/{slug}/branding`) and per client
//! (`…/tenants/{slug}/clients/{client_id}/branding`):
//!
//! - `GET` the scope's branding (`customized: false` with empty tokens when it inherits);
//! - `PUT` tokens and custom CSS (validated; contrast warnings in the response), `DELETE` back to
//!   the inherited theme;
//! - `PUT …/branding/logo` with `{"data": "<standard base64>"}` (PNG, JPEG or WebP, at most
//!   256 KiB, identified by magic bytes; SVG refused), `DELETE …/branding/logo`;
//! - `POST …/branding/preview` with a draft (same body as `PUT`): stores the draft and returns
//!   `{token, preview_url, expires_at, warnings}`; `preview_url` is the same-origin path
//!   `/t/{slug}/ui/preview?token=…` (path form for every tenant, valid 15 minutes);
//! - `POST …/branding/publish` with `{"token": "…"}`: copies that draft live.
//!
//! Validation errors are 422 problems naming the field (`colors.primary`, `radius_px`,
//! `font_family`, `colors` / `colors_dark` for contrast, `custom_css` with `line N: …`, `logo`).
//!
//! Scope: `admin:settings:{read,write}` (or `admin:read` / `admin:write`); writes to the system
//! tenant (the console's sign-in pages) also need `admin:write`. Live changes are audited
//! (`branding_updated`) by the service.

use anvil_core::error::CoreError;
use anvil_core::model::{BrandingScope, SYSTEM_TENANT_SLUG, Tenant, ThemeColors, ThemeTokens};
use anvil_core::policy::branding::{ColorScheme, ContrastPair, ThemeWarning, validate_tokens};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::branding::{BrandingInput, PREVIEW_TTL};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use utoipa::ToSchema;

use super::auth::{AdminAuth, AdminJson, AdminResult, json, no_content};
use super::dto::Problem;
use crate::request_context::AuditContext;
use crate::state::AppState;

/// Largest accepted request body of the logo upload: 256 KiB of image as base64 plus the JSON
/// envelope. Every other route keeps [`crate::BODY_LIMIT`].
pub const LOGO_BODY_LIMIT: usize = 400 * 1024;

/// Whether a request path (before tenant resolution) is a logo upload of the admin API.
pub fn is_logo_upload(path: &str) -> bool {
    path.starts_with("/api/admin/v1/tenants/") && path.ends_with("/branding/logo")
}

/// Largest accepted request body of a tenant configuration document (plan and apply only): a
/// document with several email templates does not fit [`crate::BODY_LIMIT`].
pub const CONFIG_BODY_LIMIT: usize = 1024 * 1024;

/// Whether a request (before tenant resolution) posts a configuration document to the admin API:
/// `POST /api/admin/v1/tenants/{slug}/config/plan` or `.../config/apply`, one segment for the
/// slug. The query string is not part of the path, so `apply?prune=true` matches too.
pub fn is_config_document(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/admin/v1/tenants/") else {
        return false;
    };
    let mut parts = rest.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(slug), Some("config"), Some("plan" | "apply"), None) if !slug.is_empty()
    )
}

/// Request body limit layer of the whole application: [`crate::BODY_LIMIT`] for every request,
/// [`LOGO_BODY_LIMIT`] only for the logo upload and [`CONFIG_BODY_LIMIT`] only for configuration
/// plan/apply. Both the stream limit (`RequestBodyLimit`, 413 up front for a larger
/// `Content-Length`) and the extractor limit (`DefaultBodyLimit`) are set per request, so no
/// other route accepts more than before. The size check runs before admin authentication, as for
/// every route.
pub(crate) async fn body_limit(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use tower::{ServiceBuilder, ServiceExt as _};
    let path = req.uri().path();
    let limit = if is_logo_upload(path) {
        LOGO_BODY_LIMIT
    } else if is_config_document(req.method(), path) {
        CONFIG_BODY_LIMIT
    } else {
        crate::BODY_LIMIT
    };
    let svc = ServiceBuilder::new()
        .layer(axum::extract::DefaultBodyLimit::max(limit))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(limit))
        .map_request(|r: axum::http::Request<_>| r.map(axum::body::Body::new))
        .service(next);
    match svc.oneshot(req).await {
        Ok(resp) => resp.map(axum::body::Body::new),
        Err(never) => match never {},
    }
}

/// Theme colours (`#rgb`, `#rrggbb` or `#rrggbbaa`); absent or `null` = theme default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ThemeColorsDto {
    pub primary: Option<String>,
    /// Text on `primary` (buttons).
    pub primary_text: Option<String>,
    /// Page background.
    pub bg: Option<String>,
    /// Card / form background.
    pub surface: Option<String>,
    pub text: Option<String>,
    pub muted: Option<String>,
    pub border: Option<String>,
    pub focus: Option<String>,
    pub danger: Option<String>,
}

impl From<ThemeColorsDto> for ThemeColors {
    fn from(c: ThemeColorsDto) -> Self {
        Self {
            primary: c.primary,
            primary_text: c.primary_text,
            bg: c.bg,
            surface: c.surface,
            text: c.text,
            muted: c.muted,
            border: c.border,
            focus: c.focus,
            danger: c.danger,
        }
    }
}

impl From<ThemeColors> for ThemeColorsDto {
    fn from(c: ThemeColors) -> Self {
        Self {
            primary: c.primary,
            primary_text: c.primary_text,
            bg: c.bg,
            surface: c.surface,
            text: c.text,
            muted: c.muted,
            border: c.border,
            focus: c.focus,
            danger: c.danger,
        }
    }
}

/// Design tokens of a branding scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ThemeTokensDto {
    pub colors: ThemeColorsDto,
    /// Colours for `prefers-color-scheme: dark`; `null` = derived from the light set.
    pub colors_dark: Option<ThemeColorsDto>,
    /// System font stack (letters, digits, spaces, commas, hyphens, quotes; 1-200 characters).
    pub font_family: Option<String>,
    /// Corner radius in px (0-32).
    #[schema(minimum = 0, maximum = 32)]
    pub radius_px: Option<u8>,
}

impl From<ThemeTokensDto> for ThemeTokens {
    fn from(t: ThemeTokensDto) -> Self {
        Self {
            colors: t.colors.into(),
            colors_dark: t.colors_dark.map(Into::into),
            font_family: t.font_family,
            radius_px: t.radius_px,
        }
    }
}

impl From<ThemeTokens> for ThemeTokensDto {
    fn from(t: ThemeTokens) -> Self {
        Self {
            colors: t.colors.into(),
            colors_dark: t.colors_dark.map(Into::into),
            font_family: t.font_family,
            radius_px: t.radius_px,
        }
    }
}

/// A contrast between 3:1 and 4.5:1 (accepted, shown to the admin).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ThemeWarningDto {
    /// `light` or `dark`.
    pub scheme: String,
    /// `text_on_background`, `text_on_surface` or `primary_text`.
    pub pair: String,
    /// The contrast ratio (x:1).
    pub ratio: f64,
    pub message: String,
}

impl From<ThemeWarning> for ThemeWarningDto {
    fn from(w: ThemeWarning) -> Self {
        Self {
            scheme: match w.scheme {
                ColorScheme::Light => "light",
                ColorScheme::Dark => "dark",
            }
            .to_owned(),
            pair: match w.pair {
                ContrastPair::TextOnBackground => "text_on_background",
                ContrastPair::TextOnSurface => "text_on_surface",
                ContrastPair::PrimaryText => "primary_text",
            }
            .to_owned(),
            ratio: w.ratio,
            message: format!(
                "{} {} contrast is {:.2}:1, below the recommended 4.5:1",
                w.scheme, w.pair, w.ratio
            ),
        }
    }
}

fn warnings(ws: Vec<ThemeWarning>) -> Vec<ThemeWarningDto> {
    ws.into_iter().map(Into::into).collect()
}

/// Tokens and custom CSS (live `PUT` and preview drafts).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutBranding {
    #[serde(default)]
    pub tokens: ThemeTokensDto,
    /// Custom CSS (at most 32 KiB; no `@import`, `url(`, backslashes or other constructs outside
    /// the allow-list). Absent, `null` or blank = none.
    #[serde(default)]
    pub custom_css: Option<String>,
}

impl From<PutBranding> for BrandingInput {
    fn from(b: PutBranding) -> Self {
        Self {
            tokens: b.tokens.into(),
            custom_css: b.custom_css,
        }
    }
}

/// A logo upload.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutBrandingLogo {
    /// The image bytes in standard base64 (RFC 4648 §4, padded): PNG, JPEG or WebP, at most
    /// 256 KiB decoded.
    pub data: String,
}

/// Publishes a preview draft.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishBranding {
    /// The preview token returned by the preview operation of the same scope.
    pub token: String,
}

/// The branding of a scope.
#[derive(Debug, Serialize, ToSchema)]
pub struct BrandingView {
    /// `tenant` or `client`.
    pub scope: String,
    /// The client of a client scope.
    pub client_id: Option<String>,
    /// `false` when the scope has no branding of its own (it inherits; tokens are empty).
    pub customized: bool,
    pub tokens: ThemeTokensDto,
    pub custom_css: Option<String>,
    /// Same-origin path of the scope's own logo (`/t/{slug}/theme/logo/{sha256}`), if any.
    pub logo_url: Option<String>,
    pub updated_at: Option<String>,
    /// Contrast warnings of the stored tokens.
    pub warnings: Vec<ThemeWarningDto>,
}

/// A stored preview draft.
#[derive(Debug, Serialize, ToSchema)]
pub struct BrandingPreview {
    /// The preview token (also needed to publish this draft).
    pub token: String,
    /// Same-origin path of the preview page: `/t/{slug}/ui/preview?token=…`. Only this page
    /// may be framed, and only by the same origin.
    pub preview_url: String,
    /// RFC 3339; the token stops working after this (15 minutes).
    pub expires_at: String,
    pub warnings: Vec<ThemeWarningDto>,
}

/// Checks the settings scope and resolves the tenant; writes to the system tenant need full
/// administration.
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

fn view(
    tenant: &Tenant,
    scope: &BrandingScope,
    b: Option<anvil_core::model::Branding>,
    ws: Option<Vec<ThemeWarning>>,
) -> BrandingView {
    let (kind, client_id) = match scope {
        BrandingScope::Tenant => ("tenant", None),
        BrandingScope::Client(id) => ("client", Some(id.clone())),
    };
    match b {
        None => BrandingView {
            scope: kind.to_owned(),
            client_id,
            customized: false,
            tokens: ThemeTokensDto::default(),
            custom_css: None,
            logo_url: None,
            updated_at: None,
            warnings: Vec::new(),
        },
        Some(b) => {
            let ws = ws.unwrap_or_else(|| validate_tokens(&b.tokens).unwrap_or_default());
            BrandingView {
                scope: kind.to_owned(),
                client_id,
                customized: true,
                logo_url: b
                    .logo_sha256
                    .as_ref()
                    .map(|sha| format!("/t/{}/theme/logo/{sha}", tenant.slug)),
                updated_at: b.updated_at.format(&Rfc3339).ok(),
                tokens: b.tokens.into(),
                custom_css: b.custom_css,
                warnings: warnings(ws),
            }
        }
    }
}

async fn do_get(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    scope: BrandingScope,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Read).await?;
    let b = state.branding().get(tenant.id, &scope).await?;
    Ok(json(StatusCode::OK, &view(&tenant, &scope, b, None)))
}

async fn do_put(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    scope: BrandingScope,
    body: PutBranding,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    let (b, ws) = state
        .branding()
        .put(tenant.id, &scope, body.into(), auth.actor(), ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &view(&tenant, &scope, Some(b), Some(ws)),
    ))
}

async fn do_delete(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    scope: BrandingScope,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    state
        .branding()
        .delete(tenant.id, &scope, auth.actor(), ctx)
        .await?;
    Ok(no_content())
}

async fn do_put_logo(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    scope: BrandingScope,
    body: PutBrandingLogo,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    let bytes =
        anvil_jose::encoding::b64std_decode(&body.data).map_err(|_| CoreError::Validation {
            field: "data",
            message: "must be standard base64".to_owned(),
        })?;
    let b = state
        .branding()
        .set_logo(tenant.id, &scope, bytes, auth.actor(), ctx)
        .await?;
    Ok(json(StatusCode::OK, &view(&tenant, &scope, Some(b), None)))
}

async fn do_delete_logo(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    scope: BrandingScope,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    let b = state
        .branding()
        .clear_logo(tenant.id, &scope, auth.actor(), ctx)
        .await?;
    Ok(json(StatusCode::OK, &view(&tenant, &scope, Some(b), None)))
}

async fn do_preview(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    scope: BrandingScope,
    body: PutBranding,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    let p = state
        .branding()
        .put_draft(tenant.id, &scope, body.into())
        .await?;
    debug_assert_eq!(PREVIEW_TTL.whole_minutes(), 15);
    Ok(json(
        StatusCode::OK,
        &BrandingPreview {
            preview_url: format!("/t/{}/ui/preview?token={}", tenant.slug, p.token),
            token: p.token,
            expires_at: p.expires_at.format(&Rfc3339).unwrap_or_default(),
            warnings: warnings(p.warnings),
        },
    ))
}

async fn do_publish(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    scope: BrandingScope,
    body: PublishBranding,
) -> AdminResult<Response> {
    let tenant = authorize(state, auth, slug, Access::Write).await?;
    let (b, ws) = state
        .branding()
        .publish(tenant.id, &scope, &body.token, auth.actor(), ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &view(&tenant, &scope, Some(b), Some(ws)),
    ))
}

/// Get the tenant's branding (`customized: false` when it inherits).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/branding",
    tag = "branding",
    operation_id = "getTenantBranding",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The branding", body = BrandingView),
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
pub(crate) async fn get_tenant_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    do_get(&state, &auth, &slug, BrandingScope::Tenant).await
}

/// Set the tenant's theme tokens and custom CSS (the logo is kept). Contrast below 4.5:1 is returned as warnings, below 3:1 refused.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/branding",
    tag = "branding",
    operation_id = "putTenantBranding",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = PutBranding,
    responses(
        (status = 200, description = "The stored branding with contrast warnings", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_tenant_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<PutBranding>,
) -> AdminResult<Response> {
    do_put(&state, &auth, &ctx, &slug, BrandingScope::Tenant, body).await
}

/// Remove the tenant's branding (back to the inherited theme).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/branding",
    tag = "branding",
    operation_id = "deleteTenantBranding",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant (or no branding)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_tenant_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    do_delete(&state, &auth, &ctx, &slug, BrandingScope::Tenant).await
}

/// Set the tenant's logo (PNG, JPEG or WebP, at most 256 KiB, standard base64; SVG is refused).
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/branding/logo",
    tag = "branding",
    operation_id = "putTenantBrandingLogo",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = PutBrandingLogo,
    responses(
        (status = 200, description = "The branding with the new logo", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_tenant_branding_logo(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<PutBrandingLogo>,
) -> AdminResult<Response> {
    do_put_logo(&state, &auth, &ctx, &slug, BrandingScope::Tenant, body).await
}

/// Remove the tenant's logo.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/branding/logo",
    tag = "branding",
    operation_id = "deleteTenantBrandingLogo",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The branding without logo", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant (or no logo)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_tenant_branding_logo(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    do_delete_logo(&state, &auth, &ctx, &slug, BrandingScope::Tenant).await
}

/// Store a tenant's preview draft and get a 15-minute preview URL (same origin, `/t/{slug}/ui/preview?token=…`).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/branding/preview",
    tag = "branding",
    operation_id = "previewTenantBranding",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = PutBranding,
    responses(
        (status = 200, description = "The preview token and URL", body = BrandingPreview),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn preview_tenant_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<PutBranding>,
) -> AdminResult<Response> {
    do_preview(&state, &auth, &slug, BrandingScope::Tenant, body).await
}

/// Publish a tenant's preview draft (identified by its preview token) as the live branding.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/branding/publish",
    tag = "branding",
    operation_id = "publishTenantBranding",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = PublishBranding,
    responses(
        (status = 200, description = "The published branding", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant (or unknown, expired or other-scope preview token)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn publish_tenant_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<PublishBranding>,
) -> AdminResult<Response> {
    do_publish(&state, &auth, &ctx, &slug, BrandingScope::Tenant, body).await
}

/// Get the client's branding (`customized: false` when it inherits).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding",
    tag = "branding",
    operation_id = "getClientBranding",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    responses(
        (status = 200, description = "The branding", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_client_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    do_get(&state, &auth, &slug, BrandingScope::Client(client_id)).await
}

/// Set the client's theme tokens and custom CSS (the logo is kept). Contrast below 4.5:1 is returned as warnings, below 3:1 refused.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding",
    tag = "branding",
    operation_id = "putClientBranding",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    request_body = PutBranding,
    responses(
        (status = 200, description = "The stored branding with contrast warnings", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_client_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutBranding>,
) -> AdminResult<Response> {
    do_put(
        &state,
        &auth,
        &ctx,
        &slug,
        BrandingScope::Client(client_id),
        body,
    )
    .await
}

/// Remove the client's branding (back to the inherited theme).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding",
    tag = "branding",
    operation_id = "deleteClientBranding",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client (or no branding)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_client_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    do_delete(&state, &auth, &ctx, &slug, BrandingScope::Client(client_id)).await
}

/// Set the client's logo (PNG, JPEG or WebP, at most 256 KiB, standard base64; SVG is refused).
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/logo",
    tag = "branding",
    operation_id = "putClientBrandingLogo",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    request_body = PutBrandingLogo,
    responses(
        (status = 200, description = "The branding with the new logo", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_client_branding_logo(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutBrandingLogo>,
) -> AdminResult<Response> {
    do_put_logo(
        &state,
        &auth,
        &ctx,
        &slug,
        BrandingScope::Client(client_id),
        body,
    )
    .await
}

/// Remove the client's logo.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/logo",
    tag = "branding",
    operation_id = "deleteClientBrandingLogo",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    responses(
        (status = 200, description = "The branding without logo", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client (or no logo)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_client_branding_logo(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
) -> AdminResult<Response> {
    do_delete_logo(&state, &auth, &ctx, &slug, BrandingScope::Client(client_id)).await
}

/// Store a client's preview draft and get a 15-minute preview URL (same origin, `/t/{slug}/ui/preview?token=…`).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/preview",
    tag = "branding",
    operation_id = "previewClientBranding",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    request_body = PutBranding,
    responses(
        (status = 200, description = "The preview token and URL", body = BrandingPreview),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn preview_client_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, client_id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutBranding>,
) -> AdminResult<Response> {
    do_preview(&state, &auth, &slug, BrandingScope::Client(client_id), body).await
}

/// Publish a client's preview draft (identified by its preview token) as the live branding.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/clients/{client_id}/branding/publish",
    tag = "branding",
    operation_id = "publishClientBranding",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("client_id" = String, Path, description = "Client id"),
    ),
    request_body = PublishBranding,
    responses(
        (status = 200, description = "The published branding", body = BrandingView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or client (or unknown, expired or other-scope preview token)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn publish_client_branding(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, client_id)): Path<(String, String)>,
    AdminJson(body): AdminJson<PublishBranding>,
) -> AdminResult<Response> {
    do_publish(
        &state,
        &auth,
        &ctx,
        &slug,
        BrandingScope::Client(client_id),
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn config_document_paths() {
        for p in [
            "/api/admin/v1/tenants/default/config/plan",
            "/api/admin/v1/tenants/acme/config/apply",
        ] {
            assert!(is_config_document(&Method::POST, p), "{p}");
            for m in [Method::GET, Method::PUT, Method::PATCH, Method::DELETE] {
                assert!(!is_config_document(&m, p), "{m} {p}");
            }
        }
        for p in [
            "/api/admin/v1/tenants/default/config",
            "/api/admin/v1/tenants/default/config/export",
            "/api/admin/v1/tenants/default/config/plan/x",
            "/api/admin/v1/tenants//config/plan",
            "/api/admin/v1/tenants/a/b/config/plan",
            "/api/admin/v1/tenants/config-like/clients",
            "/api/admin/v1/tenants/config/plan",
            "/api/admin/v2/tenants/default/config/plan",
            "/t/default/api/admin/v1/tenants/default/config/plan",
        ] {
            assert!(!is_config_document(&Method::POST, p), "{p}");
        }
    }
}
