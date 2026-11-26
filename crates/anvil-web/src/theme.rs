//! Per-tenant theme stylesheet and logo (tenant-relative routes, UI-03).
//!
//! - `GET /theme/theme.css`: the tenant's generated stylesheet ([`BrandingService::effective`]),
//!   linked by every tenant page after `anvil.css`. With `?flow={id}` the flow's authorization
//!   request decides the client and, through its `organization` parameter (id or slug), the
//!   organization whose branding overrides the tenant's (client > org > tenant); an unknown,
//!   expired or other-tenant flow (or one without a request), and an unknown organization,
//!   silently fall back, so the route is no oracle for flow ids or organization names. With `?preview={token}` it serves the draft behind a preview
//!   token (404 for an unknown or expired token). `Content-Type: text/css`, `Cache-Control:
//!   no-cache` and a strong `ETag` (SHA-256 of the body, [`crate::http_cache`]); a matching
//!   `If-None-Match` answers 304.
//! - `GET /theme/logo/{sha256}`: a logo stored for this tenant, with its stored content type,
//!   `Cache-Control: public, max-age=31536000, immutable` (the URL is the content hash),
//!   `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`. Logos of
//!   other tenants answer 404.
//!
//! Neither route sets cookies or reads the session; both are plain GETs on the tenant's origin,
//! so pages keep `style-src 'self'; img-src 'self'`.

use anvil_core::error::CoreError;
use anvil_core::model::{AuthRequestId, FlowId, OrgId};
use anvil_core::service::branding::{BrandingService, EffectiveTheme};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::errors::{core_error_page, error_page};
use crate::http_cache::{if_none_match, strong_etag};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Theme routes, merged into the tenant-routed router next to protocol and UI routes.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/theme/theme.css", get(theme_css))
        .route("/theme/logo/{sha}", get(logo))
}

impl AppState {
    /// The branding service (theme routes, preview page and admin API).
    pub(crate) fn branding(&self) -> BrandingService {
        BrandingService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// Query of the stylesheet route. Raw strings: a malformed flow id falls back like an unknown
/// one instead of failing the request.
#[derive(Debug, Deserialize)]
struct ThemeQuery {
    flow: Option<String>,
    preview: Option<String>,
}

/// What a flow's authorization request decides about the page theme.
#[derive(Debug, Default)]
struct FlowScopes {
    client: Option<String>,
    org: Option<OrgId>,
}

/// The organization named by an authorization request's `organization` parameter: the
/// canonical id first, then the exact slug (the same rule as the active-org resolution). `None`
/// for an unknown name.
async fn requested_org(state: &AppState, tenant: &ResolvedTenant, raw: &str) -> Option<OrgId> {
    let orgs = state.storage().organizations();
    let found = match uuid::Uuid::parse_str(raw) {
        Ok(id) if id.hyphenated().to_string() == raw => orgs.get(tenant.tenant.id, OrgId(id)).await,
        _ => orgs.get_by_slug(tenant.tenant.id, raw).await,
    };
    match found {
        Ok(o) => o.map(|o| o.id),
        Err(e) => {
            tracing::warn!(error = %e, "theme: organization lookup failed; ignoring it");
            None
        }
    }
}

/// The client and the requested organization of an unexpired flow of this tenant through its
/// authorization request; empty for anything else.
async fn flow_scopes(state: &AppState, tenant: &ResolvedTenant, raw: &str) -> FlowScopes {
    let Some(id) = uuid::Uuid::parse_str(raw).ok().map(FlowId) else {
        return FlowScopes::default();
    };
    let now = state.clock().now();
    let flow = match state.storage().flows().get(tenant.tenant.id, id, now).await {
        Ok(Some(f)) => f,
        Ok(None) => return FlowScopes::default(),
        Err(e) => {
            tracing::warn!(error = %e, "theme: flow lookup failed; using the tenant theme");
            return FlowScopes::default();
        }
    };
    let Some(request): Option<AuthRequestId> = flow.auth_request_id else {
        return FlowScopes::default();
    };
    let request = match state
        .storage()
        .grants()
        .get_authorization_request(tenant.tenant.id, request, now)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return FlowScopes::default(),
        Err(e) => {
            tracing::warn!(error = %e, "theme: request lookup failed; using the tenant theme");
            return FlowScopes::default();
        }
    };
    let org = match request.params.organization.as_deref() {
        Some(name) => requested_org(state, tenant, name).await,
        None => None,
    };
    FlowScopes {
        client: Some(request.client_id),
        org,
    }
}

/// `200 text/css` (or 304) for a generated stylesheet.
pub(crate) fn css_response(headers: &HeaderMap, theme: &EffectiveTheme) -> Response {
    let etag = strong_etag(theme.css.css.as_bytes());
    let mut resp = if if_none_match(headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, theme.css.css.clone()).into_response()
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    resp
}

fn not_found(state: &AppState, tenant: &ResolvedTenant) -> Response {
    error_page(state, Some(tenant), StatusCode::NOT_FOUND, "not_found", "")
}

/// `GET /theme/theme.css[?flow={id}|?preview={token}]`.
async fn theme_css(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    Query(q): Query<ThemeQuery>,
) -> Response {
    let service = state.branding();
    let theme = if let Some(token) = q.preview.as_deref() {
        match service.draft_for_preview(tenant.tenant.id, token).await {
            Ok(Some(t)) => Ok(t),
            Ok(None) => return not_found(&state, &tenant),
            Err(e) => Err(e),
        }
    } else {
        let scopes = match q.flow.as_deref() {
            Some(raw) => flow_scopes(&state, &tenant, raw).await,
            None => FlowScopes::default(),
        };
        service
            .effective(tenant.tenant.id, scopes.client.as_deref(), scopes.org)
            .await
    };
    match theme {
        Ok(theme) => css_response(&headers, &theme),
        Err(e) => {
            tracing::error!(error = %e, "theme: building the stylesheet failed");
            core_error_page(&state, Some(&tenant), &e)
        }
    }
}

/// `GET /theme/logo/{sha256}`.
async fn logo(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    Path(sha): Path<String>,
) -> Response {
    let logo = match state.branding().logo(tenant.tenant.id, &sha).await {
        Ok(Some(l)) => l,
        Ok(None) => return not_found(&state, &tenant),
        Err(e) => return core_error_page(&state, Some(&tenant), &e),
    };
    // Only the types the upload accepts are ever served as images.
    let content_type = match logo.content_type.as_str() {
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "image/webp" => "image/webp",
        _ => {
            return core_error_page(
                &state,
                Some(&tenant),
                &CoreError::Internal("stored logo has an unexpected content type".into()),
            );
        }
    };
    let mut resp = (StatusCode::OK, logo.bytes).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'"),
    );
    resp
}
