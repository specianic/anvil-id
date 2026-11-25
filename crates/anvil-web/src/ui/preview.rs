//! Live theme preview for the console editor (UI-03).
//!
//! `GET /ui/preview?token={preview token}` renders `preview.html`: static sample sign-in and
//! consent markup (the classes of the real pages, nothing submittable) linked to the draft
//! stylesheet `{tenant_base}/theme/theme.css?preview={token}`. The console reaches it through the
//! path form `/t/{slug}/ui/preview?…` for every tenant, so it is always same-origin with the
//! console.
//!
//! This is the only page that may be framed, and only by the same origin: its CSP is the page
//! CSP with `frame-ancestors 'self'`, `X-Frame-Options: SAMEORIGIN`; `Cache-Control: no-store`.
//! An unknown, expired or other-tenant token answers the 404 page (with the default framing
//! policy).

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::RequestLocale;
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// CSP of the preview page: the page CSP, framable by the same origin.
pub(crate) const PREVIEW_CSP: &str =
    "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'self'; base-uri 'none'";

/// Theme preview routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/ui/preview", get(preview))
}

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    token: Option<String>,
}

async fn preview(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<PreviewQuery>,
) -> Response {
    let token = q.token.unwrap_or_default();
    match state
        .branding()
        .draft_for_preview(tenant.tenant.id, &token)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_page_in(
                &state,
                Some(&tenant),
                &loc,
                StatusCode::NOT_FOUND,
                "not_found",
                "",
            );
        }
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
    let mut page = PageContext::for_tenant(&state, &tenant, &loc, "title.preview");
    // The token has the base64url shape (checked by the lookup), so it is URL-safe as is.
    page.theme_css = Some(format!(
        "{}/theme/theme.css?preview={token}",
        tenant.base_path()
    ));
    let ctx = minijinja::context! { page => page.into_value() };
    let mut resp = match state.renderer().page("preview.html", ctx) {
        Ok(html) => (StatusCode::OK, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the theme preview failed");
            return core_error_page_in(
                &state,
                Some(&tenant),
                &loc,
                &anvil_core::error::CoreError::Internal("render".into()),
            );
        }
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PREVIEW_CSP),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
