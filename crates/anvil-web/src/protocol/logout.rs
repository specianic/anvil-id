//! RP-initiated logout endpoint (`end_session_endpoint`, OIDC-12, OpenID Connect RP-Initiated
//! Logout 1.0).
//!
//! | Route | |
//! |---|---|
//! | `GET  {issuer}/logout?id_token_hint=&client_id=&post_logout_redirect_uri=&state=&ui_locales=` | end session |
//! | `POST {issuer}/logout` (form) | the same parameters as a form body |
//!
//! [`LogoutService::end_session`](anvil_core::service::logout::LogoutService::end_session)
//! decides:
//!
//! - log out now: the session and its token families are revoked (back-channel deliveries are
//!   enqueued in the same transaction), the session cookie is cleared, the delivery worker is
//!   woken, and the browser goes to the post-logout redirect (exactly `state` added, nothing
//!   else) or sees the signed-out page;
//! - ask: 303 to the confirmation page `/ui/logout` (`ui::logout`);
//! - refuse: a 400 error page with the contract sentence. It never redirects and changes nothing.
//!
//! A parameter sent twice and a POST body that is not a form are the `invalid_request` page.
//! This endpoint is not behind the Fetch-Metadata layer: relying parties post to it cross-site.
//! It changes nothing without a verified `id_token_hint` for the current session; everything
//! else needs the CSRF-protected confirmation. Every response is `Cache-Control: no-store`.

use anvil_core::model::RequestContext;
use anvil_core::service::logout::{LogoutOutcome, RawEndSession};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, LocaleInputs, negotiate};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Logout protocol routes (tenant-relative paths).
pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/logout", get(end_session_get).post(end_session_post))
}

/// The page language: the request's `ui_locales` (query or form), then `Accept-Language`, then
/// the tenant default.
fn page_locale(
    state: &AppState,
    tenant: &ResolvedTenant,
    headers: &HeaderMap,
    ui_locales: Option<&str>,
) -> Locale {
    negotiate(
        state.renderer().catalogs(),
        &LocaleInputs {
            ui_locales: ui_locales.filter(|u| !u.is_empty()),
            user_locale: None,
            accept_language: headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok()),
            tenant_default: &tenant.tenant.settings.default_locale,
        },
    )
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    resp
}

fn invalid_request(state: &AppState, tenant: &ResolvedTenant, headers: &HeaderMap) -> Response {
    let loc = page_locale(state, tenant, headers, None);
    no_store(error_page_in(
        state,
        Some(tenant),
        &loc,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "",
    ))
}

/// Decodes `application/x-www-form-urlencoded` pairs into the end-session parameters.
fn parse(bytes: &[u8]) -> Option<RawEndSession> {
    RawEndSession::from_pairs(url::form_urlencoded::parse(bytes).map(|(k, v)| (k, v.into_owned())))
        .ok()
}

async fn end_session_get(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    uri: Uri,
) -> Response {
    let Some(raw) = parse(uri.query().unwrap_or("").as_bytes()) else {
        return invalid_request(&state, &tenant, &headers);
    };
    end_session(&state, &tenant, &headers, &jar, &ctx, &raw).await
}

async fn end_session_post(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    body: Bytes,
) -> Response {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return invalid_request(&state, &tenant, &headers);
    }
    let Some(raw) = parse(&body) else {
        return invalid_request(&state, &tenant, &headers);
    };
    end_session(&state, &tenant, &headers, &jar, &ctx, &raw).await
}

async fn end_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    headers: &HeaderMap,
    jar: &CookieJar,
    ctx: &RequestContext,
    raw: &RawEndSession,
) -> Response {
    let loc = page_locale(state, tenant, headers, raw.ui_locales.as_deref());
    let session = match state.logout_current_session(tenant, jar).await {
        Ok(s) => s,
        Err(e) => return no_store(core_error_page_in(state, Some(tenant), &loc, &e)),
    };
    match state
        .ui_logout_service()
        .end_session(&tenant.tenant, &tenant.issuer, raw, session.as_ref(), ctx)
        .await
    {
        Ok(LogoutOutcome::LoggedOut { redirect, revoked }) => {
            state.logout_finished(tenant, &loc, CookieJar::new(), redirect, revoked, false)
        }
        Ok(LogoutOutcome::Confirm {
            client_id,
            redirect,
        }) => state.logout_confirm_redirect(tenant, &loc, client_id.as_deref(), redirect.as_ref()),
        Ok(LogoutOutcome::Error(e)) => state.logout_error_page(tenant, &loc, e),
        Err(e) => no_store(core_error_page_in(state, Some(tenant), &loc, &e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_repeated_parameters_and_decodes_values() {
        assert!(parse(b"state=a&state=b").is_none());
        assert!(parse(b"id_token_hint=a&id_token_hint=").is_none());
        let raw =
            parse(b"state=a%20b&post_logout_redirect_uri=https%3A%2F%2Frp%2Fx%3Fy%3D1&x=1&x=2")
                .expect("valid");
        assert_eq!(raw.state.as_deref(), Some("a b"));
        assert_eq!(
            raw.post_logout_redirect_uri.as_deref(),
            Some("https://rp/x?y=1")
        );
    }
}
