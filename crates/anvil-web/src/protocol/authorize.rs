//! Authorization endpoint (`GET`/`POST {issuer}/authorize`, OIDC Core §3.1.2) and the
//! continuation after login (`GET {issuer}/authorize/continue?request={id}`).
//!
//! The handlers only translate HTTP into [`AuthorizeService`] calls and outcomes into responses:
//! - `Redirect` → `303 See Other` to the client's redirect URI (success and error, always with `iss`);
//! - `Login` → `303` to `{issuer}/ui/login?request={id}`;
//! - `ErrorPage` → the themed `400` error page, never a redirect (unknown client, unregistered
//!   redirect URI, malformed request before the redirect URI is trusted, expired request).
//!
//! No CORS here, and no browser CSRF layer either: an authorization request is a cross-site
//! front-channel request by design.

use anvil_core::error::CoreError;
use anvil_core::model::{AuthRequestId, BrowserSession};
use anvil_core::oauth::authorize_request::{RawParams, parse_raw};
use anvil_core::service::authorize::{AuthorizeOutcome, AuthorizeService};
use anvil_core::service::session::SessionService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use crate::errors::{core_error_page, error_page};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The authorization endpoint service over this state's storage and clock.
    pub(crate) fn authorize_service(&self) -> AuthorizeService {
        AuthorizeService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }

    /// Session lookup for the authorization endpoint.
    pub(crate) fn authorize_session_service(&self) -> SessionService {
        SessionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The active browser session of this tenant, from its session cookie.
async fn current_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<BrowserSession>, CoreError> {
    let name = state.cookies().session_name(&tenant.tenant);
    let token = jar.get(&name).map(|c| c.value());
    state
        .authorize_session_service()
        .current(tenant.tenant.id, token)
        .await
}

fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (StatusCode::SEE_OTHER, [(header::LOCATION, v)]).into_response(),
        Err(_) => {
            // Redirect URIs are validated at registration and built with percent-encoding, so a
            // header-invalid location is a server bug, not client input.
            tracing::error!("authorization redirect is not a valid header value");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

fn respond(state: &AppState, tenant: &ResolvedTenant, outcome: AuthorizeOutcome) -> Response {
    match outcome {
        AuthorizeOutcome::Redirect(location) => see_other(&location),
        AuthorizeOutcome::Login { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/login?request={request_id}")))
        }
        AuthorizeOutcome::ErrorPage { error_key, detail } => error_page(
            state,
            Some(tenant),
            StatusCode::BAD_REQUEST,
            error_key,
            &detail,
        ),
    }
}

async fn authorize(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
    raw: RawParams,
) -> Response {
    let result = async {
        let session = current_session(state, tenant, jar).await?;
        state
            .authorize_service()
            .authorize(&tenant.tenant, &tenant.issuer, raw, session)
            .await
    }
    .await;
    match result {
        Ok(outcome) => respond(state, tenant, outcome),
        Err(e) => core_error_page(state, Some(tenant), &e),
    }
}

async fn authorize_get(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    RawQuery(query): RawQuery,
) -> Response {
    let raw = parse_raw(query.unwrap_or_default().as_bytes());
    authorize(&state, &tenant, &jar, raw).await
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

async fn authorize_post(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return error_page(
            &state,
            Some(&tenant),
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the authorization request must be sent as application/x-www-form-urlencoded",
        );
    }
    authorize(&state, &tenant, &jar, parse_raw(&body)).await
}

fn flow_expired(state: &AppState, tenant: &ResolvedTenant) -> Response {
    error_page(
        state,
        Some(tenant),
        StatusCode::BAD_REQUEST,
        "flow_expired",
        "",
    )
}

async fn authorize_continue(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_raw(query.unwrap_or_default().as_bytes());
    let Some(request_id) = params
        .single("request")
        .and_then(|r| uuid::Uuid::parse_str(r).ok())
        .map(AuthRequestId)
    else {
        return flow_expired(&state, &tenant);
    };
    let result = async {
        let session = current_session(&state, &tenant, &jar).await?;
        state
            .authorize_service()
            .resume(&tenant.tenant, &tenant.issuer, request_id, session)
            .await
    }
    .await;
    match result {
        Ok(outcome) => respond(&state, &tenant, outcome),
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/authorize/continue", get(authorize_continue))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_content_type_detection() {
        let mut h = HeaderMap::new();
        assert!(!is_form(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        assert!(is_form(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_form(&h));
    }
}
