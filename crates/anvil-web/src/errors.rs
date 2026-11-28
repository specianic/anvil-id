//! The single place where a [`CoreError`] becomes an HTTP response.
//!
//! - [`oauth_json`]: OAuth / RFC 6750 JSON errors for protocol endpoints.
//! - [`error_page_in`] / [`core_error_page_in`]: the themed HTML error page for browser-facing
//!   routes, always in the request's negotiated language and with a way forward.
//! - [`problem_json`]: RFC 9457 problem details for the management API.
//!
//! Status codes, error codes and client-safe descriptions come from [`CoreError::http_status`],
//! [`CoreError::oauth_error`] and [`CoreError::description`]; handlers never choose them.

use anvil_core::error::CoreError;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;

use crate::i18n::Locale;
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;
use crate::ui::nav::NavContext;

/// Errors raised while building or running the web application itself (not protocol errors).
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("template error: {0}")]
    Template(#[from] minijinja::Error),
    #[error("configuration error: {0}")]
    Config(String),
}

fn status_of(err: &CoreError) -> StatusCode {
    StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Logs server-side failures once, with their internal detail. Client-facing text stays generic.
fn log_if_internal(err: &CoreError) {
    if matches!(err, CoreError::Internal(_) | CoreError::Storage(_)) {
        tracing::error!(error = %err, "internal error");
    } else if matches!(err, CoreError::Overloaded) {
        tracing::warn!("request shed: overloaded");
    }
}

/// An OAuth JSON error response: `{"error", "error_description"}`, `Cache-Control: no-store`,
/// `WWW-Authenticate: Basic` for failed HTTP Basic client authentication (RFC 6749 §5.2) and
/// `WWW-Authenticate: Bearer error="…"` for RFC 6750 token errors.
pub fn oauth_json(err: &CoreError) -> Response {
    log_if_internal(err);
    let status = status_of(err);
    let body = json!({
        "error": err.oauth_error(),
        "error_description": err.description(),
    });
    let mut resp = (status, axum::Json(body)).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    match err {
        CoreError::InvalidClient {
            basic_auth_used: true,
            ..
        } => {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"anvilid\""),
            );
        }
        CoreError::InvalidToken(_) => {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        CoreError::InsufficientScope(_) => {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
            );
        }
        _ => {}
    }
    resp
}

/// An RFC 9457 `application/problem+json` response for the management API.
pub fn problem_json(err: &CoreError) -> Response {
    log_if_internal(err);
    let status = status_of(err);
    let errors = match err {
        CoreError::Validation { field, message } => {
            vec![json!({ "field": field, "message": message })]
        }
        _ => Vec::new(),
    };
    let body = json!({
        "type": format!("urn:anvilid:problem:{}", err.oauth_error()),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "detail": err.description(),
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

/// The themed HTML error page in the negotiated `locale` (callers negotiate it from the request:
/// [`crate::i18n::RequestLocale`], [`crate::i18n::locale_of`] or the authorization request's
/// `ui_locales`). `error_key` selects the fixed sentence (themes/default/README.md); `detail` is
/// optional technical text (empty = none), shown in development mode only. The way forward is the
/// signed-out one ([`NavContext::none`]); callers that know more use [`error_page_nav`]. The page
/// never redirects.
pub fn error_page_in(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    locale: &Locale,
    status: StatusCode,
    error_key: &str,
    detail: &str,
) -> Response {
    error_page_nav(
        state,
        tenant,
        locale,
        ErrorPage {
            status,
            error_key,
            detail,
        },
        &NavContext::none(),
        false,
    )
}

/// What an error page says: status, sentence key and optional (dev-only) detail.
#[derive(Debug, Clone, Copy)]
pub struct ErrorPage<'a> {
    pub status: StatusCode,
    pub error_key: &'a str,
    pub detail: &'a str,
}

/// The one renderer of `error.html`: friendly heading and explanation (errors_friendly.ftl), the
/// contract sentence of `error_key` unchanged, the status line, the technical `detail` only in
/// development mode, and a way forward for every key: from `nav` (an application's home or live
/// request) and `signed_in` on tenant pages, the installation's start page without a tenant.
pub(crate) fn error_page_nav(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    locale: &Locale,
    err: ErrorPage<'_>,
    nav: &NavContext,
    signed_in: bool,
) -> Response {
    let ErrorPage {
        status,
        error_key,
        detail,
    } = err;
    let page = match tenant {
        Some(t) => {
            let mut page = PageContext::for_tenant(state, t, locale, "title.error");
            page.links = nav
                .error_way_forward(state, t, locale, signed_in)
                .into_links();
            page
        }
        None => {
            let mut page = PageContext::installation(state, locale, "title.error");
            page.links.home = Some(format!(
                "{}/",
                state.config().public_url.as_str().trim_end_matches('/')
            ));
            page
        }
    };
    let dev = state.config().dev_mode();
    if !detail.is_empty() && !dev {
        tracing::debug!(
            error_key,
            detail,
            "error page detail (shown in development mode only)"
        );
    }
    let ctx = minijinja::context! {
        page => page.into_value(),
        status => status.as_u16(),
        error_key => error_key,
        heading => minijinja::Value::from(()),
        detail => (dev && !detail.is_empty()).then_some(detail),
    };
    match state.renderer().page("error.html", ctx) {
        Ok(html) => (status, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the error page failed");
            (
                status,
                Html("<!DOCTYPE html><title>Error</title><p>Something went wrong.</p>"),
            )
                .into_response()
        }
    }
}

/// [`error_page_nav`] for a handler holding the request's cookies: the way forward is the signed-in
/// one (account, sign-out) when the tenant's session cookie names an active session.
pub(crate) async fn error_page_for(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    locale: &Locale,
    jar: &CookieJar,
    err: ErrorPage<'_>,
) -> Response {
    let signed_in = match tenant {
        Some(t) => is_signed_in(state, t, jar).await,
        None => false,
    };
    error_page_nav(state, tenant, locale, err, &NavContext::none(), signed_in)
}

/// `true` if the tenant's session cookie in `jar` names an active session. A lookup failure is
/// "signed out" (the page only chooses links from it).
pub(crate) async fn is_signed_in(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> bool {
    let name = state.cookies().session_name(&tenant.tenant);
    let Some(token) = jar.get(&name).map(|c| c.value().to_owned()) else {
        return false;
    };
    match state
        .authorize_session_service()
        .current(tenant.tenant.id, Some(&token))
        .await
    {
        Ok(session) => session.is_some(),
        Err(e) => {
            tracing::warn!(error = %e, "session lookup for the page links failed");
            false
        }
    }
}

/// The error page key of a domain failure.
fn error_key(err: &CoreError) -> &'static str {
    match err {
        CoreError::NotFound => "not_found",
        CoreError::InvalidRequest(_)
        | CoreError::Validation { .. }
        | CoreError::InvalidTarget(_)
        | CoreError::InvalidClientMetadata(_)
        | CoreError::InvalidRedirectUri(_)
        | CoreError::InvalidSoftwareStatement => "invalid_request",
        // ClientMetadataUnavailable (503) and everything else: the generic sentence.
        _ => "server_error",
    }
}

/// The error page for a domain failure in the negotiated `locale`: the key is derived from the
/// error, the status from the single mapping.
pub fn core_error_page_in(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    locale: &Locale,
    err: &CoreError,
) -> Response {
    log_if_internal(err);
    error_page_in(state, tenant, locale, status_of(err), error_key(err), "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::ports::StorageError;
    use http_body_util::BodyExt;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn invalid_client_with_basic_gets_basic_challenge() {
        let resp = oauth_json(&CoreError::InvalidClient {
            reason: "bad secret".into(),
            basic_auth_used: true,
        });
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"anvilid\""
        );
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let body = body_json(resp).await;
        assert_eq!(body["error"], "invalid_client");
        assert_eq!(body["error_description"], "bad secret");
    }

    #[tokio::test]
    async fn invalid_client_without_basic_has_no_challenge() {
        let resp = oauth_json(&CoreError::InvalidClient {
            reason: "x".into(),
            basic_auth_used: false,
        });
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn bearer_errors() {
        let resp = oauth_json(&CoreError::InvalidToken("expired".into()));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );
        let resp = oauth_json(&CoreError::InsufficientScope("needs admin".into()));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"insufficient_scope\""
        );
    }

    #[tokio::test]
    async fn internal_errors_are_generic() {
        for err in [
            CoreError::Internal("db host 10.1.2.3".into()),
            CoreError::Storage(StorageError::Backend("password=hunter2".into())),
        ] {
            let resp = oauth_json(&err);
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
            let body = body_json(resp).await;
            assert_eq!(body["error"], "server_error");
            assert_eq!(body["error_description"], "internal server error");
        }
    }

    async fn raw(resp: Response) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
        let status = resp.status();
        let mut headers: Vec<(String, Vec<u8>)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        headers.sort();
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        (status, headers, body.to_vec())
    }

    #[tokio::test]
    async fn refresh_token_reuse_renders_exactly_like_invalid_grant() {
        let reuse = raw(oauth_json(&CoreError::RefreshTokenReuse)).await;
        let grant = raw(oauth_json(&CoreError::InvalidGrant(
            anvil_core::error::INVALID_GRANT_DESCRIPTION.to_owned(),
        )))
        .await;
        assert_eq!(reuse, grant, "the wire must not reveal reuse detection");
        assert_eq!(reuse.0, StatusCode::BAD_REQUEST);
        let reuse = raw(problem_json(&CoreError::RefreshTokenReuse)).await;
        let grant = raw(problem_json(&CoreError::InvalidGrant(
            anvil_core::error::INVALID_GRANT_DESCRIPTION.to_owned(),
        )))
        .await;
        assert_eq!(reuse, grant);
    }

    #[tokio::test]
    async fn phase5_errors_map_through_the_single_table() {
        let cases = [
            (
                CoreError::InvalidClientMetadata("bad".into()),
                400,
                "invalid_client_metadata",
            ),
            (
                CoreError::InvalidRedirectUri("bad".into()),
                400,
                "invalid_redirect_uri",
            ),
            (
                CoreError::InvalidSoftwareStatement,
                400,
                "invalid_software_statement",
            ),
            (
                CoreError::ClientMetadataUnavailable("connect refused".into()),
                503,
                "temporarily_unavailable",
            ),
        ];
        for (err, status, code) in cases {
            let resp = oauth_json(&err);
            assert_eq!(resp.status().as_u16(), status, "{err:?}");
            let body = body_json(resp).await;
            assert_eq!(body["error"], code, "{err:?}");
            assert!(
                !body["error_description"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("connect refused"),
                "{err:?}"
            );
        }
        let resp = problem_json(&CoreError::LastAdministrator);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            error_key(&CoreError::InvalidSoftwareStatement),
            "invalid_request"
        );
        assert_eq!(
            error_key(&CoreError::ClientMetadataUnavailable("x".into())),
            "server_error"
        );
    }

    #[tokio::test]
    async fn feature_disabled_maps_through_the_single_table() {
        let err = CoreError::FeatureDisabled("saml");
        let resp = problem_json(&err);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["type"], "urn:anvilid:problem:feature_disabled");
        assert_eq!(body["status"], 403);
        assert!(body["detail"].as_str().unwrap_or_default().contains("saml"));
        let resp = oauth_json(&err);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(resp).await["error"], "feature_disabled");
        assert_eq!(error_key(&err), "server_error");
    }

    #[tokio::test]
    async fn every_oauth_response_is_no_store() {
        for err in [
            CoreError::InvalidRequest("x".into()),
            CoreError::InvalidGrant("x".into()),
            CoreError::UnsupportedGrantType,
            CoreError::Overloaded,
        ] {
            let resp = oauth_json(&err);
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store", "{err:?}");
            assert_eq!(resp.status().as_u16(), err.http_status());
        }
    }

    #[tokio::test]
    async fn phase4_oauth_errors_map_through_the_single_table() {
        let resp = oauth_json(&CoreError::InvalidTarget("resource not allowed".into()));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "invalid_target");
        assert_eq!(body["error_description"], "resource not allowed");
        let resp = oauth_json(&CoreError::UnmetAuthenticationRequirements);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "unmet_authentication_requirements");
    }

    #[tokio::test]
    async fn problem_json_shape() {
        let resp = problem_json(&CoreError::Validation {
            field: "email",
            message: "must be an email address".into(),
        });
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], 422);
        assert_eq!(body["type"], "urn:anvilid:problem:invalid_request");
        assert_eq!(body["errors"][0]["field"], "email");
        assert_eq!(body["errors"][0]["message"], "must be an email address");

        let body = body_json(problem_json(&CoreError::NotFound)).await;
        assert_eq!(body["status"], 404);
        assert_eq!(body["errors"], json!([]));
    }
}
