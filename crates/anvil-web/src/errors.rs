//! The single place where a [`CoreError`] becomes an HTTP response.
//!
//! - [`oauth_json`]: OAuth / RFC 6750 JSON errors for protocol endpoints.
//! - [`error_page`]: the themed HTML error page for browser-facing routes.
//! - [`problem_json`]: RFC 9457 problem details for the management API.
//!
//! Status codes, error codes and client-safe descriptions come from [`CoreError::http_status`],
//! [`CoreError::oauth_error`] and [`CoreError::description`]; handlers never choose them.

use anvil_core::error::CoreError;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde_json::json;

use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

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

/// The themed HTML error page. `error_key` selects the fixed sentence (themes/default/README.md);
/// `detail` is optional extra text (empty = none). The page never redirects.
pub fn error_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    status: StatusCode,
    error_key: &str,
    detail: &str,
) -> Response {
    let page = match tenant {
        Some(t) => PageContext::for_tenant(state, t, "Error"),
        None => PageContext::installation(state, "Error"),
    };
    let ctx = minijinja::context! {
        page => page.into_value(),
        status => status.as_u16(),
        error_key => error_key,
        heading => minijinja::Value::from(()),
        detail => (!detail.is_empty()).then_some(detail),
    };
    match state.renderer().page("error.html", ctx) {
        Ok(html) => (status, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the error page failed");
            (status, Html("<!DOCTYPE html><title>Error</title><p>Something went wrong.</p>"))
                .into_response()
        }
    }
}

/// The error page for a domain failure: the key is derived from the error, the status from the
/// single mapping.
pub fn core_error_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    err: &CoreError,
) -> Response {
    log_if_internal(err);
    let key = match err {
        CoreError::NotFound => "not_found",
        CoreError::InvalidRequest(_) | CoreError::Validation { .. } => "invalid_request",
        _ => "server_error",
    };
    error_page(state, tenant, status_of(err), key, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::ports::StorageError;
    use http_body_util::BodyExt;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
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
