//! Token endpoint (RFC 6749 §3.2, OIDC Core §3.1.3): `POST /token`.
//!
//! The handler only translates HTTP into a [`TokenRequest`]; every grant, client-authentication
//! and token rule lives in [`TokenService`]. Errors go through the single
//! [`errors::oauth_json`](crate::errors::oauth_json) mapping, which adds
//! `WWW-Authenticate: Basic` when HTTP Basic client authentication failed.

use std::collections::HashMap;

use anvil_core::error::CoreError;
use anvil_core::service::client_auth::ClientAuthInput;
use anvil_core::service::token::{TokenRequest, TokenService};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::errors::oauth_json;
use crate::layers::cors::public_cors;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The token endpoint service on this state's ports.
    pub(crate) fn token_service(&self) -> TokenService {
        TokenService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/token", post(token))
        .layer(public_cors())
}

/// Whether the request carries an `application/x-www-form-urlencoded` body (parameters such as
/// `charset` are allowed).
pub(crate) fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// Parses a form body. A repeated parameter is `invalid_request` (RFC 6749 §3.2: request
/// parameters must not be included more than once). Parameters without a value are treated as
/// omitted (RFC 6749 §3.1).
pub(crate) fn parse_form(body: &[u8]) -> Result<HashMap<String, String>, CoreError> {
    let mut out = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for (k, v) in url::form_urlencoded::parse(body) {
        if !seen.insert(k.clone().into_owned()) {
            return Err(CoreError::InvalidRequest(format!(
                "parameter {k} is repeated"
            )));
        }
        if !v.is_empty() {
            out.insert(k.into_owned(), v.into_owned());
        }
    }
    Ok(out)
}

fn token_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, CoreError> {
    if !is_form(headers) {
        return Err(CoreError::InvalidRequest(
            "the token request must be application/x-www-form-urlencoded".to_owned(),
        ));
    }
    let mut form = parse_form(body)?;
    let basic = match headers.get(header::AUTHORIZATION) {
        None => None,
        Some(v) => Some(
            v.to_str()
                .map_err(|_| CoreError::InvalidClient {
                    reason: "invalid Basic authorization header".to_owned(),
                    basic_auth_used: true,
                })?
                .to_owned(),
        ),
    };
    Ok(TokenRequest {
        grant_type: form.remove("grant_type"),
        code: form.remove("code"),
        redirect_uri: form.remove("redirect_uri"),
        code_verifier: form.remove("code_verifier"),
        refresh_token: form.remove("refresh_token"),
        scope: form.remove("scope"),
        auth: ClientAuthInput {
            basic,
            client_id: form.remove("client_id"),
            client_secret: form.remove("client_secret"),
            client_assertion_type: form.remove("client_assertion_type"),
            client_assertion: form.remove("client_assertion"),
        },
    })
}

/// `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1).
pub(crate) fn no_store(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

async fn token(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match token_request(&headers, &body) {
        Ok(r) => r,
        Err(e) => return oauth_json(&e),
    };
    match state
        .token_service()
        .token(&tenant.tenant, &tenant.issuer, req)
        .await
    {
        Ok(resp) => no_store(axum::Json(resp).into_response()),
        Err(e) => oauth_json(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        h
    }

    #[test]
    fn repeated_parameters_are_invalid_request() {
        let err = parse_form(b"grant_type=a&code=x&code=y").expect_err("duplicate");
        assert_eq!(err.oauth_error(), "invalid_request");
        // Even when one of the copies is empty.
        assert!(parse_form(b"scope=&scope=openid").is_err());
    }

    #[test]
    fn empty_values_are_omitted() {
        let f = parse_form(b"grant_type=authorization_code&scope=").expect("form");
        assert_eq!(
            f.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert!(!f.contains_key("scope"));
    }

    #[test]
    fn only_form_bodies_are_accepted() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let err = token_request(&h, b"{}").expect_err("json body");
        assert_eq!(err.oauth_error(), "invalid_request");
        let err = token_request(&HeaderMap::new(), b"grant_type=x").expect_err("no type");
        assert_eq!(err.oauth_error(), "invalid_request");
        assert!(token_request(&form_headers(), b"grant_type=x").is_ok());
    }

    #[test]
    fn authorization_header_is_passed_raw() {
        let mut h = form_headers();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YTpi"),
        );
        let req = token_request(&h, b"grant_type=client_credentials&client_id=a").expect("req");
        assert_eq!(req.auth.basic.as_deref(), Some("Basic YTpi"));
        assert_eq!(req.auth.client_id.as_deref(), Some("a"));
    }
}
