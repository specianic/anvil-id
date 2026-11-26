//! `POST /par`: pushed authorization requests (RFC 9126, OIDC-18).
//!
//! The handler only translates HTTP into a [`ParService::push`] call. The body is
//! `application/x-www-form-urlencoded`; the client authenticates exactly as at `/token` (HTTP
//! Basic, `client_secret` / `client_assertion_type` / `client_assertion` in the body, or
//! `client_id` alone for public clients). The remaining parameters are the authorization request.
//!
//! - Success: `201 Created`, `{"request_uri": "urn:ietf:params:oauth:request_uri:…",
//!   "expires_in": 60}`, `Cache-Control: no-store`.
//! - Errors: the RFC 6749 §5.2 JSON shape through [`oauth_json`] (400, 401 for client
//!   authentication with `WWW-Authenticate: Basic` when Basic was used), never a redirect.
//!
//! Rate-limit class `Token` (07-04). No CORS and no Fetch-Metadata: the endpoint is
//! client-authenticated and called from the client's back end, like `/token`.

use anvil_core::error::CoreError;
use anvil_core::oauth::authorize_request::{RawParams, parse_raw};
use anvil_core::oauth::par::CLIENT_AUTH_PARAMETERS;
use anvil_core::service::client_auth::ClientAuthInput;
use anvil_core::service::par::ParService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::json;

use crate::errors::oauth_json;
use crate::protocol::token::{is_form, no_store};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The pushed authorization request service on this state's ports.
    pub(crate) fn par_service(&self) -> ParService {
        ParService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            metadata_fetcher: self.cimd_fetcher(),
        }
    }
}

/// The pushed authorization request route.
pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/par", post(par))
}

/// Splits a PAR body into the client credentials and the authorization request parameters.
/// A credential parameter sent more than once is `invalid_request`.
fn split_body(headers: &HeaderMap, body: &[u8]) -> Result<(ClientAuthInput, RawParams), CoreError> {
    let mut raw = parse_raw(body);
    let mut credential = |name: &str| -> Result<Option<String>, CoreError> {
        let mut values = Vec::new();
        raw.0.retain(|(k, v)| {
            if k == name {
                values.push(v.clone());
                false
            } else {
                true
            }
        });
        match values.as_slice() {
            [] => Ok(None),
            [v] => Ok(Some(v.clone()).filter(|v| !v.is_empty())),
            _ => Err(CoreError::InvalidRequest(format!(
                "parameter {name} is repeated"
            ))),
        }
    };
    let [secret, assertion_type, assertion] = CLIENT_AUTH_PARAMETERS;
    let client_secret = credential(secret)?;
    let client_assertion_type = credential(assertion_type)?;
    let client_assertion = credential(assertion)?;
    if raw.0.iter().filter(|(k, _)| k == "client_id").count() > 1 {
        return Err(CoreError::InvalidRequest(
            "parameter client_id is repeated".to_owned(),
        ));
    }
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
    let auth = ClientAuthInput {
        basic,
        client_id: raw.get("client_id").map(str::to_owned),
        client_secret,
        client_assertion_type,
        client_assertion,
    };
    Ok((auth, raw))
}

async fn par(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return oauth_json(&CoreError::InvalidRequest(
            "the pushed authorization request must be application/x-www-form-urlencoded".to_owned(),
        ));
    }
    let (auth, raw) = match split_body(&headers, &body) {
        Ok(v) => v,
        Err(e) => return oauth_json(&e),
    };
    match state
        .par_service()
        .push(&tenant.tenant, &tenant.issuer, &auth, raw)
        .await
    {
        Ok(pushed) => no_store(
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "request_uri": pushed.request_uri,
                    "expires_in": pushed.expires_in,
                })),
            )
                .into_response(),
        ),
        Err(e) => oauth_json(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn credentials_are_split_from_the_request_parameters() {
        let headers = HeaderMap::new();
        let (auth, raw) = split_body(
            &headers,
            b"client_id=rp&client_secret=s&response_type=code&resource=a&resource=b",
        )
        .expect("split");
        assert_eq!(auth.client_id.as_deref(), Some("rp"));
        assert_eq!(auth.client_secret.as_deref(), Some("s"));
        assert!(raw.get("client_secret").is_none());
        assert_eq!(raw.get("client_id"), Some("rp"));
        assert_eq!(raw.all("resource"), vec!["a", "b"]);
    }

    #[test]
    fn repeated_credentials_are_invalid_request() {
        let headers = HeaderMap::new();
        let err = split_body(&headers, b"client_id=rp&client_secret=a&client_secret=b")
            .expect_err("refused");
        assert_eq!(err.oauth_error(), "invalid_request");
        let err = split_body(&headers, b"client_id=rp&client_id=rp").expect_err("refused");
        assert_eq!(err.oauth_error(), "invalid_request");
    }

    #[test]
    fn basic_header_is_passed_through() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        let (auth, _) = split_body(&headers, b"response_type=code").expect("split");
        assert_eq!(auth.basic.as_deref(), Some("Basic abc"));
        assert_eq!(auth.client_id, None);
    }
}
