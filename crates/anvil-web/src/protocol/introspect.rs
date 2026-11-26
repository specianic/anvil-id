//! Token introspection endpoint (RFC 7662): `POST /introspect`.
//!
//! Follows the `/token` conventions: form body only, a repeated parameter is `invalid_request`,
//! an empty parameter counts as omitted, `Cache-Control: no-store` and `Pragma: no-cache` on
//! every answer. The caller authenticates with the single
//! [`ClientAuthenticator`]; every visibility and token rule lives in
//! [`IntrospectionService`].

use std::collections::HashMap;

use anvil_core::error::CoreError;
use anvil_core::model::{Client, Tenant};
use anvil_core::service::client_auth::{ClientAuthInput, ClientAuthenticator};
use anvil_core::service::introspect::IntrospectionService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::errors::oauth_json;
use crate::protocol::token::{is_form, no_store, parse_form};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The introspection service on this state's ports.
    pub(crate) fn introspection_service(&self) -> IntrospectionService {
        IntrospectionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            attribute_check: self.attribute_check(),
        }
    }

    /// The single client authenticator on this state's ports.
    pub(crate) fn client_authenticator(&self) -> ClientAuthenticator {
        ClientAuthenticator {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            metadata_fetcher: self.cimd_fetcher(),
        }
    }
}

/// The routes of this module (tenant-relative paths). POST only; other methods are 405.
pub fn routes() -> Router<AppState> {
    Router::new().route("/introspect", post(introspect))
}

/// A back-channel token-management request (`/introspect`, `/revoke`): the form parameters
/// other than client authentication, and the client authentication input.
pub(crate) struct ClientFormRequest {
    pub form: HashMap<String, String>,
    pub auth: ClientAuthInput,
}

impl ClientFormRequest {
    /// The required `token` parameter.
    pub fn token(&self) -> Result<&str, CoreError> {
        self.form
            .get("token")
            .map(String::as_str)
            .ok_or_else(|| CoreError::InvalidRequest("token is required".to_owned()))
    }

    pub fn hint(&self) -> Option<&str> {
        self.form.get("token_type_hint").map(String::as_str)
    }
}

/// Parses a form body with client authentication, like the token endpoint does. Pure.
pub(crate) fn client_form_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ClientFormRequest, CoreError> {
    if !is_form(headers) {
        return Err(CoreError::InvalidRequest(
            "the request must be application/x-www-form-urlencoded".to_owned(),
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
    let auth = ClientAuthInput {
        basic,
        client_id: form.remove("client_id"),
        client_secret: form.remove("client_secret"),
        client_assertion_type: form.remove("client_assertion_type"),
        client_assertion: form.remove("client_assertion"),
    };
    Ok(ClientFormRequest { form, auth })
}

/// Parses and authenticates a back-channel request.
pub(crate) async fn authenticated(
    state: &AppState,
    tenant: &Tenant,
    issuer: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(ClientFormRequest, Client), CoreError> {
    let req = client_form_request(headers, body)?;
    let client = state
        .client_authenticator()
        .authenticate(tenant, issuer, &req.auth)
        .await?;
    Ok((req, client))
}

async fn introspect(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        let (req, caller) =
            authenticated(&state, &tenant.tenant, &tenant.issuer, &headers, &body).await?;
        let token = req.token()?;
        state
            .introspection_service()
            .introspect(&tenant.tenant, &tenant.issuer, &caller, token, req.hint())
            .await
    }
    .await;
    match result {
        Ok(resp) => no_store(axum::Json(resp).into_response()),
        Err(e) => oauth_json(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn form_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        h
    }

    #[test]
    fn client_parameters_are_split_from_the_form() {
        let req = client_form_request(
            &form_headers(),
            b"token=t&token_type_hint=refresh_token&client_id=c&client_secret=s",
        )
        .expect("request");
        assert_eq!(req.token().expect("token"), "t");
        assert_eq!(req.hint(), Some("refresh_token"));
        assert_eq!(req.auth.client_id.as_deref(), Some("c"));
        assert_eq!(req.auth.client_secret.as_deref(), Some("s"));
        assert!(!req.form.contains_key("client_secret"));
    }

    #[test]
    fn bad_requests_are_invalid_request() {
        let err = client_form_request(&HeaderMap::new(), b"token=t")
            .err()
            .expect("no form");
        assert_eq!(err.oauth_error(), "invalid_request");
        let err = client_form_request(&form_headers(), b"token=a&token=b")
            .err()
            .expect("repeated");
        assert_eq!(err.oauth_error(), "invalid_request");
        let req = client_form_request(&form_headers(), b"token=").expect("empty is omitted");
        assert_eq!(
            req.token().expect_err("missing").oauth_error(),
            "invalid_request"
        );
    }
}
