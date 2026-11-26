//! UserInfo endpoint (OIDC Core §5.3): `GET /userinfo` and `POST /userinfo`.
//!
//! The access token is accepted as a Bearer token in the `Authorization` header (GET or POST) or
//! as the `access_token` field of a form body (POST, RFC 6750 §2.2). It is never accepted in the
//! query (RFC 9700 §2.3 / RFC 6750 §2.3 "SHOULD NOT"): a query `access_token` is refused, and a
//! token sent in more than one way is `invalid_request` (RFC 6750 §2). Verification is the single
//! [`UserInfoService`] / `AccessTokenVerifier` implementation in anvil-core.

use anvil_core::error::CoreError;
use anvil_core::service::userinfo::UserInfoService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::errors::oauth_json;
use crate::layers::cors::public_cors;
use crate::protocol::token::{is_form, no_store, parse_form};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The UserInfo service on this state's ports.
    pub(crate) fn userinfo_service(&self) -> UserInfoService {
        UserInfoService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            attribute_check: self.attribute_check(),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/userinfo", get(userinfo).post(userinfo))
        .layer(public_cors())
}

fn invalid_token() -> CoreError {
    CoreError::InvalidToken("the access token is invalid or expired".to_owned())
}

/// The token of an `Authorization: Bearer <token>` header (scheme case-insensitive).
fn bearer_from_header(value: &str) -> Result<String, CoreError> {
    let (scheme, token) = value.trim().split_once(' ').ok_or_else(invalid_token)?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || token.contains(' ') {
        return Err(invalid_token());
    }
    Ok(token.to_owned())
}

/// Picks the single presented access token. Pure.
fn extract_token(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, CoreError> {
    if let Some(q) = uri.query()
        && url::form_urlencoded::parse(q.as_bytes()).any(|(k, _)| k == "access_token")
    {
        // Tokens in URLs leak through logs and Referer; refuse rather than ignore.
        return Err(invalid_token());
    }
    let from_header = match headers.get(header::AUTHORIZATION) {
        None => None,
        Some(v) => Some(bearer_from_header(
            v.to_str().map_err(|_| invalid_token())?,
        )?),
    };
    let from_body = if *method == Method::POST && is_form(headers) {
        parse_form(body)?.remove("access_token")
    } else {
        None
    };
    match (from_header, from_body) {
        (Some(_), Some(_)) => Err(CoreError::InvalidRequest(
            "the access token must be sent in exactly one way".to_owned(),
        )),
        (Some(t), None) | (None, Some(t)) => Ok(t),
        (None, None) => Err(invalid_token()),
    }
}

async fn userinfo(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let token = match extract_token(&method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(e) => return oauth_json(&e),
    };
    match state
        .userinfo_service()
        .userinfo(&tenant.tenant, &tenant.issuer, &token)
        .await
    {
        Ok(claims) => no_store(axum::Json(claims).into_response()),
        Err(e) => oauth_json(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(auth: Option<&'static str>, form: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = auth {
            h.insert(header::AUTHORIZATION, HeaderValue::from_static(a));
        }
        if form {
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
        }
        h
    }

    fn uri(s: &'static str) -> Uri {
        Uri::from_static(s)
    }

    #[test]
    fn header_token_on_get_and_post() {
        for m in [Method::GET, Method::POST] {
            let t = extract_token(
                &m,
                &uri("/userinfo"),
                &headers(Some("Bearer abc"), false),
                b"",
            )
            .expect("token");
            assert_eq!(t, "abc");
        }
        let t = extract_token(
            &Method::GET,
            &uri("/userinfo"),
            &headers(Some("bearer abc"), false),
            b"",
        )
        .expect("case-insensitive scheme");
        assert_eq!(t, "abc");
    }

    #[test]
    fn body_token_only_on_form_post() {
        let t = extract_token(
            &Method::POST,
            &uri("/userinfo"),
            &headers(None, true),
            b"access_token=abc",
        )
        .expect("token");
        assert_eq!(t, "abc");
        // Not a form: the body is ignored.
        let err = extract_token(
            &Method::POST,
            &uri("/userinfo"),
            &headers(None, false),
            b"access_token=abc",
        )
        .expect_err("no token");
        assert_eq!(err.oauth_error(), "invalid_token");
    }

    #[test]
    fn query_token_is_refused() {
        let err = extract_token(
            &Method::GET,
            &uri("/userinfo?access_token=abc"),
            &headers(None, false),
            b"",
        )
        .expect_err("query");
        assert_eq!(err.http_status(), 401);
        // Also next to a valid header.
        assert!(
            extract_token(
                &Method::GET,
                &uri("/userinfo?access_token=abc"),
                &headers(Some("Bearer abc"), false),
                b"",
            )
            .is_err()
        );
    }

    #[test]
    fn header_and_body_together_are_invalid_request() {
        let err = extract_token(
            &Method::POST,
            &uri("/userinfo"),
            &headers(Some("Bearer abc"), true),
            b"access_token=abc",
        )
        .expect_err("both");
        assert_eq!(err.oauth_error(), "invalid_request");
    }

    #[test]
    fn malformed_headers_are_invalid_token() {
        for h in ["Bearer", "Bearer ", "Basic abc", "Bearer a b", "abc"] {
            let mut map = HeaderMap::new();
            map.insert(header::AUTHORIZATION, HeaderValue::from_static(h));
            let err =
                extract_token(&Method::GET, &uri("/userinfo"), &map, b"").expect_err("malformed");
            assert_eq!(err.oauth_error(), "invalid_token", "{h}");
        }
    }
}
