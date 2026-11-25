//! JWK Set endpoint (`GET {issuer}/jwks`): the tenant's published public keys (next, active and
//! not-yet-expired retired keys) through [`KeyService::jwks`]. Public keys only: the set is
//! assembled by anvil-jose, which rejects private members.
//!
//! Caching: `Cache-Control: public, max-age=3600` ([`JWKS_MAX_AGE`]) and a strong `ETag` (quoted
//! hex SHA-256 of the body). Key rotation publishes a key for at least `prepublish ≥ JWKS_MAX_AGE`
//! before it signs, so a relying party that honours the max-age always knows the signing key.
//! `If-None-Match` with the current tag answers `304 Not Modified` without a body.

use anvil_core::service::key::KeyService;
use anvil_core::service::key_rotation::JWKS_MAX_AGE;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::errors::oauth_json;
use crate::layers::cors::public_cors;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// Key service over this state's storage, KEK and clock.
    pub(crate) fn jwks_key_service(&self) -> KeyService {
        KeyService {
            storage: self.storage_arc(),
            kek: self.kek_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The quoted strong entity tag of a JWKS body.
fn etag_of(body: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = anvil_jose::encoding::sha256(body);
    let mut tag = String::with_capacity(digest.len() * 2 + 2);
    tag.push('"');
    for b in digest {
        tag.push(char::from(HEX[usize::from(b >> 4)]));
        tag.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    tag.push('"');
    tag
}

/// `If-None-Match` evaluation (RFC 9110 §13.1.2: `*` or any listed tag that matches under the
/// weak comparison the RFC prescribes for this header; our own tag is always strong).
fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|c| c == "*" || c.strip_prefix("W/").unwrap_or(c) == etag)
}

async fn jwks(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
) -> Response {
    let set = match state.jwks_key_service().jwks(tenant.tenant.id).await {
        Ok(set) => set,
        Err(e) => return oauth_json(&e),
    };
    let body = match serde_json::to_vec(&set) {
        Ok(b) => b,
        Err(_) => {
            return oauth_json(&anvil_core::error::CoreError::Internal(
                "JWKS serialisation failed".to_owned(),
            ));
        }
    };
    let etag = etag_of(&body);
    let mut resp = if not_modified(&headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response()
    };
    let h = resp.headers_mut();
    let cache = format!("public, max-age={}", JWKS_MAX_AGE.whole_seconds());
    if let Ok(v) = HeaderValue::from_str(&cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    resp
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/jwks", get(jwks)).layer(public_cors())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_is_quoted_hex_sha256() {
        assert_eq!(
            etag_of(b""),
            "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
        );
    }

    #[test]
    fn if_none_match_matching() {
        let tag = "\"abc\"";
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
            h
        };
        assert!(not_modified(&with("\"abc\""), tag));
        assert!(not_modified(&with("\"x\", \"abc\""), tag));
        assert!(not_modified(&with("*"), tag));
        assert!(not_modified(&with("W/\"abc\""), tag));
        assert!(!not_modified(&with("\"abd\""), tag));
        assert!(!not_modified(&with("abc"), tag));
        assert!(!not_modified(&HeaderMap::new(), tag));
    }
}
